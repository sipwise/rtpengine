#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <belle-sip/belle-sip.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib.h>
#include <stdbool.h>


// XXX replace char* with char[] below

struct call_info;

struct auth_info {
	char *username;
	char *domain;
	char *passwd;
};

struct transaction {
	int response_waker;

	// handler:
	void (*response)(struct transaction *, int code, const belle_sip_response_event_t *,
			belle_sip_response_t *, belle_sip_client_transaction_t *, belle_sip_provider_t *);

	// for register & invite:
	bool auth;
	bool done;

	// for invite:
	struct call *call;
};

struct listener {
	char *username;
	char *domain;
	int incoming_waker;
	GQueue calls; // struct call
};

// corresponds to a sip_dialog_t
struct call {
	belle_sip_provider_t *sip_provider;
	belle_sip_dialog_t *dlg;
	belle_sip_server_transaction_t *strans; // pending received invite
	belle_sip_client_transaction_t *ctrans; // pending outgoing invite
	enum {
		CS_INC_PENDING = 0,
		CS_INC_RINGING, // 180 sent
		CS_INC_MEDIA,   // 183 sent
		CS_OUT_PENDING, // INVITE sent
		CS_OUT_RINGING, // 180 received
		CS_OUT_MEDIA,   // 183 received
		CS_ESTABLISHED,
		CS_DEAD,
	} state;
	int terminate_waker;
};

struct call_info {
	char call_id[256];
	char body[8192]; // SDP etc
	char content_type[256];
	char from_addr[256];
	char to_addr[256];
	char from_tag[256];
	char to_tag[256];
	struct call *call;
};


static belle_sip_stack_t *sipstack;
static belle_sip_main_loop_t *main_loop;
static pthread_mutex_t main_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t run_mutex = PTHREAD_MUTEX_INITIALIZER;
static int wake_fds[2];

static pthread_mutex_t auth_mutex = PTHREAD_MUTEX_INITIALIZER;
static GHashTable *auth_info;

static pthread_mutex_t listen_mutex = PTHREAD_MUTEX_INITIALIZER;
static GHashTable *listeners;

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static GQueue logs = G_QUEUE_INIT;
static int log_fd = -1;



#define FD_TO_PTR(x) ((void *) ((long) (x)))
#define PTR_TO_FD(x) ((int) ((long) (x)))



static struct auth_info *get_auth_info(const char *un, const char *dom) {
	if (!un || !dom)
		return NULL;

	const struct auth_info req = {.username = (char *) un, .domain = (char *) dom};
	return g_hash_table_lookup(auth_info, &req);
}


#define CONCAT2(a, b) a ## b
#define CONCAT(a, b) CONCAT2(a, b)

typedef struct {
	pthread_mutex_t *m;
} lock_t;
static void auto_unlock(lock_t *l) {
	pthread_mutex_unlock(l->m);
}
static lock_t auto_lock(pthread_mutex_t *l) {
	pthread_mutex_lock(l);
	return (lock_t) {l};
}
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(lock_t, auto_unlock);
#define LOCK(m) g_auto(lock_t) CONCAT(__l, __COUNTER__) __attribute__((unused)) = auto_lock(m)


static void set_auth_info(const char *un, const char *dom, const char *pw) {
	if (!un || !dom || !pw)
		return; // XXX fail?

	LOCK(&auth_mutex);

	struct auth_info *ai = get_auth_info(un, dom);
	if (!ai) {
		ai = g_new0(struct auth_info, 1);
		ai->username = g_strdup(un);
		ai->domain = g_strdup(dom);
		g_hash_table_insert(auth_info, ai, ai);
	}

	g_free(ai->passwd);
	ai->passwd = g_strdup(pw);
}


static void log_handler(const char *domain, BctbxLogLevel lev, const char *fmt, va_list args)
{
	char *s = g_strdup_vprintf(fmt, args);
	char *p = g_strdup_printf("[%d] [%s] %s", lev, domain, s);
	g_free(s);

	LOCK(&log_mutex);
	g_queue_push_tail(&logs, p);

	if (log_fd != -1)
		(void) write(log_fd, "1", 1);
}


static void log_int(BctbxLogLevel lev, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	log_handler("internal", lev, fmt, ap);
	va_end(ap);
}


#define ASSERT_RET_VAL(a, v, m, ...) do { \
	if (G_UNLIKELY(!(a))) { \
		log_int(BCTBX_LOG_TRACE, "[%s:%d]" m, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
		return v; \
	} \
} while (0)

#define ASSERT_RET(a, m, ...) ASSERT_RET_VAL(a, (void)0, m, ##__VA_ARGS__)
#define ASSERT_RET_NULL(a, m, ...) ASSERT_RET_VAL(a, NULL, m, ##__VA_ARGS__)
#define ASSERT_RET_FALSE(a, m, ...) ASSERT_RET_VAL(a, false, m, ##__VA_ARGS__)


static void auth_resp(struct transaction *t, const belle_sip_response_event_t *event,
		belle_sip_client_transaction_t *trans,
		belle_sip_provider_t *sip_provider)
{
	struct call *c = NULL;

	belle_sip_dialog_t *dlg = belle_sip_response_event_get_dialog(event);
	if (dlg) {
		c = belle_sip_dialog_get_application_data(dlg);
		ASSERT_RET(c, "auth response without dialog");
		belle_sip_dialog_set_application_data(dlg, NULL);
	}

	belle_sip_request_t *req = belle_sip_client_transaction_create_authenticated_request(trans,
			NULL, NULL);
	ASSERT_RET(req, "failed to cast transaction to request");

	// create new transaction and move transaction & call objects
	belle_sip_transaction_set_application_data(BELLE_SIP_TRANSACTION(trans), NULL);

	trans = belle_sip_provider_create_client_transaction(sip_provider, req);
	ASSERT_RET(trans, "failed to create client transaction");

	belle_sip_transaction_set_application_data(BELLE_SIP_TRANSACTION(trans), t);
	t->auth = true;

	if (dlg) {
		belle_sip_dialog_set_application_data(dlg, NULL);

		dlg = belle_sip_provider_create_dialog(sip_provider, BELLE_SIP_TRANSACTION(trans));
		belle_sip_dialog_set_application_data(dlg, c);

		if (c->dlg)
			belle_sip_object_unref(c->dlg);

		c->dlg = dlg;
		belle_sip_object_ref(c->dlg);
	}

	belle_sip_client_transaction_send_request_to(trans, NULL);
}


static void reg_response(struct transaction *t, int code,
		const belle_sip_response_event_t *event,
		belle_sip_response_t *res,
		belle_sip_client_transaction_t *trans, belle_sip_provider_t *sip_provider)
{
	if (code == 401 && !t->auth)
		auth_resp(t, event, trans, sip_provider);
	else if (code == 200) {
		if (!t->done) {
			t->done = true;
			write(t->response_waker, "1", 1);

			belle_sip_refresher_t *rfr = belle_sip_client_transaction_create_refresher(trans);
			ASSERT_RET(rfr, "failed to create refresher");
			// XXX remove refresher on unreg
		}
	}
	else if (code >= 400) {
		if (!t->done) {
			t->done = true;
			write(t->response_waker, "0", 1);
		}
	}
	else {
		// XXX ?
	}
}


static void transaction_free(struct transaction *t) {
	g_free(t);
}


static void res_event(void *user_ctx, const belle_sip_response_event_t *event)
{
	ASSERT_RET(event, "empty event");

	belle_sip_provider_t *sip_provider = user_ctx;

	belle_sip_response_t *res = belle_sip_response_event_get_response(event);
	ASSERT_RET(res, "no response from event");

	int code = belle_sip_response_get_status_code(res);

	belle_sip_client_transaction_t *trans = belle_sip_response_event_get_client_transaction(event);
	ASSERT_RET(trans, "no transaction from event");

	struct transaction *t = belle_sip_transaction_get_application_data(BELLE_SIP_TRANSACTION(trans));

	ASSERT_RET(t, "no user transaction object");

	t->response(t, code, event, res, trans, sip_provider);
}


static void ua_unlisten(const char *un, const char *dom) {
	const struct listener lx = {.username = (char *) un, .domain = (char *) dom};

	LOCK(&listen_mutex);

	struct listener *l = NULL;
	g_hash_table_steal_extended(listeners, &lx, (void **) &l, NULL);

	if (!l)
		return;

	write(l->incoming_waker, "0", 1);
	g_free(l);
}


static void ua_listen(const char *un, const char *dom, int fd) {
	if (fd == -1) {
		ua_unlisten(un, dom);
		return;
	}

	struct listener *l = g_new0(struct listener, 1);
	l->username = g_strdup(un);
	l->domain = g_strdup(dom);
	l->incoming_waker = fd;

	LOCK(&listen_mutex);
	ASSERT_RET(g_hash_table_lookup(listeners, l) == NULL, "duplicate listener");
	g_hash_table_insert(listeners, l, l);
}


static struct listener *get_listener(const char *un, const char *dom) {
	const struct listener l = {.username = (char *) un, .domain = (char *) dom};
	return g_hash_table_lookup(listeners, &l);
}


static void req_invite(belle_sip_provider_t *sip_provider, belle_sip_request_t *req,
		const belle_sip_request_event_t *event)
{
	belle_sip_message_t *msg = BELLE_SIP_MESSAGE(req);

	belle_sip_server_transaction_t *trans = belle_sip_request_event_get_server_transaction(event);
	ASSERT_RET(trans == NULL, "server transaction already exists");

	trans = belle_sip_provider_create_server_transaction(sip_provider, req);
	ASSERT_RET(trans, "failed to create server transaction");

	belle_sip_header_to_t *to = belle_sip_message_get_header_by_type(msg, belle_sip_header_to_t);
	ASSERT_RET(to, "failed to create TO header");

	belle_sip_header_address_t *toa = BELLE_SIP_HEADER_ADDRESS(to);
	ASSERT_RET(toa, "failed to cast to header address");

	belle_sip_uri_t *to_uri = belle_sip_header_address_get_uri(toa);
	ASSERT_RET(to_uri, "failed to get URI");

	belle_sip_dialog_t *dlg = belle_sip_request_event_get_dialog(event);
	ASSERT_RET(!dlg, "dialog already exists");

	LOCK(&listen_mutex);
	struct listener *l = get_listener(belle_sip_uri_get_user(to_uri), belle_sip_uri_get_host(to_uri));
	if (!l) {
		belle_sip_response_t *res = belle_sip_response_create_from_request(req, 410);
		ASSERT_RET(res, "failed to create response");

		belle_sip_provider_send_response(sip_provider, res);

		return;
	}

	dlg = belle_sip_provider_create_dialog(sip_provider, BELLE_SIP_TRANSACTION(trans));
	ASSERT_RET(dlg, "failed to create dialog");

	struct call *c = g_new0(struct call, 1);
	c->terminate_waker = -1;

	c->sip_provider = sip_provider;
	belle_sip_object_ref(sip_provider);

	c->dlg = dlg;
	belle_sip_object_ref(dlg);

	c->strans = trans;
	belle_sip_object_ref(trans);

	belle_sip_dialog_set_application_data(dlg, c);

	// call belongs to listener
	g_queue_push_tail(&l->calls, c);

	write(l->incoming_waker, "1", 1);
}


static void req_cancel(belle_sip_provider_t *sip_provider, belle_sip_request_t *req,
		const belle_sip_request_event_t *event)
{
	belle_sip_dialog_t *dlg = belle_sip_request_event_get_dialog(event);
	ASSERT_RET(dlg, "no dialog");

	struct call *c = belle_sip_dialog_get_application_data(dlg);
	ASSERT_RET(c, "no call object");

	if (c->state != CS_DEAD) {
		if (c->terminate_waker != -1)
			write(c->terminate_waker, "1", 1);

		c->state = CS_DEAD;
	}

	// send "cancelled"
	belle_sip_request_t *ireq = belle_sip_transaction_get_request(BELLE_SIP_TRANSACTION(c->strans));
	ASSERT_RET(ireq, "no request from transaction");

	belle_sip_response_t *res = belle_sip_response_create_from_request(ireq, 487);
	ASSERT_RET(res, "failed to create response");

	belle_sip_message_t *msg = BELLE_SIP_MESSAGE(res);
	ASSERT_RET(msg, "failed to cast to message");

	belle_sip_message_add_header(msg, BELLE_SIP_HEADER(belle_sip_header_contact_new()));

	belle_sip_server_transaction_send_response(c->strans, res);

	// ok to cancel
	res = belle_sip_response_create_from_request(req, 200);
	ASSERT_RET(res, "failed to create response");

	belle_sip_provider_send_response(c->sip_provider, res);
}


static void req_bye(belle_sip_provider_t *sip_provider, belle_sip_request_t *req,
		const belle_sip_request_event_t *event)
{
	belle_sip_dialog_t *dlg = belle_sip_request_event_get_dialog(event);
	if (!dlg) {
		// XXX send resp?
		return;
	}

	struct call *c = belle_sip_dialog_get_application_data(dlg);
	ASSERT_RET(c, "no application call object");

	if (c->state != CS_DEAD) {
		if (c->terminate_waker != -1)
			write(c->terminate_waker, "1", 1);

		c->state = CS_DEAD;
	}

	belle_sip_server_transaction_t *trans = belle_sip_request_event_get_server_transaction(event);
	ASSERT_RET(!trans, "server transaction already exists");

	trans = belle_sip_provider_create_server_transaction(sip_provider, req);
	ASSERT_RET(trans, "failed to create transaction");

	belle_sip_response_t *res = belle_sip_response_create_from_request(req, 200);
	ASSERT_RET(res, "failed to create response");

	belle_sip_server_transaction_send_response(trans, res);
}


static void req_event(void *user_ctx, const belle_sip_request_event_t *event)
{
	ASSERT_RET(event, "empty event");

	belle_sip_provider_t *sip_provider = user_ctx;

	belle_sip_request_t *req = belle_sip_request_event_get_request(event);
	ASSERT_RET(req, "no request from event");

	const char *method = belle_sip_request_get_method(req);
	ASSERT_RET(method, "empty method");

	if (!strcmp(method, "OPTIONS")) {
		belle_sip_response_t *res = belle_sip_response_create_from_request(req, 200);
		ASSERT_RET(res, "failed to create response");

		belle_sip_provider_send_response(sip_provider, res);
	}
	else if (!strcmp(method, "INVITE"))
		req_invite(sip_provider, req, event);
	else if (!strcmp(method, "CANCEL"))
		req_cancel(sip_provider, req, event);
	else if (!strcmp(method, "BYE"))
		req_bye(sip_provider, req, event);
	else if (!strcmp(method, "ACK"))
	{}
	else {
		belle_sip_response_t *res = belle_sip_response_create_from_request(req, 501);
		ASSERT_RET(res, "failed to create response");

		belle_sip_provider_send_response(sip_provider, res);
	}
}


static void timeout(void *user_ctx, const belle_sip_timeout_event_t *event)
{
	printf("%s\n", __FUNCTION__);
}


static void trans_terminated(void *user_ctx, const belle_sip_transaction_terminated_event_t *event)
{
	belle_sip_transaction_t *trans = NULL;

	belle_sip_client_transaction_t *ctrans = belle_sip_transaction_terminated_event_get_client_transaction(event);

	if (ctrans)
		trans = BELLE_SIP_TRANSACTION(ctrans);
	else {
		belle_sip_server_transaction_t *strans = belle_sip_transaction_terminated_event_get_server_transaction(event);
		if (strans)
			trans = BELLE_SIP_TRANSACTION(strans);
	}

	ASSERT_RET(trans, "no transaction");

	struct transaction *t = belle_sip_transaction_get_application_data(BELLE_SIP_TRANSACTION(trans));

	if (t)
		transaction_free(t);
}


static void dlg_terminated(void *user_ctx, const belle_sip_dialog_terminated_event_t *event)
{
	belle_sip_dialog_t *dlg = belle_sip_dialog_terminated_event_get_dialog(event);
	if (!dlg)
		return;

	struct call *c = belle_sip_dialog_get_application_data(dlg);
	if (!c)
		return;

	if (c->state == CS_DEAD)
		return;

	if (c->terminate_waker != -1)
		write(c->terminate_waker, "1", 1);

	c->state = CS_DEAD;
}


static void auth_request(void *user_ctx, belle_sip_auth_event_t *auth_event)
{
	LOCK(&auth_mutex);

	struct auth_info *ai = get_auth_info(belle_sip_auth_event_get_username(auth_event),
			belle_sip_auth_event_get_domain(auth_event));

	if (ai)
		belle_sip_auth_event_set_passwd(auth_event, ai->passwd);
	// XXX else error
}


static void lst_destroy(void *user_ctx)
{
	printf("%s\n", __FUNCTION__);
}

static void io_error(void *user_ctx, const belle_sip_io_error_event_t *error)
{
	printf("%s\n", __FUNCTION__);
}

static const belle_sip_listener_callbacks_t callbacks = {
	.process_dialog_terminated = dlg_terminated,
	.process_io_error = io_error,
	.process_request_event = req_event,
	.process_response_event = res_event,
	.process_timeout = timeout,
	.process_transaction_terminated = trans_terminated,
	.process_auth_requested = auth_request,
	.listener_destroyed = lst_destroy,
};


static void *bg_loop(void *p) {
	ASSERT_RET_NULL(main_loop, "library not initialised");

	LOCK(&run_mutex);

	while (true) {
		pthread_mutex_unlock(&run_mutex);

		pthread_mutex_lock(&main_mutex);

		belle_sip_main_loop_run(main_loop);

		pthread_mutex_unlock(&main_mutex);

		pthread_mutex_lock(&run_mutex);
	}

	return NULL;
}


typedef struct {
} sip_stack_lock_t;


static sip_stack_lock_t lock_sip_stack(void) {
	assert(main_loop);

	pthread_mutex_lock(&run_mutex);

	(void) write(wake_fds[1], "x", 1);

	pthread_mutex_lock(&main_mutex);

	return (sip_stack_lock_t) {};
}


static void unlock_sip_stack(void) {
	pthread_mutex_unlock(&run_mutex);
	pthread_mutex_unlock(&main_mutex);
}


static void auto_unlock_sip_stack(sip_stack_lock_t *s) {
	unlock_sip_stack();
}
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(sip_stack_lock_t, auto_unlock_sip_stack);
#define LOCK_SIP_STACK() g_auto(sip_stack_lock_t) CONCAT(__l, __COUNTER__) __attribute__((unused)) = lock_sip_stack()


static int pipe_read(void *p, unsigned int ev) {
	char b;
	(void) read(wake_fds[0], &b, 1);

	belle_sip_main_loop_quit(main_loop);

	return BELLE_SIP_CONTINUE;
}


static guint auth_info_hash(const void *p) {
	const struct auth_info *h = p;
	return g_str_hash(h->username) ^ g_str_hash(h->domain);
}


static gboolean auth_info_eq(const void *p, const void *q) {
	const struct auth_info *a = p;
	const struct auth_info *b = q;
	return g_str_equal(a->username, b->username) && g_str_equal(a->domain, b->domain);
}


static guint listener_hash(const void *p) {
	const struct listener *h = p;
	return g_str_hash(h->username) ^ g_str_hash(h->domain);
}


static gboolean listener_eq(const void *p, const void *q) {
	const struct listener *a = p;
	const struct listener *b = q;
	return g_str_equal(a->username, b->username) && g_str_equal(a->domain, b->domain);
}


static void auth_info_free(void *p) {
	struct auth_info *h = p;
	g_free(h->username);
	g_free(h->domain);
	g_free(h->passwd);
	g_free(h);
}


bool bsw_init(void) {
	ASSERT_RET_FALSE(!sipstack, "library already initialised");

	auth_info = g_hash_table_new_full(auth_info_hash, auth_info_eq, auth_info_free, NULL);
	listeners = g_hash_table_new(listener_hash, listener_eq);

	bctbx_set_log_handler(log_handler);

	sipstack = belle_sip_stack_new(NULL);
	ASSERT_RET_FALSE(sipstack, "failed to initialise library");

	int ret = pipe2(wake_fds, O_NONBLOCK); // XXX close at exit
	ASSERT_RET_FALSE(ret == 0, "failed to create pipe");

	main_loop = belle_sip_stack_get_main_loop(sipstack);
	ASSERT_RET_FALSE(main_loop, "failed to create main loop");

	belle_sip_source_t *src = belle_sip_socket_source_new(pipe_read, NULL,
			wake_fds[0], BELLE_SIP_EVENT_READ, -1);
	belle_sip_main_loop_add_source(main_loop, src);

	pthread_t thr;
	pthread_create(&thr, NULL, bg_loop, NULL);

	return true;
}


void bsw_set_logger(int ll, int fd) {
	ASSERT_RET(fd != -1, "invalid logging fd");

	lock_sip_stack();

	belle_sip_set_log_level(ll);

	unlock_sip_stack();

	LOCK(&log_mutex);

	ASSERT_RET(log_fd == -1, "logger already set");
	log_fd = fd;

	for (unsigned int i = 0; i < logs.length; i++)
		(void) write(fd, "1", 1);
}


bool bsw_get_log(char *o, size_t len) {
	LOCK(&log_mutex);

	char *s = g_queue_pop_head(&logs);

	if (!s) {
		pthread_mutex_unlock(&log_mutex);
		return false;
	}

	g_strlcpy(o, s, len);

	g_free(s);

	return true;
}


belle_sip_provider_t *bsw_provider(const char *addr, int port, const char *proto) {
	LOCK_SIP_STACK();

	belle_sip_listening_point_t *lp =
		belle_sip_stack_create_listening_point(sipstack, addr, port, proto);
	ASSERT_RET_NULL(lp, "failed to create listening point");
	belle_sip_provider_t *sip_provider = belle_sip_stack_create_provider(sipstack, lp);
	ASSERT_RET_NULL(sip_provider, "failed to create provider");
	belle_sip_listener_t *lstn = belle_sip_listener_create_from_callbacks(&callbacks, sip_provider);
	ASSERT_RET_NULL(lstn, "failed to create listener");
	belle_sip_provider_add_sip_listener(sip_provider, lstn);

	return sip_provider;
}


void bsw_register(belle_sip_provider_t *sip_provider, int fd, const char *uri, const char *pw, int dur) {
	LOCK_SIP_STACK();

	belle_sip_uri_t *u = belle_sip_uri_parse(uri); // "sip:bench2user000005@guest02-snail.lab.sipwise.com"
	ASSERT_RET(u, "failed to parse URI");

	set_auth_info(belle_sip_uri_get_user(u), belle_sip_uri_get_host(u), pw);

	belle_sip_uri_t *uo = BELLE_SIP_URI(belle_sip_object_clone(BELLE_SIP_OBJECT(u)));
	ASSERT_RET(uo, "failed to clone URI");
	belle_sip_uri_set_user(uo, NULL); // "sip:guest02-snail.lab.sipwise.com"

	belle_sip_request_t *req = belle_sip_request_create(
			uo,
			"REGISTER",
			belle_sip_provider_create_call_id(sip_provider),
			belle_sip_header_cseq_create(1, "REGISTER"),
			belle_sip_header_from_create2(uri, BELLE_SIP_RANDOM_TAG),
			belle_sip_header_to_create2(uri, NULL),
			belle_sip_header_via_new(),
			70);
	ASSERT_RET(req, "failed to create request");

	belle_sip_message_t *msg = BELLE_SIP_MESSAGE(req);
	ASSERT_RET(msg, "failed to cast to message");

	belle_sip_message_add_header(msg, BELLE_SIP_HEADER(belle_sip_header_expires_create(dur)));
	belle_sip_message_add_header(msg, BELLE_SIP_HEADER(belle_sip_header_contact_new()));

	belle_sip_client_transaction_t *trans = belle_sip_provider_create_client_transaction(sip_provider, req);
	ASSERT_RET(trans, "failed to create transaction");

	struct transaction *t = g_new0(struct transaction, 1);
	t->response = reg_response;
	t->response_waker = fd;

	belle_sip_transaction_set_application_data(BELLE_SIP_TRANSACTION(trans), t);

	int res = belle_sip_client_transaction_send_request_to(trans, NULL);
	ASSERT_RET(res == 0, "failed to send request");
}


void bsw_listen(belle_sip_provider_t *sip_provider, int fd, const char *uri)
{
	LOCK_SIP_STACK();

	belle_sip_uri_t *u = belle_sip_uri_parse(uri); // "sip:bench2user000005@guest02-snail.lab.sipwise.com"
	ASSERT_RET(u, "failed to parse URI");

	ua_listen(belle_sip_uri_get_user(u), belle_sip_uri_get_host(u), fd);
}


bool bsw_receive(belle_sip_provider_t *sip_provider, const char *uri, struct call_info *info)
{
	LOCK_SIP_STACK();

	belle_sip_uri_t *u = belle_sip_uri_parse(uri); // "sip:bench2user000005@guest02-snail.lab.sipwise.com"
	ASSERT_RET_FALSE(u, "failed to parse URI");

	LOCK(&listen_mutex);

	struct listener *l = get_listener(belle_sip_uri_get_user(u), belle_sip_uri_get_host(u));
	if (!l)
		return false;

	if (l->calls.length == 0)
		return false;

	// transfer ownership to the external object
	struct call *c = g_queue_pop_head(&l->calls);
	info->call = c;

	belle_sip_request_t *req = belle_sip_transaction_get_request(BELLE_SIP_TRANSACTION(c->strans));
	ASSERT_RET_FALSE(req, "no request from transaction");

	belle_sip_message_t *msg = BELLE_SIP_MESSAGE(req);
	ASSERT_RET_FALSE(msg, "failed to cast to message");

	const char *s = belle_sip_message_get_body(msg);
	if (s)
		g_strlcpy(info->body, s, sizeof(info->body));

	belle_sip_header_content_type_t *ct = belle_sip_message_get_header_by_type(msg,
			belle_sip_header_content_type_t);
	if (ct) {
		s = belle_sip_header_content_type_get_type(ct);
		ASSERT_RET_FALSE(s, "failed to get content-type");
		g_strlcpy(info->content_type, s, sizeof(info->content_type));
	}

	belle_sip_header_from_t *from = belle_sip_message_get_header_by_type(msg, belle_sip_header_from_t);
	ASSERT_RET_FALSE(from, "no FROM header");

	belle_sip_header_address_t *addr = BELLE_SIP_HEADER_ADDRESS(from);
	ASSERT_RET_FALSE(addr, "no address in FROM header");

	belle_sip_uri_t *uh = belle_sip_header_address_get_uri(addr);
	ASSERT_RET_FALSE(uh, "no URI in FROM address");

	const char *un = belle_sip_uri_get_user(uh);
	const char *dm = belle_sip_uri_get_host(uh);
	const char *tg = belle_sip_header_from_get_tag(from);

	snprintf(info->from_addr, sizeof(info->from_addr), "%s@%s", un, dm);
	if (tg)
		g_strlcpy(info->from_tag, tg, sizeof(info->from_tag));

	belle_sip_header_to_t *to = belle_sip_message_get_header_by_type(msg, belle_sip_header_to_t);
	ASSERT_RET_FALSE(to, "no TO header");

	addr = BELLE_SIP_HEADER_ADDRESS(to);
	ASSERT_RET_FALSE(addr, "no address in TO header");

	uh = belle_sip_header_address_get_uri(addr);
	ASSERT_RET_FALSE(uh, "no URI in TO address");

	un = belle_sip_uri_get_user(uh);
	dm = belle_sip_uri_get_host(uh);
	tg = belle_sip_header_to_get_tag(to);

	snprintf(info->to_addr, sizeof(info->to_addr), "%s@%s", un, dm);
	if (tg)
		g_strlcpy(info->to_tag, tg, sizeof(info->to_tag));

	belle_sip_header_call_id_t *cidh = belle_sip_message_get_header_by_type(msg, belle_sip_header_call_id_t);
	ASSERT_RET_FALSE(cidh, "no CALL ID header");
	const char *cid = belle_sip_header_call_id_get_call_id(cidh);
	ASSERT_RET_FALSE(cid, "empty CALL ID header");

	g_strlcpy(info->call_id, cid, sizeof(info->call_id));

	return true;
}

void bsw_call_destroy(struct call *c) {
	LOCK_SIP_STACK();

	ASSERT_RET(c->dlg, "no dialog associated with call");

	belle_sip_dialog_set_application_data(c->dlg, NULL);
	if (c->strans)
		belle_sip_object_unref(c->strans);
	if (c->ctrans)
		belle_sip_object_unref(c->ctrans);
	belle_sip_object_unref(c->dlg);

	// XXX make sure info/pointers from pending invite transaction is removed

	g_free(c);
}


static bool bsw_call_reply(struct call *c, int code, const char *sdp) {
	if (code == 180) {
		if (c->state != CS_INC_PENDING)
			return false;
		c->state = CS_INC_RINGING;
	}
	else if (code == 183) {
		if (c->state != CS_INC_PENDING && c->state != CS_INC_RINGING)
			return false;
		c->state = CS_INC_MEDIA;
	}
	else if (code == 200) {
		if (c->state != CS_INC_PENDING && c->state != CS_INC_RINGING && c->state != CS_INC_MEDIA)
			return false;
		c->state = CS_ESTABLISHED;
	}
	else if (code >= 400) {
		if (c->state != CS_INC_PENDING && c->state != CS_INC_RINGING && c->state != CS_INC_MEDIA)
			return false;

		if (c->terminate_waker != -1)
			write(c->terminate_waker, "1", 1);

		c->state = CS_DEAD;
	}
	else 
		return false;

	belle_sip_request_t *req = belle_sip_transaction_get_request(BELLE_SIP_TRANSACTION(c->strans));
	ASSERT_RET_FALSE(req, "no request from transaction");

	belle_sip_response_t *res = belle_sip_response_create_from_request(req, code);
	ASSERT_RET_FALSE(res, "failed to create response");

	belle_sip_message_t *msg = BELLE_SIP_MESSAGE(res);
	ASSERT_RET_FALSE(msg, "failed to cast to message");

	if (sdp) {
		belle_sip_message_set_body(msg, sdp, strlen(sdp));
		belle_sip_message_add_header(msg, BELLE_SIP_HEADER(belle_sip_header_content_type_create(
						"application", "sdp")));
	}

	belle_sip_message_add_header(msg, BELLE_SIP_HEADER(belle_sip_header_contact_new()));

	belle_sip_server_transaction_send_response(c->strans, res);

	return true;
}


bool bsw_call_answer(struct call *c, int code, const char *sdp) {
	LOCK_SIP_STACK();

	ASSERT_RET_FALSE(c->sip_provider, "provider link missing");
	ASSERT_RET_FALSE(c->dlg, "no dialog associated with call");
	ASSERT_RET_FALSE(c->strans, "no transaction associated with call");

	return bsw_call_reply(c, code, sdp);
}


bool bsw_call_finished(struct call *c, int fd) {
	ASSERT_RET_FALSE(fd != -1, "invalid fd");

	LOCK_SIP_STACK();

	if (c->state == CS_DEAD)
		return true;

	c->terminate_waker = fd;

	return false;
}


static bool bsw_call_bye(struct call *c) {
	belle_sip_request_t *req = belle_sip_dialog_create_request(c->dlg, "BYE");
	ASSERT_RET_FALSE(req, "failed to create request");

	belle_sip_client_transaction_t *trans = belle_sip_provider_create_client_transaction(c->sip_provider,
			req);
	ASSERT_RET_FALSE(trans, "failed to create transaction");

	belle_sip_client_transaction_send_request(trans);

	if (c->terminate_waker != -1)
		write(c->terminate_waker, "1", 1);

	c->state = CS_DEAD;

	return true;
}


static bool bsw_call_cancel(struct call *c) {
	belle_sip_request_t *req = belle_sip_dialog_create_request(c->dlg, "BYE");
	ASSERT_RET_FALSE(req, "failed to create request");

	belle_sip_client_transaction_t *trans = belle_sip_provider_create_client_transaction(c->sip_provider,
			req);
	ASSERT_RET_FALSE(trans, "failed to create transaction");

	belle_sip_client_transaction_send_request(trans);

	if (c->terminate_waker != -1)
		write(c->terminate_waker, "1", 1);

	c->state = CS_DEAD;

	return true;
}


bool bsw_call_terminate(struct call *c) {
	LOCK_SIP_STACK();

	ASSERT_RET_FALSE(c->sip_provider, "missing provider link");
	ASSERT_RET_FALSE(c->dlg, "no dialog associated with call");

	if (c->state == CS_DEAD)
		return false;

	switch (c->state) {
		case CS_DEAD:
			return false;

		case CS_ESTABLISHED:
			return bsw_call_bye(c);

		case CS_OUT_PENDING:
		case CS_OUT_RINGING:
		case CS_OUT_MEDIA:
			return bsw_call_cancel(c);

		case CS_INC_PENDING:
		case CS_INC_RINGING:
		case CS_INC_MEDIA:
			return bsw_call_reply(c, 407, NULL);
	}

	return false;
}


static void inv_response(struct transaction *t, int code,
		const belle_sip_response_event_t *event,
		belle_sip_response_t *res,
		belle_sip_client_transaction_t *trans, belle_sip_provider_t *sip_provider)
{
	belle_sip_dialog_t *dlg = belle_sip_response_event_get_dialog(event);

	belle_sip_message_t *msg = BELLE_SIP_MESSAGE(res);
	ASSERT_RET(msg, "failed to cast to message");

	struct call *c = t->call;

	if (code == 407 && !t->auth)
		auth_resp(t, event, trans, sip_provider);
	else if (code == 180) {
		if (c && c->state == CS_OUT_PENDING) {
			c->state = CS_OUT_RINGING;
			write(t->response_waker, "1", 1);
		}

		if (c->ctrans)
			belle_sip_object_unref(c->ctrans);
		c->ctrans = trans;
		belle_sip_object_ref(trans);
	}
	else if (code == 183) {
		if (c && (c->state == CS_OUT_PENDING || c->state == CS_OUT_RINGING)) {
			c->state = CS_OUT_MEDIA;
			write(t->response_waker, "1", 1);
		}

		if (c->ctrans)
			belle_sip_object_unref(c->ctrans);
		c->ctrans = trans;
		belle_sip_object_ref(trans);
	}
	else if (code == 200) {
		if (!t->done) {
			t->done = true;
			write(t->response_waker, "1", 1);

			if (c)
				c->state = CS_ESTABLISHED;
		}


		if (c->ctrans)
			belle_sip_object_unref(c->ctrans);
		c->ctrans = trans;
		belle_sip_object_ref(trans);

		ASSERT_RET(dlg, "no dialog");

		belle_sip_request_t *ack = belle_sip_dialog_create_ack(dlg,
				belle_sip_dialog_get_local_seq_number(dlg));
		ASSERT_RET(ack, "failed to create ACK");

		belle_sip_message_remove_header(BELLE_SIP_MESSAGE(ack), "Proxy-Authorization");

		belle_sip_dialog_send_ack(dlg, ack);

		t->call = NULL;
	}
	else if (code >= 400) {
		if (!t->done) {
			t->done = true;
			write(t->response_waker, "0", 1);

			if (c)
				c->state = CS_DEAD;
		}

		//t->info = NULL;
		t->call = NULL;
	}
	else {
		// XXX ?
	}
}


struct call *bsw_call_create(belle_sip_provider_t *sip_provider, struct call_info *info, int fd)
{
	ASSERT_RET_NULL(fd != -1, "invalid fd");

	struct call *c = g_new0(struct call, 1);
	c->terminate_waker = -1;
	c->state = CS_OUT_PENDING;

	struct transaction *t = g_new0(struct transaction, 1);
	t->response = inv_response;
	t->response_waker = fd;
	t->call = c;

	LOCK_SIP_STACK();

	c->sip_provider = sip_provider;
	belle_sip_object_ref(sip_provider);

	belle_sip_uri_t *tu = belle_sip_uri_parse(info->to_addr);
	ASSERT_RET_NULL(tu, "failed to parse URI");

	belle_sip_header_call_id_t *cidh = belle_sip_header_call_id_new();
	ASSERT_RET_NULL(cidh, "failed to create CALL ID header");
	belle_sip_header_call_id_set_call_id(cidh, info->call_id);

	belle_sip_header_from_t *fh = belle_sip_header_from_create2(info->from_addr, info->from_tag); // "sip:...@..."
	ASSERT_RET_NULL(fh, "failed to create FROM header");

	belle_sip_header_address_t *ta = belle_sip_header_address_create(NULL, tu);
	ASSERT_RET_NULL(ta, "failed to create TO address");

	belle_sip_header_to_t *th = belle_sip_header_to_create(ta, NULL);
	ASSERT_RET_NULL(th, "failed to create TO header");

	belle_sip_request_t *req = belle_sip_request_create(tu, "INVITE",
			cidh, belle_sip_header_cseq_create(20, "INVITE"),
			fh, th, belle_sip_header_via_new(), 70);

	belle_sip_message_t *msg = BELLE_SIP_MESSAGE(req);

	belle_sip_message_add_header(msg, BELLE_SIP_HEADER(belle_sip_header_contact_new()));

	size_t body_len = strlen(info->body);
	if (body_len) {
		belle_sip_message_set_body(msg, info->body, strlen(info->body));
		belle_sip_message_add_header(msg, BELLE_SIP_HEADER(belle_sip_header_content_type_create(
						"application", "sdp")));
	}

	belle_sip_client_transaction_t *trans = belle_sip_provider_create_client_transaction(sip_provider, req);

	belle_sip_dialog_t *dlg = belle_sip_provider_create_dialog(sip_provider, BELLE_SIP_TRANSACTION(trans));
	ASSERT_RET_NULL(dlg, "failed to create dialog");

	c->dlg = dlg;
	belle_sip_object_ref(dlg);

	belle_sip_transaction_set_application_data(BELLE_SIP_TRANSACTION(trans), t);
	belle_sip_dialog_set_application_data(dlg, c);

	c->ctrans = trans;
	belle_sip_object_ref(trans);

	belle_sip_client_transaction_send_request(trans);

	return c;
}


int bsw_call_wait(struct call *call, struct call_info *info) {
	int ret;

	LOCK_SIP_STACK();

	ASSERT_RET_VAL(call->ctrans, -1, "no client transaction");

	belle_sip_response_t *res = belle_sip_transaction_get_response(BELLE_SIP_TRANSACTION(call->ctrans));
	ASSERT_RET_VAL(res, -1, "no response from transaction");

	belle_sip_message_t *msg = BELLE_SIP_MESSAGE(res);
	ASSERT_RET_VAL(msg, -1, "failed to cast to message");

	const char *s = belle_sip_message_get_body(msg);
	if (s)
		g_strlcpy(info->body, s, sizeof(info->body));

	belle_sip_header_content_type_t *ct = belle_sip_message_get_header_by_type(msg,
			belle_sip_header_content_type_t);
	if (ct) {
		s = belle_sip_header_content_type_get_type(ct);
		ASSERT_RET_VAL(s, -1, "failed to get content-type");
		g_strlcpy(info->content_type, s, sizeof(info->content_type));
	}

	switch (call->state) {
		case CS_DEAD:
			ret = 400;
			break;

		case CS_OUT_PENDING:
			ret = 100;
			break;

		case CS_OUT_RINGING:
			ret = 180;
			break;

		case CS_OUT_MEDIA:
			ret = 183;
			break;

		case CS_ESTABLISHED:
			ret = 200;
			break;

		default:
			ret = 500;
			break;
	}

	return ret;
}
