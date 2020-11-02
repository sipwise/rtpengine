#include "websocket.h"
#include <libwebsockets.h>
#include <assert.h>
#include <json-glib/json-glib.h>
#include "log.h"
#include "main.h"
#include "str.h"
#include "cli.h"
#include "control_ng.h"


struct websocket_message;
struct websocket_conn;


struct websocket_output {
	GString *str;
	size_t str_done;
	enum lws_write_protocol protocol;
};

struct websocket_conn {
	// used in the single threaded libwebsockets context
	struct lws *wsi;
	endpoint_t endpoint;
	char *uri; // for websocket connections only
	struct websocket_message *wm; // while in progress

	// multithreaded message processing
	mutex_t lock;
	unsigned int jobs;
	GQueue messages;
	cond_t cond;

	// output buffer - also protected by lock
	GQueue outout_q;
};


static GQueue websocket_vhost_configs;
static struct lws_context *websocket_context;
static GThreadPool *websocket_threads;


static struct websocket_message *websocket_message_new(struct websocket_conn *wc) {
	struct websocket_message *wm = g_slice_alloc0(sizeof(*wm));
	wm->body = g_string_new("");
	wm->wc = wc;
	return wm;
}


static void websocket_message_free(struct websocket_message **wm) {
	if ((*wm)->body)
		g_string_free((*wm)->body, TRUE);
	if ((*wm)->uri)
		free((*wm)->uri);
	g_slice_free1(sizeof(**wm), *wm);
	*wm = NULL;
}


static struct websocket_output *websocket_output_new(void) {
	struct websocket_output *wo = g_slice_alloc0(sizeof(*wo));
	// str remains NULL -> unused output slot
	return wo;
}

static void websocket_output_free(void *p) {
	struct websocket_output *wo = p;
	if (wo->str)
		g_string_free(wo->str, TRUE);
	g_slice_free1(sizeof(*wo), wo);
}


// appends to output buffer without triggering a response - unlocked
static void __websocket_queue_raw(struct websocket_conn *wc, const char *msg, size_t len) {
	struct websocket_output *wo = g_queue_peek_tail(&wc->outout_q);

	if (!wo->str) {
		wo->str = g_string_new("");
		// allocate pre-buffer
		g_string_set_size(wo->str, LWS_PRE);
		wo->str_done = LWS_PRE;
	}

	if (msg && len)
		g_string_append_len(wo->str, msg, len);
}


// appends to output buffer without triggering a response
void websocket_queue_raw(struct websocket_conn *wc, const char *msg, size_t len) {
	mutex_lock(&wc->lock);
	__websocket_queue_raw(wc, msg, len);
	mutex_unlock(&wc->lock);
}


// num bytes in output buffer
size_t websocket_queue_len(struct websocket_conn *wc) {
	mutex_lock(&wc->lock);
	size_t ret = 0;
	for (GList *l = wc->outout_q.head; l; l = l->next) {
		struct websocket_output *wo = l->data;
		ret += (wo->str->len - LWS_PRE);
	}
	mutex_unlock(&wc->lock);
	return ret;
}


// adds data to output buffer (can be null) and optionally triggers specified response
int websocket_write_raw(struct websocket_conn *wc, const char *msg, size_t len,
		enum lws_write_protocol protocol, int done)
{
	mutex_lock(&wc->lock);
	__websocket_queue_raw(wc, msg, len);
	struct websocket_output *wo = g_queue_peek_tail(&wc->outout_q);
	wo->protocol = protocol;
	g_queue_push_tail(&wc->outout_q, websocket_output_new());

	if (done) {
		lws_callback_on_writable(wc->wsi);
		lws_cancel_service(websocket_context);
	}

	mutex_unlock(&wc->lock);

	return 0;
}


// adds data to output buffer (can be null) and triggers specified response: http or binary websocket
int websocket_write_http_len(struct websocket_conn *wc, const char *msg, size_t len, int done) {
	return websocket_write_raw(wc, msg, len, LWS_WRITE_HTTP, done);
}
int websocket_write_http(struct websocket_conn *wc, const char *msg, int done) {
	return websocket_write_http_len(wc, msg, msg ? strlen(msg) : 0, done);
}
int websocket_write_text(struct websocket_conn *wc, const char *msg, int done) {
	return websocket_write_raw(wc, msg, strlen(msg), LWS_WRITE_TEXT, done);
}
int websocket_write_binary(struct websocket_conn *wc, const char *msg, size_t len, int done) {
	return websocket_write_raw(wc, msg, len, LWS_WRITE_BINARY, done);
}


void websocket_write_next(struct websocket_conn *wc) {
	mutex_lock(&wc->lock);
	g_queue_push_tail(&wc->outout_q, websocket_output_new());
	mutex_unlock(&wc->lock);
}


static const char *websocket_echo_process(struct websocket_message *wm) {
	ilog(LOG_DEBUG, "Returning %lu bytes websocket echo from %s", (unsigned long) wm->body->len,
			endpoint_print_buf(&wm->wc->endpoint));
	websocket_write_binary(wm->wc, wm->body->str, wm->body->len, 1);
	return NULL;
}


static void websocket_message_push(struct websocket_conn *wc, websocket_message_func_t func) {
	struct websocket_message *wm = wc->wm;
	assert(wm != NULL);

	ilog(LOG_DEBUG, "Adding HTTP/WS message to processing queue");

	wm->func = func;

	mutex_lock(&wc->lock);
	g_queue_push_tail(&wc->messages, wm);
	wc->jobs++;
	g_thread_pool_push(websocket_threads, wc, NULL);
	mutex_unlock(&wc->lock);

	wc->wm = websocket_message_new(wc);
}


static void websocket_process(void *p, void *up) {
	struct websocket_conn *wc = p;

	mutex_lock(&wc->lock);
	struct websocket_message *wm = g_queue_pop_head(&wc->messages);
	mutex_unlock(&wc->lock);

	assert(wm != NULL);

	const char *err = wm->func(wm);

	websocket_message_free(&wm);
	mutex_lock(&wc->lock);
	assert(wc->jobs >= 1);
	wc->jobs--;
	cond_signal(&wc->cond);
	mutex_unlock(&wc->lock);

	if (err)
		ilog(LOG_ERR, "Error while processing HTTP/WS message: %s", err);
}


static int websocket_dequeue(struct websocket_conn *wc) {
	if (!wc)
		return 0;

	mutex_lock(&wc->lock);
	struct websocket_output *wo;
	while ((wo = g_queue_pop_head(&wc->outout_q))) {
		// used buffer slot?
		if (wo->str) {
			// allocate post-buffer
			g_string_set_size(wo->str, wo->str->len + LWS_SEND_BUFFER_POST_PADDING);
			size_t to_send = wo->str->len - wo->str_done - LWS_SEND_BUFFER_POST_PADDING;
			if (to_send) {
				if (to_send > 500)
					ilog(LOG_DEBUG, "Writing %lu bytes to LWS", (unsigned long) to_send);
				else
					ilog(LOG_DEBUG, "Writing back to LWS: '%.*s'",
							(int) to_send, wo->str->str + wo->str_done);
				size_t ret = lws_write(wc->wsi, (unsigned char *) wo->str->str + wo->str_done,
						to_send, wo->protocol);
				if (ret != to_send)
					ilog(LOG_ERR, "Invalid LWS write: %lu != %lu",
							(unsigned long) ret,
							(unsigned long) to_send);
				wo->str_done += ret;
			}
		}
		websocket_output_free(wo);
	}
	g_queue_push_tail(&wc->outout_q, websocket_output_new());
	mutex_unlock(&wc->lock);

	return 0;
}

static const char *websocket_do_http_response(struct websocket_conn *wc, int status, const char *content_type,
		ssize_t content_length)
{
	uint8_t buf[LWS_PRE + 2048], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - LWS_PRE - 1];

	if (lws_add_http_header_status(wc->wsi, status, &p, end))
		return "Failed to add HTTP status";
	if (content_type)
		if (lws_add_http_header_by_token(wc->wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
					(const unsigned char *) content_type,
					strlen(content_type), &p, end))
			return "Failed to add content-type";
	if (content_length >= 0)
		if (lws_add_http_header_content_length(wc->wsi, content_length, &p, end))
			return "Failed to add HTTP headers to response";
	if (lws_finalize_http_header(wc->wsi, &p, end))
		return "Failed to write HTTP headers";

	size_t len = p - start;
	if (lws_write(wc->wsi, start, len, LWS_WRITE_HTTP_HEADERS) != len)
		return "Failed to write HTTP headers";

	return NULL;
}
int websocket_http_response(struct websocket_conn *wc, int status, const char *content_type,
		ssize_t content_length)
{
	const char *err = websocket_do_http_response(wc, status, content_type, content_length);
	if (!err)
		return 0;
	ilog(LOG_ERR, "Failed to write HTTP response headers: %s", err);
	return -1;
}


static const char *websocket_http_ping(struct websocket_message *wm) {
	ilog(LOG_DEBUG, "Respoding to GET /ping");

	if (websocket_http_response(wm->wc, 200, "text/plain", 5))
		return "Failed to write response HTTP headers";
	if (websocket_write_http(wm->wc, "pong\n", 1))
		return "Failed to write pong response";

	return NULL;
}


// adds printf string to output buffer without triggering response
static void websocket_queue_printf(struct cli_writer *cw, const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	char *s = g_strdup_vprintf(fmt, va);
	va_end(va);
	websocket_queue_raw(cw->ptr, s, strlen(s));
	g_free(s);
}


static const char *websocket_http_cli(struct websocket_message *wm) {
	assert(strncmp(wm->uri, "/cli/", 5) == 0);
	char *uri = wm->uri+5;

	ilog(LOG_DEBUG, "Respoding to GET /cli/%s", uri);

	str uri_cmd;
	str_init(&uri_cmd, uri);

	struct cli_writer cw = {
		.cw_printf = websocket_queue_printf,
		.ptr = wm->wc,
	};
	cli_handle(&uri_cmd, &cw);

	size_t len = websocket_queue_len(wm->wc);

	if (websocket_http_response(wm->wc, 200, "text/plain", len))
		return "Failed to write response HTTP headers";
	if (websocket_write_http(wm->wc, NULL, 1))
		return "Failed to write pong response";

	return NULL;
}


static const char *websocket_cli_process(struct websocket_message *wm) {
	ilog(LOG_DEBUG, "Processing websocket CLI req '%s'", wm->body->str);

	str uri_cmd;
	str_init_len(&uri_cmd, wm->body->str, wm->body->len);

	struct cli_writer cw = {
		.cw_printf = websocket_queue_printf,
		.ptr = wm->wc,
	};
	cli_handle(&uri_cmd, &cw);

	websocket_write_binary(wm->wc, NULL, 0, 1);
	return NULL;
}


static void websocket_ng_send_ws(str *cookie, str *body, const endpoint_t *sin, void *p1) {
	struct websocket_conn *wc = p1;
	websocket_queue_raw(wc, cookie->s, cookie->len);
	websocket_queue_raw(wc, " ", 1);
	websocket_queue_raw(wc, body->s, body->len);
	websocket_write_binary(wc, NULL, 0, 1);
}
static void websocket_ng_send_http(str *cookie, str *body, const endpoint_t *sin, void *p1) {
	struct websocket_conn *wc = p1;
	if (websocket_http_response(wc, 200, "application/x-rtpengine-ng", cookie->len + 1 + body->len))
		ilog(LOG_WARN, "Failed to write HTTP headers");
	websocket_queue_raw(wc, cookie->s, cookie->len);
	websocket_queue_raw(wc, " ", 1);
	websocket_queue_raw(wc, body->s, body->len);
	websocket_write_http(wc, NULL, 1);
}
static const char *websocket_ng_process(struct websocket_message *wm) {
	char addr[64];
	endpoint_print(&wm->wc->endpoint, addr, sizeof(addr));

	ilog(LOG_DEBUG, "Processing websocket NG req from %s", addr);

	str cmd;
	str_init_len(&cmd, wm->body->str, wm->body->len);

	control_ng_process(&cmd, &wm->wc->endpoint, addr, websocket_ng_send_ws, wm->wc);

	return NULL;
}
static const char *websocket_http_ng(struct websocket_message *wm) {
	char addr[64];

	endpoint_print(&wm->wc->endpoint, addr, sizeof(addr));

	ilog(LOG_DEBUG, "Respoding to POST /ng from %s", addr);

	str cmd;
	str_init_len(&cmd, wm->body->str, wm->body->len);

	if (control_ng_process(&cmd, &wm->wc->endpoint, addr, websocket_ng_send_http, wm->wc)) {
		websocket_http_response(wm->wc, 500, "text/plain", 6);
		websocket_write_http(wm->wc, "error\n", 1);
	}

	return NULL;
}




static int websocket_http_get(struct websocket_conn *wc) {
	struct websocket_message *wm = wc->wm;
	const char *uri = wm->uri;
	websocket_message_func_t handler = NULL;

	ilog(LOG_DEBUG, "HTTP GET from %s: '%s'", endpoint_print_buf(&wc->endpoint), wm->uri);
	wm->method = M_GET;

	if (!strcmp(uri, "/ping"))
		handler = websocket_http_ping;
	else if (!strncmp(uri, "/cli/", 5))
		handler = websocket_http_cli;

	if (!handler) {
		ilog(LOG_WARN, "Unhandled HTTP GET URI: '%s'", uri);
		websocket_http_response(wm->wc, 404, "text/plain", 10);
		websocket_write_http(wm->wc, "not found\n", 1);
		return 0;
	}

	websocket_message_push(wc, handler);
	return 0;
}


static int websocket_http_post(struct websocket_conn *wc) {
	struct websocket_message *wm = wc->wm;

	ilog(LOG_DEBUG, "HTTP POST from %s: '%s'", endpoint_print_buf(&wc->endpoint), wm->uri);
	wm->method = M_POST;

	char ct[64];
	if (lws_hdr_total_length(wc->wsi, WSI_TOKEN_HTTP_CONTENT_TYPE) >= sizeof(ct)) {
		ilog(LOG_WARN, "Too long content-type header, rejecting HTTP POST");
		return -1;
	}

	if (lws_hdr_copy(wc->wsi, ct, sizeof(ct)-1, WSI_TOKEN_HTTP_CONTENT_TYPE) <= 0) {
		ilog(LOG_WARN, "Failed to get Content-type header, rejecting HTTP POST");
		return -1;
	}

	if (lws_hdr_total_length(wc->wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH) <= 0) {
		ilog(LOG_WARN, "Failed to get Content-length header, rejecting HTTP POST");
		return -1;
	}

	ilog(LOG_DEBUG, "POST content-type: %s", ct);

	if (!strcasecmp(ct, "application/json"))
		wm->content_type = CT_JSON;
	else if (!strcasecmp(ct, "application/x-rtpengine-ng"))
		wm->content_type = CT_NG;
	else
		ilog(LOG_WARN, "Unsupported content-type '%s'", ct);

	return 0;
}


static int websocket_http_body(struct websocket_conn *wc, const char *body, size_t len) {
	struct websocket_message *wm = wc->wm;
	const char *uri = wm->uri;
	websocket_message_func_t handler = NULL;

	if (wm->method != M_POST) {
		ilog(LOG_WARN, "Rejecting HTTP body on unsupported method");
		return -1;
	}

	if (len) {
		ilog(LOG_DEBUG, "HTTP body: %lu bytes", (unsigned long) len);
		g_string_append_len(wm->body, body, len);
		return 0;
	}

	ilog(LOG_DEBUG, "HTTP body complete: '%.*s'", (int) wm->body->len, wm->body->str);

	if (!strcmp(uri, "/ng") && wm->method == M_POST && wm->content_type == CT_NG)
		handler = websocket_http_ng;

	if (!handler) {
		ilog(LOG_WARN, "Unhandled HTTP POST URI: '%s'", wm->uri);
		websocket_http_response(wm->wc, 404, "text/plain", 10);
		websocket_write_http(wm->wc, "not found\n", 1);
		return 0;
	}

	websocket_message_push(wc, handler);
	return 0;
}


static void websocket_conn_cleanup(struct websocket_conn *wc) {
	if (!wc)
		return;
	if (!wc->wsi) // not initialised
		return;

	// wait until all remaining tasks are finished
	mutex_lock(&wc->lock);
	while (wc->jobs)
		cond_wait(&wc->cond, &wc->lock);
	mutex_unlock(&wc->lock);

	assert(wc->messages.length == 0);

	g_string_free(wc->wm->body, TRUE);
	if (wc->wm->uri)
		free(wc->wm->uri);
	g_slice_free1(sizeof(*wc->wm), wc->wm);
	wc->wm = NULL;
	g_queue_clear_full(&wc->outout_q, websocket_output_free);
	if (wc->uri)
		free(wc->uri);

	mutex_destroy(&wc->lock);

	memset(wc, 0, sizeof(*wc));
}


static void websocket_conn_init(struct lws *wsi, void *p) {
	struct websocket_conn *wc = p;

	if (!wc)
		return;

	memset(wc, 0, sizeof(*wc));
	wc->wsi = wsi;
	mutex_init(&wc->lock);
	cond_init(&wc->cond);
	g_queue_init(&wc->messages);
	g_queue_push_tail(&wc->outout_q, websocket_output_new());

	struct sockaddr_storage sa = {0,};
	socklen_t sl = sizeof(sa);
#if LWS_LIBRARY_VERSION_MAJOR >= 3
	struct lws *network_wsi = lws_get_network_wsi(wsi);
	int fd = lws_get_socket_fd(network_wsi);
	if (fd == -1) {
		// SSL?
		SSL *ssl = lws_get_ssl(network_wsi);
		if (ssl)
			fd = SSL_get_fd(ssl);
	}
#else
	int fd = lws_get_socket_fd(wsi);
#endif
	if (getpeername(fd, (struct sockaddr *) &sa, &sl))
		ilog(LOG_ERR, "Failed to get remote address of HTTP/WS connection (fd %i): %s",
				fd, strerror(errno));
	else
		endpoint_parse_sockaddr_storage(&wc->endpoint, &sa);

	wc->wm = websocket_message_new(wc);
}


static int websocket_do_http(struct lws *wsi, struct websocket_conn *wc, const char *uri) {
	ilog(LOG_DEBUG, "HTTP request start: %s", uri);

	websocket_conn_init(wsi, wc);
	wc->wm->uri = strdup(uri);

	if (lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI))
		return websocket_http_get(wc);
	if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI))
		return websocket_http_post(wc);

	ilog(LOG_INFO, "Ignoring HTTP request to %s with unsupported method", uri);
	return 0;
}


static int websocket_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in,
		size_t len)
{
	ilog(LOG_DEBUG, "http-only callback %i %p %p", reason, wsi, user);

	gettimeofday(&rtpe_now, NULL);

	switch (reason) {
		case LWS_CALLBACK_PROTOCOL_INIT:
		case LWS_CALLBACK_PROTOCOL_DESTROY:
		case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
		case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
#if LWS_LIBRARY_VERSION_MAJOR >= 4
		case LWS_CALLBACK_HTTP_CONFIRM_UPGRADE:
		case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
#endif
#if LWS_LIBRARY_VERSION_MAJOR >= 3
		case LWS_CALLBACK_ADD_HEADERS:
		case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		case LWS_CALLBACK_EVENT_WAIT_CANCELLED: // ?
#endif
			break;
		case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
			return -1; // disallow non supported websocket protocols
		case LWS_CALLBACK_GET_THREAD_ID:
			return (long int) pthread_self();
		case LWS_CALLBACK_WSI_CREATE:
			ilog(LOG_DEBUG, "WS client created %p", wsi);
			break;
		case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
			ilog(LOG_DEBUG, "New WS client %p", wsi);
			break;
		case LWS_CALLBACK_HTTP:
			return websocket_do_http(wsi, user, in);
		case LWS_CALLBACK_HTTP_BODY:
			if (len == 0)
				return 0;
			return websocket_http_body(user, in, len);
		case LWS_CALLBACK_HTTP_BODY_COMPLETION:
			return websocket_http_body(user, NULL, 0);
		case LWS_CALLBACK_CLOSED_HTTP:
			ilog(LOG_DEBUG, "HTTP connection closed %p", wsi);
			websocket_conn_cleanup(user);
			break;
		case LWS_CALLBACK_WSI_DESTROY:
			ilog(LOG_DEBUG, "WS client destroyed %p", wsi);
			break;
		case LWS_CALLBACK_ESTABLISHED:
		case LWS_CALLBACK_RECEIVE:
		case LWS_CALLBACK_CLOSED:
			ilog(LOG_WARN, "Invalid HTTP callback %i", reason);
			return -1;
		case LWS_CALLBACK_HTTP_WRITEABLE:
			return websocket_dequeue(user);
		default:
			ilog(LOG_DEBUG, "Unhandled HTTP callback %i", reason);
			break;
	}

	return 0;
}


static int websocket_protocol(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in,
		size_t len, websocket_message_func_t handler_func, const char *name)
{
	struct websocket_conn *wc = user;

	ilog(LOG_DEBUG, "Websocket protocol '%s' callback %i %p %p", name, reason, wsi, wc);

	gettimeofday(&rtpe_now, NULL);

	switch (reason) {
		case LWS_CALLBACK_PROTOCOL_INIT:
		case LWS_CALLBACK_PROTOCOL_DESTROY:
		case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
#if LWS_LIBRARY_VERSION_MAJOR >= 4
		case LWS_CALLBACK_WS_SERVER_BIND_PROTOCOL:
		case LWS_CALLBACK_WS_SERVER_DROP_PROTOCOL:
#endif
#if LWS_LIBRARY_VERSION_MAJOR >= 3
		case LWS_CALLBACK_ADD_HEADERS:
		case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
		case LWS_CALLBACK_EVENT_WAIT_CANCELLED: // ?
		case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
#endif
			break;
		case LWS_CALLBACK_GET_THREAD_ID:
			return (long int) pthread_self();
		case LWS_CALLBACK_ESTABLISHED:
			ilog(LOG_DEBUG, "Websocket protocol '%s' established", name);
			websocket_conn_init(wsi, wc);
			int get_len = lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI);
			if (get_len > 0) {
				wc->uri = malloc(get_len + 1);
				if (wc->uri) {
					if (lws_hdr_copy(wsi, wc->uri, get_len + 1, WSI_TOKEN_GET_URI) <= 0) {
						free(wc->uri);
						wc->uri = NULL;
					}
				}
			}
			break;
		case LWS_CALLBACK_CLOSED:
			ilog(LOG_DEBUG, "Websocket protocol '%s' closed", name);
			websocket_conn_cleanup(wc);
			ilog(LOG_DEBUG, "Websocket protocol '%s' ready for cleanup", name);
			break;
		case LWS_CALLBACK_RECEIVE:;
			ilog(LOG_DEBUG, "Websocket protocol '%s' data received for '%s': '%.*s'",
					name, wc->uri, (int) len, (const char *) in);
			wc->wm->method = M_WEBSOCKET;
			g_string_append_len(wc->wm->body, in, len);
			websocket_message_push(wc, handler_func);
			break;
		case LWS_CALLBACK_SERVER_WRITEABLE:
			return websocket_dequeue(user);
		default:
			ilog(LOG_DEBUG, "Unhandled websocket protocol '%s' callback %i", name, reason);
			break;
	}

	return 0;
}


static int websocket_rtpengine_echo(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in,
		size_t len)
{
	return websocket_protocol(wsi, reason, user, in, len, websocket_echo_process, "echo.rtpengine.com");
}
static int websocket_rtpengine_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in,
		size_t len)
{
	return websocket_protocol(wsi, reason, user, in, len, websocket_cli_process, "rtpengine-cli");
}
static int websocket_rtpengine_ng(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in,
		size_t len)
{
	return websocket_protocol(wsi, reason, user, in, len, websocket_ng_process, "rtpengine-ng");
}


static const struct lws_protocols websocket_protocols[] = {
	{
		.name = "http-only",
		.callback = websocket_http,
		.per_session_data_size = sizeof(struct websocket_conn),
	},
	{
		.name = "echo.rtpengine.com",
		.callback = websocket_rtpengine_echo,
		.per_session_data_size = sizeof(struct websocket_conn),
	},
	{
		.name = "cli.rtpengine.com",
		.callback = websocket_rtpengine_cli,
		.per_session_data_size = sizeof(struct websocket_conn),
	},
	{
		.name = "ng.rtpengine.com",
		.callback = websocket_rtpengine_ng,
		.per_session_data_size = sizeof(struct websocket_conn),
	},
	{ 0, }
};


static void websocket_log(int level, const char *line) {
	if ((level & LLL_ERR))
		level = LOG_ERR;
	else if ((level & LLL_WARN))
		level = LOG_WARN;
	else if ((level & LLL_NOTICE))
		level = LOG_NOTICE;
	else if ((level & LLL_INFO))
		level = LOG_INFO;
	else
		level = LOG_DEBUG;
	ilog(level, "libwebsockets: %s", line);
}


static void websocket_cleanup(void) {
	if (websocket_context)
		lws_context_destroy(websocket_context);
	websocket_context = NULL;
	if (websocket_threads)
		g_thread_pool_free(websocket_threads, TRUE, TRUE);
	websocket_threads = NULL;

	while (websocket_vhost_configs.length) {
		struct lws_context_creation_info *vhost = g_queue_pop_head(&websocket_vhost_configs);
		free((void *) vhost->iface);
		free(vhost);
	}
}


int websocket_init(void) {
	assert(websocket_context == NULL);

	if ((!rtpe_config.http_ifs || !*rtpe_config.http_ifs) &&
			(!rtpe_config.https_ifs || !*rtpe_config.https_ifs))
		return 0;

	const char *err = NULL;

	lws_set_log_level(LLL_ERR | LLL_WARN, websocket_log);

	struct lws_context_creation_info wci = {
		.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
#if LWS_LIBRARY_VERSION_MAJOR >= 4
			LWS_SERVER_OPTION_FAIL_UPON_UNABLE_TO_BIND |
#endif
			0,
	};
	websocket_context = lws_create_context(&wci);
	err = "Failed to create LWS context";
	if (!websocket_context)
		goto err;

	for (char **ifp = rtpe_config.http_ifs; ifp && *ifp; ifp++) {
		char *ifa = *ifp;
		ilog(LOG_DEBUG, "Starting HTTP/WS '%s'", ifa);
		endpoint_t ep;
		err = "Failed to parse address/port";
		if (endpoint_parse_any_getaddrinfo(&ep, ifa))
			goto err;

		struct lws_context_creation_info *vhost = malloc(sizeof(*vhost));
		g_queue_push_tail(&websocket_vhost_configs, vhost);

		*vhost = (struct lws_context_creation_info) {
			.port = ep.port,
			.iface = strdup(sockaddr_print_buf(&ep.address)),
			.protocols = websocket_protocols,
		};
		vhost->vhost_name = vhost->iface;
		err = "LWS failed to create vhost";
		if (!lws_create_vhost(websocket_context, vhost))
			goto err;
	}

	for (char **ifp = rtpe_config.https_ifs; ifp && *ifp; ifp++) {
		err = "HTTPS/WSS listener requested, but no certificate given";
		if (!rtpe_config.https_cert)
			goto err;

		char *ifa = *ifp;
		ilog(LOG_DEBUG, "Starting HTTPS/WSS '%s'", ifa);
		endpoint_t ep;
		err = "Failed to parse address/port";
		if (endpoint_parse_any_getaddrinfo(&ep, ifa))
			goto err;

		struct lws_context_creation_info *vhost = malloc(sizeof(*vhost));
		g_queue_push_tail(&websocket_vhost_configs, vhost);

		*vhost = (struct lws_context_creation_info) {
			.port = ep.port,
			.iface = strdup(sockaddr_print_buf(&ep.address)),
			.protocols = websocket_protocols,
			.ssl_cert_filepath = rtpe_config.https_cert,
			.ssl_private_key_filepath = rtpe_config.https_key ? : rtpe_config.https_cert,
			.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT,
			// XXX cipher list, key password
		};
		vhost->vhost_name = vhost->iface;
		err = "LWS failed to create vhost";
		if (!lws_create_vhost(websocket_context, vhost))
			goto err;
	}

	int num_threads = rtpe_config.http_threads ? : rtpe_config.num_threads;
	websocket_threads = g_thread_pool_new(websocket_process, NULL, num_threads, FALSE, NULL);

	ilog(LOG_DEBUG, "Websocket init complete with %i threads", num_threads);
	return 0;

err:
	ilog(LOG_ERROR, "Failed to start websocket listener: %s", err);
	websocket_cleanup();
	return -1;
}

static void websocket_loop(void *p) {
	ilog(LOG_INFO, "Websocket listener thread running");
	while (!rtpe_shutdown)
		lws_service(websocket_context, 100);

	websocket_cleanup();
}

void websocket_start(void) {
	if (!websocket_context)
		return;
	thread_create_detach_prio(websocket_loop, NULL, rtpe_config.scheduling, rtpe_config.priority);
}
