#include "control_ng.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <json-glib/json-glib.h>

#include "obj.h"
#include "poller.h"
#include "bencode.h"
#include "log.h"
#include "cookie_cache.h"
#include "call.h"
#include "sdp.h"
#include "call_interfaces.h"
#include "socket.h"
#include "log_funcs.h"
#include "main.h"
#include "statistics.h"
#include "streambuf.h"
#include "str.h"
#include "homer.h"
#include "tcp_listener.h"
#include "main.h"

mutex_t rtpe_cngs_lock;
mutex_t tcp_connections_lock;
GHashTable *rtpe_cngs_hash;
GHashTable *tcp_connections_hash;
static struct cookie_cache ng_cookie_cache;
static bool trace_ng = false;

const char magic_load_limit_strings[__LOAD_LIMIT_MAX][64] = {
	[LOAD_LIMIT_MAX_SESSIONS] = "Parallel session limit reached",
	[LOAD_LIMIT_CPU] = "CPU usage limit exceeded",
	[LOAD_LIMIT_LOAD] = "Load limit exceeded",
	[LOAD_LIMIT_BW] = "Bandwidth limit exceeded",
};
const char *ng_command_strings[NGC_COUNT] = {
	"ping", "offer", "answer", "delete", "query", "list",
	"start recording", "stop recording", "pause recording",
	"start forwarding", "stop forwarding", "block DTMF",
	"unblock DTMF", "block media", "unblock media", "play media", "stop media",
	"play DTMF", "statistics", "silence media", "unsilence media",
	"publish", "subscribe request",
	"subscribe answer", "unsubscribe",
};
const char *ng_command_strings_esc[NGC_COUNT] = {
	"ping", "offer", "answer", "delete", "query", "list",
	"start_recording", "stop_recording", "pause_recording",
	"start_forwarding", "stop_forwarding", "block_DTMF",
	"unblock_DTMF", "block_media", "unblock_media", "play_media", "stop_media",
	"play_DTMF", "statistics", "silence_media", "unsilence_media",
	"publish", "subscribe_request",
	"subscribe_answer", "unsubscribe",
};
const char *ng_command_strings_short[NGC_COUNT] = {
	"Ping", "Offer", "Answer", "Delete", "Query", "List",
	"StartRec", "StopRec", "PauseRec",
	"StartFwd", "StopFwd", "BlkDTMF",
	"UnblkDTMF", "BlkMedia", "UnblkMedia", "PlayMedia", "StopMedia",
	"PlayDTMF", "Stats", "SlnMedia", "UnslnMedia",
	"Pub", "SubReq", "SubAns", "Unsub",
};

typedef struct ng_ctx {
	str callid;
	int command;
	str cookie;
	bool should_trace;
	const endpoint_t *sin_ep;
	const endpoint_t *local_ep;
} ng_ctx;

#define CH(func, ...) do { \
	if (trace_ng) \
		func( __VA_ARGS__); \
} while (0)

void init_ng_tracing(void) {
	if (rtpe_config.homer_ng_on &&  has_homer())
		trace_ng = true;
}

static GString *create_homer_msg(str *cookie, str *data) {
	GString *msg = g_string_sized_new(cookie->len + 1 + data->len);
	g_string_append_printf(msg, "%.*s %.*s", STR_FMT(cookie), STR_FMT(data));
	return msg;
}

static bool should_trace_msg(enum ng_command command) {
	switch (command) {
		case NGC_PING:
			return false;
		default:
			return true;
	}
}

static void homer_fill_values(ng_ctx *hctx, str *callid, int command) {
	if (hctx) {
		hctx->command = command;
		hctx->callid = *callid;
	}
}

static void homer_trace_msg_in(ng_ctx *hctx, str *data) {
	if (hctx) {
		hctx->should_trace = should_trace_msg(hctx->command);
		if (hctx->should_trace)	{
			struct timeval tv;
			gettimeofday(&tv, NULL);
			GString *msg = create_homer_msg(&hctx->cookie, data);
			homer_send(msg, &hctx->callid, hctx->sin_ep, hctx->local_ep, &tv, rtpe_config.homer_ng_capt_proto);
		}
	}
}

static void homer_trace_msg_out(ng_ctx *hctx, str *data) {
	if (hctx && hctx->should_trace) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		GString *msg = create_homer_msg(&hctx->cookie, data);
		homer_send(msg, &hctx->callid, hctx->local_ep, hctx->sin_ep, &tv, rtpe_config.homer_ng_capt_proto);
	}
}

static void pretty_print(bencode_item_t *el, GString *s) {
	bencode_item_t *chld;
	const char *sep;

	switch (el->type) {
		case BENCODE_STRING:
			g_string_append(s, "\"");
			g_string_append_len(s, el->iov[1].iov_base, el->iov[1].iov_len);
			g_string_append(s, "\"");
			break;

		case BENCODE_INTEGER:
			g_string_append_printf(s, "%lli", el->value);
			break;

		case BENCODE_LIST:
			g_string_append(s, "[ ");
			sep = "";
			for (chld = el->child; chld; chld = chld->sibling) {
				g_string_append(s, sep);
				pretty_print(chld, s);
				sep = ", ";
			}
			g_string_append(s, " ]");
			break;

		case BENCODE_DICTIONARY:
			g_string_append(s, "{ ");
			sep = "";
			for (chld = el->child; chld; chld = chld->sibling) {
				g_string_append(s, sep);
				pretty_print(chld, s);
				g_string_append(s, ": ");
				chld = chld->sibling;
				pretty_print(chld, s);
				sep = ", ";
			}
			g_string_append(s, " }");
			break;

		default:
			abort();
	}
}

struct control_ng_stats* get_control_ng_stats(const sockaddr_t *addr) {
	struct control_ng_stats* cur;

	mutex_lock(&rtpe_cngs_lock);
	cur = g_hash_table_lookup(rtpe_cngs_hash, addr);
	if (!cur) {
		cur = g_slice_alloc0(sizeof(struct control_ng_stats));
		cur->proxy = *addr;
		ilogs(control, LOG_DEBUG,"Adding a proxy for control ng stats:%s", sockaddr_print_buf(addr));

		for (int i = 0; i < NGC_COUNT; i++) {
			struct ng_command_stats *c = &cur->cmd[i];
			mutex_init(&c->lock);
		}

		g_hash_table_insert(rtpe_cngs_hash, &cur->proxy, cur);
	}
	mutex_unlock(&rtpe_cngs_lock);
	return cur;
}

static void __ng_buffer_free(void *p) {
	ng_buffer *ngbuf = p;
	bencode_buffer_free(&ngbuf->buffer);
	if (ngbuf->ref)
		obj_put_o(ngbuf->ref);
}

ng_buffer *ng_buffer_new(struct obj *ref) {
	ng_buffer *ngbuf = obj_alloc0("ng_buffer", sizeof(*ngbuf), __ng_buffer_free);
	if (ref)
		ngbuf->ref = obj_get_o(ref); // hold until we're done

	int ret = bencode_buffer_init(&ngbuf->buffer);
	assert(ret == 0);
	(void) ret;

	return ngbuf;
}

static void control_ng_process_payload(ng_ctx *hctx, str *reply, str *data, const endpoint_t *sin, char *addr, struct obj *ref,
		struct ng_buffer **ngbufp)
{
	bencode_item_t *dict, *resp;
	str cmd = STR_NULL, callid;
	const char *errstr, *resultstr;
	GString *log_str;
	struct timeval cmd_start, cmd_stop, cmd_process_time;
	struct control_ng_stats* cur = get_control_ng_stats(&sin->address);
	enum ng_command command = -1;

	struct ng_buffer *ngbuf = *ngbufp = ng_buffer_new(ref);

	resp = bencode_dictionary(&ngbuf->buffer);
	assert(resp != NULL);

	str *(*collapse_func)(bencode_item_t *root, str *out) = bencode_collapse_str;

	errstr = "Invalid data (no payload)";
	if (data->len <= 0)
		goto err_send;

	/* Bencode dictionary */
	if (data->s[0] == 'd') {
		dict = bencode_decode_expect_str(&ngbuf->buffer, data, BENCODE_DICTIONARY);
		errstr = "Could not decode bencode dictionary";
		if (!dict)
			goto err_send;
	}

	/* JSON */
	else if (data->s[0] == '{') {
		collapse_func = bencode_collapse_str_json;
		JsonParser *json = json_parser_new();
		bencode_buffer_destroy_add(&ngbuf->buffer, g_object_unref, json);
		errstr = "Failed to parse JSON document";
		if (!json_parser_load_from_data(json, data->s, data->len, NULL))
			goto err_send;
		dict = bencode_convert_json(&ngbuf->buffer, json);
		errstr = "Could not decode bencode dictionary";
		if (!dict || dict->type != BENCODE_DICTIONARY)
			goto err_send;
	}

	else {
		errstr = "Invalid NG data format";
		goto err_send;
	}

	bencode_dictionary_get_str(dict, "command", &cmd);
	errstr = "Dictionary contains no key \"command\"";
	if (!cmd.s)
		goto err_send;

	bencode_dictionary_get_str(dict, "call-id", &callid);
	log_info_str(&callid);

	ilogs(control, LOG_INFO, "Received command '"STR_FORMAT"' from %s", STR_FMT(&cmd), addr);

	if (get_log_level(control) >= LOG_DEBUG) {
		log_str = g_string_sized_new(256);
		g_string_append_printf(log_str, "Dump for '"STR_FORMAT"' from %s: %s", STR_FMT(&cmd), addr,
				rtpe_config.common.log_mark_prefix);
		pretty_print(dict, log_str);
		g_string_append(log_str, rtpe_config.common.log_mark_suffix);
		ilogs(control, LOG_DEBUG, "%.*s", (int) log_str->len, log_str->str);
		g_string_free(log_str, TRUE);
	}

	errstr = NULL;
	resultstr = "ok";

	// start command timer
	gettimeofday(&cmd_start, NULL);

	switch (__csh_lookup(&cmd)) {
		case CSH_LOOKUP("ping"):
			resultstr = "pong";
			command = NGC_PING;
			break;
		case CSH_LOOKUP("offer"):
			errstr = call_offer_ng(ngbuf, dict, resp, addr, sin);
			command = NGC_OFFER;
			break;
		case CSH_LOOKUP("answer"):
			errstr = call_answer_ng(ngbuf, dict, resp);
			command = NGC_ANSWER;
			break;
		case CSH_LOOKUP("delete"):
			errstr = call_delete_ng(dict, resp);
			command = NGC_DELETE;
			break;
		case CSH_LOOKUP("query"):
			errstr = call_query_ng(dict, resp);
			command = NGC_QUERY;
			break;
		case CSH_LOOKUP("list"):
			errstr = call_list_ng(dict, resp);
			command = NGC_LIST;
			break;
		case CSH_LOOKUP("start recording"):
			errstr = call_start_recording_ng(dict, resp);
			command = NGC_START_RECORDING;
			break;
		case CSH_LOOKUP("stop recording"):
			errstr = call_stop_recording_ng(dict, resp);
			command = NGC_STOP_RECORDING;
			break;
		case CSH_LOOKUP("pause recording"):
			errstr = call_pause_recording_ng(dict, resp);
			command = NGC_PAUSE_RECORDING;
			break;
		case CSH_LOOKUP("start forwarding"):
			errstr = call_start_forwarding_ng(dict, resp);
			command = NGC_START_FORWARDING;
			break;
		case CSH_LOOKUP("stop forwarding"):
			errstr = call_stop_forwarding_ng(dict, resp);
			command = NGC_STOP_FORWARDING;
			break;
		case CSH_LOOKUP("block DTMF"):
			errstr = call_block_dtmf_ng(dict, resp);
			command = NGC_BLOCK_DTMF;
			break;
		case CSH_LOOKUP("unblock DTMF"):
			errstr = call_unblock_dtmf_ng(dict, resp);
			command = NGC_UNBLOCK_DTMF;
			break;
		case CSH_LOOKUP("block media"):
			errstr = call_block_media_ng(dict, resp);
			command = NGC_BLOCK_MEDIA;
			break;
		case CSH_LOOKUP("unblock media"):
			errstr = call_unblock_media_ng(dict, resp);
			command = NGC_UNBLOCK_MEDIA;
			break;
		case CSH_LOOKUP("silence media"):
			errstr = call_silence_media_ng(dict, resp);
			command = NGC_SILENCE_MEDIA;
			break;
		case CSH_LOOKUP("unsilence media"):
			errstr = call_unsilence_media_ng(dict, resp);
			command = NGC_UNSILENCE_MEDIA;
			break;
		case CSH_LOOKUP("play media"):
			errstr = call_play_media_ng(dict, resp);
			command = NGC_PLAY_MEDIA;
			break;
		case CSH_LOOKUP("stop media"):
			errstr = call_stop_media_ng(dict, resp);
			command = NGC_STOP_MEDIA;
			break;
		case CSH_LOOKUP("play DTMF"):
			errstr = call_play_dtmf_ng(dict, resp);
			command = NGC_PLAY_DTMF;
			break;
		case CSH_LOOKUP("statistics"):
			errstr = statistics_ng(dict, resp);
			command = NGC_STATISTICS;
			break;
		case CSH_LOOKUP("publish"):
			errstr = call_publish_ng(ngbuf, dict, resp, addr, sin);
			command = NGC_PUBLISH;
			break;
		case CSH_LOOKUP("subscribe request"):
			errstr = call_subscribe_request_ng(dict, resp);
			command = NGC_SUBSCRIBE_REQ;
			break;
		case CSH_LOOKUP("subscribe answer"):
			errstr = call_subscribe_answer_ng(ngbuf, dict, resp);
			command = NGC_SUBSCRIBE_ANS;
			break;
		case CSH_LOOKUP("unsubscribe"):
			errstr = call_unsubscribe_ng(dict, resp);
			command = NGC_UNSUBSCRIBE;
			break;
		default:
			errstr = "Unrecognized command";
	}

	CH(homer_fill_values, hctx, &callid, command);
	CH(homer_trace_msg_in, hctx, data);

	// stop command timer
	gettimeofday(&cmd_stop, NULL);
	//print command duration
	timeval_from_us(&cmd_process_time, timeval_diff(&cmd_stop, &cmd_start));

	if (command >= 0 && command < NGC_COUNT) {
		mutex_lock(&cur->cmd[command].lock);
		cur->cmd[command].count++;
		timeval_add(&cur->cmd[command].time, &cur->cmd[command].time, &cmd_process_time);
		mutex_unlock(&cur->cmd[command].lock);
	}

	if (errstr)
		goto err_send;

	bencode_dictionary_add_string(resp, "result", resultstr);

	// update interval statistics
	RTPE_STATS_INC(ng_commands[command]);
	RTPE_STATS_SAMPLE(ng_command_times[command], timeval_us(&cmd_process_time));

	goto send_resp;

err_send:

	if (errstr < magic_load_limit_strings[0] || errstr > magic_load_limit_strings[__LOAD_LIMIT_MAX-1]) {
		ilogs(control, LOG_WARNING, "Protocol error in packet from %s: %s [" STR_FORMAT_M "]",
				addr, errstr, STR_FMT_M(data));
		bencode_dictionary_add_string(resp, "result", "error");
		bencode_dictionary_add_string(resp, "error-reason", errstr);
		g_atomic_int_inc(&cur->errors);
		cmd = STR_NULL;
	}
	else {
		bencode_dictionary_add_string(resp, "result", "load limit");
		bencode_dictionary_add_string(resp, "message", errstr);
	}

send_resp:
	collapse_func(resp, reply);

	if (cmd.s) {
		ilogs(control, LOG_INFO, "Replying to '"STR_FORMAT"' from %s (elapsed time %llu.%06llu sec)", STR_FMT(&cmd), addr, (unsigned long long)cmd_process_time.tv_sec, (unsigned long long)cmd_process_time.tv_usec);

		if (get_log_level(control) >= LOG_DEBUG) {
			dict = bencode_decode_expect_str(&ngbuf->buffer, reply, BENCODE_DICTIONARY);
			if (dict) {
				log_str = g_string_sized_new(256);
				g_string_append_printf(log_str, "Response dump for '"STR_FORMAT"' to %s: %s",
						STR_FMT(&cmd), addr,
						rtpe_config.common.log_mark_prefix);
				pretty_print(dict, log_str);
				g_string_append(log_str, rtpe_config.common.log_mark_suffix);
				ilogs(control, LOG_DEBUG, "%.*s", (int) log_str->len, log_str->str);
				g_string_free(log_str, TRUE);
			}
		}
	}

	release_closed_sockets();
	log_info_pop_until(&callid);
	CH(homer_trace_msg_out ,hctx, reply);
}

int control_ng_process(str *buf, const endpoint_t *sin, char *addr, const sockaddr_t *local,
		void (*cb)(str *, str *, const endpoint_t *, const sockaddr_t *, void *),
		void *p1, struct obj *ref)
{
	str data;
	str_chr_str(&data, buf, ' ');
	if (!data.s || data.s == buf->s) {
		ilogs(control, LOG_WARNING, "Received invalid NG data (no cookie) from %s: " STR_FORMAT_M,
				addr, STR_FMT_M(buf));
		return -1;
	}

	str cookie = *buf;
	cookie.len -= data.len;
	*data.s++ = '\0';
	data.len--;

	cache_entry *cached = cookie_cache_lookup(&ng_cookie_cache, &cookie);
	if (cached) {
		ilogs(control, LOG_INFO, "Detected command from %s as a duplicate", addr);

		ng_ctx hctx  = {.sin_ep = sin,
				.local_ep = p1 ? &(((socket_t*)p1)->local) : NULL,
				.cookie = cookie,
				.command = cached->command,
				.callid = *cached->callid,
				.should_trace = should_trace_msg(cached->command)};

		CH(homer_trace_msg_in, &hctx, &data);
		cb(&cookie, cached->reply, sin, local, p1);
		CH(homer_trace_msg_out, &hctx, cached->reply);

		cache_entry_free(cached);
		return 0;
	}

	str reply;
	g_autoptr(ng_buffer) ngbuf = NULL;

	ng_ctx hctx = {.sin_ep = sin,
			.local_ep = p1 ? &(((socket_t*)p1)->local) : NULL,
			.cookie = cookie,
			.command = -1};

	control_ng_process_payload(trace_ng ? &hctx : NULL,
								&reply, &data, sin, addr, ref, &ngbuf);

	cb(&cookie, &reply, sin, local, p1);
	cache_entry ce = {.reply = &reply, .command = hctx.command, .callid = &hctx.callid};
	cookie_cache_insert(&ng_cookie_cache, &cookie, &ce);

	return 0;
}

int control_ng_process_plain(str *data, const endpoint_t *sin, char *addr, const sockaddr_t *local,
		void (*cb)(str *, str *, const endpoint_t *, const sockaddr_t *, void *),
		void *p1, struct obj *ref)
{
	g_autoptr(ng_buffer) ngbuf = NULL;

	str reply;
	control_ng_process_payload(NULL, &reply, data, sin, addr, ref, &ngbuf);
	cb(NULL, &reply, sin, local, p1);

	return 0;
}

INLINE void control_ng_send_generic(str *cookie, str *body, const endpoint_t *sin, const sockaddr_t *from,
		void *p1)
{
	socket_t *ul = p1;
	struct iovec iov[3];
	unsigned int iovlen;

	iovlen = 3;

	iov[0].iov_base = cookie->s;
	iov[0].iov_len = cookie->len;
	iov[1].iov_base = " ";
	iov[1].iov_len = 1;
	iov[2].iov_base = body->s;
	iov[2].iov_len = body->len;

	socket_sendiov(ul, iov, iovlen, sin, from);
}
static void control_ng_send(str *cookie, str *body, const endpoint_t *sin, const sockaddr_t *from, void *p1) {
	control_ng_send_generic(cookie, body, sin, NULL, p1);
}
static void control_ng_send_from(str *cookie, str *body, const endpoint_t *sin, const sockaddr_t *from, void *p1) {
	control_ng_send_generic(cookie, body, sin, from, p1);
}

static void control_ng_incoming(struct obj *obj, struct udp_buffer *udp_buf)
{
	control_ng_process(&udp_buf->str, &udp_buf->sin, udp_buf->addr, &udp_buf->local_addr,
			control_ng_send_from, udp_buf->listener,
			&udp_buf->obj);
}

static void control_incoming(struct streambuf_stream *s) {
	ilog(LOG_INFO, "New TCP control ng connection from %s", s->addr);
	mutex_lock(&tcp_connections_lock);
	g_hash_table_insert(tcp_connections_hash, s->addr, s);
	mutex_unlock(&tcp_connections_lock);
	ilog(LOG_DEBUG, "TCP connections map size: %d", g_hash_table_size(tcp_connections_hash));
}

static void control_closed(struct streambuf_stream *s) {
	ilog(LOG_INFO, "TCP control ng connection from %s is closing", s->addr);
	mutex_lock(&tcp_connections_lock);
	g_hash_table_remove(tcp_connections_hash, s->addr);
	mutex_unlock(&tcp_connections_lock);
	ilog(LOG_DEBUG, "TCP connections map size: %d", g_hash_table_size(tcp_connections_hash));
}

static str *chunk_message(struct streambuf *b) {
	char *p = NULL;
	int len, to_del, bsize;
	str *ret = NULL;

	mutex_lock(&b->lock);

	for (;;) {
		if (b->eof)
			break;

		p = memchr(b->buf->str, ' ', b->buf->len);
		if (!p)
			break;

		len = p - b->buf->str;
		if (len == b->buf->len)
			break;

		++p; /* bencode dictionary here */
		bsize = bencode_valid(p, b->buf->str + b->buf->len - p);
		if (bsize < 0)
			break; /* not enough data to parse bencoded dictionary */

		p += bsize;
		len = p - b->buf->str;
		to_del = len;

		ret = str_alloc(len);
		memcpy(ret->s, b->buf->str, len);
		ret->len = len;
		g_string_erase(b->buf, 0, to_del);

		break;
	}

	mutex_unlock(&b->lock);
	return ret;
}

static void control_stream_readable(struct streambuf_stream *s) {
	str *data;

	ilog(LOG_DEBUG, "Got %zu bytes from %s", s->inbuf->buf->len, s->addr);
	while ((data = chunk_message(s->inbuf))) {
		ilog(LOG_DEBUG, "Got control ng message from %s", s->addr);
		control_ng_process(data, &s->sock.remote, s->addr, NULL, control_ng_send, &s->sock, s->parent);
		free(data);
	}

	if (streambuf_bufsize(s->inbuf) > 1024) {
		ilog(LOG_WARNING, "Buffer length exceeded in control connection from %s", s->addr);
		goto close;
	}

	return;

	close:
	streambuf_stream_close(s);
}

void control_ng_free(void *p) {
	struct control_ng *c = p;
	// XXX this should go elsewhere
	if (rtpe_cngs_hash) {
		GList *ll = g_hash_table_get_values(rtpe_cngs_hash);
		for (GList *l = ll; l; l = l->next) {
			struct control_ng_stats *s = l->data;
			g_slice_free1(sizeof(*s), s);
		}
		g_list_free(ll);
		g_hash_table_destroy(rtpe_cngs_hash);
		rtpe_cngs_hash = NULL;
	}
	poller_del_item(rtpe_control_poller, c->udp_listener.fd);
	close_socket(&c->udp_listener);
	streambuf_listener_shutdown(&c->tcp_listener);
	if (tcp_connections_hash)
		g_hash_table_destroy(tcp_connections_hash);
}

struct control_ng *control_ng_new(const endpoint_t *ep) {
	struct control_ng *c;

	c = obj_alloc0("control_ng", sizeof(*c), control_ng_free);

	c->udp_listener.fd = -1;

	if (udp_listener_init(&c->udp_listener, ep, control_ng_incoming, &c->obj))
		goto fail2;
	if (rtpe_config.control_tos)
		set_tos(&c->udp_listener, rtpe_config.control_tos);
	if (rtpe_config.control_pmtu)
		set_pmtu_disc(&c->udp_listener,
				rtpe_config.control_pmtu == PMTU_DISC_WANT ? IP_PMTUDISC_WANT : IP_PMTUDISC_DONT);
	return c;

fail2:
	obj_put(c);
	return NULL;
}

struct control_ng *control_ng_tcp_new(const endpoint_t *ep) {
	struct control_ng * ctrl_ng = obj_alloc0("control_ng", sizeof(*ctrl_ng), NULL);
	ctrl_ng->udp_listener.fd = -1;

	if (streambuf_listener_init(&ctrl_ng->tcp_listener, ep,
								control_incoming, control_stream_readable,
								control_closed,
								&ctrl_ng->obj)) {
		ilog(LOG_ERR, "Failed to open TCP control port: %s", strerror(errno));
		goto fail;
	}

	tcp_connections_hash = g_hash_table_new(g_str_hash, g_str_equal);
	mutex_init(&tcp_connections_lock);
	return ctrl_ng;

fail:
	obj_put(ctrl_ng);
	return NULL;
}

static void notify_tcp_client(gpointer key, gpointer value, gpointer user_data) {
	struct streambuf_stream *s = (struct streambuf_stream *)value;
	str *to_send = (str *)user_data;
	char cookie_buf[17];
	str cookie = STR_CONST_INIT(cookie_buf);

	rand_hex_str(cookie_buf, cookie.len / 2);
	control_ng_send(&cookie, to_send, &s->sock.remote, NULL, &s->sock);
}

void notify_ng_tcp_clients(str *data) {
	mutex_lock(&tcp_connections_lock);
	g_hash_table_foreach(tcp_connections_hash, notify_tcp_client, data);
	mutex_unlock(&tcp_connections_lock);
}

void control_ng_init(void) {
	mutex_init(&rtpe_cngs_lock);
	rtpe_cngs_hash = g_hash_table_new(sockaddr_t_hash, sockaddr_t_eq);
	cookie_cache_init(&ng_cookie_cache);
}
void control_ng_cleanup(void) {
	cookie_cache_cleanup(&ng_cookie_cache);
}
