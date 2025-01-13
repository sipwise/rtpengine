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
#include "cli.h"

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
const char *ng_command_strings[OP_COUNT] = {
	"ping", "offer", "answer", "delete", "query", "list",
	"start recording", "stop recording", "pause recording",
	"start forwarding", "stop forwarding", "block DTMF",
	"unblock DTMF", "block media", "unblock media", "play media", "stop media",
	"play DTMF", "statistics", "silence media", "unsilence media",
	"block silence media", "unblock silence media",
	"publish", "subscribe request",
	"subscribe answer", "unsubscribe",
	"connect", "cli"
};
const char *ng_command_strings_esc[OP_COUNT] = {
	"ping", "offer", "answer", "delete", "query", "list",
	"start_recording", "stop_recording", "pause_recording",
	"start_forwarding", "stop_forwarding", "block_DTMF",
	"unblock_DTMF", "block_media", "unblock_media", "play_media", "stop_media",
	"play_DTMF", "statistics", "silence_media", "unsilence_media",
	"block_silence_media", "unblock_silence_media",
	"publish", "subscribe_request",
	"subscribe_answer", "unsubscribe",
	"connect", "cli"
};
const char *ng_command_strings_short[OP_COUNT] = {
	"Ping", "Offer", "Answer", "Delete", "Query", "List",
	"StartRec", "StopRec", "PauseRec",
	"StartFwd", "StopFwd", "BlkDTMF",
	"UnblkDTMF", "BlkMedia", "UnblkMedia", "PlayMedia", "StopMedia",
	"PlayDTMF", "Stats", "SlnMedia", "UnslnMedia",
	"BlkSlnMedia", "UnblkSlnMedia",
	"Pub", "SubReq", "SubAns", "Unsub",
	"Conn", "CLI"
};

typedef struct ng_ctx {
	str callid;
	enum ng_opmode command;
	str cookie;
	bool should_trace;
	const endpoint_t *sin_ep;
	const endpoint_t *local_ep;
} ng_ctx;

#define CH(func, ...) do { \
	if (trace_ng) \
		func( __VA_ARGS__); \
} while (0)


static bool bencode_dict_iter(const ng_parser_t *parser, bencode_item_t *input,
		void (*callback)(const ng_parser_t *, str *key, bencode_item_t *value, helper_arg),
		helper_arg arg)
{
	if (input->type != BENCODE_DICTIONARY)
		return false;

	bencode_item_t *value = NULL;
	for (bencode_item_t *key = input->child; key; key = value->sibling) {
		value = key->sibling;
		if (!value)
			break;

		str k;
		if (!bencode_get_str(key, &k))
			continue;

		callback(parser, &k, value, arg);
	}

	return true;
}
static bool bencode_is_dict(bencode_item_t *arg) {
	return arg->type == BENCODE_DICTIONARY;
}
static bool bencode_is_list(bencode_item_t *arg) {
	return arg->type == BENCODE_LIST;
}
static bool bencode_is_int(bencode_item_t *arg) {
	return arg->type == BENCODE_INTEGER;
}
static void bencode_list_iter(const ng_parser_t *parser, bencode_item_t *list,
		void (*str_callback)(str *key, unsigned int, helper_arg),
		void (*item_callback)(const ng_parser_t *, bencode_item_t *, helper_arg),
		helper_arg arg)
{
	if (list->type != BENCODE_LIST)
		return;
	str s;
	unsigned int idx = 0;
	for (bencode_item_t *it = list->child; it; it = it->sibling) {
		if (bencode_get_str(it, &s))
			str_callback(&s, idx, arg);
		else if (item_callback)
			item_callback(parser, it, arg);
		else
			ilog(LOG_DEBUG, "Ignoring non-string value in list");
		idx++;
	}
}
static long long bencode_get_int(bencode_item_t *arg) {
	return arg->value;
}
static parser_arg __bencode_dict(ng_parser_ctx_t *ctx) {
	return (parser_arg) bencode_dictionary(ctx->buffer);
}
static parser_arg __bencode_list(ng_parser_ctx_t *ctx) {
	return (parser_arg) bencode_list(ctx->buffer);
}

static void bencode_pretty_print(bencode_item_t *el, GString *s);

static parser_arg __bencode_dictionary_get_expect(bencode_item_t *arg, const char *ele, bencode_type_t type) {
	return (parser_arg) bencode_dictionary_get_expect(arg, ele, type);
}
static bool __bencode_dictionary_contains(bencode_item_t *d, const char *ele) {
	return bencode_dictionary_get(d, ele) != NULL;
}
static parser_arg __bencode_dictionary_add(bencode_item_t *n, const char *e, bencode_item_t *v) {
	return (parser_arg) bencode_dictionary_add(n, e, v);
}
static parser_arg __bencode_dictionary_add_dictionary(bencode_item_t *n, const char *e) {
	return (parser_arg) bencode_dictionary_add_dictionary(n, e);
}
static parser_arg __bencode_dictionary_add_dictionary_dup(bencode_item_t *n, const char *e) {
	size_t len = strlen(e) + 1;
	char *s = bencode_buffer_alloc(n->buffer, len);
	memcpy(s, e, len);
	return (parser_arg) bencode_dictionary_add_dictionary(n, s);
}
static parser_arg __bencode_dictionary_add_list(bencode_item_t *n, const char *e) {
	return (parser_arg) bencode_dictionary_add_list(n, e);
}
static parser_arg __bencode_dictionary_add_list_dup(bencode_item_t *n, const char *e) {
	size_t len = strlen(e) + 1;
	char *s = bencode_buffer_alloc(n->buffer, len);
	memcpy(s, e, len);
	return (parser_arg) bencode_dictionary_add_list(n, s);
}
static parser_arg __bencode_list_add(bencode_item_t *l, bencode_item_t *e) {
	return (parser_arg) bencode_list_add(l, e);
}
static parser_arg __bencode_list_add_dictionary(bencode_item_t *l) {
	return (parser_arg) bencode_list_add_dictionary(l);
}
static str __bencode_collapse_str(ng_parser_ctx_t *ctx, bencode_item_t *a, void **to_free) {
	return bencode_collapse_str(a);
}
static const char *__bencode_strdup(ng_parser_ctx_t *ctx, const char *s) {
	return bencode_strdup(ctx->buffer, s);
}
static void __bencode_ctx_init(ng_parser_ctx_t *ctx, bencode_buffer_t *buf) {
	bencode_buffer_init(buf);
	*ctx = (ng_parser_ctx_t) { .parser = &ng_parser_native, .buffer = buf };
}

static bool json_is_dict(JsonNode *n) {
	return json_node_get_node_type(n) == JSON_NODE_OBJECT;
}
static bool json_is_list(JsonNode *n) {
	return json_node_get_node_type(n) == JSON_NODE_ARRAY;
}
static bool json_is_int(JsonNode *n) {
	if (json_node_get_node_type(n) != JSON_NODE_VALUE)
		return false;
	GType type = json_node_get_value_type(n);
	switch (type) {
		case G_TYPE_INT:
		case G_TYPE_UINT:
		case G_TYPE_LONG:
		case G_TYPE_ULONG:
		case G_TYPE_INT64:
		case G_TYPE_UINT64:
		case G_TYPE_BOOLEAN:
			return true;
	}
	return false;
}
static char *json_dict_get_str(JsonNode *dict, const char *entry, str *out) {
	JsonObject *o = json_node_get_object(dict);
	if (!o)
		goto out;
	JsonNode *n = json_object_get_member(o, entry);
	if (!n)
		goto out;
	const char *s = json_node_get_string(n);
	if (!s)
		goto out;
	*out = STR(s);
	return out->s;
out:
	*out = STR_NULL;
	return NULL;
}
static void json_pretty_print(JsonNode *a, GString *out) {
	JsonGenerator *g = json_generator_new();
	json_generator_set_root(g, a);
	json_generator_to_gstring(g, out);
	g_object_unref(g);
}
static long long json_get_int_str(JsonNode *n, long long def) {
	if (json_node_get_node_type(n) != JSON_NODE_VALUE)
		return def;
	GType type = json_node_get_value_type(n);
	switch (type) {
		case G_TYPE_INT:
		case G_TYPE_UINT:
		case G_TYPE_LONG:
		case G_TYPE_ULONG:
		case G_TYPE_INT64:
		case G_TYPE_UINT64:
		case G_TYPE_BOOLEAN:
			return json_node_get_int(n);
		case G_TYPE_STRING:;
			const char *s = json_node_get_string(n);
			char *ep;
			long long r = strtoll(s, &ep, 0);
			if (ep == s)
				return def;
			return r;
		default:
			return def;
	}
}
static long long json_get_int(JsonNode *n) {
	if (json_node_get_node_type(n) != JSON_NODE_VALUE)
		return 0;
	if (!json_is_int(n))
		return 0;
	return json_node_get_int(n);
}
static long long json_dict_get_int_str(JsonNode *dict, const char *entry, long long def) {
	JsonObject *o = json_node_get_object(dict);
	if (!o)
		return def;
	JsonNode *n = json_object_get_member(o, entry);
	if (!n)
		return def;
	if (json_node_get_node_type(n) != JSON_NODE_VALUE)
		return def;
	return json_get_int_str(n, def);
}
static parser_arg json_dict_get_expect(JsonNode *dict, const char *entry, bencode_type_t type) {
	JsonObject *o = json_node_get_object(dict);
	if (!o)
		return (parser_arg) NULL;
	JsonNode *n = json_object_get_member(o, entry);
	if (!n)
		return (parser_arg) NULL;
	switch (type) {
		case BENCODE_LIST:
			if (json_node_get_node_type(n) != JSON_NODE_ARRAY)
				return (parser_arg) NULL;
			return (parser_arg) n;
		case BENCODE_DICTIONARY:
			if (json_node_get_node_type(n) != JSON_NODE_OBJECT)
				return (parser_arg) NULL;
			return (parser_arg) n;
		default:
			abort();
	}
}
static bool json_dict_contains(JsonNode *on, const char *ele) {
	JsonObject *o = json_node_get_object(on);
	if (!o)
		return false;
	JsonNode *n = json_object_get_member(o, ele);
	return n != NULL;
}
static void json_dict_iter_fn(JsonObject *o, const char *key, JsonNode *val, void *arg) {
	void **ptrs = arg;
	void (*callback)(const ng_parser_t *, str *key, JsonNode *value, helper_arg) = ptrs[1];
	callback(ptrs[0], STR_PTR(key), val, ptrs[2]);
}

static bool json_dict_iter(const ng_parser_t *parser, JsonNode *input,
		void (*callback)(const ng_parser_t *, str *key, JsonNode *value, helper_arg),
		helper_arg arg)
{
	if (json_node_get_node_type(input) != JSON_NODE_OBJECT)
		return false;

	JsonObject *o = json_node_get_object(input);
	if (!o)
		return false;

	const void *ptrs[3] = { parser, callback, arg.generic };
	json_object_foreach_member(o, json_dict_iter_fn, ptrs);

	return true;
}
static void json_list_iter(const ng_parser_t *parser, JsonNode *list,
		void (*str_callback)(str *key, unsigned int, helper_arg),
		void (*item_callback)(const ng_parser_t *parser, JsonNode *, helper_arg),
		helper_arg arg)
{
	if (json_node_get_node_type(list) != JSON_NODE_ARRAY)
		return;

	JsonArray *a = json_node_get_array(list);
	if (!a)
		return;

	unsigned int l = json_array_get_length(a);
	for (unsigned int i = 0; i < l; i++) {
		JsonNode *n = json_array_get_element(a, i);
		if (json_node_get_node_type(n) == JSON_NODE_VALUE
				&& json_node_get_value_type(n) == G_TYPE_STRING)
		{
			const char *s = json_node_get_string(n);
			if (s)
				str_callback(STR_PTR(s), i, arg);
		}
		else
			item_callback(parser, n, arg);
	}
}
static str *json_get_str(JsonNode *a, str *out) {
	const char *s = json_node_get_string(a);
	if (!s)
		return NULL;
	*out = STR(s);
	return out;
}
static int json_strcmp(JsonNode *n, const char *b) {
	if (json_node_get_node_type(n) != JSON_NODE_VALUE)
		return 2;
	if (json_node_get_value_type(n) != G_TYPE_STRING)
		return 1;
	const char *s = json_node_get_string(n);
	return strcmp(s, b);
}
static const char *__json_strdup(ng_parser_ctx_t *ctx, const char *s) {
	return s;
}
static parser_arg json_dict(ng_parser_ctx_t *c) {
	JsonObject *o = json_object_new();
	JsonNode *n = json_node_init_object(json_node_new(JSON_NODE_OBJECT), o);
	json_object_unref(o);
	return (parser_arg) n;
}
static void json_dict_add_string(JsonNode *n, const char *k, const char *v) {
	json_object_set_string_member(json_node_get_object(n), k, v);
}
static void json_dict_add_str(JsonNode *n, const char *k, const str *v) {
	g_autoptr(char) s = g_malloc(v->len + 1);
	memcpy(s, v->s, v->len);
	s[v->len] = 0;
	json_object_set_string_member(json_node_get_object(n), k, s);
}
static void json_dict_add_int(JsonNode *n, const char *k, long long i) {
	json_object_set_int_member(json_node_get_object(n), k, i);
}
static parser_arg json_dict_add(JsonNode *n, const char *k, JsonNode *v) {
	json_object_set_member(json_node_get_object(n), k, v);
	return (parser_arg) v;
}
static parser_arg json_dict_add_list(JsonNode *n, const char *e) {
	JsonArray *a = json_array_new();
	JsonNode *an = json_node_init_array(json_node_new(JSON_NODE_ARRAY), a);
	json_object_set_member(json_node_get_object(n), e, an);
	json_array_unref(a);
	return (parser_arg) an;
}
static parser_arg json_list(ng_parser_ctx_t *c) {
	JsonArray *a = json_array_new();
	JsonNode *n = json_node_init_array(json_node_new(JSON_NODE_ARRAY), a);
	json_array_unref(a);
	return (parser_arg) n;
}
static parser_arg json_list_add(JsonNode *n, JsonNode *e) {
	json_array_add_element(json_node_get_array(n), e);
	return (parser_arg) e;
}
static parser_arg json_list_add_dict(JsonNode *n) {
	JsonObject *o = json_object_new();
	JsonNode *on = json_node_init_object(json_node_new(JSON_NODE_OBJECT), o);
	json_array_add_element(json_node_get_array(n), on);
	json_object_unref(o);
	return (parser_arg) on;
}
static parser_arg json_dict_add_dict(JsonNode *n, const char *e) {
	JsonObject *o = json_object_new();
	JsonNode *on = json_node_init_object(json_node_new(JSON_NODE_OBJECT), o);
	json_object_set_member(json_node_get_object(n), e, on);
	json_object_unref(o);
	return (parser_arg) on;
}
static void json_list_add_str(JsonNode *n, const str *v) {
	g_autoptr(char) s = g_malloc(v->len + 1);
	memcpy(s, v->s, v->len);
	s[v->len] = 0;
	json_array_add_string_element(json_node_get_array(n), s);
}
static void json_list_add_string(JsonNode *n, const char *s) {
	json_array_add_string_element(json_node_get_array(n), s);
}
static str json_collapse(ng_parser_ctx_t *ctx, JsonNode *a, void **to_free) {
	JsonGenerator *g = json_generator_new();
	json_generator_set_root(g, a);
	size_t len;
	char *s = json_generator_to_data(g, &len);
	*to_free = s;
	g_object_unref(g);
	str out = STR_LEN(s, len);
	json_node_unref(a);
	return out;
}
static void json_ctx_init(ng_parser_ctx_t *ctx, bencode_buffer_t *buf) {
	*ctx = (ng_parser_ctx_t) { .parser = &ng_parser_json };
}
static str dummy_encode_len(char *out, const char *in, size_t in_len) {
	return STR_LEN(in, in_len);
}
static str *dummy_decode_len(const char *in, size_t len) {
	str *r = str_alloc(len);
	memcpy(r->s, in, len);
	r->len = len;
	r->s[len] = '\0';
	return r;
}

const ng_parser_t ng_parser_native = {
	.init = __bencode_ctx_init,
	.collapse = __bencode_collapse_str,
	.dict_iter = bencode_dict_iter,
	.is_list = bencode_is_list,
	.list_iter = bencode_list_iter,
	.get_str = bencode_get_str,
	.strcmp = bencode_strcmp,
	.strdup = __bencode_strdup,
	.get_int_str = bencode_get_integer_str,
	.is_int = bencode_is_int,
	.get_int = bencode_get_int,
	.is_dict = bencode_is_dict,
	.dict = __bencode_dict,
	.dict_get_str = bencode_dictionary_get_str,
	.dict_get_int_str = bencode_dictionary_get_int_str,
	.dict_get_expect = __bencode_dictionary_get_expect,
	.dict_contains = __bencode_dictionary_contains,
	.dict_add = __bencode_dictionary_add,
	.dict_add_string = bencode_dictionary_add_string,
	.dict_add_str = bencode_dictionary_add_str,
	.dict_add_str_dup = bencode_dictionary_add_str_dup,
	.dict_add_int = bencode_dictionary_add_integer,
	.dict_add_dict = __bencode_dictionary_add_dictionary,
	.dict_add_dict_dup = __bencode_dictionary_add_dictionary_dup,
	.dict_add_list = __bencode_dictionary_add_list,
	.dict_add_list_dup = __bencode_dictionary_add_list_dup,
	.list = __bencode_list,
	.list_add = __bencode_list_add,
	.list_add_dict = __bencode_list_add_dictionary,
	.list_add_string = bencode_list_add_string,
	.list_add_str_dup = bencode_list_add_str_dup,
	.pretty_print = bencode_pretty_print,
	.escape = dummy_encode_len,
	.unescape = dummy_decode_len,
};
const ng_parser_t ng_parser_json = {
	.init = json_ctx_init,
	.collapse = json_collapse,
	.dict_iter = json_dict_iter,
	.is_list = json_is_list,
	.list_iter = json_list_iter,
	.get_str = json_get_str,
	.strcmp = json_strcmp,
	.strdup = __json_strdup,
	.get_int_str = json_get_int_str,
	.is_int = json_is_int,
	.get_int = json_get_int,
	.is_dict = json_is_dict,
	.dict = json_dict,
	.dict_get_str = json_dict_get_str,
	.dict_get_int_str = json_dict_get_int_str,
	.dict_get_expect = json_dict_get_expect,
	.dict_contains = json_dict_contains,
	.dict_add = json_dict_add,
	.dict_add_string = json_dict_add_string,
	.dict_add_str = json_dict_add_str,
	.dict_add_str_dup = json_dict_add_str,
	.dict_add_int = json_dict_add_int,
	.dict_add_dict = json_dict_add_dict,
	.dict_add_dict_dup = json_dict_add_dict,
	.dict_add_list = json_dict_add_list,
	.dict_add_list_dup = json_dict_add_list,
	.list = json_list,
	.list_add = json_list_add,
	.list_add_dict = json_list_add_dict,
	.list_add_string = json_list_add_string,
	.list_add_str_dup = json_list_add_str,
	.pretty_print = json_pretty_print,
	.escape = str_uri_encode_len,
	.unescape = str_uri_decode_len,
};


void init_ng_tracing(void) {
	if (rtpe_config.homer_ng_on &&  has_homer())
		trace_ng = true;
}

static GString *create_homer_msg(str *cookie, str *data) {
	GString *msg = g_string_sized_new(cookie->len + 1 + data->len);
	g_string_append_printf(msg, "%.*s %.*s", STR_FMT(cookie), STR_FMT(data));
	return msg;
}

static bool should_trace_msg(enum ng_opmode command) {
	switch (command) {
		case OP_PING:
			return false;
		default:
			return true;
	}
}

static void homer_fill_values(ng_ctx *hctx, str *callid, enum ng_opmode command) {
	if (hctx) {
		hctx->command = command;
		hctx->callid = *callid;
	}
}

static void homer_trace_msg_in(ng_ctx *hctx, str *data) {
	if (hctx && hctx->local_ep) {
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

static void bencode_pretty_print(bencode_item_t *el, GString *s) {
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
				bencode_pretty_print(chld, s);
				sep = ", ";
			}
			g_string_append(s, " ]");
			break;

		case BENCODE_DICTIONARY:
			g_string_append(s, "{ ");
			sep = "";
			for (chld = el->child; chld; chld = chld->sibling) {
				g_string_append(s, sep);
				bencode_pretty_print(chld, s);
				g_string_append(s, ": ");
				chld = chld->sibling;
				bencode_pretty_print(chld, s);
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

		for (int i = 0; i < OP_COUNT; i++) {
			struct ng_command_stats *c = &cur->cmd[i];
			mutex_init(&c->lock);
		}

		g_hash_table_insert(rtpe_cngs_hash, &cur->proxy, cur);
	}
	mutex_unlock(&rtpe_cngs_lock);
	return cur;
}

static void __ng_buffer_free(ng_buffer *ngbuf) {
	bencode_buffer_free(&ngbuf->buffer);
	if (ngbuf->ref)
		obj_put_o(ngbuf->ref);
	if (ngbuf->json)
		g_object_unref(ngbuf->json);
	g_free(ngbuf->sdp_out);
	if (ngbuf->call)
		obj_put(ngbuf->call);
	g_free(ngbuf->collapsed);
}

ng_buffer *ng_buffer_new(struct obj *ref) {
	__auto_type ngbuf = obj_alloc0(ng_buffer, __ng_buffer_free);
	if (ref)
		ngbuf->ref = obj_get_o(ref); // hold until we're done

	return ngbuf;
}

static void control_ng_process_payload(ng_ctx *hctx, str *reply, str *data, const endpoint_t *sin, char *addr, struct obj *ref,
		struct ng_buffer **ngbufp)
{
	str cmd = STR_NULL, callid;
	const char *errstr, *resultstr;
	GString *log_str;
	struct timeval cmd_start, cmd_stop, cmd_process_time = {0};
	struct control_ng_stats* cur = get_control_ng_stats(&sin->address);

	ng_command_ctx_t command_ctx = {.opmode = -1};
	const ng_parser_t *parser = &ng_parser_native;

	command_ctx.ngbuf = *ngbufp = ng_buffer_new(ref);

	errstr = "Invalid data (no payload)";
	if (data->len <= 0)
		goto err_send;

	/* Bencode dictionary */
	if (data->s[0] == 'd') {
		ng_parser_native.init(&command_ctx.parser_ctx, &command_ctx.ngbuf->buffer);

		command_ctx.req.benc = bencode_decode_expect_str(&command_ctx.ngbuf->buffer, data, BENCODE_DICTIONARY);
		errstr = "Could not decode bencode dictionary";
		if (!command_ctx.req.benc)
			goto err_send;
	}

	/* JSON */
	else if (data->s[0] == '{') {
		ng_parser_json.init(&command_ctx.parser_ctx, &command_ctx.ngbuf->buffer);
		command_ctx.ngbuf->json = json_parser_new();
		errstr = "Failed to parse JSON document";
		if (!json_parser_load_from_data(command_ctx.ngbuf->json, data->s, data->len, NULL))
			goto err_send;
		command_ctx.req.json = json_parser_get_root(command_ctx.ngbuf->json);
		errstr = "Could not decode bencode dictionary";
		if (!command_ctx.req.json || !ng_parser_json.is_dict(command_ctx.req))
			goto err_send;
	}

	else {
		errstr = "Invalid NG data format";
		goto err_send;
	}

	parser = command_ctx.parser_ctx.parser;

	command_ctx.resp = parser->dict(&command_ctx.parser_ctx);
	assert(command_ctx.resp.gen != NULL);

	parser->dict_get_str(command_ctx.req, "command", &cmd);
	errstr = "Dictionary contains no key \"command\"";
	if (!cmd.s)
		goto err_send;

	parser->dict_get_str(command_ctx.req, "call-id", &callid);
	log_info_str(&callid);

	ilogs(control, LOG_INFO, "Received command '"STR_FORMAT"' from %s", STR_FMT(&cmd), addr);

	if (get_log_level(control) >= LOG_DEBUG) {
		log_str = g_string_sized_new(256);
		g_string_append_printf(log_str, "Dump for '"STR_FORMAT"' from %s: %s", STR_FMT(&cmd), addr,
				rtpe_config.common.log_mark_prefix);
		parser->pretty_print(command_ctx.req, log_str);
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
			command_ctx.opmode = OP_PING;
			break;
		case CSH_LOOKUP("offer"):
			command_ctx.opmode = OP_OFFER;
			errstr = call_offer_ng(&command_ctx, addr, sin);
			break;
		case CSH_LOOKUP("answer"):
			command_ctx.opmode = OP_ANSWER;
			errstr = call_answer_ng(&command_ctx);
			break;
		case CSH_LOOKUP("delete"):
			command_ctx.opmode = OP_DELETE;
			errstr = call_delete_ng(&command_ctx);
			break;
		case CSH_LOOKUP("query"):
			command_ctx.opmode = OP_QUERY;
			errstr = call_query_ng(&command_ctx);
			break;
		case CSH_LOOKUP("list"):
			command_ctx.opmode = OP_LIST;
			errstr = call_list_ng(&command_ctx);
			break;
		case CSH_LOOKUP("start recording"):
			command_ctx.opmode = OP_START_RECORDING;
			errstr = call_start_recording_ng(&command_ctx);
			break;
		case CSH_LOOKUP("stop recording"):
			command_ctx.opmode = OP_STOP_RECORDING;
			errstr = call_stop_recording_ng(&command_ctx);
			break;
		case CSH_LOOKUP("pause recording"):
			command_ctx.opmode = OP_PAUSE_RECORDING;
			errstr = call_pause_recording_ng(&command_ctx);
			break;
		case CSH_LOOKUP("start forwarding"):
			command_ctx.opmode = OP_START_FORWARDING;
			errstr = call_start_forwarding_ng(&command_ctx);
			break;
		case CSH_LOOKUP("stop forwarding"):
			command_ctx.opmode = OP_STOP_FORWARDING;
			errstr = call_stop_forwarding_ng(&command_ctx);
			break;
		case CSH_LOOKUP("block DTMF"):
			command_ctx.opmode = OP_BLOCK_DTMF;
			errstr = call_block_dtmf_ng(&command_ctx);
			break;
		case CSH_LOOKUP("unblock DTMF"):
			command_ctx.opmode = OP_UNBLOCK_DTMF;
			errstr = call_unblock_dtmf_ng(&command_ctx);
			break;
		case CSH_LOOKUP("block media"):
			command_ctx.opmode = OP_BLOCK_MEDIA;
			errstr = call_block_media_ng(&command_ctx);
			break;
		case CSH_LOOKUP("unblock media"):
			command_ctx.opmode = OP_UNBLOCK_MEDIA;
			errstr = call_unblock_media_ng(&command_ctx);
			break;
		case CSH_LOOKUP("silence media"):
			command_ctx.opmode = OP_SILENCE_MEDIA;
			errstr = call_silence_media_ng(&command_ctx);
			break;
		case CSH_LOOKUP("unsilence media"):
			command_ctx.opmode = OP_UNSILENCE_MEDIA;
			errstr = call_unsilence_media_ng(&command_ctx);
			break;
		case CSH_LOOKUP("play media"):
			command_ctx.opmode = OP_PLAY_MEDIA;
			errstr = call_play_media_ng(&command_ctx);
			break;
		case CSH_LOOKUP("stop media"):
			command_ctx.opmode = OP_STOP_MEDIA;
			errstr = call_stop_media_ng(&command_ctx);
			break;
		case CSH_LOOKUP("play DTMF"):
			command_ctx.opmode = OP_PLAY_DTMF;
			errstr = call_play_dtmf_ng(&command_ctx);
			break;
		case CSH_LOOKUP("statistics"):
			command_ctx.opmode = OP_STATISTICS;
			errstr = statistics_ng(&command_ctx);
			break;
		case CSH_LOOKUP("publish"):
			command_ctx.opmode = OP_PUBLISH;
			errstr = call_publish_ng(&command_ctx, addr, sin);
			break;
		case CSH_LOOKUP("subscribe request"):
			command_ctx.opmode = OP_SUBSCRIBE_REQ;
			errstr = call_subscribe_request_ng(&command_ctx);
			break;
		case CSH_LOOKUP("subscribe answer"):
			command_ctx.opmode = OP_SUBSCRIBE_ANS;
			errstr = call_subscribe_answer_ng(&command_ctx);
			break;
		case CSH_LOOKUP("unsubscribe"):
			command_ctx.opmode = OP_UNSUBSCRIBE;
			errstr = call_unsubscribe_ng(&command_ctx);
			break;
		case CSH_LOOKUP("connect"):
			command_ctx.opmode = OP_CONNECT;
			errstr = call_connect_ng(&command_ctx);
			break;
		case CSH_LOOKUP("cli"):
		case CSH_LOOKUP("CLI"):
			command_ctx.opmode = OP_CLI;
			errstr = cli_ng(&command_ctx);
			break;
		default:
			errstr = "Unrecognized command";
	}

	CH(homer_fill_values, hctx, &callid, command_ctx.opmode);
	CH(homer_trace_msg_in, hctx, data);

	// stop command timer
	gettimeofday(&cmd_stop, NULL);
	//print command duration
	timeval_from_us(&cmd_process_time, timeval_diff(&cmd_stop, &cmd_start));

	if (command_ctx.opmode >= 0 && command_ctx.opmode < OP_COUNT) {
		mutex_lock(&cur->cmd[command_ctx.opmode].lock);
		cur->cmd[command_ctx.opmode].count++;
		timeval_add(&cur->cmd[command_ctx.opmode].time, &cur->cmd[command_ctx.opmode].time, &cmd_process_time);
		mutex_unlock(&cur->cmd[command_ctx.opmode].lock);
	}

	if (errstr)
		goto err_send;

	parser->dict_add_string(command_ctx.resp, "result", resultstr);

	// update interval statistics
	RTPE_STATS_INC(ng_commands[command_ctx.opmode]);
	RTPE_STATS_SAMPLE(ng_command_times[command_ctx.opmode], timeval_us(&cmd_process_time));

	goto send_resp;

err_send:

	if (errstr < magic_load_limit_strings[0] || errstr > magic_load_limit_strings[__LOAD_LIMIT_MAX-1]) {
		ilogs(control, LOG_WARNING, "Protocol error in packet from %s: %s [" STR_FORMAT_M "]",
				addr, errstr, STR_FMT_M(data));
		parser->dict_add_string(command_ctx.resp, "result", "error");
		parser->dict_add_string(command_ctx.resp, "error-reason", errstr);
		g_atomic_int_inc(&cur->errors);
		cmd = STR_NULL;
	}
	else {
		parser->dict_add_string(command_ctx.resp, "result", "load limit");
		parser->dict_add_string(command_ctx.resp, "message", errstr);
	}

send_resp:
	if (cmd.s) {
		ilogs(control, LOG_INFO, "Replying to '"STR_FORMAT"' from %s (elapsed time %llu.%06llu sec)", STR_FMT(&cmd), addr, (unsigned long long)cmd_process_time.tv_sec, (unsigned long long)cmd_process_time.tv_usec);

		if (get_log_level(control) >= LOG_DEBUG) {
			log_str = g_string_sized_new(256);
			g_string_append_printf(log_str, "Response dump for '"STR_FORMAT"' to %s: %s",
					STR_FMT(&cmd), addr,
					rtpe_config.common.log_mark_prefix);
			parser->pretty_print(command_ctx.resp, log_str);
			g_string_append(log_str, rtpe_config.common.log_mark_suffix);
			ilogs(control, LOG_DEBUG, "%.*s", (int) log_str->len, log_str->str);
			g_string_free(log_str, TRUE);
		}
	}

	*reply = parser->collapse(&command_ctx.parser_ctx, command_ctx.resp, &command_ctx.ngbuf->collapsed);

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
				.callid = cached->callid,
				.should_trace = should_trace_msg(cached->command)};

		CH(homer_trace_msg_in, &hctx, &data);
		cb(&cookie, &cached->reply, sin, local, p1);
		CH(homer_trace_msg_out, &hctx, &cached->reply);

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
	cache_entry ce = {.reply = reply, .command = hctx.command, .callid = hctx.callid};
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

void control_ng_free(struct control_ng *c) {
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
	rtpe_poller_del_item(rtpe_control_poller, c->udp_listener.fd);
	reset_socket(&c->udp_listener);
	streambuf_listener_shutdown(&c->tcp_listener);
	if (tcp_connections_hash)
		g_hash_table_destroy(tcp_connections_hash);
}

struct control_ng *control_ng_new(const endpoint_t *ep) {
	struct control_ng *c;

	c = obj_alloc0(struct control_ng, control_ng_free);

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
	struct control_ng *ctrl_ng = obj_alloc0(struct control_ng, NULL);
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
	str cookie = STR_CONST(cookie_buf);

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
