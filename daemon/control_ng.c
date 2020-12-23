#include "control_ng.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>

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


mutex_t rtpe_cngs_lock;
GHashTable *rtpe_cngs_hash;
struct control_ng *rtpe_control_ng;
static struct cookie_cache ng_cookie_cache;

const char magic_load_limit_strings[__LOAD_LIMIT_MAX][64] = {
	[LOAD_LIMIT_MAX_SESSIONS] = "Parallel session limit reached",
	[LOAD_LIMIT_CPU] = "CPU usage limit exceeded",
	[LOAD_LIMIT_LOAD] = "Load limit exceeded",
	[LOAD_LIMIT_BW] = "Bandwidth limit exceeded",
};
const char *ng_command_strings[NGC_COUNT] = {
	"ping", "offer", "answer", "delete", "query", "list", "start recording",
	"stop recording", "start forwarding", "stop forwarding", "block DTMF",
	"unblock DTMF", "block media", "unblock media", "play media", "stop media",
	"play DTMF", "statistics",
};
const char *ng_command_strings_short[NGC_COUNT] = {
	"Ping", "Offer", "Answer", "Delete", "Query", "List", "StartRec",
	"StopRec", "StartFwd", "StopFwd", "BlkDTMF",
	"UnblkDTMF", "BlkMedia", "UnblkMedia", "PlayMedia", "StopMedia",
	"PlayDTMF", "Stats",
};


static void timeval_update_request_time(struct request_time *request, const struct timeval *offer_diff) {
	// lock offers
	mutex_lock(&request->lock);

	// update min value
	if (timeval_us(&request->time_min) == 0 ||
	    timeval_cmp(&request->time_min, offer_diff) > 0) {
		timeval_from_us(&request->time_min, timeval_us(offer_diff));
	}

	// update max value
	if (timeval_us(&request->time_max) == 0 ||
	    timeval_cmp(&request->time_max, offer_diff) < 0) {
		timeval_from_us(&request->time_max, timeval_us(offer_diff));
	}

	// update avg value
	timeval_add(&request->time_avg, &request->time_avg, offer_diff);
	request->count++;

	// unlock offers
	mutex_unlock(&request->lock);
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
	struct ng_buffer *ngbuf = p;
	bencode_buffer_free(&ngbuf->buffer);
	if (ngbuf->ref)
		__obj_put(ngbuf->ref);
}

int control_ng_process(str *buf, const endpoint_t *sin, char *addr,
		void (*cb)(str *, str *, const endpoint_t *, void *), void *p1, struct obj *ref)
{
	struct ng_buffer *ngbuf;
	bencode_item_t *dict, *resp;
	str cmd = STR_NULL, cookie, data, reply, *to_send, callid;
	const char *errstr, *resultstr;
	GString *log_str;
	struct timeval cmd_start, cmd_stop, cmd_process_time;
	struct control_ng_stats* cur = get_control_ng_stats(&sin->address);
	int funcret = -1;
	enum ng_command command = -1;

	str_chr_str(&data, buf, ' ');
	if (!data.s || data.s == buf->s) {
		ilogs(control, LOG_WARNING, "Received invalid data on NG port (no cookie) from %s: " STR_FORMAT_M,
				addr, STR_FMT_M(buf));
		return funcret;
	}

	// init decode buffer object
	ngbuf = obj_alloc0("ng_buffer", sizeof(*ngbuf), __ng_buffer_free);
	mutex_init(&ngbuf->lock);
	mutex_lock(&ngbuf->lock);
	if (ref)
		ngbuf->ref = __obj_get(ref); // hold until we're done

	int ret = bencode_buffer_init(&ngbuf->buffer);
	assert(ret == 0);
	(void) ret;
	resp = bencode_dictionary(&ngbuf->buffer);
	assert(resp != NULL);

	cookie = *buf;
	cookie.len -= data.len;
	*data.s++ = '\0';
	data.len--;

	errstr = "Invalid data (no payload)";
	if (data.len <= 0)
		goto err_send;

	to_send = cookie_cache_lookup(&ng_cookie_cache, &cookie);
	if (to_send) {
		ilogs(control, LOG_INFO, "Detected command from %s as a duplicate", addr);
		resp = NULL;
		goto send_only;
	}

	dict = bencode_decode_expect_str(&ngbuf->buffer, &data, BENCODE_DICTIONARY);
	errstr = "Could not decode dictionary";
	if (!dict)
		goto err_send;

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
		default:
			errstr = "Unrecognized command";
	}

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
	// XXX could generalise these, same as above
	switch (command) {
		case NGC_OFFER:
			atomic64_inc(&rtpe_statsps.offers);
			timeval_update_request_time(&rtpe_totalstats_interval.offer, &cmd_process_time);
			break;
		case NGC_ANSWER:
			atomic64_inc(&rtpe_statsps.answers);
			timeval_update_request_time(&rtpe_totalstats_interval.answer, &cmd_process_time);
			break;
		case NGC_DELETE:
			atomic64_inc(&rtpe_statsps.deletes);
			timeval_update_request_time(&rtpe_totalstats_interval.delete, &cmd_process_time);
			break;
		default:
			break;
	}

	goto send_resp;

err_send:

	if (errstr < magic_load_limit_strings[0] || errstr > magic_load_limit_strings[__LOAD_LIMIT_MAX-1]) {
		ilogs(control, LOG_WARNING, "Protocol error in packet from %s: %s [" STR_FORMAT_M "]",
				addr, errstr, STR_FMT_M(&data));
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
	bencode_collapse_str(resp, &reply);
	to_send = &reply;

	if (cmd.s) {
		ilogs(control, LOG_INFO, "Replying to '"STR_FORMAT"' from %s (elapsed time %llu.%06llu sec)", STR_FMT(&cmd), addr, (unsigned long long)cmd_process_time.tv_sec, (unsigned long long)cmd_process_time.tv_usec);

		if (get_log_level(control) >= LOG_DEBUG) {
			dict = bencode_decode_expect_str(&ngbuf->buffer, to_send, BENCODE_DICTIONARY);
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

send_only:
	funcret = 0;
	cb(&cookie, to_send, sin, p1);

	if (resp)
		cookie_cache_insert(&ng_cookie_cache, &cookie, &reply);
	else
		free(to_send);

	goto out;

out:
	ng_buffer_release(ngbuf);
	log_info_clear();
	return funcret;
}


static void control_ng_send(str *cookie, str *body, const endpoint_t *sin, void *p1) {
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

	socket_sendiov(ul, iov, iovlen, sin);
}


static void control_ng_incoming(struct obj *obj, struct udp_buffer *udp_buf)
{
	control_ng_process(&udp_buf->str, &udp_buf->sin, udp_buf->addr, control_ng_send, udp_buf->listener,
			&udp_buf->obj);
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
	poller_del_item(c->poller, c->udp_listeners[0].fd);
	poller_del_item(c->poller, c->udp_listeners[1].fd);
	close_socket(&c->udp_listeners[0]);
	close_socket(&c->udp_listeners[1]);
}


struct control_ng *control_ng_new(struct poller *p, endpoint_t *ep, unsigned char tos) {
	struct control_ng *c;

	if (!p)
		return NULL;

	c = obj_alloc0("control_ng", sizeof(*c), control_ng_free);

	c->udp_listeners[0].fd = -1;
	c->udp_listeners[1].fd = -1;
	c->poller = p;

	if (udp_listener_init(&c->udp_listeners[0], p, ep, control_ng_incoming, &c->obj))
		goto fail2;
	if (tos)
		set_tos(&c->udp_listeners[0],tos);
	if (ipv46_any_convert(ep)) {
		if (udp_listener_init(&c->udp_listeners[1], p, ep, control_ng_incoming, &c->obj))
			goto fail2;
		if (tos)
			set_tos(&c->udp_listeners[1],tos);
	}
	return c;

fail2:
	obj_put(c);
	return NULL;

}


void control_ng_init() {
	mutex_init(&rtpe_cngs_lock);
	rtpe_cngs_hash = g_hash_table_new(g_sockaddr_hash, g_sockaddr_eq);
	cookie_cache_init(&ng_cookie_cache);
}
void control_ng_cleanup() {
	cookie_cache_cleanup(&ng_cookie_cache);
}
