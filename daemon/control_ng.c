#include "control_ng.h"

#include <sys/types.h>
#include <sys/socket.h>

#include "obj.h"
#include "poller.h"
#include "bencode.h"
#include "log.h"
#include "cookie_cache.h"
#include "call.h"
#include "sdp.h"
#include "call_interfaces.h"
#include "socket.h"


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

struct control_ng_stats* get_control_ng_stats(struct control_ng* c, const sockaddr_t *addr) {
	struct callmaster *m = c->callmaster;
	struct control_ng_stats* cur;

	mutex_lock(&m->cngs_lock);
	cur = g_hash_table_lookup(m->cngs_hash, addr);
	if (!cur) {
		cur = g_slice_alloc0(sizeof(struct control_ng_stats));
		cur->proxy = *addr;
		ilog(LOG_DEBUG,"Adding a proxy for control ng stats:%s", sockaddr_print_buf(addr));
		g_hash_table_insert(m->cngs_hash, &cur->proxy, cur);
	}
	mutex_unlock(&m->cngs_lock);
	return cur;
}

static void control_ng_incoming(struct obj *obj, str *buf, const endpoint_t *sin, char *addr) {
	struct control_ng *c = (void *) obj;
	bencode_buffer_t bencbuf;
	bencode_item_t *dict, *resp;
	str cmd, cookie, data, reply, *to_send, callid;
	const char *errstr;
	struct msghdr mh;
	struct iovec iov[3];
	GString *log_str;

	struct control_ng_stats* cur = get_control_ng_stats(c,&sin->address);

	str_chr_str(&data, buf, ' ');
	if (!data.s || data.s == buf->s) {
		ilog(LOG_WARNING, "Received invalid data on NG port (no cookie) from %s: "STR_FORMAT, addr, STR_FMT(buf));
		return;
	}

	bencode_buffer_init(&bencbuf);
	resp = bencode_dictionary(&bencbuf);

	cookie = *buf;
	cookie.len -= data.len;
	*data.s++ = '\0';
	data.len--;

	errstr = "Invalid data (no payload)";
	if (data.len <= 0)
		goto err_send;

	to_send = cookie_cache_lookup(&c->cookie_cache, &cookie);
	if (to_send) {
		ilog(LOG_INFO, "Detected command from %s as a duplicate", addr);
		resp = NULL;
		goto send_only;
	}

	dict = bencode_decode_expect_str(&bencbuf, &data, BENCODE_DICTIONARY);
	errstr = "Could not decode dictionary";
	if (!dict)
		goto err_send;

	bencode_dictionary_get_str(dict, "command", &cmd);
	errstr = "Dictionary contains no key \"command\"";
	if (!cmd.s)
		goto err_send;

	bencode_dictionary_get_str(dict, "call-id", &callid);
	log_info_str(&callid);

	ilog(LOG_INFO, "Received command '"STR_FORMAT"' from %s", STR_FMT(&cmd), addr);

	if (get_log_level() >= LOG_DEBUG) {
		log_str = g_string_sized_new(256);
		g_string_append_printf(log_str, "Dump for '"STR_FORMAT"' from %s: ", STR_FMT(&cmd), addr);
		pretty_print(dict, log_str);
		ilog(LOG_DEBUG, "%.*s", (int) log_str->len, log_str->str);
		g_string_free(log_str, TRUE);
	}

	errstr = NULL;
	if (!str_cmp(&cmd, "ping")) {
		bencode_dictionary_add_string(resp, "result", "pong");
		g_atomic_int_inc(&cur->ping);
	}
	else if (!str_cmp(&cmd, "offer")) {
		errstr = call_offer_ng(dict, c->callmaster, resp, addr, sin);
		g_atomic_int_inc(&cur->offer);
	}
	else if (!str_cmp(&cmd, "answer")) {
		errstr = call_answer_ng(dict, c->callmaster, resp);
		g_atomic_int_inc(&cur->answer);
	}
	else if (!str_cmp(&cmd, "delete")) {
		errstr = call_delete_ng(dict, c->callmaster, resp);
		g_atomic_int_inc(&cur->delete);
	}
	else if (!str_cmp(&cmd, "query")) {
		errstr = call_query_ng(dict, c->callmaster, resp);
		g_atomic_int_inc(&cur->query);
	}
	else if (!str_cmp(&cmd, "list")) {
	    errstr = call_list_ng(dict, c->callmaster, resp);
	    g_atomic_int_inc(&cur->list);
	}
	else
		errstr = "Unrecognized command";

	if (errstr)
		goto err_send;

	goto send_resp;

err_send:
	ilog(LOG_WARNING, "Protocol error in packet from %s: %s ["STR_FORMAT"]", addr, errstr, STR_FMT(&data));
	bencode_dictionary_add_string(resp, "result", "error");
	bencode_dictionary_add_string(resp, "error-reason", errstr);
	g_atomic_int_inc(&cur->errors);
	cmd = STR_NULL;

send_resp:
	bencode_collapse_str(resp, &reply);
	to_send = &reply;

	if (cmd.s) {
		ilog(LOG_INFO, "Replying to '"STR_FORMAT"' from %s", STR_FMT(&cmd), addr);

		if (get_log_level() >= LOG_DEBUG) {
			dict = bencode_decode_expect_str(&bencbuf, to_send, BENCODE_DICTIONARY);
			if (dict) {
				log_str = g_string_sized_new(256);
				g_string_append_printf(log_str, "Response dump for '"STR_FORMAT"' to %s: ",
						STR_FMT(&cmd), addr);
				pretty_print(dict, log_str);
				ilog(LOG_DEBUG, "%.*s", (int) log_str->len, log_str->str);
				g_string_free(log_str, TRUE);
			}
		}
	}

send_only:
	ZERO(mh);
	mh.msg_iov = iov;
	mh.msg_iovlen = 3;

	iov[0].iov_base = cookie.s;
	iov[0].iov_len = cookie.len;
	iov[1].iov_base = " ";
	iov[1].iov_len = 1;
	iov[2].iov_base = to_send->s;
	iov[2].iov_len = to_send->len;

	socket_sendmsg(&c->udp_listener.sock, &mh, sin);

	if (resp)
		cookie_cache_insert(&c->cookie_cache, &cookie, &reply);
	else
		free(to_send);

	goto out;

out:
	bencode_buffer_free(&bencbuf);
	log_info_clear();
}



struct control_ng *control_ng_new(struct poller *p, const endpoint_t *ep, struct callmaster *m) {
	struct control_ng *c;

	if (!p || !m)
		return NULL;

	c = obj_alloc0("control_ng", sizeof(*c), NULL);

	c->callmaster = m;
	cookie_cache_init(&c->cookie_cache);

	if (udp_listener_init(&c->udp_listener, p, ep, control_ng_incoming, &c->obj))
		goto fail2;

	return c;

fail2:
	obj_put(c);
	return NULL;

}
