#include "control_ng.h"
#include "obj.h"
#include "poller.h"
#include "bencode.h"
#include "log.h"
#include "cookie_cache.h"
#include "call.h"


static void control_ng_incoming(struct obj *obj, str *buf, struct sockaddr_in6 *sin, char *addr) {
	struct control_ng *c = (void *) obj;
	bencode_buffer_t bencbuf;
	bencode_item_t *dict, *resp;
	str cmd, cookie, data, reply, *to_send;
	const char *errstr;
	struct msghdr mh;
	struct iovec iov[3];

	str_chr_str(&data, buf, ' ');
	if (!data.s || data.s == buf->s) {
		mylog(LOG_WARNING, "Received invalid data on NG port (no cookie) from %s: %.*s", addr, STR_FMT(buf));
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
		mylog(LOG_INFO, "Detected command from %s as a duplicate", addr);
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

	mylog(LOG_INFO, "Got valid command from %s: %.*s [%.*s]", addr, STR_FMT(&cmd), STR_FMT(&data));

	errstr = NULL;
	if (!str_cmp(&cmd, "ping"))
		bencode_dictionary_add_string(resp, "result", "pong");
	else if (!str_cmp(&cmd, "offer")) {
		errstr = call_offer(dict, c->callmaster, resp);
	}
	else if (!str_cmp(&cmd, "answer")) {
		errstr = call_answer(dict, c->callmaster, resp);
	}
	else
		errstr = "Unrecognized command";

	if (errstr)
		goto err_send;

	goto send_resp;

err_send:
	mylog(LOG_WARNING, "Protocol error in packet from %s: %s [%.*s]", addr, errstr, STR_FMT(&data));
	bencode_dictionary_add_string(resp, "result", "error");
	bencode_dictionary_add_string(resp, "error-reason", errstr);
	goto send_resp;

send_resp:
	bencode_collapse_str(resp, &reply);
	to_send = &reply;

send_only:
	mylog(LOG_INFO, "Returning to SIP proxy: %.*s", STR_FMT(to_send));

	ZERO(mh);
	mh.msg_name = sin;
	mh.msg_namelen = sizeof(*sin);
	mh.msg_iov = iov;
	mh.msg_iovlen = 3;

	iov[0].iov_base = cookie.s;
	iov[0].iov_len = cookie.len;
	iov[1].iov_base = " ";
	iov[1].iov_len = 1;
	iov[2].iov_base = to_send->s;
	iov[2].iov_len = to_send->len;

	sendmsg(c->udp_listener.fd, &mh, 0);

	if (resp)
		cookie_cache_insert(&c->cookie_cache, &cookie, &reply);
	else
		free(to_send);

	goto out;

out:
	bencode_buffer_free(&bencbuf);
}



struct control_ng *control_ng_new(struct poller *p, struct in6_addr ip, u_int16_t port, struct callmaster *m) {
	struct control_ng *c;

	if (!p || !m)
		return NULL;

	c = obj_alloc0("control_ng", sizeof(*c), NULL);

	c->callmaster = m;
	cookie_cache_init(&c->cookie_cache);

	if (udp_listener_init(&c->udp_listener, p, ip, port, control_ng_incoming, &c->obj))
		goto fail2;

	return c;

fail2:
	obj_put(c);
	return NULL;

}
