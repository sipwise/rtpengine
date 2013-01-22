#include "control_ng.h"
#include "obj.h"
#include "poller.h"
#include "bencode.h"
#include "log.h"
#include "cookie_cache.h"
#include "call.h"


static void control_ng_incoming(struct obj *obj, char *buf, int buf_len, struct sockaddr_in6 *sin, char *addr) {
	struct control_ng *c = (void *) obj;
	char *data;
	bencode_buffer_t bencbuf;
	bencode_item_t *dict, *resp;
	char *reply;
	const char *cmd, *errstr, *cookie;
	int cmd_len, cookie_len, data_len, reply_len;
	struct msghdr mh;
	struct iovec iov[3];

	data = memchr(buf, ' ', buf_len);
	if (!data || data == buf) {
		mylog(LOG_WARNING, "Received invalid data on NG port (no cookie) from %s:%u: %.*s", addr, ntohs(sin->sin6_port), buf_len, buf);
		return;
	}

	bencode_buffer_init(&bencbuf);
	resp = bencode_dictionary(&bencbuf);

	cookie = buf;
	cookie_len = data - buf;
	*data++ = '\0';
	data_len = buf_len - cookie_len - 1;

	errstr = "Invalid data (no payload)";
	if (data_len <= 0)
		goto err_send;

	reply = cookie_cache_lookup(&c->cookie_cache, cookie);
	if (reply) {
		mylog(LOG_INFO, "Detected command from %s:%u as a duplicate", addr, ntohs(sin->sin6_port));
		reply_len = strlen(reply); /* XXX fails for embedded nulls */
		resp = NULL;
		goto send_only;
	}

	dict = bencode_decode_expect(&bencbuf, data, data_len, BENCODE_DICTIONARY);
	errstr = "Could not decode dictionary";
	if (!dict)
		goto err_send;

	cmd = bencode_dictionary_get_string(dict, "command", &cmd_len);
	errstr = "Dictionary contains no key \"command\"";
	if (!cmd)
		goto err_send;

	mylog(LOG_INFO, "Got valid command from %s:%u: %.*s [%.*s]", addr, ntohs(sin->sin6_port), cmd_len, cmd, data_len, data);

	errstr = NULL;
	if (!strmemcmp(cmd, cmd_len, "ping"))
		bencode_dictionary_add_string(resp, "result", "pong");
	else if (!strmemcmp(cmd, cmd_len, "offer")) {
		errstr = call_offer(dict, c->callmaster, resp);
	}
	else if (!strmemcmp(cmd, cmd_len, "answer")) {
		errstr = call_answer(dict, c->callmaster, resp);
	}
	else
		errstr = "Unrecognized command";

	if (errstr)
		goto err_send;

	goto send_out;

err_send:
	mylog(LOG_WARNING, "Protocol error in packet from %s:%u: %s [%.*s]", addr, ntohs(sin->sin6_port), errstr, data_len, data);
	bencode_dictionary_add_string(resp, "result", "error");
	bencode_dictionary_add_string(resp, "error-reason", errstr);
	goto send_out;

send_out:
	reply = bencode_collapse(resp, &reply_len);

send_only:
	ZERO(mh);
	mh.msg_name = sin;
	mh.msg_namelen = sizeof(*sin);
	mh.msg_iov = iov;
	mh.msg_iovlen = 3;

	iov[0].iov_base = (void *) cookie;
	iov[0].iov_len = cookie_len;
	iov[1].iov_base = " ";
	iov[1].iov_len = 1;
	iov[2].iov_base = reply;
	iov[2].iov_len = reply_len;

	sendmsg(c->udp_listener.fd, &mh, 0);

	if (resp)
		cookie_cache_insert(&c->cookie_cache, cookie, reply, reply_len);

	goto out;

	cookie_cache_remove(&c->cookie_cache, cookie);
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
