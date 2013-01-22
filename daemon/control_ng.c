#include "control_ng.h"
#include "obj.h"
#include "poller.h"
#include "bencode.h"


static void control_ng_incoming(struct obj *obj, char *buf, int len, struct sockaddr_in6 *sin, char *addr) {
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
