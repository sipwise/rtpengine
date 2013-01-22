#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>

#include "udp_listener.h"
#include "poller.h"
#include "aux.h"

static void udp_listener_closed(int fd, void *p, uintptr_t x) {
	abort();
}

int udp_listener_init(struct udp_listener *u, struct poller *p, struct in6_addr ip, u_int16_t port, poller_func_t func, struct obj *obj) {
	struct sockaddr_in6 sin;
	struct poller_item i;

	u->fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (u->fd == -1)
		return -1;

	nonblock(u->fd);
	reuseaddr(u->fd);
	ipv6only(u->fd, 0);

	ZERO(sin);
	sin.sin6_family = AF_INET6;
	sin.sin6_addr = ip;
	sin.sin6_port = htons(port);
	if (bind(u->fd, (struct sockaddr *) &sin, sizeof(sin)))
		goto fail;

	ZERO(i);
	i.fd = u->fd;
	i.closed = udp_listener_closed;
	i.readable = func;
	i.obj = obj;
	if (poller_add_item(p, &i))
		goto fail;

fail:
	close(u->fd);
	return -1;
}
