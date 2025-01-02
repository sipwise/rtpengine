#include "udp_listener.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "poller.h"
#include "helpers.h"
#include "str.h"
#include "log.h"
#include "obj.h"
#include "socket.h"
#include "log_funcs.h"
#include "uring.h"

struct udp_listener_callback {
	struct obj obj;
	udp_listener_callback_t func;
	socket_t *ul;
	struct obj *p;
};

static void udp_listener_closed(int fd, void *p) {
	if (!rtpe_shutdown)
		abort();
}

static void udp_listener_incoming(int fd, void *p) {
	struct udp_listener_callback *cb = p;
	int len;
	struct udp_buffer *udp_buf = NULL;

	for (;;) {
		if (!udp_buf) {
			// initialise if we need to
			udp_buf = obj_alloc0(struct udp_buffer, NULL);
			udp_buf->str.s = udp_buf->buf + RTP_BUFFER_HEAD_ROOM;
			udp_buf->listener = cb->ul;
		}

		len = socket_recvfrom_to(udp_buf->listener, udp_buf->str.s, MAX_UDP_LENGTH, &udp_buf->sin,
				&udp_buf->local_addr);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EWOULDBLOCK && errno != EAGAIN)
				ilog(LOG_WARNING, "Error reading from UDP socket");
			break;
		}

		udp_buf->str.s[len] = '\0';
		endpoint_print(&udp_buf->sin, udp_buf->addr, sizeof(udp_buf->addr));

		udp_buf->str.len = len;
		cb->func(cb->p, udp_buf);

		// we can re-use the object if only one reference (ours) is left. this is not
		// totally race-free, but in the worst case we end up re-allocating another
		// new object when we didn't need to.
		if (udp_buf->obj.ref != 1) {
			obj_put(udp_buf);
			udp_buf = NULL;
		}

		release_closed_sockets();
		log_info_reset();
	}
	obj_put(udp_buf);
}

static void __ulc_free(struct udp_listener_callback *cb) {
	obj_put_o(cb->p);
}

int udp_listener_init(socket_t *sock, const endpoint_t *ep,
		udp_listener_callback_t func, struct obj *obj)
{
	struct poller_item i;
	struct udp_listener_callback *cb;

	cb = obj_alloc(struct udp_listener_callback, __ulc_free);
	cb->func = func;
	cb->p = obj_get_o(obj);
	cb->ul = sock;

	if (open_socket(sock, SOCK_DGRAM, ep->port, &ep->address))
		goto fail;

	socket_pktinfo(sock);

	ZERO(i);
	i.fd = sock->fd;
	i.closed = udp_listener_closed;
	i.readable = udp_listener_incoming;
	i.obj = &cb->obj;
	if (!rtpe_poller_add_item(rtpe_control_poller, &i))
		goto fail;

	obj_put(cb);
	return 0;

fail:
	close_socket(sock);
	obj_put(cb);
	return -1;
}
