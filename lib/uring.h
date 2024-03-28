#ifndef _URING_H_
#define _URING_H_

#include "socket.h"

struct uring_req;

typedef void uring_req_handler_fn(struct uring_req *, int32_t res, uint32_t flags);

struct uring_req {
	uring_req_handler_fn *handler;
};

extern __thread ssize_t (*uring_sendmsg)(socket_t *, struct msghdr *, const endpoint_t *,
		struct sockaddr_storage *, struct uring_req *);

INLINE void uring_req_buffer_free(struct uring_req *r, int32_t res, uint32_t flags) {
	g_free(r);
}
INLINE void uring_req_free(struct uring_req *r) {
	g_free(r);
}

INLINE void *uring_alloc_req(size_t len, uring_req_handler_fn *fn) {
	struct uring_req *ret = g_malloc0(len);
	ret->handler = fn;
	return ret;
}

INLINE void *uring_alloc_buffer_req(size_t len) {
	return uring_alloc_req(len, uring_req_buffer_free);
}

#ifdef HAVE_LIBURING

#include "bufferpool.h"

void uring_thread_init(void);
void uring_thread_cleanup(void);

#endif

#endif
