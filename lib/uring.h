#ifndef _URING_H_
#define _URING_H_

#include "socket.h"

struct uring_req;

typedef void uring_req_handler_fn(struct uring_req *, int32_t res, uint32_t flags);

struct uring_req {
	uring_req_handler_fn *handler;
};

struct uring_methods {
	ssize_t (*sendmsg)(socket_t *, struct msghdr *, const endpoint_t *,
			struct sockaddr_storage *, struct uring_req *);
	unsigned int (*thread_loop)(void);
};

extern __thread struct uring_methods uring_methods;

INLINE void uring_req_buffer_free(struct uring_req *r, int32_t res, uint32_t flags) {
	g_free(r);
}
INLINE void uring_req_free(struct uring_req *r) {
	g_free(r);
}

#define uring_alloc_req(T, fn) ({ \
			T *__ret = g_new0(T, 1); \
			__ret->req.handler = (fn); \
			__ret; \
		})

#define uring_alloc_buffer_req(T) uring_alloc_req(T, uring_req_buffer_free)


#ifdef HAVE_LIBURING

#include "bufferpool.h"

void uring_thread_init(void);
void uring_thread_cleanup(void);

struct poller_item;
struct poller *uring_poller_new(void);
void uring_poller_free(struct poller **pp);
void uring_poller_add_waker(struct poller *p);
void uring_poller_wake(struct poller *p);
void uring_poller_poll(struct poller *);
void uring_poller_clear(struct poller *);

bool uring_poller_add_item(struct poller *p, struct poller_item *i);
bool uring_poller_del_item(struct poller *p, int fd);
void uring_poller_blocked(struct poller *p, void *fdp);
bool uring_poller_isblocked(struct poller *p, void *fdp);
void uring_poller_error(struct poller *p, void *fdp);
bool uring_poller_del_item_callback(struct poller *p, int fd, void (*callback)(void *), void *arg);

#endif

#endif
