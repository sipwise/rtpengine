#include "uring.h"
#include <errno.h>
#include <string.h>
#include <poll.h>
#include "log.h"
#include "loglib.h"
#include "socket.h"
#include "poller.h"
#include "bufferpool.h"
#include "call.h"


#define BUFFER_SIZE RTP_BUFFER_SIZE	// size of individual buffer
#define BUFFERS_COUNT 1024		// number of buffers allocated in one pool, should be 2^n
#define BUFFER_POOLS 8			// number of pools to keep alive

static_assert(BUFFERS_COUNT * BUFFER_POOLS < (1<<16), "too many buffers (>= 2^16)");

struct uring_buffer {
	void *buf;
	struct poller *poller;
	unsigned int num;
};

struct poller {
	mutex_t lock;
	GQueue reqs;
	int waker_fds[2];
	GPtrArray *evs; // holds uring_poll_event by fd
	struct bufferpool *bufferpool;
	struct uring_buffer *buffers[BUFFER_POOLS];
	GArray *blocked;
};

struct poller_req {
	enum { ADD, BLOCKED, ERROR, DEL, BUFFERS, RECV } type;
	union {
		struct poller_item it;
		struct {
			int fd;
			void (*callback)(void *);
			void *arg;
		};
		struct {
			void *buf;
			unsigned int num;
		};
	};
};

static ssize_t __socket_sendmsg(socket_t *s, struct msghdr *m, const endpoint_t *e,
		struct sockaddr_storage *ss, struct uring_req *r)
{
	ssize_t ret = socket_sendmsg(s, m, e);
	r->handler(r, 0, 0);
	return ret;
}


__thread __typeof(__socket_sendmsg) (*uring_sendmsg) = __socket_sendmsg;


#ifdef HAVE_LIBURING

#include <liburing.h>


static __thread struct io_uring rtpe_uring;


static ssize_t __uring_sendmsg(socket_t *s, struct msghdr *m, const endpoint_t *e,
		struct sockaddr_storage *ss, struct uring_req *r)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(&rtpe_uring);
	assert(sqe != NULL);
	s->family->endpoint2sockaddr(ss, e);
	m->msg_name = ss;
	m->msg_namelen = s->family->sockaddr_size;
	io_uring_sqe_set_data(sqe, r);
	io_uring_prep_sendmsg(sqe, s->fd, m, 0);

	return 0;
}

static unsigned int __uring_thread_loop(void) {
	io_uring_submit_and_get_events(&rtpe_uring);

	struct io_uring_cqe *cqe;
	unsigned int head, num = 0;
	io_uring_for_each_cqe(&rtpe_uring, head, cqe) {
		struct uring_req *req = io_uring_cqe_get_data(cqe);
		req->handler(req, cqe->res, cqe->flags);
		num++;
	}

	io_uring_cq_advance(&rtpe_uring, num);

	return num;
}

void uring_thread_init(void) {
	struct io_uring_params params = {0};
	int ret = io_uring_queue_init_params(rtpe_common_config_ptr->io_uring_buffers, &rtpe_uring, &params);
	if (ret)
		die("io_uring init failed (%s)", strerror(errno));

	uring_sendmsg = __uring_sendmsg;
	uring_thread_loop = __uring_thread_loop;
}

void uring_thread_cleanup(void) {
	io_uring_queue_exit(&rtpe_uring);
}


static void uring_submit_buffer(struct poller *p, void *b, unsigned int num) {
	struct poller_req *req = g_new0(__typeof(*req), 1);
	req->type = BUFFERS;
	req->buf = b;

	LOCK(&p->lock);

	g_queue_push_tail(&p->reqs, req);
	uring_poller_wake(p);
	req->num = num;
}
static unsigned int uring_buffer_recycle(void *p) {
	//ilog(LOG_INFO, "uring buffer recycle");
	struct uring_buffer *b = p;
	struct poller *poller = b->poller;
	uring_submit_buffer(poller, b->buf, b->num);
	return BUFFERS_COUNT;
}
struct poller *uring_poller_new(void) {
	struct poller *ret = g_new0(__typeof(*ret), 1);

	mutex_init(&ret->lock);
	g_queue_init(&ret->reqs);
	int ok = socketpair(AF_UNIX, SOCK_STREAM, 0, ret->waker_fds);
	if (ok != 0)
		return false;
	nonblock(ret->waker_fds[0]);
	nonblock(ret->waker_fds[1]);
	ret->evs = g_ptr_array_new();
	ret->blocked = g_array_new(false, true, sizeof(char));

	ret->bufferpool = bufferpool_new(g_malloc, g_free, BUFFER_SIZE * BUFFERS_COUNT);
	for (int i = 0; i < BUFFER_POOLS; i++) {
		ret->buffers[i] = g_new0(__typeof(*ret->buffers[i]), 1);
		ret->buffers[i]->buf = bufferpool_reserve(ret->bufferpool, BUFFERS_COUNT,
				uring_buffer_recycle, ret->buffers[i]);
		ret->buffers[i]->buf += RTP_BUFFER_HEAD_ROOM;
		ret->buffers[i]->num = i;
		ret->buffers[i]->poller = ret;
		uring_submit_buffer(ret, ret->buffers[i]->buf, i);
	}

	return ret;
}

void uring_poller_free(struct poller **pp) {
	// XXX cleanup of reqs
	close((*pp)->waker_fds[0]);
	close((*pp)->waker_fds[1]);
	g_ptr_array_free((*pp)->evs, true);
	g_array_free((*pp)->blocked, true);
	for (int i = 0; i < BUFFER_POOLS; i++) {
		bufferpool_release((*pp)->buffers[i]->buf);
		g_free((*pp)->buffers[i]);
	}
	bufferpool_destroy((*pp)->bufferpool);
	g_free(*pp);
	*pp = NULL;
}

void uring_poller_wake(struct poller *p) {
	ssize_t ret = write(p->waker_fds[0], "", 1);
	(void)ret; // ignore return value
}

bool uring_poller_add_item(struct poller *p, struct poller_item *i) {
	if (!p)
		return false;
	if (!i)
		return false;
	if (i->fd < 0)
		return false;
	if (!i->readable)
		return false;
	if (!i->closed)
		return false;

	struct poller_req *req = g_new0(__typeof(*req), 1);
	if (i->recv)
		req->type = RECV;
	else
		req->type = ADD;
	req->it = *i;

	if (req->it.obj)
		obj_hold_o(req->it.obj);

	LOCK(&p->lock);

	g_queue_push_tail(&p->reqs, req);
	uring_poller_wake(p);

	return true;
}
void uring_poller_blocked(struct poller *p, void *fdp) {
	struct poller_req *req = g_new0(__typeof(*req), 1);
	req->type = BLOCKED;
	req->fd = GPOINTER_TO_INT(fdp);

	LOCK(&p->lock);

	if (p->blocked->len <= req->fd)
		g_array_set_size(p->blocked, req->fd + 1);
	g_array_index(p->blocked, char, req->fd) = 1;

	g_queue_push_tail(&p->reqs, req);
	uring_poller_wake(p);
}
bool uring_poller_isblocked(struct poller *p, void *fdp) {
	int fd = GPOINTER_TO_INT(fdp);
	if (fd < 0)
		return false;

	LOCK(&p->lock);

	if (p->blocked->len <= fd)
		return false;
	return !!g_array_index(p->blocked, char, fd);
}
void uring_poller_error(struct poller *p, void *fdp) {
	struct poller_req *req = g_new0(__typeof(*req), 1);
	req->type = ERROR;
	req->fd = GPOINTER_TO_INT(fdp);

	LOCK(&p->lock);

	g_queue_push_tail(&p->reqs, req);
	uring_poller_wake(p);
}
bool uring_poller_del_item_callback(struct poller *p, int fd, void (*callback)(void *), void *arg) {
	if (rtpe_shutdown)
		return true;

	struct poller_req *req = g_new0(__typeof(*req), 1);
	req->type = DEL;
	req->fd = fd;
	req->callback = callback;
	req->arg = arg;

	LOCK(&p->lock);

	g_queue_push_tail(&p->reqs, req);
	uring_poller_wake(p);

	return true;
}
bool uring_poller_del_item(struct poller *p, int fd) {
	return uring_poller_del_item_callback(p, fd, NULL, NULL);
}

struct uring_poll_event {
	struct uring_req req; // must be first
	struct poller_item it;
	struct poller *poller;
	bool closed:1;
};
static void uring_poll_event(struct uring_req *req, int32_t res, uint32_t flags) {
	struct uring_poll_event *ereq = (__typeof(ereq)) req;
	bool closed = false;

	//ilog(LOG_INFO, "uring poll event %i %i %i", ereq->it.fd, res, flags);

	if (res < 0) {
		if (res != -ECANCELED)
			ilog(LOG_WARNING | LOG_FLAG_LIMIT, "io_uring poll error on fd %i: %s",
					ereq->it.fd, strerror(-res));
		closed = true;
	}
	else if ((res & (POLLERR | POLLHUP))) {
		//ilog(LOG_INFO, "uring poll fd error %i %i", ereq->it.fd, res);
		closed = true;
	}
	else if ((res & POLLIN))
		ereq->it.readable(ereq->it.fd, ereq->it.obj);
	else {
		ilog(LOG_WARNING | LOG_FLAG_LIMIT, "unhandled io_uring poll event mask on fd %i: %i",
				ereq->it.fd, res);
		closed = true;
	}

	if (closed) {
		if (!ereq->closed)
			ereq->it.closed(ereq->it.fd, ereq->it.obj);
		ereq->closed = true;
	}

	if (!(flags & IORING_CQE_F_MORE)) {
		if (ereq->it.obj)
			obj_put_o(ereq->it.obj);
		struct poller *p = ereq->poller;
		{
			LOCK(&p->lock);
			if (p->evs->len > ereq->it.fd && p->evs->pdata[ereq->it.fd] == ereq)
				p->evs->pdata[ereq->it.fd] = NULL;
		}
		uring_req_free(&ereq->req);
	}
}

struct uring_poll_removed {
	struct uring_req req; // must be first
	int fd;
	void (*callback)(void *);
	void *arg;
	struct poller *poller;
};
static void uring_poll_removed(struct uring_req *req, int32_t res, uint32_t flags) {
	struct uring_poll_removed *rreq = (__typeof(rreq)) req;
	//ilog(LOG_INFO, "poll removed fd %i with cb %p/%p", rreq->fd, rreq->callback, rreq->arg);
	if (rreq->callback)
		rreq->callback(rreq->arg);
	else
		close(rreq->fd);
	uring_req_free(req);
}

struct uring_poll_unblocked {
	struct uring_req req; // must be first
	struct poller_item it;
	struct poller *poller;
};
static void uring_poll_unblocked(struct uring_req *req, int32_t res, uint32_t flags) {
	struct uring_poll_unblocked *ureq = (__typeof(ureq)) req;
	bool closed = false;
	if (res < 0) {
		ilog(LOG_WARNING | LOG_FLAG_LIMIT, "io_uring poll write error on fd %i: %s",
				ureq->it.fd, strerror(-res));
		closed = true;
	}
	else if (!(res & (POLLOUT))) {
		ilog(LOG_WARNING | LOG_FLAG_LIMIT, "unhandled io_uring poll event write mask on fd %i: %i",
				ureq->it.fd, res);
		closed = true;
	}
	else {
		struct poller *p = ureq->poller;
		if (p->blocked->len > ureq->it.fd)
			g_array_index(p->blocked, char, ureq->it.fd) = 0;
		ureq->it.writeable(ureq->it.fd, ureq->it.obj);
	}

	assert((flags & IORING_CQE_F_MORE) == 0);

	if (closed)
		ureq->it.closed(ureq->it.fd, ureq->it.obj);

	if (ureq->it.obj)
		obj_put_o(ureq->it.obj);
	uring_req_free(req);
}

struct uring_poll_recv {
	struct uring_req req; // must be first
	struct poller_item it;
	struct msghdr msg;
	struct iovec iov;
	struct poller *poller;
	bool closed:1;
};
INLINE void uring_recvmsg_parse_cmsg(struct timeval *tv,
		sockaddr_t *to, bool (*parse)(struct cmsghdr *, sockaddr_t *),
		struct io_uring_recvmsg_out *out, struct msghdr *mh)
{
	socket_recvfrom_parse_cmsg(&tv, &to, parse, mh,
			io_uring_recvmsg_cmsg_firsthdr(out, mh),
			io_uring_recvmsg_cmsg_nexthdr(out, mh, cm));
}
static void uring_poll_recv(struct uring_req *req, int32_t res, uint32_t flags) {
	struct uring_poll_recv *rreq =  (__typeof(rreq)) req;
	struct poller *p = rreq->poller;
	bool closed = false;

	//ilog(LOG_INFO, "uring recvmsg event %i %i %i", rreq->it.fd, res, flags);

	if (res < 0) {
		if (res != -ECANCELED)
			ilog(LOG_WARNING | LOG_FLAG_LIMIT, "io_uring recvmsg error on fd %i: %s",
					rreq->it.fd, strerror(-res));
		closed = true;
	}
	else {
		assert((flags & IORING_CQE_F_BUFFER) != 0);
		unsigned int buffer_id = flags >> IORING_CQE_BUFFER_SHIFT;
		unsigned int pool_id = buffer_id / BUFFERS_COUNT;
		unsigned int pool_offset = buffer_id % BUFFERS_COUNT;
		//ilog(LOG_INFO, "pool id %u buf id %u", pool_id, pool_offset);
		assert(pool_id < BUFFER_POOLS);
		struct uring_buffer *ubuf = p->buffers[pool_id];
		void *buf = ubuf->buf + BUFFER_SIZE * pool_offset;

		struct io_uring_recvmsg_out *out = io_uring_recvmsg_validate(buf, BUFFER_SIZE, &rreq->msg);
		assert(out != NULL);
		void *payload = io_uring_recvmsg_payload(out, &rreq->msg);
		struct sockaddr *sa = io_uring_recvmsg_name(out);

		struct timeval tv = {0};
		uring_recvmsg_parse_cmsg(&tv, NULL, NULL, out, &rreq->msg);

		rreq->it.recv(rreq->it.obj, payload, out->payloadlen, sa, &tv);
	}

	if (!(flags & IORING_CQE_F_MORE))
		closed = true;

	if (closed) {
		if (!rreq->closed)
			rreq->it.closed(rreq->it.fd, rreq->it.obj);
		rreq->closed = true;
	}

	if (!(flags & IORING_CQE_F_MORE)) {
		//ilog(LOG_INFO, "last uring recv event for fd %i for %p (%i)", rreq->it.fd, rreq->it.obj, rreq->it.obj->ref);
		if (rreq->it.obj)
			obj_put_o(rreq->it.obj);
		uring_req_free(&rreq->req);
	}
}

static void uring_poller_do_add(struct poller *p, struct poller_req *preq) {
	// don't allow duplicates
	if (p->evs->len > preq->it.fd && p->evs->pdata[preq->it.fd])
		abort(); // XXX handle gracefully?
	struct uring_poll_event *ereq
		= uring_alloc_req(sizeof(*ereq), uring_poll_event);
	ereq->it = preq->it;
	ereq->poller = p;
	struct io_uring_sqe *sqe = io_uring_get_sqe(&rtpe_uring);
	io_uring_prep_poll_multishot(sqe, ereq->it.fd, POLLHUP | POLLERR | POLLIN);
	io_uring_sqe_set_data(sqe, ereq);
	// save ereq for write blocks. no extra obj reference
	if (p->evs->len <= ereq->it.fd)
		g_ptr_array_set_size(p->evs, ereq->it.fd + 1);
	p->evs->pdata[ereq->it.fd] = ereq;
}
static void uring_poller_do_blocked(struct poller *p, struct poller_req *preq) {
	// valid fd?
	if (p->evs->len <= preq->fd || !p->evs->pdata[preq->fd])
		abort(); // XXX handle gracefully?
	struct uring_poll_event *ereq = p->evs->pdata[preq->fd];
	struct uring_poll_unblocked *ureq
		= uring_alloc_req(sizeof(*ureq), uring_poll_unblocked);
	ureq->it = ereq->it;
	ureq->poller = p;
	if (ureq->it.obj)
		obj_hold_o(ureq->it.obj);
	struct io_uring_sqe *sqe = io_uring_get_sqe(&rtpe_uring);
	io_uring_prep_poll_add(sqe, ureq->it.fd, POLLOUT);
	io_uring_sqe_set_data(sqe, ureq);
}
static void uring_poller_do_error(struct poller *p, struct poller_req *preq) {
	// do nothing?
}
static void uring_poller_do_del(struct poller *p, struct poller_req *preq) {
	//ilog(LOG_INFO, "del fd %i on %p", preq->fd, p);
	struct uring_poll_removed *rreq
		= uring_alloc_req(sizeof(*rreq), uring_poll_removed);
	rreq->fd = preq->fd;
	rreq->poller = p;
	rreq->callback = preq->callback;
	rreq->arg = preq->arg;
	struct io_uring_sqe *sqe = io_uring_get_sqe(&rtpe_uring);
	io_uring_prep_cancel_fd(sqe, rreq->fd, IORING_ASYNC_CANCEL_ALL);
	io_uring_sqe_set_data(sqe, rreq);
}
static void uring_poller_do_buffers(struct poller *p, struct poller_req *preq) {
	//ilog(LOG_INFO, "XXXXXXXXX adding buffers %p %u", p, preq->num);
	struct io_uring_sqe *sqe = io_uring_get_sqe(&rtpe_uring);
	io_uring_prep_provide_buffers(sqe, preq->buf, BUFFER_SIZE, BUFFERS_COUNT, 0,
			preq->num * BUFFERS_COUNT);
	struct uring_req *breq = uring_alloc_buffer_req(sizeof(*breq));
	io_uring_sqe_set_data(sqe, breq); // XXX no content? not needed?
}
static void uring_poller_do_recv(struct poller *p, struct poller_req *preq) {
	//ilog(LOG_INFO, "adding recv fd %i on %p for %p", preq->it.fd, p, preq->it.obj);
	struct uring_poll_recv *rreq
		= uring_alloc_req(sizeof(*rreq), uring_poll_recv);
	rreq->it = preq->it;
	rreq->poller = p;
	struct io_uring_sqe *sqe = io_uring_get_sqe(&rtpe_uring);
	rreq->iov = (__typeof(rreq->iov)) {
		.iov_len = MAX_RTP_PACKET_SIZE,
	};
	rreq->msg = (__typeof(rreq->msg)) {
		.msg_iov = &rreq->iov,
		.msg_iovlen = 1,
		.msg_namelen = sizeof(struct sockaddr_storage),
		.msg_controllen = 64,
	};
	io_uring_prep_recvmsg_multishot(sqe, rreq->it.fd, &rreq->msg, 0);
	sqe->ioprio |= IORING_RECVSEND_POLL_FIRST;
	io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
	sqe->buf_group = 0;
	io_uring_sqe_set_data(sqe, rreq);
}

static void uring_poller_do_reqs(struct poller *p) {
	LOCK(&p->lock);

	while (p->reqs.length) {
		struct poller_req *preq = g_queue_pop_head(&p->reqs);

		switch (preq->type) {
			case ADD:
				uring_poller_do_add(p, preq);
				break;
			case BLOCKED:
				uring_poller_do_blocked(p, preq);
				break;
			case ERROR:
				uring_poller_do_error(p, preq);
				break;
			case DEL:
				uring_poller_do_del(p, preq);
				break;
			case BUFFERS:
				uring_poller_do_buffers(p, preq);
				break;
			case RECV:
				uring_poller_do_recv(p, preq);
				break;
			default:
				abort();
		}

		g_free(preq);
	}
}

void uring_poller_waker_read(int fd, void *p) {
	char buf[32];
	while (read(fd, buf, sizeof(buf)) > 0) { }
}
void uring_poller_waker_closed(int fd, void *p) {
	if (!rtpe_shutdown)
		abort();
}

void uring_poller_add_waker(struct poller *p) {
	uring_poller_add_item(p,
			&(struct poller_item) {
				.readable = uring_poller_waker_read,
				.closed = uring_poller_waker_closed,
				.fd = p->waker_fds[1],
			});
}

void uring_poller_poll(struct poller *p) {
	uring_poller_do_reqs(p);

	unsigned int events = __uring_thread_loop();

	if (events == 0) {
		struct io_uring_cqe *cqe; // ignored
		thread_cancel_enable();
		io_uring_wait_cqe(&rtpe_uring, &cqe); // maybe not a cancellation point
		thread_cancel_disable();
	}
}

void uring_poller_clear(struct poller *p) {
	struct uring_req *req = uring_alloc_buffer_req(sizeof(*req));
	struct io_uring_sqe *sqe = io_uring_get_sqe(&rtpe_uring);
	io_uring_prep_cancel(sqe, 0, IORING_ASYNC_CANCEL_ANY);
	io_uring_sqe_set_data(sqe, req);
	while (__uring_thread_loop() != 0) { }
}

#endif
