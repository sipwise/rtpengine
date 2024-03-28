#include "uring.h"
#include <errno.h>
#include <string.h>
#include "log.h"
#include "loglib.h"
#include "socket.h"
#include "poller.h"


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
	int ret = io_uring_queue_init_params(4096, &rtpe_uring, &params);
	if (ret)
		die("io_uring init failed (%s)", strerror(errno));

	uring_sendmsg = __uring_sendmsg;
	uring_thread_loop = __uring_thread_loop;
}

void uring_thread_cleanup(void) {
	io_uring_queue_exit(&rtpe_uring);
}

#endif
