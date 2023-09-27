#include "epoll.h"
#include <sys/epoll.h>
#include <glib.h>
#include <pthread.h>
#include <unistd.h>
#include <mysql.h>
#include "log.h"
#include "main.h"
#include "garbage.h"
#include "db.h"


static int epoll_fd = -1;


void epoll_setup(void) {
	epoll_fd = epoll_create1(0);
	if (epoll_fd == -1)
		die_errno("epoll_create1 failed");

}


int epoll_add(int fd, uint32_t events, handler_t *handler) {
	struct epoll_event epev = { .events = events | EPOLLET, .data = { .ptr = handler } };
	int ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &epev);
	return ret;
}


void epoll_del(int fd) {
	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
}


static void poller_thread_end(void *ptr) {
	mysql_thread_end();
	db_thread_end();
}


void *poller_thread(void *ptr) {
	struct epoll_event epev;
	unsigned int me_num = GPOINTER_TO_UINT(ptr);

	dbg("poller thread %u running", me_num);

	mysql_thread_init();

	thread_cleanup_push(poller_thread_end, NULL);

	while (!shutdown_flag) {
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		int ret = epoll_wait(epoll_fd, &epev, 1, 10000);
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

		if (ret == -1) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			die_errno("epoll_wait failed");
		}

		if (ret > 0) {
			dbg("thread %u handling event", me_num);

			handler_t *handler = epev.data.ptr;
			handler->func(handler);
		}

		garbage_collect(me_num);
	}

	thread_cleanup_pop(true);

	return NULL;
}


void epoll_cleanup(void) {
	close(epoll_fd);
}
