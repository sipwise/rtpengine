#include "inotify.h"
#include <sys/inotify.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "log.h"
#include "main.h"
#include "epoll.h"
#include "metafile.h"


static int inotify_fd = -1;


static handler_func inotify_handler_func;
static handler_t inotify_handler = {
	.func = inotify_handler_func,
};


static void inotify_close_write(struct inotify_event *inev) {
	dbg("inotify close_write(%s%s%s)", FMT_M(inev->name));
	metafile_change(inev->name);
}


static void inotify_delete(struct inotify_event *inev) {
	dbg("inotify delete(%s%s%s)", FMT_M(inev->name));
	metafile_delete(inev->name);
}


static void inotify_handler_func(handler_t *handler) {
	char buf[4 * (sizeof(struct inotify_event) + NAME_MAX + 1)];

	while (1) {
		int ret = read(inotify_fd, buf, sizeof(buf));
		if (ret == -1) {
			if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
				break;
			die_errno("read on inotify fd failed");
		}
		if (ret == 0)
			die("EOF on inotify fd");

		char *bufend = buf + ret;
		char *bufhead = buf;
		while (bufhead < bufend) {
			struct inotify_event *inev = (void *) bufhead;

			if ((inev->mask & IN_DELETE))
				inotify_delete(inev);
			if ((inev->mask & IN_CLOSE_WRITE))
				inotify_close_write(inev);

			bufhead += sizeof(*inev) + inev->len;
		}
	}
}


void inotify_setup(void) {
	inotify_fd = inotify_init1(IN_NONBLOCK);
	if (inotify_fd == -1)
		die_errno("inotify_init1 failed");

	int ret = inotify_add_watch(inotify_fd, spool_dir, IN_CLOSE_WRITE | IN_DELETE);
	if (ret == -1)
		die_errno("inotify_add_watch failed");

	if (epoll_add(inotify_fd, EPOLLIN, &inotify_handler))
		die_errno("failed to add inotify_fd to epoll");
}


void inotify_cleanup(void) {
	close(inotify_fd);
}
