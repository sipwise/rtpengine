#include "poller.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <sys/epoll.h>
#include <glib.h>
#include <sys/time.h>


#include "obj.h"
#include "log_funcs.h"
#include "auxlib.h"
#include "uring.h"



struct poller_item_int {
	struct obj			obj;
	struct poller_item		item;

	unsigned int			blocked:1;
	unsigned int			error:1;
};

struct poller {
	int				fd;
	mutex_t				lock;
	GPtrArray			*items;
};

bool (*rtpe_poller_add_item)(struct poller *, struct poller_item *) = poller_add_item;
bool (*rtpe_poller_del_item)(struct poller *, int) = poller_del_item;
bool (*rtpe_poller_del_item_callback)(struct poller *, int, void (*)(void *), void *) = poller_del_item_callback;
void (*rtpe_poller_blocked)(struct poller *, void *) = poller_blocked;
bool (*rtpe_poller_isblocked)(struct poller *, void *) = poller_isblocked;
void (*rtpe_poller_error)(struct poller *, void *) = poller_error;


static void poller_free_item(struct poller_item_int *ele) {
	if (ele)
		obj_put(ele);
}

struct poller *poller_new(void) {
	struct poller *p;

	p = g_slice_alloc0(sizeof(*p));
	mutex_init(&p->lock);
	p->fd = epoll_create1(0);
	if (p->fd == -1)
		goto err;
	p->items = g_ptr_array_new_full(1024, (GDestroyNotify) poller_free_item);

	return p;

err:
	poller_free(&p);
	return NULL;
}

void poller_free(struct poller **pp) {
	struct poller *p = *pp;

	// prevent recursion into poller_del_item from item's free functions
	GPtrArray *arr = p->items;
	p->items = NULL;
	g_ptr_array_free(arr, TRUE); // calls the clear function to release references

	if (p->fd != -1)
		close(p->fd);
	p->fd = -1;
	g_slice_free1(sizeof(*p), p);
	*pp = NULL;
}


static int epoll_events(struct poller_item *it, struct poller_item_int *ii) {
	if (!it)
		it = &ii->item;
	return EPOLLHUP | EPOLLERR | EPOLLET |
		((it->writeable && ii && ii->blocked) ? EPOLLOUT : 0) |
		(it->readable ? EPOLLIN : 0);
}


static void poller_item_free(struct poller_item_int *i) {
	obj_put_o(i->item.obj);
}


bool poller_add_item(struct poller *p, struct poller_item *i) {
	struct poller_item_int *ip;
	struct epoll_event e;

	if (!p)
		return false;
	if (!i)
		return false;
	if (i->fd < 0)
		return false;
	if (!i->readable && !i->writeable)
		return false;
	if (!i->closed)
		return false;

	{

	LOCK(&p->lock);

	if (i->fd < p->items->len && p->items->pdata[i->fd])
		return false;

	ZERO(e);
	e.events = epoll_events(i, NULL);
	e.data.fd = i->fd;
	if (epoll_ctl(p->fd, EPOLL_CTL_ADD, i->fd, &e))
		return false;

	if (i->fd >= p->items->len)
		g_ptr_array_set_size(p->items, i->fd + 1);

	ip = obj_alloc0(struct poller_item_int, poller_item_free);
	memcpy(&ip->item, i, sizeof(*i));
	obj_hold_o(ip->item.obj); /* new ref in *ip */
	p->items->pdata[i->fd] = obj_get(ip);

	} // unlock

	obj_put(ip);

	return true;
}


bool poller_del_item_callback(struct poller *p, int fd, void (*callback)(void *), void *arg) {
	struct poller_item_int *it;

	if (!p || fd < 0)
		return false;

	{

	LOCK(&p->lock);

	if (!p->items) // can happen during shutdown/free only
		return false;
	if (fd >= p->items->len)
		return false;
	if (!(it = p->items->pdata[fd]))
		return false;

	if (epoll_ctl(p->fd, EPOLL_CTL_DEL, fd, NULL))
		return false;

	p->items->pdata[fd] = NULL; /* stealing the ref */

	} // unlock

	obj_put(it);

	if (callback)
		callback(arg);
	else
		close(fd);

	return true;
}
bool poller_del_item(struct poller *p, int fd) {
	return poller_del_item_callback(p, fd, NULL, NULL);
}


static int poller_poll(struct poller *p, int timeout, struct epoll_event *evs, int poller_size) {
	int ret, i;
	struct poller_item_int *it;
	struct epoll_event *ev, e;

	if (!p)
		return -1;

	errno = 0;
	thread_cancel_enable();
	ret = epoll_wait(p->fd, evs, poller_size, timeout);
	thread_cancel_disable();

	mutex_lock(&p->lock);

	if (errno == EINTR)
		ret = 0;
	if (ret == 0)
		ret = 0;
	if (ret <= 0)
		goto out;

	gettimeofday(&rtpe_now, NULL);

	for (i = 0; i < ret; i++) {
		ev = &evs[i];

		if (ev->data.fd < 0)
			continue;

		it = (ev->data.fd < p->items->len) ? p->items->pdata[ev->data.fd] : NULL;
		if (!it)
			continue;

		obj_hold(it);
		mutex_unlock(&p->lock);

		if (it->error) {
			it->item.closed(it->item.fd, it->item.obj);
			goto next;
		}

		if ((ev->events & (POLLERR | POLLHUP)))
			it->item.closed(it->item.fd, it->item.obj);
		else if ((ev->events & POLLOUT)) {
			mutex_lock(&p->lock);
			it->blocked = 0;

			ZERO(e);
			e.events = epoll_events(NULL, it);
			e.data.fd = it->item.fd;
			int eret = epoll_ctl(p->fd, EPOLL_CTL_MOD, it->item.fd, &e);

			mutex_unlock(&p->lock);

			if (eret == 0 && it->item.writeable)
				it->item.writeable(it->item.fd, it->item.obj);
		}
		else if ((ev->events & POLLIN))
			it->item.readable(it->item.fd, it->item.obj);
		else if (!ev->events)
			goto next;
		else
			goto next;

next:
		obj_put(it);
		log_info_reset();
		mutex_lock(&p->lock);
	}


out:
	mutex_unlock(&p->lock);
	return ret;
}


void poller_blocked(struct poller *p, void *fdp) {
	int fd = GPOINTER_TO_INT(fdp);
	struct epoll_event e;

	if (!p || fd < 0)
		return;

	LOCK(&p->lock);

	if (fd >= p->items->len)
		return;
	struct poller_item_int *it;
	if (!(it = p->items->pdata[fd]))
		return;
	if (!it->item.writeable)
		return;

	it->blocked = 1;

	ZERO(e);
	e.events = epoll_events(NULL, it);
	e.data.fd = fd;
	epoll_ctl(p->fd, EPOLL_CTL_MOD, fd, &e);
}

void poller_error(struct poller *p, void *fdp) {
	int fd = GPOINTER_TO_INT(fdp);
	if (!p || fd < 0)
		return;

	LOCK(&p->lock);

	if (fd >= p->items->len)
		return;
	struct poller_item_int *it;
	if (!(it = p->items->pdata[fd]))
		return;
	if (!it->item.writeable)
		return;

	it->error = 1;
	it->blocked = 1;
}

#ifdef HAVE_LIBURING

static unsigned int __uring_thread_loop_dummy(void) { return 0; }

__thread unsigned int (*uring_thread_loop)(void) = __uring_thread_loop_dummy;

#endif

bool poller_isblocked(struct poller *p, void *fdp) {
	int fd = GPOINTER_TO_INT(fdp);
	int ret;

	if (!p || fd < 0)
		return false;

	LOCK(&p->lock);

	ret = -1;
	if (fd >= p->items->len)
		goto out;
	struct poller_item_int *it;
	if (!(it = p->items->pdata[fd]))
		goto out;
	if (!it->item.writeable)
		goto out;

	ret = !!it->blocked;

out:
	return ret;
}

void poller_loop(void *d) {
	struct poller *p = d;
	int poller_size = rtpe_common_config_ptr->poller_size;
	struct epoll_event *evs;

	evs = g_malloc(sizeof(*evs) * poller_size);

	thread_cleanup_push(g_free, evs);

	while (!rtpe_shutdown) {
		int ret = poller_poll(p, thread_sleep_time, evs, poller_size);
		if (ret < 0)
			usleep(20 * 1000);
		uring_thread_loop();
	}

	thread_cleanup_pop(true);
}
