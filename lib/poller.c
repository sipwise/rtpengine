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
#include "loglib.h"
#include "auxlib.h"
#include "uring.h"



struct poller_item_int {
	struct poller_item		item;

	bool				blocked:1;
	bool				error:1;
};


struct poller {
	int				fd;
	int32_t				gen;
	static_assert(sizeof(int) == sizeof(int32_t), "int fd is not 32 bits");
	mutex_t				lock;
	GArray				*items;
};

#define arr_item(a, i) g_array_index((a), struct poller_item_int, (i))
#define p_arr_item(p, i) arr_item((p)->items, i)


bool (*rtpe_poller_add_item)(struct poller *, struct poller_item *) = poller_add_item;
bool (*rtpe_poller_del_item)(struct poller *, int) = poller_del_item;
bool (*rtpe_poller_del_item_callback)(struct poller *, int, void (*)(void *), void *) = poller_del_item_callback;
void (*rtpe_poller_blocked)(struct poller *, void *) = poller_blocked;
bool (*rtpe_poller_isblocked)(struct poller *, void *) = poller_isblocked;
void (*rtpe_poller_error)(struct poller *, void *) = poller_error;


struct poller *poller_new(void) {
	struct poller *p;

	p = g_new0(__typeof(*p), 1);
	mutex_init(&p->lock);
	p->fd = epoll_create1(0);
	if (p->fd == -1)
		goto err;
	p->items = g_array_new(FALSE, TRUE, sizeof(struct poller_item_int));

	return p;

err:
	poller_free(&p);
	return NULL;
}

void poller_free(struct poller **pp) {
	struct poller *p = *pp;

	// prevent recursion into poller_del_item from item's free functions
	GArray *arr = p->items;
	p->items = NULL;

	for (unsigned int i = 0; i < arr->len; i++)
		obj_release(arr_item(arr, i).item.obj);

	g_array_free(arr, TRUE);

	if (p->fd != -1)
		close(p->fd);
	p->fd = -1;
	g_free(p);
	*pp = NULL;
}


static int epoll_events(struct poller_item *it, struct poller_item_int *ii) {
	if (!it)
		it = &ii->item;
	return EPOLLHUP | EPOLLERR | EPOLLET |
		((it->writeable && ii && ii->blocked) ? EPOLLOUT : 0) |
		(it->readable ? EPOLLIN : 0);
}


bool poller_add_item(struct poller *p, struct poller_item *i) {
	struct poller_item_int *ip;
	struct epoll_event e;

	if (!p)
		return false;
	if (!i)
		return false;
	if (i->u.fd < 0)
		return false;
	if (!i->readable && !i->writeable)
		return false;
	if (!i->closed)
		return false;

	{

	LOCK(&p->lock);

	if (i->u.fd < p->items->len && p_arr_item(p, i->u.fd).item.obj)
		return false;

	i->u.gen = ++p->gen;

	ZERO(e);
	e.events = epoll_events(i, NULL);
	e.data.u64 = i->u.u64;
	if (epoll_ctl(p->fd, EPOLL_CTL_ADD, i->u.fd, &e))
		return false;

	if (i->u.fd >= p->items->len)
		g_array_set_size(p->items, i->u.fd + 1);

	ip = &p_arr_item(p, i->u.fd);
	memcpy(&ip->item, i, sizeof(*i));
	obj_hold_o(ip->item.obj); /* new ref in *ip */

	} // unlock

	return true;
}


bool poller_del_item_callback(struct poller *p, int fd, void (*callback)(void *), void *arg) {
	bool ret = false;

	if (!p || fd < 0)
		goto out;

	struct obj *o;

	{

	LOCK(&p->lock);

	if (!p->items) // can happen during shutdown/free only
		goto out;
	if (fd >= p->items->len)
		goto out;
	struct poller_item_int *it = &p_arr_item(p, fd);
	if (!it->item.obj)
		goto out;

	if (epoll_ctl(p->fd, EPOLL_CTL_DEL, fd, NULL))
		goto out;

	o = it->item.obj; // steal the ref
	memset(it, 0, sizeof(*it));

	} // unlock

	obj_put_o(o);

	ret = true;

out:
	if (callback)
		callback(arg);
	else
		close(fd);

	return ret;
}
bool poller_del_item(struct poller *p, int fd) {
	return poller_del_item_callback(p, fd, NULL, NULL);
}


static int poller_poll(struct poller *p, int timeout, struct epoll_event *evs, int poller_size) {
	int ret, i;
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
	if (ret <= 0)
		goto out;

	rtpe_now = now_us();

	for (i = 0; i < ret; i++) {
		ev = &evs[i];

		union poller_item_u64 u64 = { .u64 = ev->data.u64 };

		if (u64.fd < 0)
			continue;

		struct poller_item_int *itp = (u64.fd < p->items->len) ? &p_arr_item(p, u64.fd) : NULL;
		if (!itp || !itp->item.obj)
			continue;

		if (itp->item.u.u64 != u64.u64)
			continue;

		struct poller_item_int it = *itp;
		obj_hold_o(it.item.obj);
		mutex_unlock(&p->lock);

		if (it.error) {
			it.item.closed(it.item.u.fd, it.item.obj);
			goto next;
		}

		if ((ev->events & (POLLERR | POLLHUP)))
			it.item.closed(it.item.u.fd, it.item.obj);
		else if ((ev->events & POLLOUT)) {
			mutex_lock(&p->lock);

			int eret = -1;

			if (p_arr_item(p, it.item.u.fd).item.u.u64 == it.item.u.u64) {
				it.blocked = 0;

				ZERO(e);
				e.events = epoll_events(NULL, &it);
				e.data.u64 = it.item.u.u64;
				eret = epoll_ctl(p->fd, EPOLL_CTL_MOD, it.item.u.fd, &e);
			}

			mutex_unlock(&p->lock);

			if (eret == 0 && it.item.writeable)
				it.item.writeable(it.item.u.fd, it.item.obj);
		}
		else if ((ev->events & POLLIN))
			it.item.readable(it.item.u.fd, it.item.obj);
		else if (!ev->events)
			goto next;
		else
			goto next;

next:
		obj_put_o(it.item.obj);
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
	struct poller_item_int *it = &p_arr_item(p, fd);
	if (!it->item.obj)
		return;
	if (!it->item.writeable)
		return;

	it->blocked = 1;

	ZERO(e);
	e.events = epoll_events(NULL, it);
	e.data.u64 = it->item.u.u64;
	epoll_ctl(p->fd, EPOLL_CTL_MOD, fd, &e);
}

void poller_error(struct poller *p, void *fdp) {
	int fd = GPOINTER_TO_INT(fdp);
	if (!p || fd < 0)
		return;

	LOCK(&p->lock);

	if (fd >= p->items->len)
		return;
	struct poller_item_int *it = &p_arr_item(p, fd);
	if (!it->item.obj)
		return;
	if (!it->item.writeable)
		return;

	it->error = 1;
	it->blocked = 1;
}

bool poller_isblocked(struct poller *p, void *fdp) {
	int fd = GPOINTER_TO_INT(fdp);
	int ret;

	if (!p || fd < 0)
		return false;

	LOCK(&p->lock);

	ret = -1;
	if (fd >= p->items->len)
		goto out;
	struct poller_item_int *it = &p_arr_item(p, fd);
	if (!it->item.obj)
		goto out;
	if (!it->item.writeable)
		goto out;

	ret = !!it->blocked;

out:
	return ret;
}

void poller_loop(struct poller_thread *pt) {
	struct poller *p = pt->poller;
	pt->pid = gettid();
	int poller_size = rtpe_common_config_ptr->poller_size;
	struct epoll_event *evs;

	evs = g_malloc(sizeof(*evs) * poller_size);

	thread_cleanup_push(g_free, evs);

	while (!rtpe_shutdown) {
		int ret = poller_poll(p, thread_sleep_time, evs, poller_size);
		if (ret < 0)
			usleep(20 * 1000);
		else {
			atomic64_inc_na(&pt->wakeups);
			atomic64_add_na(&pt->items, ret);
		}
		uring_methods.thread_loop();
	}

	thread_cleanup_pop(true);
}
