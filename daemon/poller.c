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

#include "aux.h"
#include "obj.h"




struct timer_item {
	struct obj			obj;
	void				(*func)(void *);
	struct obj			*obj_ptr;
};

struct poller_item_int {
	struct obj			obj;
	struct poller_item		item;

	int				blocked:1;
	int				error:1;
};

struct poller {
	int				fd;
	mutex_t				lock;
	struct poller_item_int		**items;
	unsigned int			items_size;

	mutex_t				timers_lock;
	GSList				*timers;
	mutex_t				timers_add_del_lock; /* nested below timers_lock */
	GSList				*timers_add;
	GSList				*timers_del;
};





__thread time_t poller_now;





struct poller *poller_new(void) {
	struct poller *p;

	p = malloc(sizeof(*p));
	memset(p, 0, sizeof(*p));
	poller_now = time(NULL);
	p->fd = epoll_create1(0);
	if (p->fd == -1)
		abort();
	mutex_init(&p->lock);
	mutex_init(&p->timers_lock);
	mutex_init(&p->timers_add_del_lock);

	return p;
}


static int epoll_events(struct poller_item *it, struct poller_item_int *ii) {
	if (!it)
		it = &ii->item;
	return EPOLLHUP | EPOLLERR | EPOLLET |
		((it->writeable && ii && ii->blocked) ? EPOLLOUT : 0) |
		(it->readable ? EPOLLIN : 0);
}


static void poller_fd_timer(void *p) {
	struct poller_item_int *it = p;

	if (it->item.timer)
		it->item.timer(it->item.fd, it->item.obj, it->item.uintp);
}


static void poller_item_free(void *p) {
	struct poller_item_int *i = p;
	obj_put_o(i->item.obj);
}


/* unlocks on return */
static int __poller_add_item(struct poller *p, struct poller_item *i, int has_lock) {
	struct poller_item_int *ip;
	unsigned int u;
	struct epoll_event e;

	if (!p || !i)
		goto fail_lock;
	if (i->fd < 0)
		goto fail_lock;
	if (!i->readable && !i->writeable)
		goto fail_lock;
	if (!i->closed)
		goto fail_lock;

	if (!has_lock)
		mutex_lock(&p->lock);

	if (i->fd < p->items_size && p->items[i->fd])
		goto fail;

	ZERO(e);
	e.events = epoll_events(i, NULL);
	e.data.fd = i->fd;
	if (epoll_ctl(p->fd, EPOLL_CTL_ADD, i->fd, &e))
		abort();

	if (i->fd >= p->items_size) {
		u = p->items_size;
		p->items_size = i->fd + 1;
		p->items = realloc(p->items, sizeof(*p->items) * p->items_size);
		memset(p->items + u, 0, sizeof(*p->items) * (p->items_size - u - 1));
	}

	ip = obj_alloc0("poller_item_int", sizeof(*ip), poller_item_free);
	memcpy(&ip->item, i, sizeof(*i));
	obj_hold_o(ip->item.obj); /* new ref in *ip */
	p->items[i->fd] = obj_get(ip);

	mutex_unlock(&p->lock);

	if (i->timer)
		poller_add_timer(p, poller_fd_timer, &ip->obj);

	obj_put(ip);

	return 0;

fail:
	mutex_unlock(&p->lock);
	return -1;
fail_lock:
	if (has_lock)
		mutex_unlock(&p->lock);
	return -1;
}


int poller_add_item(struct poller *p, struct poller_item *i) {
	return __poller_add_item(p, i, 0);
}


int poller_del_item(struct poller *p, int fd) {
	struct poller_item_int *it;

	if (!p || fd < 0)
		return -1;

	mutex_lock(&p->lock);

	if (fd >= p->items_size)
		goto fail;
	if (!p->items || !(it = p->items[fd]))
		goto fail;

	if (epoll_ctl(p->fd, EPOLL_CTL_DEL, fd, NULL))
		abort();

	p->items[fd] = NULL; /* stealing the ref */

	mutex_unlock(&p->lock);

	if (it->item.timer)
		poller_del_timer(p, poller_fd_timer, &it->obj);

	obj_put(it);

	return 0;

fail:
	mutex_unlock(&p->lock);
	return -1;
}


int poller_update_item(struct poller *p, struct poller_item *i) {
	struct poller_item_int *np;

	if (!p || !i)
		return -1;
	if (i->fd < 0)
		return -1;
	if (!i->readable && !i->writeable)
		return -1;
	if (!i->closed)
		return -1;

	mutex_lock(&p->lock);

	if (i->fd >= p->items_size || !(np = p->items[i->fd]))
		return __poller_add_item(p, i, 1);

	obj_hold_o(i->obj);
	obj_put_o(np->item.obj);
	np->item.obj = i->obj;
	np->item.uintp = i->uintp;
	np->item.readable = i->readable;
	np->item.writeable = i->writeable;
	np->item.closed = i->closed;
	/* updating timer is not supported */

	mutex_unlock(&p->lock);

	return 0;
}


/* timers_lock and timers_add_del_lock must be held */
static void poller_timers_mod(struct poller *p) {
	GSList *l, **ll, **kk;
	struct timer_item *ti, *tj;

	ll = &p->timers_add;
	while (*ll) {
		l = *ll;
		*ll = l->next;
		l->next = p->timers;
		p->timers = l;
	}

	ll = &p->timers_del;
	while (*ll) {
		ti = (*ll)->data;
		kk = &p->timers;
		while (*kk) {
			tj = (*kk)->data;
			if (tj->func != ti->func)
				goto next;
			if (tj->obj_ptr != ti->obj_ptr)
				goto next;
			goto found;
next:
			kk = &(*kk)->next;
		}
		/* deleted a timer that wasn't added yet. possible race, otherwise bug */
		ll = &(*ll)->next;
		continue;
found:
		l = *ll;
		*ll = (*ll)->next;
		obj_put_o(l->data);
		g_slist_free_1(l);

		l = *kk;
		*kk = (*kk)->next;
		obj_put_o(l->data);
		g_slist_free_1(l);
	}
}


static void poller_timers_run(struct poller *p) {
	GSList *l;
	struct timer_item *ti;

	mutex_lock(&p->timers_lock);
	mutex_lock(&p->timers_add_del_lock);
	poller_timers_mod(p);
	mutex_unlock(&p->timers_add_del_lock);

	for (l = p->timers; l; l = l->next) {
		ti = l->data;
		ti->func(ti->obj_ptr);
	}

	mutex_lock(&p->timers_add_del_lock);
	poller_timers_mod(p);
	mutex_unlock(&p->timers_add_del_lock);
	mutex_unlock(&p->timers_lock);
}


int poller_poll(struct poller *p, int timeout) {
	int ret, i;
	struct poller_item_int *it;
	struct epoll_event evs[128], *ev, e;

	if (!p)
		return -1;

	mutex_lock(&p->lock);

	ret = -1;
	if (!p->items || !p->items_size)
		goto out;

	mutex_unlock(&p->lock);
	errno = 0;
	ret = epoll_wait(p->fd, evs, sizeof(evs) / sizeof(*evs), timeout);
	mutex_lock(&p->lock);

	if (errno == EINTR)
		ret = 0;
	if (ret == 0)
		ret = 0;
	if (ret <= 0)
		goto out;

	poller_now = time(NULL);

	for (i = 0; i < ret; i++) {
		ev = &evs[i];

		if (ev->data.fd < 0)
			continue;

		it = (ev->data.fd < p->items_size) ? p->items[ev->data.fd] : NULL;
		if (!it)
			continue;

		obj_hold(it);
		mutex_unlock(&p->lock);

		if (it->error) {
			it->item.closed(it->item.fd, it->item.obj, it->item.uintp);
			goto next;
		}

		if ((ev->events & (POLLERR | POLLHUP)))
			it->item.closed(it->item.fd, it->item.obj, it->item.uintp);
		else if ((ev->events & POLLOUT)) {
			mutex_lock(&p->lock);
			it->blocked = 0;

			ZERO(e);
			e.events = epoll_events(NULL, it);
			e.data.fd = it->item.fd;
			if (epoll_ctl(p->fd, EPOLL_CTL_MOD, it->item.fd, &e))
				abort();

			mutex_unlock(&p->lock);
			it->item.writeable(it->item.fd, it->item.obj, it->item.uintp);
		}
		else if ((ev->events & POLLIN))
			it->item.readable(it->item.fd, it->item.obj, it->item.uintp);
		else if (!ev->events)
			goto next;
		else
			abort();

next:
		obj_put(it);
		mutex_lock(&p->lock);
	}


out:
	mutex_unlock(&p->lock);
	return ret;
}


void poller_blocked(struct poller *p, int fd) {
	struct epoll_event e;

	if (!p || fd < 0)
		return;

	mutex_lock(&p->lock);

	if (fd >= p->items_size)
		goto fail;
	if (!p->items || !p->items[fd])
		goto fail;
	if (!p->items[fd]->item.writeable)
		goto fail;

	p->items[fd]->blocked = 1;

	ZERO(e);
	e.events = epoll_events(NULL, p->items[fd]);
	e.data.fd = fd;
	if (epoll_ctl(p->fd, EPOLL_CTL_MOD, fd, &e))
		abort();

fail:
	mutex_unlock(&p->lock);
}

void poller_error(struct poller *p, int fd) {
	if (!p || fd < 0)
		return;

	mutex_lock(&p->lock);

	if (fd >= p->items_size)
		goto fail;
	if (!p->items || !p->items[fd])
		goto fail;
	if (!p->items[fd]->item.writeable)
		goto fail;

	p->items[fd]->error = 1;
	p->items[fd]->blocked = 1;

fail:
	mutex_unlock(&p->lock);
}

int poller_isblocked(struct poller *p, int fd) {
	int ret;

	if (!p || fd < 0)
		return -1;

	mutex_lock(&p->lock);

	ret = -1;
	if (fd >= p->items_size)
		goto out;
	if (!p->items || !p->items[fd])
		goto out;
	if (!p->items[fd]->item.writeable)
		goto out;

	ret = p->items[fd]->blocked ? 1 : 0;

out:
	mutex_unlock(&p->lock);
	return ret;
}



static void timer_item_free(void *p) {
	struct timer_item *i = p;
	if (i->obj_ptr)
		obj_put_o(i->obj_ptr);
}

static int poller_timer_link(struct poller *p, GSList **lp, void (*f)(void *), struct obj *o) {
	struct timer_item *i;

	if (!f)
		return -1;

	i = obj_alloc0("timer_item", sizeof(*i), timer_item_free);

	i->func = f;
	i->obj_ptr = o ? obj_hold_o(o) : NULL;

	mutex_lock(&p->timers_add_del_lock);
	*lp = g_slist_prepend(*lp, i);

	if (!mutex_trylock(&p->timers_lock)) {
		poller_timers_mod(p);
		mutex_unlock(&p->timers_lock);
	}

	mutex_unlock(&p->timers_add_del_lock);

	return 0;
}

int poller_del_timer(struct poller *p, void (*f)(void *), struct obj *o) {
	return poller_timer_link(p, &p->timers_del, f, o);
}

int poller_add_timer(struct poller *p, void (*f)(void *), struct obj *o) {
	return poller_timer_link(p, &p->timers_add, f, o);
}

/* run in thread separate from poller_poll() */
void poller_timers_wait_run(struct poller *p, int max) {
	struct timeval tv;
	int wt;
	int i = 0;

	max *= 1000;

retry:
	gettimeofday(&tv, NULL);
	if (tv.tv_sec != poller_now)
		goto now;
	if (i)
		return;

	wt = 1000000 - tv.tv_usec;
	if (max >= 0 && max < wt)
		wt = max;
	usleep(wt);
	i = 1;
	goto retry;

now:
	poller_now = tv.tv_sec;
	poller_timers_run(p);
}
