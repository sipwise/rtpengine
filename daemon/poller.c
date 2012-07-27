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

#include "poller.h"
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
	GStaticMutex			lock;
	struct poller_item_int		**items;
	unsigned int			items_size;
	GList				*timers;

	time_t				now;
};







struct poller *poller_new(void) {
	struct poller *p;

	p = malloc(sizeof(*p));
	memset(p, 0, sizeof(*p));
	p->now = time(NULL);
	p->fd = epoll_create1(0);
	if (p->fd == -1)
		abort();
	g_static_mutex_init(&p->lock);

	return p;
}


static int epoll_events(struct poller_item *it, struct poller_item_int *ii) {
	if (!it)
		it = &ii->item;
	return EPOLLHUP | EPOLLERR |
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
	obj_put(i->item.obj);
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
		g_static_mutex_lock(&p->lock);

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
	obj_hold(ip->item.obj); /* new ref in *ip */
	p->items[i->fd] = obj_get(&ip->obj);

	g_static_mutex_unlock(&p->lock);

	if (i->timer)
		poller_timer(p, poller_fd_timer, &ip->obj);

	obj_put(&ip->obj);

	return 0;

fail:
	g_static_mutex_unlock(&p->lock);
	return -1;
fail_lock:
	if (has_lock)
		g_static_mutex_unlock(&p->lock);
	return -1;
}


int poller_add_item(struct poller *p, struct poller_item *i) {
	return __poller_add_item(p, i, 0);
}


int poller_find_timer(gconstpointer a, gconstpointer b) {
	const struct timer_item *it = a;
	const struct obj *x = b;

	if (it->obj_ptr == x)
		return 0;
	return 1;
}


int poller_del_item(struct poller *p, int fd) {
	struct poller_item_int *it;
	GList *l;
	struct timer_item *ti;

	if (!p || fd < 0)
		return -1;

	g_static_mutex_lock(&p->lock);

	if (fd >= p->items_size)
		goto fail;
	if (!p->items || !(it = p->items[fd]))
		goto fail;

	if (epoll_ctl(p->fd, EPOLL_CTL_DEL, fd, NULL))
		abort();

	p->items[fd] = NULL; /* stealing the ref */

	g_static_mutex_unlock(&p->lock);

	if (it->item.timer) {
		while (1) {
			/* rare but possible race with poller_add_item above */
			l = g_list_find_custom(p->timers, &it->obj, poller_find_timer);
			if (l)
				break;
		}
		p->timers = g_list_remove_link(p->timers, l);
		ti = l->data;
		obj_put(&ti->obj);
		g_list_free_1(l);
	}

	obj_put(&it->obj);

	return 0;

fail:
	g_static_mutex_unlock(&p->lock);
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

	g_static_mutex_lock(&p->lock);

	if (i->fd >= p->items_size || !(np = p->items[i->fd]))
		return __poller_add_item(p, i, 1);

	obj_hold(i->obj);
	obj_put(np->item.obj);
	np->item.obj = i->obj;
	np->item.uintp = i->uintp;
	np->item.readable = i->readable;
	np->item.writeable = i->writeable;
	np->item.closed = i->closed;
	/* updating timer is not supported */

	g_static_mutex_unlock(&p->lock);

	return 0;
}


int poller_poll(struct poller *p, int timeout) {
	int ret, i;
	struct poller_item_int *it;
	time_t last;
	GList *li, *ne;
	struct timer_item *ti;
	struct epoll_event evs[128], *ev, e;

	if (!p)
		return -1;

	g_static_mutex_lock(&p->lock);

	ret = -1;
	if (!p->items || !p->items_size)
		goto out;

	last = p->now;
	p->now = time(NULL);
	if (last != p->now) {
		for (li = p->timers; li; li = ne) {
			ne = li->next;
			ti = li->data;
			/* XXX not safe */
			g_static_mutex_unlock(&p->lock);
			ti->func(ti->obj_ptr);
			g_static_mutex_lock(&p->lock);
		}
		ret = p->items_size;
		goto out;
	}

	g_static_mutex_unlock(&p->lock);
	errno = 0;
	ret = epoll_wait(p->fd, evs, sizeof(evs) / sizeof(*evs), timeout);
	g_static_mutex_lock(&p->lock);

	if (errno == EINTR)
		ret = 0;
	if (ret < 0)
		goto out;

	for (i = 0; i < ret; i++) {
		ev = &evs[i];

		if (ev->data.fd < 0)
			continue;

		it = (ev->data.fd < p->items_size) ? p->items[ev->data.fd] : NULL;
		if (!it)
			continue;

		obj_hold(&it->obj);
		g_static_mutex_unlock(&p->lock);

		if (it->error) {
			it->item.closed(it->item.fd, it->item.obj, it->item.uintp);
			goto next;
		}

		if ((ev->events & (POLLERR | POLLHUP)))
			it->item.closed(it->item.fd, it->item.obj, it->item.uintp);
		else if ((ev->events & POLLOUT)) {
			g_static_mutex_lock(&p->lock);
			it->blocked = 0;

			ZERO(e);
			e.events = epoll_events(NULL, it);
			e.data.fd = it->item.fd;
			if (epoll_ctl(p->fd, EPOLL_CTL_MOD, it->item.fd, &e))
				abort();

			g_static_mutex_unlock(&p->lock);
			it->item.writeable(it->item.fd, it->item.obj, it->item.uintp);
		}
		else if ((ev->events & POLLIN))
			it->item.readable(it->item.fd, it->item.obj, it->item.uintp);
		else if (!ev->events)
			goto next;
		else
			abort();

next:
		obj_put(&it->obj);
		g_static_mutex_lock(&p->lock);
	}


out:
	g_static_mutex_unlock(&p->lock);
	return ret;
}


void poller_blocked(struct poller *p, int fd) {
	struct epoll_event e;

	if (!p || fd < 0)
		return;

	g_static_mutex_lock(&p->lock);

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
	g_static_mutex_unlock(&p->lock);
}

void poller_error(struct poller *p, int fd) {
	if (!p || fd < 0)
		return;

	g_static_mutex_lock(&p->lock);

	if (fd >= p->items_size)
		goto fail;
	if (!p->items || !p->items[fd])
		goto fail;
	if (!p->items[fd]->item.writeable)
		goto fail;

	p->items[fd]->error = 1;
	p->items[fd]->blocked = 1;

fail:
	g_static_mutex_unlock(&p->lock);
}

int poller_isblocked(struct poller *p, int fd) {
	int ret;

	if (!p || fd < 0)
		return -1;

	g_static_mutex_lock(&p->lock);

	ret = -1;
	if (fd >= p->items_size)
		goto out;
	if (!p->items || !p->items[fd])
		goto out;
	if (!p->items[fd]->item.writeable)
		goto out;

	ret = p->items[fd]->blocked ? 1 : 0;

out:
	g_static_mutex_unlock(&p->lock);
	return ret;
}



static void timer_item_free(void *p) {
	struct timer_item *i = p;
	obj_put(i->obj_ptr);
}

int poller_timer(struct poller *p, void (*f)(void *), struct obj *o) {
	struct timer_item *i;

	if (!o || !f)
		return -1;

	i = obj_alloc0("timer_item", sizeof(*i), timer_item_free);

	i->func = f;
	i->obj_ptr = obj_hold(o);

	p->timers = g_list_prepend(p->timers, i);

	return 0;
}

time_t poller_now(struct poller *p) {
	return p->now;
}
