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
#include <main.h>
#include <redis.h>
#include <hiredis/adapters/libevent.h>


#include "aux.h"
#include "obj.h"
#include "log_funcs.h"




struct timer_item {
	struct obj			obj;
	void				(*func)(void *);
	struct obj			*obj_ptr;
};

struct poller_item_int {
	struct obj			obj;
	struct poller_item		item;

	unsigned int			blocked:1;
	unsigned int			error:1;
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

struct poller_map {
	mutex_t				lock;
	GHashTable			*table;
};

struct poller_map *poller_map_new(void) {
	struct poller_map *p;

	p = malloc(sizeof(*p));
	memset(p, 0, sizeof(*p));
	mutex_init(&p->lock);
	p->table = g_hash_table_new(g_direct_hash, g_direct_equal);

	return p;
}

void poller_map_add(struct poller_map *map) {
	pthread_t tid = -1;
	struct poller *p;
	if (!map)
		return;
	tid = pthread_self();

	mutex_lock(&map->lock);
	p = poller_new();
	g_hash_table_insert(map->table, (gpointer)tid, p);
	mutex_unlock(&map->lock);
}

struct poller *poller_map_get(struct poller_map *map) {
	if (!map)
		return NULL;

	struct poller *p = NULL;
	pthread_t tid = pthread_self();
	mutex_lock(&map->lock);
	p = g_hash_table_lookup(map->table, (gpointer)tid);
	if (!p) {
		gpointer *arr = g_hash_table_get_keys_as_array(map->table, NULL);
		p = g_hash_table_lookup(map->table, arr[ssl_random() % g_hash_table_size(map->table)]);
		g_free(arr);
	}
	mutex_unlock(&map->lock);
	return p;
}

static void poller_map_free_poller(gpointer k, gpointer v, gpointer d) {
	struct poller *p = (struct poller *)v;
	poller_free(&p);
}

void poller_map_free(struct poller_map **map) {
	struct poller_map *m = *map;
	if (!m)
		return;
	mutex_lock(&m->lock);
	g_hash_table_foreach(m->table, poller_map_free_poller, NULL);
	g_hash_table_destroy(m->table);
	mutex_unlock(&m->lock);
	mutex_destroy(&m->lock);
	free(m);
	*map = NULL;
}

struct poller *poller_new(void) {
	struct poller *p;

	p = malloc(sizeof(*p));
	memset(p, 0, sizeof(*p));
	gettimeofday(&rtpe_now, NULL);
	p->fd = epoll_create1(0);
	if (p->fd == -1)
		abort();
	mutex_init(&p->lock);
	mutex_init(&p->timers_lock);
	mutex_init(&p->timers_add_del_lock);

	return p;
}

static void __ti_put(void *p) {
	struct timer_item *ti = p;
	obj_put(ti);
}
void poller_free(struct poller **pp) {
	struct poller *p = *pp;
	for (unsigned int i = 0; i < p->items_size; i++) {
		struct poller_item_int *ip = p->items[i];
		if (!ip)
			continue;
		p->items[i] = NULL;
		obj_put(ip);
	}
	g_slist_free_full(p->timers, __ti_put);
	g_slist_free_full(p->timers_add, __ti_put);
	g_slist_free_full(p->timers_del, __ti_put);
	if (p->fd != -1)
		close(p->fd);
	p->fd = -1;
	if (p->items)
		free(p->items);
	free(p);
	*pp = NULL;
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

	if (!p)
		return -1;
	if (!i)
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
		log_info_reset();
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

	mutex_unlock(&p->lock);
	errno = 0;
	thread_cancel_enable();
	ret = epoll_wait(p->fd, evs, sizeof(evs) / sizeof(*evs), timeout);
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
			int ret = epoll_ctl(p->fd, EPOLL_CTL_MOD, it->item.fd, &e);

			mutex_unlock(&p->lock);

			if (ret == 0 && it->item.writeable)
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
	epoll_ctl(p->fd, EPOLL_CTL_MOD, fd, &e);

fail:
	mutex_unlock(&p->lock);
}

void poller_error(struct poller *p, void *fdp) {
	int fd = GPOINTER_TO_INT(fdp);
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

int poller_isblocked(struct poller *p, void *fdp) {
	int fd = GPOINTER_TO_INT(fdp);
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

	// coverity[lock_order : FALSE]
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
void poller_timer_loop(void *d) {
	struct poller *p = d;

	while (!rtpe_shutdown) {
		// run once a second on top of each second
		struct timeval now;
		gettimeofday(&now, NULL);
		struct timeval next = { rtpe_now.tv_sec + 1, 0 };
		if (now.tv_sec >= next.tv_sec)
			goto now;

		long long sleeptime = timeval_diff(&next, &now);
		if (sleeptime <= 0)
			goto now;

		thread_cancel_enable();
		usleep(sleeptime);
		thread_cancel_disable();

		continue;

now:
		gettimeofday(&rtpe_now, NULL);
		if (rtpe_redis_write && rtpe_redis_write->async_ev &&
				(rtpe_redis_write->async_last + rtpe_config.redis_delete_async_interval
				 <= rtpe_now.tv_sec))
		{
			redis_async_event_base_action(rtpe_redis_write, EVENT_BASE_LOOPBREAK);
			rtpe_redis_write->async_last = rtpe_now.tv_sec;
		}
		poller_timers_run(p);
	}
}

void poller_loop(void *d) {
	struct poller_map *map = d;
	poller_map_add(map);
	struct poller *p = poller_map_get(map);

	poller_loop2(p);
}

void poller_loop2(void *d) {
	struct poller *p = d;

	while (!rtpe_shutdown) {
		int ret = poller_poll(p, thread_sleep_time);
		if (ret < 0)
			usleep(20 * 1000);
	}
}
