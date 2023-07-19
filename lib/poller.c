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
};

struct poller_map {
	mutex_t				lock;
	GHashTable			*table;
};

struct poller_map *poller_map_new(void) {
	struct poller_map *p;

	p = g_slice_alloc0(sizeof(*p));
	mutex_init(&p->lock);
	p->table = g_hash_table_new(g_direct_hash, g_direct_equal);

	return p;
}

static void poller_map_add(struct poller_map *map) {
	pthread_t tid = -1;
	struct poller *p;
	if (!map)
		return;
	tid = pthread_self();

	LOCK(&map->lock);
	p = poller_new();
	g_hash_table_insert(map->table, (gpointer)tid, p);
}

struct poller *poller_map_get(struct poller_map *map) {
	if (!map)
		return NULL;

	struct poller *p = NULL;
	pthread_t tid = pthread_self();
	LOCK(&map->lock);
	p = g_hash_table_lookup(map->table, (gpointer)tid);
	if (!p) {
		gpointer *arr = g_hash_table_get_keys_as_array(map->table, NULL);
		p = g_hash_table_lookup(map->table, arr[ssl_random() % g_hash_table_size(map->table)]);
		g_free(arr);
	}
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
	g_hash_table_foreach(m->table, poller_map_free_poller, NULL);
	g_hash_table_destroy(m->table);
	mutex_destroy(&m->lock);
	g_slice_free1(sizeof(*m), m);
	*map = NULL;
}

struct poller *poller_new(void) {
	struct poller *p;

	p = g_slice_alloc0(sizeof(*p));
	gettimeofday(&rtpe_now, NULL);
	p->fd = epoll_create1(0);
	if (p->fd == -1)
		abort();
	mutex_init(&p->lock);

	return p;
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
	if (p->fd != -1)
		close(p->fd);
	p->fd = -1;
	if (p->items)
		free(p->items);
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


static void poller_item_free(void *p) {
	struct poller_item_int *i = p;
	obj_put_o(i->item.obj);
}


int poller_add_item(struct poller *p, struct poller_item *i) {
	struct poller_item_int *ip;
	unsigned int u;
	struct epoll_event e;

	if (!p)
		return -1;
	if (!i)
		return -1;
	if (i->fd < 0)
		return -1;
	if (!i->readable && !i->writeable)
		return -1;
	if (!i->closed)
		return -1;

	{

	LOCK(&p->lock);

	if (i->fd < p->items_size && p->items[i->fd])
		return -1;

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

	} // unlock

	obj_put(ip);

	return 0;
}


int poller_del_item(struct poller *p, int fd) {
	struct poller_item_int *it;

	if (!p || fd < 0)
		return -1;

	{

	LOCK(&p->lock);

	if (fd >= p->items_size)
		return -1;
	if (!p->items || !(it = p->items[fd]))
		return -1;

	if (epoll_ctl(p->fd, EPOLL_CTL_DEL, fd, NULL))
		abort();

	p->items[fd] = NULL; /* stealing the ref */

	} // unlock

	obj_put(it);

	return 0;
}


static int poller_poll(struct poller *p, int timeout) {
	int ret, i;
	struct poller_item_int *it;
	struct epoll_event evs[128], *ev, e;

	if (!p)
		return -1;

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
			int eret = epoll_ctl(p->fd, EPOLL_CTL_MOD, it->item.fd, &e);

			mutex_unlock(&p->lock);

			if (eret == 0 && it->item.writeable)
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

	LOCK(&p->lock);

	if (fd >= p->items_size)
		return;
	if (!p->items || !p->items[fd])
		return;
	if (!p->items[fd]->item.writeable)
		return;

	p->items[fd]->blocked = 1;

	ZERO(e);
	e.events = epoll_events(NULL, p->items[fd]);
	e.data.fd = fd;
	epoll_ctl(p->fd, EPOLL_CTL_MOD, fd, &e);
}

void poller_error(struct poller *p, void *fdp) {
	int fd = GPOINTER_TO_INT(fdp);
	if (!p || fd < 0)
		return;

	LOCK(&p->lock);

	if (fd >= p->items_size)
		return;
	if (!p->items || !p->items[fd])
		return;
	if (!p->items[fd]->item.writeable)
		return;

	p->items[fd]->error = 1;
	p->items[fd]->blocked = 1;
}

int poller_isblocked(struct poller *p, void *fdp) {
	int fd = GPOINTER_TO_INT(fdp);
	int ret;

	if (!p || fd < 0)
		return -1;

	LOCK(&p->lock);

	ret = -1;
	if (fd >= p->items_size)
		goto out;
	if (!p->items || !p->items[fd])
		goto out;
	if (!p->items[fd]->item.writeable)
		goto out;

	ret = p->items[fd]->blocked ? 1 : 0;

out:
	return ret;
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
