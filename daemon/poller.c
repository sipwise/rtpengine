#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <errno.h>

#include "poller.h"
#include "aux.h"




#define POLLER_BSEARCH(b,l,k,e)	mybsearch(b, l, sizeof(struct pollfd), k, OFFSET_OF(struct pollfd, fd), sizeof(*(k)), e)




struct timer_item {
	void		(*func)(void *);
	void		*ptr;
};





struct poller *poller_new(void) {
	struct poller *p;

	p = malloc(sizeof(*p));
	memset(p, 0, sizeof(*p));
	p->now = time(NULL);

	return p;
}


int poller_add_item(struct poller *p, struct poller_item *i) {
	struct poller_item *ip;
	struct pollfd *pf;
	int idx;
	unsigned int u;

	if (!p || !i)
		return -1;
	if (i->fd < 0)
		return -1;
	if (!i->readable && !i->writeable)
		return -1;
	if (!i->closed)
		return -1;

	if (i->fd < p->items_size && p->items[i->fd])
		return -1;

	idx = POLLER_BSEARCH(p->pollfds, p->pollfds_size, &i->fd, 0);
	assert(idx < 0);

	idx *= -1;
	idx--;

	p->pollfds_size++;
	p->pollfds = realloc(p->pollfds, p->pollfds_size * sizeof(*p->pollfds));
	memmove(p->pollfds + idx + 1, p->pollfds + idx, (p->pollfds_size - idx - 1) * sizeof(*p->pollfds));
	pf = &p->pollfds[idx];

	pf->fd = i->fd;
	pf->events = POLLHUP | POLLERR | ((i->writeable && i->blocked) ? POLLOUT : 0) | (i->readable ? POLLIN : 0);
	pf->revents = 0;

	if (i->fd >= p->items_size) {
		u = p->items_size;
		p->items_size = i->fd + 1;
		p->items = realloc(p->items, sizeof(*p->items) * p->items_size);
		memset(p->items + u, 0, sizeof(*p->items) * (p->items_size - u - 1));
	}

	ip = malloc(sizeof(*ip));
	memcpy(ip, i, sizeof(*ip));
	p->items[i->fd] = ip;

	return 0;
}


int poller_del_item(struct poller *p, int fd) {
	int idx;

	if (!p || fd < 0)
		return -1;
	if (fd >= p->items_size)
		return -1;
	if (!p->items || !p->items[fd])
		return -1;
	if (!p->pollfds || !p->pollfds_size)
		return -1;

	idx = POLLER_BSEARCH(p->pollfds, p->pollfds_size, &fd, 1);
	assert(idx != -1);

	memmove(p->pollfds + idx, p->pollfds + idx + 1, (p->pollfds_size - idx - 1) * sizeof(*p->pollfds));
	p->pollfds_size--;
	p->pollfds = realloc(p->pollfds, p->pollfds_size * sizeof(*p->pollfds));

	if (p->pollfds_work) {
		idx = POLLER_BSEARCH(p->pollfds_work, p->pollfds_work_size, &fd, 1);

		if (idx != -1)
			p->pollfds_work[idx].fd = -1;
	}

	free(p->items[fd]);
	p->items[fd] = NULL;

	return 0;
}


int poller_update_item(struct poller *p, struct poller_item *i) {
	struct poller_item *np;

	if (!p || !i)
		return -1;
	if (i->fd < 0)
		return -1;
	if (!i->readable && !i->writeable)
		return -1;
	if (!i->closed)
		return -1;

	if (i->fd >= p->items_size || !(np = p->items[i->fd]))
		return poller_add_item(p, i);

	np->ptr = i->ptr;
	np->readable = i->readable;
	np->writeable = i->writeable;
	np->closed = i->closed;
	np->timer = i->timer;

	return 0;
}


int poller_poll(struct poller *p, int timeout) {
	struct pollfd *pfd, *pf;
	int ret, i;
	struct poller_item *it;
	int idx;
	time_t last;
	int do_timer;
	GList *li;
	struct timer_item *ti;

	if (!p)
		return -1;
	if (!p->pollfds || !p->pollfds_size)
		return -1;
	if (!p->items || !p->items_size)
		return -1;

	p->pollfds_work_size = i = p->pollfds_size;
	p->pollfds_work = pfd = malloc(sizeof(*pfd) * i);
	memcpy(pfd, p->pollfds, sizeof(*pfd) * i);

	do_timer = 0;
	last = p->now;
	p->now = time(NULL);
	if (last != p->now) {
		do_timer = 1;
		ret = i;

		for (li = p->timers; li; li = li->next) {
			ti = li->data;
			ti->func(ti->ptr);
		}
	}
	else {
		ret = poll(pfd, i, timeout);
		if (errno == EINTR)
			ret = 0;
		if (ret < 0)
			goto out;
	}

	pf = pfd;
	for (pf = pfd; i; pf++) {
		i--;

		if (pf->fd < 0)
			continue;

		it = (pf->fd < p->items_size) ? p->items[pf->fd] : NULL;
		if (!it)
			continue;

		if (do_timer) {
			if (it->timer)
				it->timer(it->fd, it->ptr);
			continue;
		}

		if (it->error) {
			it->closed(it->fd, it->ptr);
			continue;
		}

		if ((pf->revents & (POLLERR | POLLHUP)))
			it->closed(it->fd, it->ptr);
		else if ((pf->revents & POLLOUT)) {
			it->blocked = 0;

			idx = POLLER_BSEARCH(p->pollfds, p->pollfds_size, &it->fd, 1);
			assert(idx != -1);

			p->pollfds[idx].events &= ~POLLOUT;

			it->writeable(it->fd, it->ptr);
		}
		else if ((pf->revents & POLLIN))
			it->readable(it->fd, it->ptr);
		else if (!pf->revents)
			continue;
		else
			abort();
	}


out:
	free(pfd);
	p->pollfds_work = NULL;
	p->pollfds_work_size = 0;
	return ret;
}


void poller_blocked(struct poller *p, int fd) {
	int idx;

	if (!p || fd < 0)
		return;
	if (fd >= p->items_size)
		return;
	if (!p->items || !p->items[fd])
		return;
	if (!p->pollfds || !p->pollfds_size)
		return;
	if (!p->items[fd]->writeable)
		return;

	p->items[fd]->blocked = 1;

	idx = POLLER_BSEARCH(p->pollfds, p->pollfds_size, &fd, 1);
	assert(idx != -1);

	p->pollfds[idx].events |= POLLOUT;
}

void poller_error(struct poller *p, int fd) {
	if (!p || fd < 0)
		return;
	if (fd >= p->items_size)
		return;
	if (!p->items || !p->items[fd])
		return;
	if (!p->pollfds || !p->pollfds_size)
		return;
	if (!p->items[fd]->writeable)
		return;

	p->items[fd]->error = 1;
	p->items[fd]->blocked = 1;
}

int poller_isblocked(struct poller *p, int fd) {
	if (!p || fd < 0)
		return -1;
	if (fd >= p->items_size)
		return -1;
	if (!p->items || !p->items[fd])
		return -1;
	if (!p->pollfds || !p->pollfds_size)
		return -1;
	if (!p->items[fd]->writeable)
		return -1;

	return p->items[fd]->blocked;
}




int poller_timer(struct poller *p, void (*f)(void *), void *ptr) {
	struct timer_item *i;

	if (!p || !f)
		return -1;

	i = malloc(sizeof(*i));
	ZERO(*i);

	i->func = f;
	i->ptr = ptr;

	p->timers = g_list_prepend(p->timers, i);

	return 0;
}
