#ifndef __POLLER_H__
#define __POLLER_H__



#include <sys/types.h>
#include <stdint.h>
#include <time.h>
#include <glib.h>
#include <stdbool.h>
#include "compat.h"


struct obj;
struct sockaddr;


typedef void (*poller_func_t)(int, void *);

struct poller_item {
	int				fd;
	struct obj			*obj;

	poller_func_t			readable;
	void				(*recv)(struct obj *, char *b, size_t len, struct sockaddr *,
						struct timeval *);
	poller_func_t			writeable;
	poller_func_t			closed;
};

struct poller;

struct poller *poller_new(void);
void poller_free(struct poller **);
bool poller_add_item(struct poller *, struct poller_item *);
bool poller_del_item(struct poller *, int);
bool poller_del_item_callback(struct poller *, int, void (*)(void *), void *);

void poller_blocked(struct poller *, void *);
bool poller_isblocked(struct poller *, void *);
void poller_error(struct poller *, void *);

void poller_loop(void *);

extern bool (*rtpe_poller_add_item)(struct poller *, struct poller_item *);
extern bool (*rtpe_poller_del_item)(struct poller *, int);
extern bool (*rtpe_poller_del_item_callback)(struct poller *, int, void (*)(void *), void *);
extern void (*rtpe_poller_blocked)(struct poller *, void *);
extern bool (*rtpe_poller_isblocked)(struct poller *, void *);
extern void (*rtpe_poller_error)(struct poller *, void *);


#ifdef HAVE_LIBURING
extern __thread unsigned int (*uring_thread_loop)(void);
#else
INLINE unsigned int uring_thread_loop(void) { return 0; }
#endif


#endif
