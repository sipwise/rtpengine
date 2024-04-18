#ifndef __POLLER_H__
#define __POLLER_H__



#include <sys/types.h>
#include <stdint.h>
#include <time.h>
#include <glib.h>
#include <stdbool.h>


struct obj;



typedef void (*poller_func_t)(int, void *, uintptr_t);

struct poller_item {
	int				fd;
	struct obj			*obj;
	uintptr_t			uintp;

	poller_func_t			readable;
	poller_func_t			writeable;
	poller_func_t			closed;
};

struct poller;

struct poller *poller_new(void);
void poller_free(struct poller **);
bool poller_add_item(struct poller *, struct poller_item *);
bool poller_del_item(struct poller *, int);

void poller_blocked(struct poller *, void *);
int poller_isblocked(struct poller *, void *);
void poller_error(struct poller *, void *);

void poller_loop(void *);


#endif
