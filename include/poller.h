#ifndef __POLLER_H__
#define __POLLER_H__



#include <sys/types.h>
#include <stdint.h>
#include <time.h>
#include <glib.h>



struct obj;



typedef void (*poller_func_t)(int, void *, uintptr_t);

struct poller_item {
	int				fd;
	struct obj			*obj;
	uintptr_t			uintp;

	poller_func_t			readable;
	poller_func_t			writeable;
	poller_func_t			closed;
	poller_func_t			timer;
};

struct poller;


struct poller *poller_new(void);
int poller_add_item(struct poller *, struct poller_item *);
int poller_update_item(struct poller *, struct poller_item *);
int poller_del_item(struct poller *, int);

void poller_blocked(struct poller *, void *);
int poller_isblocked(struct poller *, void *);
void poller_error(struct poller *, void *);

int poller_poll(struct poller *, int);
void poller_timer_loop(void *);
void poller_loop(void *);

int poller_add_timer(struct poller *, void (*)(void *), struct obj *);
int poller_del_timer(struct poller *, void (*)(void *), struct obj *);


#endif
