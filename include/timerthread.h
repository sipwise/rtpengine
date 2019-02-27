#ifndef _TIMERTHREAD_H_
#define _TIMERTHREAD_H_

#include "obj.h"
#include <glib.h>
#include <sys/time.h>
#include "auxlib.h"


struct timerthread {
	GTree *tree;
	mutex_t lock;
	cond_t cond;
	void (*func)(void *);
};

struct timerthread_obj {
	struct obj obj;

	struct timerthread *tt;
	struct timeval next_check; /* protected by ->lock */
	struct timeval last_run; /* ditto */
};


void timerthread_init(struct timerthread *, void (*)(void *));
void timerthread_run(void *);

void timerthread_obj_schedule_abs_nl(struct timerthread_obj *, const struct timeval *);
void timerthread_obj_deschedule(struct timerthread_obj *);


#endif
