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

struct timerthread_queue {
	struct timerthread_obj tt_obj;
	const char *type;
	mutex_t lock;
	GTree *entries;
	void (*run_now_func)(struct timerthread_queue *, void *);
	void (*run_later_func)(struct timerthread_queue *, void *);
	void (*free_func)(void *);
	void (*entry_free_func)(void *);
};

struct timerthread_queue_entry {
	struct timeval when;
	void *source; // opaque
	char __rest[0];
};


void timerthread_init(struct timerthread *, void (*)(void *));
void timerthread_run(void *);

void timerthread_obj_schedule_abs_nl(struct timerthread_obj *, const struct timeval *);
void timerthread_obj_deschedule(struct timerthread_obj *);

// run_now_func = called if newly inserted object can be processed immediately by timerthread_queue_push within its calling context
// run_later_func = called from the separate timer thread
void *timerthread_queue_new(const char *type, size_t size,
		struct timerthread *tt,
		void (*run_now_func)(struct timerthread_queue *, void *),
		void (*run_later_func)(struct timerthread_queue *, void *), // optional
		void (*free_func)(void *),
		void (*entry_free_func)(void *));
void timerthread_queue_run(void *ptr);
void timerthread_queue_push(struct timerthread_queue *, struct timerthread_queue_entry *);
unsigned int timerthread_queue_flush(struct timerthread_queue *, void *);

INLINE void timerthread_obj_schedule_abs(struct timerthread_obj *tt_obj, const struct timeval *tv) {
	if (!tt_obj)
		return;
	mutex_lock(&tt_obj->tt->lock);
	timerthread_obj_schedule_abs_nl(tt_obj, tv);
	mutex_unlock(&tt_obj->tt->lock);
}


#endif
