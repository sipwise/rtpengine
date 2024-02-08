#ifndef _TIMERTHREAD_H_
#define _TIMERTHREAD_H_

#include <glib.h>
#include <sys/time.h>

#include "auxlib.h"
#include "obj.h"

struct timerthread;

struct timerthread_thread {
	struct timerthread *parent;
	GTree *tree; // XXX investigate other structures
	mutex_t lock;
	cond_t cond;
	struct timeval next_wake;
	struct timerthread_obj *obj;
};

struct timerthread {
	unsigned int num_threads;
	struct timerthread_thread *threads;
	unsigned int thread_idx;
	void (*func)(void *);
};

struct timerthread_obj {
	struct obj obj;

	struct timerthread *tt;
	struct timerthread_thread *thread; // set once and then static
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
	unsigned int idx; // for equal timestamps
	void *source; // opaque
	char __rest[0];
};


void timerthread_init(struct timerthread *, unsigned int, void (*)(void *));
void timerthread_free(struct timerthread *);
void timerthread_launch(struct timerthread *, const char *scheduler, int prio, const char *name);

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
void timerthread_queue_flush_data(void *ptr);
void timerthread_queue_push(struct timerthread_queue *, struct timerthread_queue_entry *);
unsigned int timerthread_queue_flush(struct timerthread_queue *, void *);

INLINE struct timerthread_thread *timerthread_get_next(struct timerthread *tt) {
	unsigned int idx = g_atomic_int_add(&tt->thread_idx, 1);
	idx = idx % tt->num_threads; // XXX check perf without %
	return &tt->threads[idx];
}

INLINE void timerthread_obj_schedule_abs(struct timerthread_obj *tt_obj, const struct timeval *tv) {
	if (!tt_obj)
		return;
	struct timerthread_thread *tt = tt_obj->thread;
	if (!tt) {
		tt = timerthread_get_next(tt_obj->tt);
		g_atomic_pointer_compare_and_exchange(&tt_obj->thread, NULL, tt);
	}
	tt = tt_obj->thread;
	mutex_lock(&tt->lock);
	timerthread_obj_schedule_abs_nl(tt_obj, tv);
	mutex_unlock(&tt->lock);
}


#endif
