#include "garbage.h"
#include <glib.h>
#include <pthread.h>
#include "log.h"


typedef struct {
	void *ptr;
	void (*free_func)(void *);
	int *wait_threads;
	unsigned int array_len;
	unsigned int threads_left;
} garbage_t;


static pthread_mutex_t garbage_lock = PTHREAD_MUTEX_INITIALIZER;
static GQueue garbage = G_QUEUE_INIT;
static volatile int garbage_thread_num;


unsigned int garbage_new_thread_num(void) {
	return g_atomic_int_add(&garbage_thread_num, 1);
}


void garbage_add(void *ptr, free_func_t *free_func) {
	// Each running poller thread has a unique number associated with it, starting
	// with 0. A garbage entry uses an array of boolean flags, one for each running
	// thread, to keep track of which threads have seen this entry. Once a garbage
	// entry has been seen by all threads, the free function is finally called.
	// This is to make sure that all poller threads have left epoll_wait() after
	// an fd has been removed from the watch list.

	garbage_t *garb = g_slice_alloc(sizeof(*garb));
	garb->ptr = ptr;
	garb->free_func = free_func;

	pthread_mutex_lock(&garbage_lock);

	garb->array_len = g_atomic_int_get(&garbage_thread_num);
	garb->threads_left = garb->array_len;
	garb->wait_threads = malloc(sizeof(int) * garb->array_len);
	memset(garb->wait_threads, 0, sizeof(int) * garb->array_len);

	g_queue_push_tail(&garbage, garb);

	pthread_mutex_unlock(&garbage_lock);
}


static void garbage_collect1(garbage_t *garb) {
	garb->free_func(garb->ptr);

	free(garb->wait_threads);
	g_slice_free1(sizeof(*garb), garb);
}


void garbage_collect(unsigned int num) {
	dbg("running garbage collection thread %u", num);

restart:
	pthread_mutex_lock(&garbage_lock);

	for (GList *l = garbage.head; l; l = l->next) {
		garbage_t *garb = l->data;
		// has this been created before we were running?
		if (garb->array_len <= num)
			continue;
		// have we processed this already?
		if (garb->wait_threads[num])
			continue;
		dbg("marking garbage entry %p as seen by %u with %u threads left", garb, num,
				garb->threads_left);
		garb->wait_threads[num] = 1;
		garb->threads_left--;
		// anything left?
		if (!garb->threads_left) {
			// remove from list and process
			g_queue_delete_link(&garbage, l);
			pthread_mutex_unlock(&garbage_lock);
			garbage_collect1(garb);

			goto restart;
		}
	}

	pthread_mutex_unlock(&garbage_lock);
}


void garbage_collect_all(void) {
	garbage_t *garb;
	while ((garb = g_queue_pop_head(&garbage)))
		garbage_collect1(garb);
}
