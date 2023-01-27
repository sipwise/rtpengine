#include "aux.h"
#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <pcre.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/resource.h>
#include <errno.h>
#include <unistd.h>
#include "log.h"
#include "main.h"



#if 0
#define BSDB(x...) fprintf(stderr, x)
#else
#define BSDB(x...) ((void)0)
#endif




struct detach_thread {
	void		(*func)(void *);
	void		*data;
	const char	*scheduler;
	int		priority;
};
struct scheduler {
	const char *name;
	int num;
	int nice;
};


static mutex_t threads_lists_lock = MUTEX_STATIC_INIT;
static GList *threads_to_join;
static GList *threads_running;
static cond_t threads_cond = COND_STATIC_INIT;
static mutex_t thread_wakers_lock = MUTEX_STATIC_INIT;
static GList *thread_wakers;

volatile int rtpe_shutdown;

#ifdef NEED_ATOMIC64_MUTEX
mutex_t __atomic64_mutex = MUTEX_STATIC_INIT;
#endif

static const struct scheduler schedulers[] = {
	{ "default",	-1,		1 },
	{ "none",	-1,		1 },
#ifdef SCHED_FIFO
	{ "fifo",	SCHED_FIFO,	0 },
#endif
#ifdef SCHED_RR
	{ "rr",		SCHED_RR,	0 },
#endif
//#ifdef SCHED_DEADLINE
//	{ "deadline",	SCHED_DEADLINE,	0 },
//#endif
#ifdef SCHED_OTHER
	{ "other",	SCHED_OTHER,	1 },
#endif
#ifdef SCHED_BATCH
	{ "batch",	SCHED_BATCH,	1 },
#endif
#ifdef SCHED_IDLE
	{ "idle",	SCHED_IDLE,	0 },
#endif
};



GList *g_list_link(GList *list, GList *el) {
	el->prev = NULL;
	el->next = list;
	if (list)
		list->prev = el;
	return el;
}


int pcre_multi_match(pcre *re, pcre_extra *ree, const char *s, unsigned int num, parse_func f,
		void *p, GQueue *q)
{
	unsigned int start, len;
	int ovec[60];
	int *ov;
	char **el;
	unsigned int i;
	void *ins;

	el = malloc(sizeof(*el) * num);

	for (start = 0, len = strlen(s); pcre_exec(re, ree, s + start, len - start, 0, 0, ovec, G_N_ELEMENTS(ovec)) > 0; start += ovec[1]) {
		for (i = 0; i < num; i++) {
			ov = ovec + 2 + i*2;
			el[i] = (ov[0] == -1) ? NULL : g_strndup(s + start + ov[0], ov[1] - ov[0]);
		}

		if (!f(el, &ins, p))
			g_queue_push_tail(q, ins);

		for (i = 0; i < num; i++) {
			if (el[i])
				free(el[i]);
		}
	}

	free(el);

	return q ? q->length : 0;
}




static void thread_join_me(void) {
	pthread_t *me;

	me = g_slice_alloc(sizeof(*me));
	*me = pthread_self();
	mutex_lock(&threads_lists_lock);
	threads_to_join = g_list_prepend(threads_to_join, me);
	cond_broadcast(&threads_cond);
	mutex_unlock(&threads_lists_lock);
}

static gint thread_equal(gconstpointer a, gconstpointer b) {
	const pthread_t *x = a, *y = b;
	return !pthread_equal(*x, *y);
}

void threads_join_all(bool cancel) {
	pthread_t *t;
	GList *l;

	while (1) {
		if (cancel) {
			mutex_lock(&thread_wakers_lock);
			for (l = thread_wakers; l; l = l->next) {
				struct thread_waker *wk = l->data;
				mutex_lock(wk->lock);
				cond_broadcast(wk->cond);
				mutex_unlock(wk->lock);
			}
			mutex_unlock(&thread_wakers_lock);

			mutex_lock(&threads_lists_lock);
			for (l = threads_running; l; l = l->next) {
				t = l->data;
				pthread_cancel(*t);
			}
			mutex_unlock(&threads_lists_lock);
		}

		mutex_lock(&threads_lists_lock);
		while (threads_to_join) {
			t = threads_to_join->data;
			pthread_join(*t, NULL);
			threads_to_join = g_list_delete_link(threads_to_join, threads_to_join);
			l = g_list_find_custom(threads_running, t, thread_equal);
			if (l) {
				g_slice_free1(sizeof(*t), l->data);
				threads_running = g_list_delete_link(threads_running, l);
			}
			else
				abort();
			g_slice_free1(sizeof(*t), t);
		}

		if ((!cancel && rtpe_shutdown) || (cancel && !threads_running)) {
			mutex_unlock(&threads_lists_lock);
			break;
		}
		cond_wait(&threads_cond, &threads_lists_lock);
		mutex_unlock(&threads_lists_lock);
	}
}

void thread_waker_add(struct thread_waker *wk) {
	mutex_lock(&thread_wakers_lock);
	thread_wakers = g_list_prepend(thread_wakers, wk);
	mutex_unlock(&thread_wakers_lock);
}
void thread_waker_del(struct thread_waker *wk) {
	mutex_lock(&thread_wakers_lock);
	thread_wakers = g_list_remove(thread_wakers, wk);
	mutex_unlock(&thread_wakers_lock);
}

static void thread_detach_cleanup(void *dtp) {
	struct detach_thread *dt = dtp;
	g_slice_free1(sizeof(*dt), dt);
	thread_join_me();
}

static void *thread_detach_func(void *d) {
	struct detach_thread *dt = d;
	pthread_t *t;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	t = g_slice_alloc(sizeof(*t));
	*t = pthread_self();
	mutex_lock(&threads_lists_lock);
	threads_running = g_list_prepend(threads_running, t);
	mutex_unlock(&threads_lists_lock);

	const struct scheduler *scheduler = NULL;

	if (dt->scheduler) {
		for (int i = 0; i < G_N_ELEMENTS(schedulers); i++) {
			if (!strcmp(dt->scheduler, schedulers[i].name)) {
				scheduler = &schedulers[i];
				break;
			}
		}

		if (!scheduler)
			ilog(LOG_ERR, "Specified scheduler policy '%s' not found", dt->scheduler);
		else if (scheduler->num != -1) {
			struct sched_param param = { 0 };

			if (!scheduler->nice)
				param.sched_priority = dt->priority;

			ilog(LOG_DEBUG, "Setting thread scheduling parameters to '%s' (%i) / %i",
					dt->scheduler, scheduler->num, param.sched_priority);

			if (pthread_setschedparam(*t, scheduler->num, &param))
				ilog(LOG_ERR, "Failed to set thread scheduling parameters to '%s' (%i) / %i: %s",
						dt->scheduler, scheduler->num, param.sched_priority,
						strerror(errno));

		}
	}

	if ((!scheduler && dt->priority) || (scheduler && scheduler->nice)) {
		ilog(LOG_DEBUG, "Setting thread nice value to %i", dt->priority);

		if (setpriority(PRIO_PROCESS, 0, dt->priority))
			ilog(LOG_ERR, "Failed to set thread nice value to %i: %s",
					dt->priority, strerror(errno));
	}

#ifndef ASAN_BUILD
	pthread_cleanup_push(thread_detach_cleanup, dt);
#endif
	dt->func(dt->data);
#ifndef ASAN_BUILD
	pthread_cleanup_pop(true);
#else
	thread_detach_cleanup(dt);
#endif

	return NULL;
}

static int thread_create(void *(*func)(void *), void *arg, int joinable, pthread_t *handle, const char *name) {
	pthread_attr_t att;
	pthread_t thr;
	int ret;

	if (pthread_attr_init(&att))
		abort();
	if (pthread_attr_setdetachstate(&att, joinable ? PTHREAD_CREATE_JOINABLE : PTHREAD_CREATE_DETACHED))
		abort();
	if (rtpe_config.common.thread_stack > 0) {
		if (pthread_attr_setstacksize(&att, rtpe_config.common.thread_stack * 1024)) {
			ilog(LOG_ERR, "Failed to set thread stack size to %llu",
					(unsigned long long) rtpe_config.common.thread_stack * 1024);
			abort();
		}
	}
	ret = pthread_create(&thr, &att, func, arg);
	pthread_attr_destroy(&att);
	if (ret)
		return ret;
	if (handle)
		*handle = thr;
#ifdef __GLIBC__
	if (name)
		pthread_setname_np(thr, name);
#endif

	return 0;
}

void thread_create_detach_prio(void (*f)(void *), void *d, const char *scheduler, int priority,
		const char *name)
{
	struct detach_thread *dt;

	dt = g_slice_alloc(sizeof(*dt));
	dt->func = f;
	dt->data = d;
	dt->scheduler = scheduler;
	dt->priority = priority;

	if (thread_create(thread_detach_func, dt, 1, NULL, name))
		abort();
}
