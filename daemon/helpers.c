#include "helpers.h"

#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <pcre2.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/resource.h>
#include <errno.h>
#include <unistd.h>

#include "log.h"
#include "main.h"
#include "bufferpool.h"
#include "media_socket.h"
#include "uring.h"
#include "poller.h"

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
struct looper_thread {
	enum thread_looper_action (*f)(void);
	const char *name;
	long long interval_us;
};


static mutex_t threads_lists_lock = MUTEX_STATIC_INIT;
static GList *threads_to_join;
static GList *threads_running;
static cond_t threads_cond = COND_STATIC_INIT;
static mutex_t thread_wakers_lock = MUTEX_STATIC_INIT;
static GList *thread_wakers;


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



int pcre2_multi_match(pcre2_code *re, const char *s, unsigned int num, parse_func f,
		void *p, GQueue *q)
{
	size_t start, len, next;
	char **el;
	unsigned int i;
	void *ins;

	el = malloc(sizeof(*el) * num);
	pcre2_match_data *md = pcre2_match_data_create(num, NULL);

	for (start = 0, len = strlen(s);
			pcre2_match(re, (PCRE2_SPTR8) s + start, len - start, 0, 0, md, NULL) >= 0;
			start += next)
	{
		PCRE2_SIZE *ovec = pcre2_get_ovector_pointer(md);
		uint32_t count = pcre2_get_ovector_count(md);
		next = ovec[1];
		for (i = 0; i < num; i++) {
			size_t *ov = ovec + 2 + i*2;
			el[i] = (i + 1 >= count) ? NULL : g_strndup(s + start + ov[0], ov[1] - ov[0]);
		}

		if (f(el, &ins, p))
			g_queue_push_tail(q, ins);

		for (i = 0; i < num; i++)
			g_free(el[i]);
	}

	free(el);
	pcre2_match_data_free(md);

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
				wk->func(wk);
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

static void thread_waker_wake_cond(struct thread_waker *wk) {
	mutex_lock(wk->lock);
	cond_broadcast(wk->cond);
	mutex_unlock(wk->lock);
}
void thread_waker_add(struct thread_waker *wk) {
	wk->func = thread_waker_wake_cond;
	thread_waker_add_generic(wk);
}
void thread_waker_add_generic(struct thread_waker *wk) {
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
	bufferpool_destroy(media_bufferpool);
#ifdef HAVE_LIBURING
	if (rtpe_config.common.io_uring)
		uring_thread_cleanup();
#endif
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

	media_bufferpool = bufferpool_new(g_malloc, g_free, 64 * 65536);
#ifdef HAVE_LIBURING
	if (rtpe_config.common.io_uring)
		uring_thread_init();
#endif

	thread_cleanup_push(thread_detach_cleanup, dt);
	dt->func(dt->data);
	thread_cleanup_pop(true);

	return NULL;
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

	if (thread_create(thread_detach_func, dt, true, NULL, name))
		abort();
}

static void thread_looper_helper(void *fp) {
	// move object to stack and free it, so we can be cancelled without having a leak
	struct looper_thread *lhp = fp;
	struct looper_thread lh = *lhp;
	g_slice_free1(sizeof(*lhp), lhp);

	long long interval_us = lh.interval_us;
#ifdef ASAN_BUILD
	interval_us = MIN(interval_us, 100000);
#endif
	static const long long warn_limit_pct = 20; // 20%
	long long warn_limit_us = interval_us * warn_limit_pct / 100;
	struct timespec interval_ts = {
		.tv_sec = interval_us / 1000000,
		.tv_nsec = (interval_us % 1000000) * 1000,
	};

	while (!rtpe_shutdown) {
		gettimeofday(&rtpe_now, NULL);

		enum thread_looper_action ret = lh.f();

		uring_thread_loop();

		if (ret == TLA_BREAK)
			break;

		struct timeval stop;
		gettimeofday(&stop, NULL);
		long long duration_us = timeval_diff(&stop, &rtpe_now);
		if (duration_us > warn_limit_us)
			ilog(LOG_WARN, "Run time of timer \"%s\": %lli.%06lli sec, "
					"exceeding limit of %lli%% (%lli.%06lli sec)",
					lh.name,
					duration_us / 1000000, duration_us % 1000000,
					warn_limit_pct,
					warn_limit_us / 1000000, warn_limit_us % 1000000);

		struct timespec sleeptime = interval_ts;
		struct timespec remtime;
		while (true) {
			thread_cancel_enable();
			int res = nanosleep(&sleeptime, &remtime);
			thread_cancel_disable();
			if (res == -1 && errno == EINTR) {
				sleeptime = remtime;
				continue;
			}
			break;
		}
	}
}

void thread_create_looper(enum thread_looper_action (*f)(void), const char *scheduler, int priority,
		const char *name,
		long long interval_us)
{
	struct looper_thread *lh = g_slice_alloc(sizeof(*lh));
	*lh = (__typeof__(*lh)) {
		.f = f,
		.name = name,
		.interval_us = interval_us,
	};
	thread_create_detach_prio(thread_looper_helper, lh, scheduler, priority, name);
}
