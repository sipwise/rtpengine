#include "timerthread.h"
#include "aux.h"


static int tt_obj_cmp(const void *a, const void *b) {
	const struct timerthread_obj *A = a, *B = b;
	return timeval_cmp_ptr(&A->next_check, &B->next_check);
}

void timerthread_init(struct timerthread *tt, void (*func)(void *)) {
	tt->tree = g_tree_new(tt_obj_cmp);
	mutex_init(&tt->lock);
	cond_init(&tt->cond);
	tt->func = func;
}

void timerthread_run(void *p) {
	struct timerthread *tt = p;

	mutex_lock(&tt->lock);

	while (!rtpe_shutdown) {
		gettimeofday(&rtpe_now, NULL);

		/* lock our list and get the first element */
		struct timerthread_obj *tt_obj = g_tree_find_first(tt->tree, NULL, NULL);
		/* scheduled to run? if not, we just go to sleep, otherwise we remove it from the tree,
		 * steal the reference and run it */
		if (!tt_obj)
			goto sleep;
		if (timeval_cmp(&rtpe_now, &tt_obj->next_check) < 0)
			goto sleep;

		// steal reference
		g_tree_remove(tt->tree, tt_obj);
		ZERO(tt_obj->next_check);
		tt_obj->last_run = rtpe_now;
		mutex_unlock(&tt->lock);

		// run and release
		tt->func(tt_obj);
		obj_put(tt_obj);

		mutex_lock(&tt->lock);
		continue;

sleep:;
		/* figure out how long we should sleep */
		long long sleeptime = tt_obj ? timeval_diff(&tt_obj->next_check, &rtpe_now) : 100000;
		sleeptime = MIN(100000, sleeptime); /* 100 ms at the most */
		struct timeval tv = rtpe_now;
		timeval_add_usec(&tv, sleeptime);
		cond_timedwait(&tt->cond, &tt->lock, &tv);
	}

	mutex_unlock(&tt->lock);
}

void timerthread_obj_schedule_abs_nl(struct timerthread_obj *tt_obj, const struct timeval *tv) {
	if (!tt_obj)
		return;

	ilog(LOG_DEBUG, "scheduling timer object at %llu.%06lu", (unsigned long long) tv->tv_sec,
			(unsigned long) tv->tv_usec);

	struct timerthread *tt = tt_obj->tt;
	if (tt_obj->next_check.tv_sec && timeval_cmp(&tt_obj->next_check, tv) <= 0)
		return; /* already scheduled sooner */
	if (!g_tree_remove(tt->tree, tt_obj))
		obj_hold(tt_obj); /* if it wasn't removed, we make a new reference */
	tt_obj->next_check = *tv;
	g_tree_insert(tt->tree, tt_obj, tt_obj);
	cond_broadcast(&tt->cond);
}

void timerthread_obj_deschedule(struct timerthread_obj *tt_obj) {
	if (!tt_obj)
		return;

	struct timerthread *tt = tt_obj->tt;
	mutex_lock(&tt->lock);
	if (!tt_obj->next_check.tv_sec)
		goto nope; /* already descheduled */
	int ret = g_tree_remove(tt->tree, tt_obj);
	ZERO(tt_obj->next_check);
	if (ret)
		obj_put(tt_obj);
nope:
	mutex_unlock(&tt->lock);
}
