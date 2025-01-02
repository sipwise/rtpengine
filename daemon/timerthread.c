#include "timerthread.h"

#include "helpers.h"
#include "log_funcs.h"
#include "poller.h"


static int tt_obj_cmp(const void *a, const void *b) {
	const struct timerthread_obj *A = a, *B = b;
	return timeval_cmp_ptr(&A->next_check, &B->next_check);
}

static void timerthread_thread_init(struct timerthread_thread *tt, struct timerthread *parent) {
	tt->tree = g_tree_new(tt_obj_cmp);
	mutex_init(&tt->lock);
	cond_init(&tt->cond);
	tt->parent = parent;
	ZERO(tt->next_wake);
	tt->obj = NULL;
}

void timerthread_init(struct timerthread *tt, unsigned int num, void (*func)(void *)) {
	tt->func = func;
	tt->num_threads = num;
	tt->threads = g_malloc(sizeof(*tt->threads) * num);
	for (unsigned int i = 0; i < num; i++)
		timerthread_thread_init(&tt->threads[i], tt);
}

static int __tt_put_all(void *k, void *d, void *p) {
	struct timerthread_obj *tto = d;
	//struct timerthread *tt = p;
	obj_put(tto);
	return FALSE;
}

static void timerthread_thread_destroy(struct timerthread_thread *tt) {
	g_tree_foreach(tt->tree, __tt_put_all, tt);
	g_tree_destroy(tt->tree);
	if (tt->obj)
		obj_put(tt->obj);
	mutex_destroy(&tt->lock);
}

void timerthread_free(struct timerthread *tt) {
	for (unsigned int i = 0; i < tt->num_threads; i++)
		timerthread_thread_destroy(&tt->threads[i]);
	g_free(tt->threads);
}

static void timerthread_run(void *p) {
	struct timerthread_thread *tt = p;
	struct timerthread *parent = tt->parent;

	struct thread_waker waker = { .lock = &tt->lock, .cond = &tt->cond };
	thread_waker_add(&waker);

	mutex_lock(&tt->lock);

	while (!rtpe_shutdown) {
		gettimeofday(&rtpe_now, NULL);

		long long sleeptime = 10000000;
		// find the first element if we haven't determined it yet
		struct timerthread_obj *tt_obj = tt->obj;
		if (!tt_obj) {
			tt_obj = g_tree_find_first(tt->tree, NULL, NULL);
			if (!tt_obj)
				goto sleep_now;

			// immediately steal reference
			// XXX ideally we would have a tree_steal_first() function
			g_tree_remove(tt->tree, tt_obj);
		}

		// scheduled to run? if not, then we remember this object/reference and go to sleep
		sleeptime = timeval_diff(&tt_obj->next_check, &rtpe_now);

		if (sleeptime > 0) {
			tt->obj = tt_obj;
			goto sleep;
		}

		// pretend we're running exactly at the scheduled time
		rtpe_now = tt_obj->next_check;
		ZERO(tt_obj->next_check);
		tt_obj->last_run = rtpe_now;
		ZERO(tt->next_wake);
		tt->obj = NULL;
		mutex_unlock(&tt->lock);

		// run and release
		parent->func(tt_obj);
		obj_put(tt_obj);

		log_info_reset();
		uring_thread_loop();

		mutex_lock(&tt->lock);
		continue;

sleep:
		/* figure out how long we should sleep */
		sleeptime = MIN(10000000, sleeptime);
sleep_now:;
		struct timeval tv = rtpe_now;
		timeval_add_usec(&tv, sleeptime);
		tt->next_wake = tv;
		cond_timedwait(&tt->cond, &tt->lock, &tv);
	}

	mutex_unlock(&tt->lock);
	thread_waker_del(&waker);
}

void timerthread_launch(struct timerthread *tt, const char *scheduler, int prio, const char *name) {
	for (unsigned int i = 0; i < tt->num_threads; i++)
		thread_create_detach_prio(timerthread_run, &tt->threads[i], scheduler, prio, name);
}

void timerthread_obj_schedule_abs_nl(struct timerthread_obj *tt_obj, const struct timeval *tv) {
	if (!tt_obj)
		return;
	struct timerthread_thread *tt = tt_obj->thread;

	//ilog(LOG_DEBUG, "scheduling timer object at %llu.%06lu", (unsigned long long) tv->tv_sec,
			//(unsigned long) tv->tv_usec);

	if (tt_obj->next_check.tv_sec && timeval_cmp(&tt_obj->next_check, tv) <= 0)
		return; /* already scheduled sooner */
	if (!g_tree_remove(tt->tree, tt_obj)) {
		if (tt->obj == tt_obj)
			tt->obj = NULL;
		else
			obj_hold(tt_obj); /* if it wasn't removed, we make a new reference */
	}
	tt_obj->next_check = *tv;
	g_tree_insert(tt->tree, tt_obj, tt_obj);
	// need to wake the thread?
	if (tt->next_wake.tv_sec && timeval_cmp(tv, &tt->next_wake) < 0) {
		// make sure we can get picked first: move pre-picked object back into tree
		if (tt->obj && tt->obj != tt_obj) {
			g_tree_insert(tt->tree, tt->obj, tt->obj);
			tt->obj = NULL;
		}
		cond_signal(&tt->cond);
	}
}

void timerthread_obj_deschedule(struct timerthread_obj *tt_obj) {
	if (!tt_obj)
		return;

	struct timerthread_thread *tt = tt_obj->thread;
	if (!tt)
		return;

	mutex_lock(&tt->lock);
	if (!tt_obj->next_check.tv_sec)
		goto nope; /* already descheduled */
	gboolean ret = g_tree_remove(tt->tree, tt_obj);
	if (!ret) {
		if (tt->obj == tt_obj) {
			tt->obj = NULL;
			ret = TRUE;
		}
	}
	ZERO(tt_obj->next_check);
	if (ret)
		obj_put(tt_obj);
nope:
	mutex_unlock(&tt->lock);
}

static int timerthread_queue_run_one(struct timerthread_queue *ttq,
		struct timerthread_queue_entry *ttqe,
		void (*run_func)(struct timerthread_queue *, void *)) {
	if (ttqe->when.tv_sec && timeval_cmp(&ttqe->when, &rtpe_now) > 0) {
		if(timeval_diff(&ttqe->when, &rtpe_now) > 1000) // not to queue packet less than 1ms
			return -1; // not yet
	}
	run_func(ttq, ttqe);
	return 0;
}


void timerthread_queue_run(void *ptr) {
	struct timerthread_queue *ttq = ptr;

	//ilog(LOG_DEBUG, "running timerthread_queue");

	struct timeval next_send = {0,};

	mutex_lock(&ttq->lock);

	while (g_tree_nnodes(ttq->entries)) {
		struct timerthread_queue_entry *ttqe = g_tree_find_first(ttq->entries, NULL, NULL);
		assert(ttqe != NULL);
		g_tree_remove(ttq->entries, ttqe);

		mutex_unlock(&ttq->lock);

		int ret = timerthread_queue_run_one(ttq, ttqe, ttq->run_later_func);

		mutex_lock(&ttq->lock);

		if (!ret)
			continue;
		// couldn't send the last one. remember time to schedule
		g_tree_insert(ttq->entries, ttqe, ttqe);
		next_send = ttqe->when;
		break;
	}

	mutex_unlock(&ttq->lock);

	if (next_send.tv_sec)
		timerthread_obj_schedule_abs(&ttq->tt_obj, &next_send);
}

static int ttqe_free_all(void *k, void *v, void *d) {
	struct timerthread_queue *ttq = d;
	if (ttq->entry_free_func)
		ttq->entry_free_func(k);
	return FALSE;
}

static void __timerthread_queue_free(void *p) {
	struct timerthread_queue *ttq = p;
	g_tree_foreach(ttq->entries, ttqe_free_all, ttq);
	g_tree_destroy(ttq->entries);
	mutex_destroy(&ttq->lock);
	if (ttq->free_func)
		ttq->free_func(p);
}

static int ttqe_compare(const void *a, const void *b) {
	const struct timerthread_queue_entry *t1 = a;
	const struct timerthread_queue_entry *t2 = b;
	int ret = timeval_cmp_zero(&t1->when, &t2->when);
	if (ret)
		return ret;
	if (t1->idx < t2->idx)
		return -1;
	if (t1->idx == t2->idx)
		return 0;
	return 1;
}
 
void *timerthread_queue_new(const char *type, size_t size,
		struct timerthread *tt,
		void (*run_now_func)(struct timerthread_queue *, void *),
		void (*run_later_func)(struct timerthread_queue *, void *),
		void (*free_func)(void *),
		void (*entry_free_func)(void *))
{
	struct timerthread_queue *ttq = obj_alloc0_gen(type, size, __timerthread_queue_free);
	ttq->type = type;
	ttq->tt_obj.tt = tt;
	assert(tt->func == timerthread_queue_run);
	ttq->run_now_func = run_now_func;
	ttq->run_later_func = run_later_func;
	if (!ttq->run_later_func)
		ttq->run_later_func = run_now_func;
	ttq->free_func = free_func;
	ttq->entry_free_func = entry_free_func;
	mutex_init(&ttq->lock);
	ttq->entries = g_tree_new(ttqe_compare);
	return ttq;
}

int __ttqe_find_last_idx(const void *a, const void *b) {
	const struct timerthread_queue_entry *ttqe_a = a;
	void **data = (void **) b;
	const struct timerthread_queue_entry *ttqe_b = data[0];
	int ret = timeval_cmp(&ttqe_b->when, &ttqe_a->when);
	if (ret)
		return ret;
	// same timestamp. track highest seen idx
	if (GPOINTER_TO_UINT(data[1]) < ttqe_a->idx)
		data[1] = GUINT_TO_POINTER(ttqe_a->idx);
	return 1; // and continue to higher idx
}
void timerthread_queue_push(struct timerthread_queue *ttq, struct timerthread_queue_entry *ttqe) {
	// can we send immediately?
	if (ttq->run_now_func && timerthread_queue_run_one(ttq, ttqe, ttq->run_now_func) == 0)
		return;

	// queue for sending

	//ilog(LOG_DEBUG, "queuing up %s object for processing at %lu.%06u",
			//ttq->type,
			//(unsigned long) ttqe->when.tv_sec,
			//(unsigned int) ttqe->when.tv_usec);

	// XXX recover log line fields
//	struct rtp_header *rh = (void *) cp->s.s;
//	ilog(LOG_DEBUG, "queuing up packet for delivery at %lu.%06u (RTP seq %u TS %u)",
//			(unsigned long) cp->to_send.tv_sec,
//			(unsigned int) cp->to_send.tv_usec,
//			ntohs(rh->seq_num),
//			ntohl(rh->timestamp));

	ttqe->idx = 0;

	mutex_lock(&ttq->lock);

	// check for most common case: no timestamp collision exists
	if (!g_tree_lookup(ttq->entries, ttqe))
		;
	else {
		// something else exists with the same timestamp. find the highest idx
		void *data[2];
		data[0] = ttqe;
		data[1] = 0;
		g_tree_search(ttq->entries, __ttqe_find_last_idx, data);
		ttqe->idx = GPOINTER_TO_UINT(data[1] + 1);
	}

	// this hands over ownership of cp, so we must copy the timeval out
	struct timeval tv_send = ttqe->when;
	g_tree_insert(ttq->entries, ttqe, ttqe);
	struct timerthread_queue_entry *first_ttqe = g_tree_find_first(ttq->entries, NULL, NULL);
	mutex_unlock(&ttq->lock);

	// first packet in? we're probably not scheduled yet
	if (first_ttqe == ttqe)
		timerthread_obj_schedule_abs(&ttq->tt_obj, &tv_send);
}

static int ttqe_ptr_match(const void *ent, const void *ptr) {
	const struct timerthread_queue_entry *ttqe = ent;
	return ttqe->source == ptr;
}
unsigned int timerthread_queue_flush(struct timerthread_queue *ttq, void *ptr) {
	if (!ttq)
		return 0;

	mutex_lock(&ttq->lock);

	unsigned int num = 0;
	GQueue matches = G_QUEUE_INIT;
	g_tree_find_all(&matches, ttq->entries, ttqe_ptr_match, ptr);

	while (matches.length) {
		struct timerthread_queue_entry *ttqe = g_queue_pop_head(&matches);
		g_tree_remove(ttq->entries, ttqe);
		if (ttq->entry_free_func)
			ttq->entry_free_func(ttqe);
		num++;
	}

	mutex_unlock(&ttq->lock);

	return num;
}

void timerthread_queue_flush_data(void *ptr) {
        struct timerthread_queue *ttq = ptr;

        //ilog(LOG_DEBUG, "timerthread_queue_flush_data");

        mutex_lock(&ttq->lock);
        while (g_tree_nnodes(ttq->entries)) {
                struct timerthread_queue_entry *ttqe = g_tree_find_first(ttq->entries, NULL, NULL);
                assert(ttqe != NULL);
                g_tree_remove(ttq->entries, ttqe);

                mutex_unlock(&ttq->lock);

                ttq->run_later_func(ttq, ttqe);

                mutex_lock(&ttq->lock);
        }
        mutex_unlock(&ttq->lock);
}
