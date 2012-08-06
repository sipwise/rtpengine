#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <pcre.h>
#include <stdlib.h>
#include <pthread.h>

#include "aux.h"



#if 0
#define BSDB(x...) fprintf(stderr, x)
#else
#define BSDB(x...) ((void)0)
#endif




struct detach_thread {
	void		(*func)(void *);
	void		*data;
};


mutex_t threads_to_join_lock = MUTEX_STATIC_INIT;
static GSList *threads_to_join;



GList *g_list_link(GList *list, GList *el) {
	el->prev = NULL;
	el->next = list;
	if (list)
		list->prev = el;
	return el;
}


GQueue *pcre_multi_match(pcre *re, pcre_extra *ree, const char *s, unsigned int num, parse_func f, void *p) {
	GQueue *q;
	unsigned int start, len;
	int ovec[60];
	int *ov;
	char **el;
	unsigned int i;
	void *ins;

	q = g_queue_new();
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

	return q;
}


void strmove(char **d, char **s) {
	if (*d)
		free(*d);
	*d = *s;
	*s = strdup("");
}

void strdupfree(char **d, const char *s) {
	if (*d)
		free(*d);
	*d = strdup(s);
}



#if !GLIB_CHECK_VERSION(2,14,0)

void g_string_vprintf(GString *string, const gchar *format, va_list args) {
	char *s;
	int r;

	r = vasprintf(&s, format, args);
	if (r < 0)
		return;

	g_string_assign(string, s);
	free(s);
}

void g_queue_clear(GQueue *q) {
	GList *l, *n;

	if (!q)
		return;

	for (l = q->head; l; l = n) {
		n = l->next;
		g_list_free_1(l);
	}

	q->head = q->tail = NULL;
	q->length = 0;
}

#endif



void thread_join_me() {
	pthread_t *me;

	me = g_slice_alloc(sizeof(*me));
	*me = pthread_self();
	mutex_lock(&threads_to_join_lock);
	threads_to_join = g_slist_prepend(threads_to_join, me);
	mutex_unlock(&threads_to_join_lock);
}

void threads_join_all() {
	pthread_t *t;

	mutex_lock(&threads_to_join_lock);
	while (threads_to_join) {
		t = threads_to_join->data;
		pthread_join(*t, NULL);
		threads_to_join = g_slist_delete_link(threads_to_join, threads_to_join);
		g_slice_free1(sizeof(*t), t);
	}
	mutex_unlock(&threads_to_join_lock);
}

static gpointer thread_detach_func(gpointer d) {
	struct detach_thread *dt = d;

	dt->func(dt->data);
	g_slice_free1(sizeof(*dt), dt);
	thread_join_me();
	return NULL;
}

int thread_create(void *(*func)(void *), void *arg, int joinable, pthread_t *handle) {
	pthread_attr_t att;
	pthread_t thr;
	int ret;

	if (pthread_attr_init(&att))
		abort();
	if (pthread_attr_setdetachstate(&att, joinable ? PTHREAD_CREATE_JOINABLE : PTHREAD_CREATE_DETACHED))
		abort();
	ret = pthread_create(&thr, &att, func, arg);
	pthread_attr_destroy(&att);
	if (!ret && handle)
		*handle = thr;
	return ret;
}

void thread_create_detach(void (*f)(void *), void *d) {
	struct detach_thread *dt;

	dt = g_slice_alloc(sizeof(*dt));
	dt->func = f;
	dt->data = d;

	if (thread_create(thread_detach_func, dt, 1, NULL))
		abort();
}
