#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <pcre.h>
#include <stdlib.h>

#include "aux.h"



#if 0
#define BSDB(x...) fprintf(stderr, x)
#else
#define BSDB(x...) ((void)0)
#endif




struct detach_thread {
	GThreadFunc	func;
	gpointer	data;
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
	mutex_lock(&threads_to_join_lock);
	threads_to_join = g_slist_prepend(threads_to_join, g_thread_self());
	mutex_unlock(&threads_to_join_lock);
}

void threads_join_all() {
	GThread *t;

	mutex_lock(&threads_to_join_lock);
	while (threads_to_join) {
		t = threads_to_join->data;
		g_thread_join(t);
		threads_to_join = g_slist_delete_link(threads_to_join, threads_to_join);
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

void thread_create_detach(GThreadFunc f, gpointer d) {
	struct detach_thread *dt;

	dt = g_slice_alloc(sizeof(*dt));
	dt->func = f;
	dt->data = d;

	if (!g_thread_create(thread_detach_func, dt, TRUE, NULL))
		abort();
}
