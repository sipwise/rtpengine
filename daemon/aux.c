#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <pcre.h>

#include "aux.h"



#if 0
#define BSDB(x...) fprintf(stderr, x)
#else
#define BSDB(x...) ((void)0)
#endif



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
