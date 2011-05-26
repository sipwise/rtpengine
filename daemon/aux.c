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



int mybsearch(void *base, unsigned int len, unsigned int size, void *key, unsigned int key_off, unsigned int key_size, int exact) {
	unsigned char *cbase = base;
	int pos;
	unsigned char *cur;
	int res;
	unsigned int num;

	if (!len) {
		BSDB("zero length array\n");
		return -1;
	}

	pos = len / 2;
	num = pos;
	num += 3;
	num /= 2;
	pos--;
	if (pos < 0)
		pos = 0;

	BSDB("starting pos=%u, num=%u\n", pos, num);

	for (;;) {
		cur = cbase + (pos * size);
		res = memcmp(cur + key_off, key, key_size);
		BSDB("compare=%i\n", res);
		if (!res)
			return pos;
		if (!num) {
			BSDB("nothing found\n");
			if (exact)
				return -1;
			if (res > 0)	/* cur > key */
				return -1 * pos - 1;
			return -1 * pos - 2;
		}

		if (res < 0) {	/* cur < key */
			pos += num;
			if (pos >= len)
				pos = len - 1;
		}
		else {
			pos -= num;
			if (pos < 0)
				pos = 0;
		}

		BSDB("new pos=%u\n", pos);

		if (num == 1)
			num = 0;
		else {
			num++;
			num /= 2;
		}

		BSDB("new num=%u\n", num);
	}
}


GList *g_list_link(GList *list, GList *el) {
	el->prev = NULL;
	el->next = list;
	if (list)
		list->prev = el;
	return el;
}


GQueue *pcre_multi_match(pcre **re, pcre_extra **ree, const char *rex, const char *s, unsigned int num, parse_func f, void *p) {
	GQueue *q;
	const char *errptr;
	int erroff;
	unsigned int start, len;
	int ovec[60];
	int *ov;
	char **el;
	unsigned int i;
	void *ins;

	if (!*re) {
		*re = pcre_compile(rex, PCRE_DOLLAR_ENDONLY | PCRE_DOTALL, &errptr, &erroff, NULL);
		if (!*re)
			return NULL;
		*ree = pcre_study(*re, 0, &errptr);
	}

	q = g_queue_new();
	el = malloc(sizeof(*el) * num);

	for (start = 0, len = strlen(s); pcre_exec(*re, *ree, s + start, len - start, 0, 0, ovec, G_N_ELEMENTS(ovec)) > 0; start += ovec[1]) {
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

#endif
