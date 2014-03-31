#ifndef _STR_H_
#define _STR_H_

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <stdio.h>
#include "compat.h"



struct _str {
	char *s;
	int len;
};

typedef struct _str str;



#define STR_FORMAT "%.*s"
#define STR_FMT(str) (str)->len, (str)->s
#define STR_FMT0(str) ((str) ? (str)->len : 6), ((str) ? (str)->s : "(NULL)")
#define STR_NULL ((str) { NULL, 0 })
#define STR_EMPTY ((str) { "", 0 })



/* returns pointer to end of str (s->s + s->len) */
INLINE char *str_end(const str *s);
/* returns pointer to first occurence of "c" in s */
INLINE char *str_chr(const str *s, int c);
/* sets "out" to point to first occurence of c in s. adjusts len also */
INLINE str *str_chr_str(str *out, const str *s, int c);
/* compares a str to a regular string */
INLINE int str_cmp(const str *a, const char *b);
/* compares a str to a non-null-terminated string */
INLINE int str_cmp_len(const str *a, const char *b, int len);
/* compares two str objects */
INLINE int str_cmp_str(const str *a, const str *b);
/* compares two str objects, allows either to be NULL */
INLINE int str_cmp_str0(const str *a, const str *b);
/* inits a str object from a regular string. returns out */
INLINE str *str_init(str *out, char *s);
/* inits a str object from any binary string. returns out */
INLINE str *str_init_len(str *out, char *s, int len);
INLINE str *str_init_len_assert_len(str *out, char *s, int buflen, int len);
#define str_init_len_assert(out, s, len) str_init_len_assert_len(out, s, sizeof(s), len)
/* returns new str object allocated with malloc, including buffer */
INLINE str *str_dup(const str *s);
/* returns new str object allocated from chunk, including buffer */
INLINE str *str_chunk_insert(GStringChunk *c, const str *s);
/* shifts pointer by len chars and decrements len. returns -1 if buffer too short, 0 otherwise */
INLINE int str_shift(str *s, int len);
/* binary compares str object with memory chunk of equal size */
INLINE int str_memcmp(const str *s, void *m);

/* asprintf() analogs */
#define str_sprintf(fmt, a...) __str_sprintf(STR_MALLOC_PADDING fmt, a)
#define str_vsprintf(fmt, a)   __str_vsprintf(STR_MALLOC_PADDING fmt, a)

/* creates a new empty GString that has mem allocated for a new str object */
INLINE GString *g_string_new_str(void);
/* frees the GString object and returns the new str object */
INLINE str *g_string_free_str(GString *gs);

/* for GHashTables */
guint str_hash(gconstpointer s);
gboolean str_equal(gconstpointer a, gconstpointer b);





INLINE str *str_chunk_insert(GStringChunk *c, const str *s) {
	str *i;
	i = (void *) g_string_chunk_insert_len(c, (void *) s, sizeof(*s));
	i->s = g_string_chunk_insert_len(c, s->s, s->len);
	return i;
}
INLINE char *str_end(const str *s) {
	return s->s + s->len;
}
INLINE int str_shift(str *s, int len) {
	if (s->len < len)
		return -1;
	s->s += len;
	s->len -= len;
	return 0;
}
INLINE char *str_chr(const str *s, int c) {
	return memchr(s->s, c, s->len);
}
INLINE str *str_chr_str(str *out, const str *s, int c) {
	out->s = str_chr(s, c);
	out->len = out->s ? (s->len - (out->s - s->s)) : 0;
	return out;
}
INLINE int str_cmp_len(const str *a, const char *b, int l) {
	if (a->len < l)
		return -1;
	if (a->len > l)
		return 1;
	if (a->len == 0 && l == 0)
		return 0;
	return memcmp(a->s, b, l);
}
INLINE int str_cmp(const str *a, const char *b) {
	return str_cmp_len(a, b, strlen(b));
}
INLINE int str_cmp_str(const str *a, const str *b) {
	if (a->len < b->len)
		return -1;
	if (a->len > b->len)
		return 1;
	if (a->len == 0 && b->len == 0)
		return 0;
	return memcmp(a->s, b->s, a->len);
}
INLINE int str_cmp_str0(const str *a, const str *b) {
	if (!a) {
		if (!b)
			return 0;
		if (b->len == 0)
			return 0;
		return -1;
	}
	if (!b) {
		if (a->len == 0)
			return 0;
		return 1;
	}
	return str_cmp_str(a, b);
}
INLINE str *str_init(str *out, char *s) {
	out->s = s;
	out->len = s ? strlen(s) : 0;
	return out;
}
INLINE str *str_init_len(str *out, char *s, int len) {
	out->s = s;
	out->len = len;
	return out;
}
INLINE str *str_init_len_assert_len(str *out, char *s, int buflen, int len) {
	assert(buflen >= len);
	return str_init_len(out, s, len);
}
INLINE str *str_dup(const str *s) {
	str *r;
	r = malloc(sizeof(*r) + s->len + 1);
	r->s = ((char *) r) + sizeof(*r);
	r->len = s->len;
	memcpy(r->s, s->s, s->len);
	r->s[s->len] = '\0';
	return r;
}

#define STR_MALLOC_PADDING "xxxxxxxxxxxxxxxx"
INLINE str *__str_vsprintf(const char *fmt, va_list ap) {
	char *r;
	int l, pl;
	str *ret;

	l = vasprintf(&r, fmt, ap);
	if (l < 0)
		abort();
	pl = strlen(STR_MALLOC_PADDING);
	assert(pl >= sizeof(*ret));
	ret = (void *) r;
	ret->s = r + pl;
	ret->len = l - pl;
	return ret;
}
str *__str_sprintf(const char *fmt, ...) __attribute__((format(printf,1,2)));

INLINE GString *g_string_new_str(void) {
	int pl;
	GString *ret;

	ret = g_string_new("");
	pl = strlen(STR_MALLOC_PADDING);
	assert(pl >= sizeof(str));
	g_string_append_len(ret, STR_MALLOC_PADDING, pl);
	return ret;
}
INLINE str *g_string_free_str(GString *gs) {
	str *ret;
	int pl;

	pl = strlen(STR_MALLOC_PADDING);
	assert(gs->len >= pl);
	assert(memcmp(gs->str, STR_MALLOC_PADDING, pl) == 0);
	ret = (void *) gs->str;
	ret->s = gs->str + pl;
	ret->len = gs->len - pl;
	g_string_free(gs, FALSE);
	return ret;
}
INLINE int str_memcmp(const str *s, void *m) {
	return memcmp(s->s, m, s->len);
}

#endif
