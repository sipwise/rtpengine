#ifndef _STR_H_
#define _STR_H_

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <stdio.h>



struct _str {
	char *s;
	int len;
};

typedef struct _str str;

#define STR_FORMAT "%.*s"
#define STR_FMT(str) (str)->len, (str)->s



static inline int str_cmp_str(const str *a, const str *b) {
	if (a->len < b->len)
		return -1;
	if (a->len > b->len)
		return 1;
	return memcmp(a->s, b->s, a->len);
}
/* for GHashTables */
guint str_hash(gconstpointer s);
static inline gboolean str_equal(gconstpointer a, gconstpointer b) {
	return str_cmp_str((str *) a, (str *) b) == 0;
}



static inline str *str_chunk_insert(GStringChunk *c, const str *s) {
	str *i;
	i = (void *) g_string_chunk_insert_len(c, (void *) s, sizeof(*s));
	i->s = g_string_chunk_insert_len(c, s->s, s->len);
	return i;
}
static inline char *str_end(const str *s) {
	return s->s + s->len;
}
static inline char *str_chr(const str *s, int c) {
	return memchr(s->s, c, s->len);
}
static inline char *str_chr_str(str *out, const str *s, int c) {
	out->s = str_chr(s, c);
	out->len = out->s ? out->s - s->s : 0;
	return out->s;
}
static inline int str_cmp(const str *a, const char *b) {
	int l = strlen(b);
	if (a->len < l)
		return -1;
	if (a->len > l)
		return 1;
	return memcmp(a->s, b, l);
}
static inline void str_init(str *out, char *s) {
	out->s = s;
	out->len = strlen(s);
}
static inline str *str_dup(const str *s) {
	str *r;
	r = malloc(sizeof(*r) + s->len + 1);
	r->s = ((char *) r) + sizeof(*r);
	r->len = s->len;
	memcpy(r->s, s->s, s->len);
	r->s[s->len] = '\0';
	return r;
}

#define STR_MALLOC_PADDING "xxxxxxxxxxxxxxxx"
static inline str *__str_vsprintf(const char *fmt, va_list ap) {
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
static inline str *__str_sprintf(const char *fmt, ...) __attribute__((format(printf,1,2)));
static inline str *__str_sprintf(const char *fmt, ...) {
	str *ret;
	va_list ap;
	va_start(ap, fmt);
	ret = __str_vsprintf(fmt, ap);
	va_end(ap);
	return ret;
}
#define str_sprintf(fmt, a...) __str_sprintf(STR_MALLOC_PADDING fmt, a)
#define str_vsprintf(fmt, a)   __str_vsprintf(STR_MALLOC_PADDING fmt, a)

static inline GString *g_string_new_str(void) {
	int pl;
	GString *ret;

	ret = g_string_new("");
	pl = strlen(STR_MALLOC_PADDING);
	assert(pl >= sizeof(str));
	g_string_append_len(ret, STR_MALLOC_PADDING, pl);
	return ret;
}
static inline str *g_string_free_str(GString *gs) {
	str *ret;
	int pl;

	pl = strlen(STR_MALLOC_PADDING);
	assert(gs->len >= pl);
	ret = (void *) gs->str;
	ret->s = gs->str + pl;
	ret->len = gs->len - pl;
	g_string_free(gs, FALSE);
	return ret;
}

#endif
