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
#define STR_FORMAT_M "%s%.*s%s"
#define STR_FMT(str) (str)->len, (str)->s
#define STR_FMT_M(str) FMT_M(STR_FMT(str))
#define STR_FMT0(str) ((str) ? (str)->len : 6), ((str) ? (str)->s : "(NULL)")
#define STR_FMT0_M(str) FMT_M(STR_FMT0(str))
#define G_STR_FMT(gstr) (int) (gstr)->len, (gstr)->str // for glib GString

#define FMT_M(x...) rtpe_common_config_ptr->log_mark_prefix, x, \
	rtpe_common_config_ptr->log_mark_suffix

#define STR_NULL ((str) { NULL, 0 })
#define STR_EMPTY ((str) { "", 0 })
#define STR_CONST_INIT(str) { str, sizeof(str)-1 }
#define STR_CONST_INIT_LEN(str, len) { str, len }
#define STR_CONST_INIT_BUF(buf) { (char *) &buf, sizeof(buf) }



/* returns pointer to end of str (s->s + s->len) */
INLINE char *str_end(const str *s);
/* returns pointer to first occurrence of "c" in s */
INLINE char *str_chr(const str *s, int c);
/* sets "out" to point to first occurrence of c in s. adjusts len also */
INLINE char *str_chr_str(str *out, const str *s, int c);
/* compares a str to a regular string */
INLINE int str_cmp(const str *a, const char *b);
/* compares a str to a non-null-terminated string */
INLINE int str_cmp_len(const str *a, const char *b, int len);
/* compares two str objects */
INLINE int str_cmp_str(const str *a, const str *b);
INLINE int str_casecmp_str(const str *a, const str *b);
/* compares two str objects, allows either to be NULL */
INLINE int str_cmp_str0(const str *a, const str *b);
/* inits a str object from a regular string. returns out */
INLINE str *str_init(str *out, char *s);
/* inits a str object from any binary string. returns out */
INLINE str *str_init_len(str *out, char *s, int len);
INLINE str *str_init_len_assert_len(str *out, char *s, int buflen, int len);
#define str_init_len_assert(out, s, len) str_init_len_assert_len(out, s, sizeof(s), len)
/* returns new str object with uninitialized buffer large enough to hold `len` characters (+1 for null byte) */
INLINE str *str_alloc(int len);
/* returns new str object allocated with malloc, including buffer */
INLINE str *str_dup(const str *s);
/* returns new str object allocated from chunk, including buffer */
INLINE str *str_chunk_insert(GStringChunk *c, const str *s);
/* shifts pointer by len chars and decrements len. returns -1 if buffer too short, 0 otherwise */
INLINE int str_shift(str *s, int len);
/* eats the supplied string from the beginning of s. returns -1 if string head doesn't match */
INLINE int str_shift_cmp(str *s, const char *);
/* shifts the string by given length and returns the shifted part. returns -1 if string is too short */
INLINE int str_shift_ret(str *s, int len, str *ret);
/* binary compares str object with memory chunk of equal size */
INLINE int str_memcmp(const str *s, void *m);
/* locate a substring within a string, returns character index or -1 */
INLINE int str_str(const str *s, const char *sub);
/* swaps the contents of two str objects */
INLINE void str_swap(str *a, str *b);
/* parses a string into an int, returns default if conversion fails */
INLINE int str_to_i(str *s, int def);
/* parses a string uinto an int, returns default if conversion fails */
INLINE uint str_to_ui(str *s, int def);
/* extracts the first/next token into "new_token" and modifies "ori_and_remaidner" in place */
INLINE int str_token(str *new_token, str *ori_and_remainder, int sep);
/* same as str_token but allows for a trailing non-empty token (e.g. "foo,bar" -> "foo", "bar" ) */
INLINE int str_token_sep(str *new_token, str *ori_and_remainder, int sep);
/* copy a string to a regular C string buffer, limiting the max size */
INLINE char *str_ncpy(char *dst, size_t bufsize, const str *src);

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
guint str_case_hash(gconstpointer s);
gboolean str_case_equal(gconstpointer a, gconstpointer b);

/* returns a new str object, duplicates the pointers but doesn't duplicate the contents */
INLINE str *str_slice_dup(const str *);
/* destroy function, frees a slice-alloc'd str */
void str_slice_free(void *);

/* saves "in" into "out" pseudo-URI encoded. "out" point to a buffer with sufficient length. returns length */
int str_uri_encode_len(char *out, const char *in, int in_len);
INLINE int str_uri_encode(char *out, const str *in);
/* reverse of the above. returns newly allocated str + buffer as per str_alloc (must be free'd) */
str *str_uri_decode_len(const char *in, int in_len);





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
	return str_shift_ret(s, len, NULL);
}
INLINE int str_shift_ret(str *s, int len, str *ret) {
	if (s->len < len)
		return -1;
	if (ret)
		str_init_len(ret, s->s, len);
	s->s += len;
	s->len -= len;
	return 0;
}
INLINE int str_shift_cmp(str *s, const char *t) {
	int len = strlen(t);
	if (s->len < len)
		return -1;
	if (memcmp(s->s, t, len))
		return -1;
	s->s += len;
	s->len -= len;
	return 0;
}
INLINE char *str_chr(const str *s, int c) {
	return memchr(s->s, c, s->len);
}
INLINE char *str_chr_str(str *out, const str *s, int c) {
	char *p;
	p = str_chr(s, c);
	if (!p) {
		*out = STR_NULL;
		return NULL;
	}
	*out = *s;
	str_shift(out, p - out->s);
	return out->s;
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
INLINE int str_casecmp_str(const str *a, const str *b) {
	if (a->len < b->len)
		return -1;
	if (a->len > b->len)
		return 1;
	if (a->len == 0 && b->len == 0)
		return 0;
	// fail if any strings contains a null byte
	if (memchr(a->s, '\0', a->len))
		return -1;
	if (memchr(b->s, '\0', a->len))
		return 1;
	return strncasecmp(a->s, b->s, a->len);
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
INLINE str *str_alloc(int len) {
	str *r;
	r = malloc(sizeof(*r) + len + 1);
	r->s = ((char *) r) + sizeof(*r);
	r->len = 0;
	return r;
}
INLINE str *str_dup(const str *s) {
	str *r;
	r = str_alloc(s->len);
	r->len = s->len;
	memcpy(r->s, s->s, s->len);
	r->s[s->len] = '\0';
	return r;
}
INLINE str *str_slice_dup(const str *s) {
	str *r;
	r = g_slice_alloc(sizeof(*r));
	*r = *s;
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
INLINE int str_str(const str *s, const char *sub) {
	void *p = memmem(s->s, s->len, sub, strlen(sub));
	if (!p)
		return -1;
	return p - (void *) s->s;
}
INLINE void str_swap(str *a, str *b) {
	str t;
	t = *a;
	*a = *b;
	*b = t;
}

INLINE int str_to_i(str *s, int def) {
	char c, *ep;
	long ret;
	if (s->len <= 0)
		return def;
	c = s->s[s->len];
	s->s[s->len] = '\0';
	ret = strtol(s->s, &ep, 10);
	s->s[s->len] = c;
	if (ep == s->s)
		return def;
	if (ret > INT_MAX)
		return def;
	if (ret < INT_MIN)
		return def;
	return ret;
}

INLINE unsigned int str_to_ui(str *s, int def) {
	char c, *ep;
	long ret;
	if (s->len <= 0)
		return def;
	c = s->s[s->len];
	s->s[s->len] = '\0';
	ret = strtol(s->s, &ep, 10);
	s->s[s->len] = c;
	if (ep == s->s)
		return def;
	return ret;
}

INLINE int str_token(str *new_token, str *ori_and_remainder, int sep) {
	*new_token = *ori_and_remainder;
	if (!str_chr_str(ori_and_remainder, ori_and_remainder, sep))
		return -1;
	new_token->len = ori_and_remainder->s - new_token->s;
	if (str_shift(ori_and_remainder, 1))
		return -1;
	return 0;
}

INLINE int str_token_sep(str *new_token, str *ori_and_remainder, int sep) {
	str ori = *ori_and_remainder;
	if (!str_token(new_token, ori_and_remainder, sep))
		return 0;
	// separator not found, use remainder as final token if not empty
	if (!ori.len)
		return -1;
	*new_token = ori;
	return 0;
}

INLINE int str_uri_encode(char *out, const str *in) {
	return str_uri_encode_len(out, in->s, in->len);
}

INLINE char *str_ncpy(char *dst, size_t bufsize, const str *src) {
	size_t to_copy = src->len;
	if (to_copy >= bufsize)
		to_copy = bufsize - 1;
	memcpy(dst, src->s, to_copy);
	dst[to_copy] = 0;
	return dst;
}


/* Generates a hex string representing n random bytes. len(rand_str) = 2*num_bytes + 1 */
char *rand_hex_str(char *rand_str, int num_bytes);


#endif
