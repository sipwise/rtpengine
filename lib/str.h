#ifndef _STR_H_
#define _STR_H_

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <stdio.h>
#include "compat.h"
#include "containers.h"



struct _str {
	char *s;
	size_t len;
	char *(*dup)(const char *, size_t);
};

typedef struct _str str;

TYPED_GQUEUE(charp, char)
TYPED_GQUEUE(str, str)



#define STR_FORMAT "%.*s"
#define STR_FORMAT_M "%s%.*s%s"
#define STR_FMT(str) (int) (str)->len, (str)->s
#define STR_FMT_M(str) FMT_M(STR_FMT(str))
#define STR_FMT0(str) ((str) ? (int) (str)->len : 6), ((str) ? (str)->s : "(NULL)")
#define STR_FMT0_M(str) FMT_M(STR_FMT0(str))
#define G_STR_FMT(gstr) (int) (gstr)->len, (gstr)->str // for glib GString

#define FMT_M(x...) rtpe_common_config_ptr->log_mark_prefix, x, \
	rtpe_common_config_ptr->log_mark_suffix

#define STR_NULL ((str) { NULL, 0, NULL })
#define STR_EMPTY ((str) { "", 0, NULL })
#define STR_CONST(s) ((str) { s, sizeof(s)-1, NULL })
#define STR(s) ({ const char *__s = (s); (str) { (char *) (__s), (__s) ? strlen(__s) : 0, NULL }; })
#define STR_PTR(s) (&((str) { (char *) (s), (s) ? strlen(s) : 0, NULL }))
#define STR_NC(s) ((str) { (char *) (s), strlen(s), NULL })
#define STR_GS(s) ((str) { (s)->str, (s)->len, NULL })
#define STR_LEN(s, len) ((str) { (char *) (s), len, NULL })
#define STR_LEN_ASSERT(s, len) ({ assert(sizeof(s) >= len); (str) { (char *) (s), len, NULL }; })
#define STR_DUP(s) ({ const char *__s = (s); size_t __l = strlen(__s); (str) { __g_memdup(__s, __l + 1), __l, NULL }; })
#define STR_CONST_BUF(buf) ((str) { (char *) &buf, sizeof(buf), NULL })



/* returns pointer to end of str (s->s + s->len) */
__attribute__((nonnull(1)))
ACCESS(read_only, 1)
INLINE char *str_end(const str *s);
/* returns pointer to first occurrence of "c" in s */
__attribute__((nonnull(1)))
ACCESS(read_only, 1)
INLINE char *str_chr(const str *s, int c);
/* sets "out" to point to first occurrence of c in s. adjusts len also */
__attribute__((nonnull(1, 2)))
ACCESS(write_only, 1)
ACCESS(read_only, 2)
INLINE char *str_chr_str(str *out, const str *s, int c);
/* compares a str to a regular string */
__attribute__((nonnull(1, 2)))
ACCESS(read_only, 1)
ACCESS(read_only, 2)
INLINE int str_cmp(const str *a, const char *b);
__attribute__((nonnull(1, 2)))
ACCESS(read_only, 1)
ACCESS(read_only, 2)
INLINE bool str_eq(const str *a, const char *b);
/* compares a str to a non-null-terminated string */
__attribute__((nonnull(1, 2)))
ACCESS(read_only, 1)
ACCESS(read_only, 2)
INLINE int str_cmp_len(const str *a, const char *b, size_t len);
/* compares two str objects */
__attribute__((nonnull(1, 2)))
ACCESS(read_only, 1)
ACCESS(read_only, 2)
INLINE int str_cmp_str(const str *a, const str *b);
__attribute__((nonnull(1, 2)))
ACCESS(read_only, 1)
ACCESS(read_only, 2)
INLINE int str_casecmp_str(const str *a, const str *b);
/* compares two str objects, allows either to be NULL */
ACCESS(read_only, 1)
ACCESS(read_only, 2)
INLINE int str_cmp_str0(const str *a, const str *b);
/* inits a str object from a regular string and duplicates the contents */
ACCESS(read_only, 1)
INLINE str str_dup_str(const str *s);
INLINE void str_free_dup(str *out);
/* returns new str object with uninitialized buffer large enough to hold `len` characters (+1 for null byte) */
INLINE str *str_alloc(size_t len);
/* returns new str object allocated with malloc, including buffer */
__attribute__((nonnull(1)))
ACCESS(read_only, 1)
INLINE str *str_dup(const str *s);
/* free function corresponding to str_dup() */
__attribute__((nonnull(1)))
ACCESS(read_write, 1)
INLINE void str_free(str *s);
/* shifts pointer by len chars and decrements len. returns -1 if buffer too short, 0 otherwise */
ACCESS(read_write, 1)
INLINE int str_shift(str *s, size_t len);
/* to revert a previously successful str_shift(). no error checking */
__attribute__((nonnull(1)))
ACCESS(read_write, 1)
INLINE void str_unshift(str *s, size_t len);
/* eats the supplied string from the beginning of s. returns -1 if string head doesn't match */
__attribute__((nonnull(1, 2)))
ACCESS(read_write, 1)
ACCESS(read_only, 2)
INLINE int str_shift_cmp(str *s, const char *);
/* shifts the string by given length and returns the shifted part. returns -1 if string is too short */
__attribute__((nonnull(1)))
ACCESS(read_write, 1)
ACCESS(write_only, 3)
INLINE int str_shift_ret(str *s, size_t len, str *ret);
/* binary compares str object with memory chunk of equal size */
__attribute__((nonnull(1, 2)))
ACCESS(read_only, 1)
ACCESS(read_only, 2)
INLINE int str_memcmp(const str *s, const void *m);
/* locate a substring within a string, returns character index or -1 */
__attribute__((nonnull(1, 2)))
ACCESS(read_only, 1)
ACCESS(read_only, 2)
INLINE ssize_t str_str(const str *s, const char *sub);
/* swaps the contents of two str objects */
__attribute__((nonnull(1, 2)))
ACCESS(read_write, 1)
ACCESS(read_write, 2)
INLINE void str_swap(str *a, str *b);
/* parses a string into an int, returns default if conversion fails */
__attribute__((nonnull(1)))
ACCESS(read_only, 1)
INLINE long long str_to_i(const str *s, long long def);
/* parses a string into an uint, returns default if conversion fails */
__attribute__((nonnull(1)))
ACCESS(read_only, 1)
INLINE unsigned long long str_to_ui(const str *s, unsigned long long def);
/* extracts the first/next token into "new_token" and modifies "ori_and_remaidner" in place */
__attribute__((nonnull(1, 2)))
ACCESS(write_only, 1)
ACCESS(read_write, 2)
INLINE bool str_token(str *new_token, str *ori_and_remainder, int sep);
/* same as str_token but allows for a trailing non-empty token (e.g. "foo,bar" -> "foo", "bar" ) */
__attribute__((nonnull(1, 2)))
ACCESS(write_only, 1)
ACCESS(read_write, 2)
INLINE bool str_token_sep(str *new_token, str *ori_and_remainder, int sep);
/* copy a string to a regular C string buffer, limiting the max size */
__attribute__((nonnull(1, 3)))
ACCESS(write_only, 1, 2)
ACCESS(read_only, 3)
INLINE char *str_ncpy(char *dst, size_t bufsize, const str *src);

/* asprintf() analogs */
str str_sprintf(const char *fmt, ...) __attribute__((format(printf,1,2)));
INLINE str str_vsprintf(const char *fmt, va_list ap);

/* frees the GString object and returns the new str object */
INLINE str g_string_free_str(GString *gs);

/* for GHashTables */
guint str_hash(const str *s);
gboolean str_equal(const str *a, const str *b);
guint str_case_hash(const str *s);
gboolean str_case_equal(const str *a, const str *b);

TYPED_GHASHTABLE(str_case_ht, str, str, str_case_hash, str_case_equal, free, NULL)
TYPED_GHASHTABLE(str_case_value_ht, str, str, str_case_hash, str_case_equal, free, free)


/* returns a new str object, duplicates the pointers but doesn't duplicate the contents */
INLINE str *str_slice_dup(const str *);
/* destroy function, frees a slice-alloc'd str */
INLINE void str_slice_free(str *);

/* saves "in" into "out" pseudo-URI encoded. "out" point to a buffer with sufficient length. returns length */
str str_uri_encode_len(char *out, const char *in, size_t in_len);
/* reverse of the above. returns newly allocated str + buffer as per str_alloc (must be free'd) */
str *str_uri_decode_len(const char *in, size_t in_len);


G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(str, str_free_dup);

typedef str_q str_slice_q;
INLINE void str_slice_q_clear_full(str_slice_q *q) {
	t_queue_clear_full(q, str_slice_free);
}
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(str_slice_q, str_slice_q_clear_full)




INLINE char *str_end(const str *s) {
	return s->s + s->len;
}
INLINE int str_shift(str *s, size_t len) {
	return str_shift_ret(s, len, NULL);
}
INLINE int str_shift_ret(str *s, size_t len, str *ret) {
	if (s->len < len)
		return -1;
	if (ret)
		*ret = STR_LEN(s->s, len);
	s->s += len;
	s->len -= len;
	return 0;
}
INLINE void str_unshift(str *s, size_t len) {
	s->s -= len;
	s->len += len;
}
INLINE int str_shift_cmp(str *s, const char *t) {
	size_t len = strlen(t);
	if (s->len < len)
		return -1;
	if (memcmp(s->s, t, len))
		return -1;
	s->s += len;
	s->len -= len;
	return 0;
}
INLINE char *str_chr(const str *s, int c) {
	if (!s->len)
		return NULL;
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
INLINE int str_cmp_len(const str *a, const char *b, size_t l) {
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
INLINE bool str_eq(const str *a, const char *b) {
	return str_cmp(a, b) == 0;
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
INLINE str str_dup_len(const char *s, size_t len) {
	char *buf = g_malloc(len + 1);
	if (s && len)
		memcpy(buf, s, len);
	buf[len] = '\0';
	return STR_LEN(buf, len);
}
INLINE str str_dup_str(const str *s) {
	if (!s)
		return STR_NULL;
	return str_dup_len(s->s, s->len);
}
INLINE void str_free_dup(str *out) {
	if (!out)
		return;

	if (out->s)
		g_free(out->s);

	out->s = NULL;
	out->len = 0;
}
INLINE str *str_alloc(size_t len) {
	str *r;
	r = malloc(sizeof(*r) + len + 1);
	r->s = ((char *) r) + sizeof(*r);
	r->len = 0;
	r->dup = NULL;
	return r;
}
INLINE str *str_dup(const str *s) {
	str *r;
	r = str_alloc(s->len);
	r->len = s->len;
	if (s->len)
		memcpy(r->s, s->s, s->len);
	r->s[s->len] = '\0';
	return r;
}
INLINE void str_free(str *s) {
	free(s);
}
INLINE str *str_slice_dup(const str *s) {
	str *r;
	r = g_new(str, 1);
	*r = *s;
	return r;
}
INLINE void str_slice_free(str *p) {
	g_free(p);
}

INLINE str str_vsprintf(const char *fmt, va_list ap) {
	char *r;
	int l;
	l = vasprintf(&r, fmt, ap);
	if (l < 0)
		abort();
	return STR_LEN(r, l);
}

INLINE str g_string_free_str(GString *gs) {
	size_t len = gs->len;
	return STR_LEN(g_string_free(gs, FALSE), len);
}
INLINE int str_memcmp(const str *s, const void *m) {
	return memcmp(s->s, m, s->len);
}
INLINE ssize_t str_str(const str *s, const char *sub) {
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

INLINE long long str_to_i(const str *s, long long def) {
	char c, *ep;
	long long ret;
	if (s->len <= 0)
		return def;
	c = s->s[s->len];
	s->s[s->len] = '\0';
	ret = strtoll(s->s, &ep, 10);
	s->s[s->len] = c;
	if (ep == s->s)
		return def;
	if (ret > INT_MAX)
		return def;
	if (ret < INT_MIN)
		return def;
	return ret;
}

INLINE unsigned long long str_to_ui(const str *s, unsigned long long def) {
	char c, *ep;
	unsigned long long ret;
	if (s->len <= 0)
		return def;
	c = s->s[s->len];
	s->s[s->len] = '\0';
	ret = strtoull(s->s, &ep, 10);
	s->s[s->len] = c;
	if (ep == s->s)
		return def;
	return ret;
}

INLINE bool str_token(str *new_token, str *ori_and_remainder, int sep) {
	*new_token = *ori_and_remainder;
	if (!str_chr_str(ori_and_remainder, ori_and_remainder, sep)) {
		*ori_and_remainder = *new_token;
		str_shift(ori_and_remainder, ori_and_remainder->len);
		return false;
	}
	new_token->len = ori_and_remainder->s - new_token->s;
	if (str_shift(ori_and_remainder, 1))
		return false;
	return true;
}

INLINE bool str_token_sep(str *new_token, str *ori_and_remainder, int sep) {
	if (ori_and_remainder->len == 0) {
		*new_token = STR_NULL;
		return false;
	}
	str ori = *ori_and_remainder;
	if (str_token(new_token, ori_and_remainder, sep))
		return true;
	// separator not found, use remainder as final token if not empty
	if (!ori.len)
		return false;
	*new_token = ori;
	return true;
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
