#ifndef _ARENA_H_
#define _ARENA_H_

#include "compat.h"
#include "bencode.h"

typedef bencode_buffer_t memory_arena_t;

extern __thread memory_arena_t *memory_arena;

#define memory_arena_init bencode_buffer_init
#define memory_arena_free bencode_buffer_free

INLINE void *__memory_arena_alloc(size_t len) {
	void *ret;
	ret = bencode_buffer_alloc(memory_arena, len);
	return ret;
}
#define memory_arena_alloc(type) ((type *) __memory_arena_alloc(sizeof(type)))
INLINE void *__memory_arena_alloc0(size_t len) {
	void *ret = __memory_arena_alloc(len);
	memset(ret, 0, len);
	return ret;
}
#define memory_arena_alloc0(type) ((type *) __memory_arena_alloc0(sizeof(type)))
INLINE char *memory_arena_dup(const char *b, size_t len) {
	char *ret = __memory_arena_alloc(len + 1);
	memcpy(ret, b, len);
	ret[len] = '\0';
	return ret;
}
INLINE char *memory_arena_ref(const char *b, size_t len) {
	return (char *) b;
}
INLINE char *memory_arena_strdup_len(const char *s, size_t len, char *(*dup)(const char *, size_t)) {
	char *r;
	if (!s)
		return NULL;
	dup = dup ?: memory_arena_dup;
	r = dup(s, len);
	return r;
}

INLINE char *memory_arena_strdup(const char *s) {
	if (!s)
		return NULL;
	return memory_arena_strdup_len(s, strlen(s), NULL);
}
INLINE char *memory_arena_strdup_str(const str *s) {
	if (!s)
		return NULL;
	return memory_arena_strdup_len(s->s, s->len, s->dup);
}
INLINE str memory_arena_str_cpy_fn(const char *in, size_t len, char *(*dup)(const char *, size_t)) {
	str out;
	if (!in) {
		out = STR_NULL;
		return out;
	}
	out.s = memory_arena_strdup_len(in, len, dup);
	out.len = len;
	out.dup = memory_arena_ref;
	return out;
}
INLINE str memory_arena_str_cpy_len(const char *in, size_t len) {
	return memory_arena_str_cpy_fn(in, len, NULL);
}
INLINE str memory_arena_str_cpy(const str *in) {
	return memory_arena_str_cpy_fn((in ? in->s : NULL), (in ? in->len : 0), (in ? in->dup : NULL));
}
INLINE str memory_arena_str_cpy_c(const char *in) {
	return memory_arena_str_cpy_len(in, in ? strlen(in) : 0);
}
INLINE str *memory_arena_str_dup(const str *in) {
	__auto_type out = memory_arena_alloc(str);
	*out = memory_arena_str_cpy_len(in->s, in->len);
	return out;
}

#endif
