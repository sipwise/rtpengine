#ifndef _MEMORY_ARENA_H_
#define _MEMORY_ARENA_H_

#include "compat.h"
#include "arena.h"

typedef arena_t memory_arena_t;

extern __thread memory_arena_t *memory_arena;

void *memory_arena_malloc(size_t);
void memory_arena_free(void *);

INLINE void *__memory_arena_alloc(size_t len) {
	void *ret;
	ret = arena_alloc(memory_arena, len);
	return ret;
}

#define memory_arena_alloc(type) ((type *) __memory_arena_alloc(sizeof(type)))

INLINE void *__memory_arena_alloc0(size_t len) {
	void *ret = __memory_arena_alloc(len);
	memset(ret, 0, len);
	return ret;
}

#define memory_arena_alloc0(type) ((type *) __memory_arena_alloc0(sizeof(type)))

INLINE char *__memory_arena_memdup(const void *b, size_t len) {
	char *ret = __memory_arena_alloc(len);
	memcpy(ret, b, len);
	return ret;
}
#define memory_arena_objdup(o) ((__typeof(&(o))) __memory_arena_memdup(&(o), sizeof(o)))

INLINE char *memory_arena_dup(const char *b, size_t len) {
	char *ret = __memory_arena_alloc(len + 1);
	memcpy(ret, b, len);
	ret[len] = '\0';
	return ret;
}
INLINE char *memory_arena_strdup_len(const char *s, size_t len, void *arena) {
	if (!s)
		return NULL;
	if (arena == memory_arena)
		return (char *) s;
	return memory_arena_dup(s, len);
}

INLINE char *memory_arena_strdup(const char *s) {
	if (!s)
		return NULL;
	return memory_arena_strdup_len(s, strlen(s), NULL);
}
INLINE char *memory_arena_strdup_str(const str *s) {
	if (!s)
		return NULL;
	return memory_arena_strdup_len(s->s, s->len, s->arena);
}
INLINE str memory_arena_str_cpy_fn(const char *in, size_t len, void *arena) {
	str out;
	if (!in) {
		out = STR_NULL;
		return out;
	}
	out.s = memory_arena_strdup_len(in, len, arena);
	out.len = len;
	out.arena = memory_arena;
	return out;
}
INLINE str memory_arena_str_cpy_len(const char *in, size_t len) {
	return memory_arena_str_cpy_fn(in, len, NULL);
}
INLINE str memory_arena_str_cpy(const str *in) {
	return memory_arena_str_cpy_fn((in ? in->s : NULL), (in ? in->len : 0), (in ? in->arena : NULL));
}
INLINE str memory_arena_str_cpy_c(const char *in) {
	return memory_arena_str_cpy_len(in, in ? strlen(in) : 0);
}
INLINE str *memory_arena_str_dup(const str *in) {
	__auto_type out = memory_arena_alloc(str);
	*out = memory_arena_str_cpy_fn(in->s, in->len, in->arena);
	return out;
}


extern void *(*__memory_arena_alloc_lw)(size_t len);
extern void *(*__memory_arena_alloc0_lw)(size_t len);
extern void (*memory_arena_free_lw)(void *);

#define memory_arena_alloc0_lw(type) ((type *) __memory_arena_alloc0_lw(sizeof(type)))
#define memory_arena_alloc_lw(type) ((type *) __memory_arena_alloc_lw(sizeof(type)))

INLINE char *memory_arena_dup_lw(const char *b, size_t len) {
	char *ret = __memory_arena_alloc_lw(len + 1);
	memcpy(ret, b, len);
	ret[len] = '\0';
	return ret;
}
INLINE char *memory_arena_strdup_len_lw(const char *s, size_t len) {
	if (!s)
		return NULL;
	return memory_arena_dup_lw(s, len);
}
INLINE str memory_arena_str_cpy_fn_lw(const char *in, size_t len) {
	str out;
	if (!in) {
		out = STR_NULL;
		return out;
	}
	out.s = memory_arena_strdup_len_lw(in, len);
	out.len = len;
	out.arena = NULL;
	return out;
}
INLINE str memory_arena_str_cpy_lw(const str *in) {
	return memory_arena_str_cpy_fn_lw((in ? in->s : NULL), (in ? in->len : 0));
}
INLINE str memory_arena_str_cpy_len_lw(const char *in, size_t len) {
	return memory_arena_str_cpy_fn_lw(in, len);
}
INLINE str memory_arena_str_cpy_c_lw(const char *in) {
	return memory_arena_str_cpy_len_lw(in, in ? strlen(in) : 0);
}
INLINE str *memory_arena_str_dup_lw(const str *in) {
	__auto_type out = memory_arena_alloc_lw(str);
	*out = memory_arena_str_cpy_fn_lw(in->s, in->len);
	return out;
}

INLINE void memory_arena_str_dup_free_lw(str *s) {
	memory_arena_free_lw(s->s);
	memory_arena_free_lw(s);
}

void memory_arena_set_leightweight(void);

#endif
