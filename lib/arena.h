#ifndef _ARENA_H_
#define _ARENA_H_


#include <unistd.h>
#include <stdbool.h>

#include "str.h"


#define ARENA_ALLOC_ALIGN 8


struct arena_piece;

struct arena {
	struct arena_piece *pieces;
	void *(*alloc)(size_t);
	void (*free)(void *);
};
typedef struct arena arena_t;


bool arena_init(arena_t *, void *(*alloc_fn)(size_t), void (*free_fn)(void *));
void *arena_alloc(arena_t *, size_t);
void arena_free(arena_t *);
void arena_merge(arena_t *to, arena_t *from);


INLINE char *arena_strdup(arena_t *buf, const char *s) {
	char *ret = arena_alloc(buf, strlen(s) + 1);
	strcpy(ret, s);
	return ret;
}

INLINE str arena_strdup_str(arena_t *buf, const char *s) {
	str o = STR_NULL;
	o.len = strlen(s);
	o.s = arena_alloc(buf, o.len);
	memcpy(o.s, s, o.len);
	return o;
}



#endif
