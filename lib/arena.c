#include "arena.h"
#include "helpers.h"


#define ARENA_INITIAL_PIECE_ORDER 12 // 4096

// enable to perform each allocation separately, to make debugging (valgrind...) easier
//#define ARENA_ALLOC_DEBUG

struct arena_piece {
	char *tail;
	size_t left;
	struct arena_piece *next;
	char buf[0] __attribute__ ((aligned (ARENA_ALLOC_ALIGN)));
};


static struct arena_piece *arena_piece_new(arena_t *arena, size_t size, void *(*alloc_fn)(size_t)) {
	struct arena_piece *ret;

	static const unsigned long overhead = sizeof(*ret) + ARENA_ALLOC_ALIGN;
	unsigned long needed_size = size + overhead;

#ifndef ARENA_ALLOC_DEBUG
	unsigned long alloc_size = 1L << arena->piece_order;

	if (needed_size > alloc_size) {
		arena->piece_order = LONG_BIT - __builtin_clzl(needed_size);
		alloc_size = 1L << arena->piece_order;
	}

	arena->piece_order++; // next needed piece will be larger
#else
	unsigned long alloc_size = needed_size;
#endif

	ret = alloc_fn(alloc_size);
	if (!ret)
		return NULL;

	ret->tail = ret->buf;
	ret->left = alloc_size - overhead;
	ret->next = NULL;

	return ret;
}

bool arena_init(arena_t *arena, void *(*alloc_fn)(size_t), void (*free_fn)(void *)) {
	arena->alloc = alloc_fn;
	arena->free = free_fn;
	arena->piece_order = ARENA_INITIAL_PIECE_ORDER;
	arena->pieces = arena_piece_new(arena, 0, alloc_fn);
	if (!arena->pieces)
		return false;
	return true;
}

void *arena_alloc(arena_t *arena, size_t size) {
	struct arena_piece *piece;
	void *ret;
	size_t align_size = ((size + ARENA_ALLOC_ALIGN - 1) / ARENA_ALLOC_ALIGN) * ARENA_ALLOC_ALIGN;

	if (!arena)
		return NULL;

	piece = arena->pieces;

	if (size <= piece->left)
		goto alloc;

	piece = arena_piece_new(arena, size, arena->alloc);
	if (!piece)
		return NULL;
	piece->next = arena->pieces;
	arena->pieces = piece;

	assert(size <= piece->left);

alloc:
	if (piece->left >= align_size)
		piece->left -= align_size;
	else
		piece->left = 0;
	ret = piece->tail;
	piece->tail += align_size;
	return ret;
}

void arena_free(arena_t *arena) {
	struct arena_piece *piece, *next;

	if (!arena)
		return;

	for (piece = arena->pieces; piece; piece = next) {
		next = piece->next;
		arena->free(piece);
	}
}

void arena_merge(arena_t *to, arena_t *from) {
	struct arena_piece *last = to->pieces;
	while (last->next)
		last = last->next;
	last->next = from->pieces;
	from->pieces = NULL;
}
