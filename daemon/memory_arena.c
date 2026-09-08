#include "memory_arena.h"
#include <sys/mman.h>

__thread memory_arena_t *memory_arena;

void *memory_arena_malloc(size_t size) {
	return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

void memory_arena_free(void *p) {
	size_t *s = p; // first element is the size
	munmap(p, *s);
}


static void dummy_free(void *p) { }

void *(*__memory_arena_alloc_lw)(size_t len) = __memory_arena_alloc;
void *(*__memory_arena_alloc0_lw)(size_t len) = __memory_arena_alloc0;
void (*memory_arena_free_lw)(void *) = dummy_free;

void memory_arena_set_leightweight(void) {
	__memory_arena_alloc_lw = g_malloc;
	__memory_arena_alloc0_lw = g_malloc0;
	memory_arena_free_lw = g_free;
}
