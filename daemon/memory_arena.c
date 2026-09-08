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
