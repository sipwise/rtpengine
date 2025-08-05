#ifndef _BUFFERPOOL_H_
#define _BUFFERPOOL_H_

#include "obj.h"

#define BUFFERPOOL_ALIGNMENT (MAX(sizeof(void *), 8)) // bytes
#define BUFFERPOOL_ALIGN(x) (((x + BUFFERPOOL_ALIGNMENT - 1) / BUFFERPOOL_ALIGNMENT) * BUFFERPOOL_ALIGNMENT)

#define BUFFERPOOL_SHARD_SIZE ((size_t) (1LL<<24)) // 16 MB, must be a power of two
#define BUFFERPOOL_OVERHEAD BUFFERPOOL_ALIGN(sizeof(void *)) // storage space not available

#define BUFFERPOOL_BOTTOM_MASK (BUFFERPOOL_SHARD_SIZE - 1)
#define BUFFERPOOL_TOP_MASK (~BUFFERPOOL_BOTTOM_MASK)

struct bufferpool;
struct bpool_shard;

void bufferpool_init(void);
void bufferpool_cleanup(void);

struct bufferpool *bufferpool_new(void *(*alloc)(void), void (*dealloc)(void *));
void bufferpool_destroy(struct bufferpool *);

void *bufferpool_alloc(struct bufferpool *bp, size_t len);
void *bufferpool_reserve(struct bufferpool *bp, unsigned int refs, unsigned int (*recycle)(void *), void *arg);
void *bufferpool_ref(void *);
void bufferpool_unref(void *);
void bufferpool_release(void *); // remove all refs

INLINE void *bufferpool_alloc0(struct bufferpool *bp, size_t len) {
	void *ret = bufferpool_alloc(bp, len);
	if (!ret)
		return NULL;
	memset(ret, 0, len);
	return ret;
}

void *bufferpool_aligned_alloc(void);
void bufferpool_aligned_free(void *);

typedef char bp_char;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(bp_char, bufferpool_unref);
typedef char bp_void;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(bp_void, bufferpool_unref);


#endif
