#ifndef _BUFFERPOOL_H_
#define _BUFFERPOOL_H_

#include "obj.h"

struct bufferpool;
struct bpool_shard;

void bufferpool_init(void);
void bufferpool_cleanup(void);

struct bufferpool *bufferpool_new(void *(*alloc)(size_t), void (*dealloc)(void *), size_t shard_size);
struct bufferpool *bufferpool_new2(void *(*alloc)(size_t), void (*dealloc)(void *, size_t), size_t shard_size);
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

typedef char bp_char;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(bp_char, bufferpool_unref);
typedef char bp_void;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(bp_void, bufferpool_unref);


#endif
