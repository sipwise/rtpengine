#ifndef _SSRCLIB_H_
#define _SSRCLIB_H_

#include "obj.h"
#include <stdint.h>
#include <glib.h>

struct ssrc_entry {
	struct obj obj;
	GList link;
	mutex_t lock;
	uint32_t ssrc;
};

typedef struct ssrc_entry *(*ssrc_create_func_t)(void *uptr);

struct ssrc_hash {
	GQueue nq;
	mutex_t lock;
	ssrc_create_func_t create_func;
	void *uptr;
	struct ssrc_entry *precreat; // next used entry
	unsigned int iters; // tracks changes
};

void ssrc_hash_foreach(struct ssrc_hash *, void (*)(void *, void *), void *);
void ssrc_hash_full_init(struct ssrc_hash *, ssrc_create_func_t, void *uptr); // pre-creates one object
void ssrc_hash_full_fast_init(struct ssrc_hash *, ssrc_create_func_t, void *uptr); // doesn't pre-create object
void ssrc_hash_destroy(struct ssrc_hash *);

void *get_ssrc_full(uint32_t, struct ssrc_hash *, bool *created); // creates new entry if not found
INLINE void *get_ssrc(uint32_t ssrc, struct ssrc_hash *ht) {
	return get_ssrc_full(ssrc, ht, NULL);
}

#endif
