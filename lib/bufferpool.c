#include "bufferpool.h"
#include <glib.h>
#include <stdbool.h>
#include "obj.h"

static_assert((BUFFERPOOL_SHARD_SIZE & (BUFFERPOOL_SHARD_SIZE - 1)) == 0,
		"BUFFERPOOL_SHARD_SIZE is not a power of two");

struct bpool_shard;

struct bufferpool {
	void *(*alloc)(void);
	void (*dealloc)(void *);
	unsigned int refs; // sum of all refs from shards, plus the handle itself

	rwlock_t shards_lock;
	struct bpool_shard **shards;
	unsigned int num_shards;
	unsigned int max_shards;
	unsigned int empty_shard_idx;
};

struct bpool_shard {
	struct bufferpool *bp;
	unsigned int refs;
	void *buf; // actual head of buffer, given to free()
	void *empty; // head of usable buffer, head == empty if empty
	void *end;
	void *head;
	unsigned int (*recycle)(void *);
	void *arg;
	bool full;
};

struct bufferpool *bufferpool_new(void *(*alloc)(void), void (*dealloc)(void *)) {
	struct bufferpool *ret = g_new0(__typeof(*ret), 1);
	ret->alloc = alloc;
	ret->dealloc = dealloc;
	ret->refs = 1; // count the bufferpool handle itself as a reference
	rwlock_init(&ret->shards_lock);
	ret->max_shards = 8;
	ret->shards = g_new0(struct bpool_shard *, ret->max_shards);
	return ret;
}

// shard has zero refs and is marked as full
static void bufferpool_recycle(struct bpool_shard *shard) {
	struct bufferpool *bp = shard->bp;
	atomic_set_na(&shard->head, shard->empty);

	unsigned int refs = 0;
	if (shard->recycle)
		refs = shard->recycle(shard->arg);

	if (refs) {
		atomic_add(&shard->refs, refs);
		atomic_add(&bp->refs, refs);
	}
	else
		atomic_set(&shard->full, false);
}

static void bufferpool_dealloc(struct bpool_shard *shard) {
	struct bufferpool *bp = shard->bp;
	bp->dealloc(shard->buf);
}

static struct bpool_shard *bufferpool_new_shard(struct bufferpool *bp) {
	void *buf = bp->alloc();
	if (!buf)
		return NULL;

	// all bottom bits must be zero
	assert(((size_t) buf & BUFFERPOOL_BOTTOM_MASK) == 0);

	struct bpool_shard *ret = g_new0(__typeof(*ret), 1);
	ret->bp = bp;
	ret->buf = buf;
	ret->end = buf + BUFFERPOOL_SHARD_SIZE;

	struct bpool_shard **head = buf;
	*head = ret;

	static_assert(BUFFERPOOL_ALIGN(sizeof(void *)) == BUFFERPOOL_OVERHEAD,
			"wrong BUFFERPOOL_OVERHEAD size");
	buf += BUFFERPOOL_ALIGN(sizeof(void *));

	ret->empty = buf;
	ret->head = buf;

	return ret;
}

static void bpool_shard_destroy(struct bpool_shard *shard) {
	bufferpool_dealloc(shard);
	g_free(shard);
}

// called when references drop to zero
static void __bufferpool_destroy(struct bufferpool *bp) {
	for (unsigned int i = 0; i < bp->num_shards; i++) {
		struct bpool_shard *shard = bp->shards[i];
		bpool_shard_destroy(shard);
	}

	g_free(bp->shards);
	rwlock_destroy(&bp->shards_lock);
	g_free(bp);
}

// may destroy bufferpool
static inline void __bufferpool_unref_n(struct bufferpool *bp, unsigned int n) {
	assert(atomic_get_na(&bp->refs) >= n);

	unsigned int refs = atomic_sub(&bp->refs, n);
	if (refs != n)
		return;

	// no more references
	__bufferpool_destroy(bp);
}

static inline void __bufferpool_unref(struct bufferpool *bp) {
	__bufferpool_unref_n(bp, 1);
}

static void bufferpool_shard_unref(struct bpool_shard *shard) {
	assert(atomic_get_na(&shard->refs) != 0);

	bool full = atomic_get(&shard->full);

	unsigned int refs = atomic_dec(&shard->refs);
	// if shard was set to full and this was the last reference, we can recycle
	if (!full || refs != 1)
		return;

	// return shard to empty list (or reserve again)
	bufferpool_recycle(shard);
}

// must hold reference on the bufferpool
// must hold the lock in R, may intermittently be released
static struct bpool_shard *bufferpool_make_shard(struct bufferpool *bp) {
	struct bpool_shard *shard = bufferpool_new_shard(bp);
	if (!shard) // epic fail
		return NULL;

	// Find a place to insert it
	while (true) {
		unsigned int idx = atomic_get_na(&bp->num_shards);

		// Is there room to insert?
		if (idx < bp->max_shards) {
			// Attempt to insert. Slot must be empty
			struct bpool_shard *expected = NULL;
			if (!__atomic_compare_exchange_n(&bp->shards[idx], &expected, shard,
						false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
				continue; // Somebody beat us to it. Try again

			// Success. Record the new count
			atomic_set(&bp->num_shards, idx + 1);

			// We now definitely have a new empty shard. Tell everybody to use it
			// and return success
			atomic_set_na(&bp->empty_shard_idx, idx);

			return shard;
		}

		// Out of room. Now it gets difficult. We must resize
		unsigned int old_size = bp->max_shards;

		rwlock_unlock_r(&bp->shards_lock);

		// Allocate new array first
		unsigned int new_size = old_size * 2;
		struct bpool_shard **new_shards = g_new(struct bpool_shard *, new_size);

		rwlock_lock_w(&bp->shards_lock);

		// Double check, somebody might have beaten us
		if (bp->max_shards != old_size) {
			// OK, just try again
			rwlock_unlock_w(&bp->shards_lock);
			g_free(new_shards);
			rwlock_lock_r(&bp->shards_lock);
			continue;
		}

		// Copy, initialise, and swap
		memcpy(new_shards, bp->shards, sizeof(*bp->shards) * old_size);
		memset(new_shards + old_size, 0, sizeof(*bp->shards) * (new_size - old_size));
		struct bpool_shard **old_shards = bp->shards;
		bp->shards = new_shards;
		bp->max_shards = new_size;

		rwlock_unlock_w(&bp->shards_lock);

		g_free(old_shards);

		// OK, now try again
		rwlock_lock_r(&bp->shards_lock);
	}
}

void *bufferpool_alloc(struct bufferpool *bp, size_t len) {
	len = BUFFERPOOL_ALIGN(len);

	if (len > BUFFERPOOL_SHARD_SIZE - BUFFERPOOL_OVERHEAD)
		return NULL;

	atomic_inc(&bp->refs);

	// Check existing shards if one has enough room. If not, create a new one

	rwlock_lock_r(&bp->shards_lock);

	// Outer loop: To retry after creating a new shard if it was needed
	while (true) {
		unsigned int idx = atomic_get_na(&bp->empty_shard_idx);
		unsigned int start = idx;

		// Inner loop: To cycle through all existing shards, looking for room
		while (true) {
			if (idx >= atomic_get_na(&bp->num_shards)) {
				if (idx == 0)
					break; // we don't have any shards
				if (start == 0)
					break; // circled around, found nothing
				idx = 0;
			}

			struct bpool_shard *shard = atomic_get_na(&bp->shards[idx]);

			// Only attempt allocation if known not to be full. This comes first
			if (!atomic_get(&shard->full)) {
				// Register as a reference
				atomic_inc(&shard->refs);

				// Attempt to allocate
				void *ret = atomic_add(&shard->head, len);

				// Was the allocation successful? (Shard not full)
				if (ret + len <= shard->end) {
					rwlock_unlock_r(&bp->shards_lock);

					// remember empty index for next user
					if (idx != start)
						atomic_set_na(&bp->empty_shard_idx, idx);
					return ret;
				}

				// Shard full. Go to next one and try again
				// Set to full first, then drop reference
				atomic_set(&shard->full, true);
				bufferpool_shard_unref(shard);
			}

			idx++;
			if (idx == start)
				break; // exhausted all our options
		}

		// Found nothing. Must create new shard and put it into the array
		if (!bufferpool_make_shard(bp)) {
			// disaster struck
			rwlock_unlock_r(&bp->shards_lock);
			__bufferpool_unref(bp);
			return NULL;
		}
	}
}

// Get a completely empty shard. Create one if needed.
// XXX can be improved to avoid always using entire shards?
// XXX doesn't currently mix with alloc/unref because of "full" being racy
void *bufferpool_reserve(struct bufferpool *bp, unsigned int refs, unsigned int (*recycle)(void *), void *arg) {
	atomic_add(&bp->refs, refs);
	rwlock_lock_r(&bp->shards_lock);

	struct bpool_shard *shard = bufferpool_make_shard(bp);

	if (!shard) {
		// disaster struck
		rwlock_unlock_r(&bp->shards_lock);
		__bufferpool_unref(bp);
		return NULL;
	}

	// set references, set recycle callback
	assert(atomic_get_na(&shard->refs) == 0);
	atomic_set(&shard->refs, refs);

	atomic_set(&shard->full, true);
	shard->recycle = recycle;
	shard->arg = arg;

	return shard->empty;
}

static struct bpool_shard *bpool_find_shard(void *p) {
	struct bpool_shard **head = (struct bpool_shard **) ((size_t) p & BUFFERPOOL_TOP_MASK);
	return *head;
}

void bufferpool_unref(void *p) {
	if (!p)
		return;

	struct bpool_shard *shard = bpool_find_shard(p);
	if (!shard) // should only happen during shutdown
		return;

	bufferpool_shard_unref(shard);
	__bufferpool_unref(shard->bp);
}

// currently called from synchronous context relative to bufferpool_destroy, so no need
// to check for delayed destruction
void bufferpool_release(void *p) {
	if (!p)
		return;

	struct bpool_shard *shard = bpool_find_shard(p);

	unsigned int refs = atomic_exchange_na(&shard->refs, 0);
	__bufferpool_unref_n(shard->bp, refs);
}

void *bufferpool_ref(void *p) {
	if (!p)
		return NULL;

	struct bpool_shard *shard = bpool_find_shard(p);

	assert(atomic_get_na(&shard->refs) != 0);

	atomic_inc(&shard->refs);
	atomic_inc(&shard->bp->refs);

	return p;
}

void bufferpool_destroy(struct bufferpool *bp) {
	__bufferpool_unref(bp);
}

void bufferpool_init(void) {
}

void bufferpool_cleanup(void) {
}

void *bufferpool_aligned_alloc(void) {
	void *m = aligned_alloc(BUFFERPOOL_SHARD_SIZE, BUFFERPOOL_SHARD_SIZE);
	assert(m != NULL);
	return m;
}

void bufferpool_aligned_free(void *p) {
	free(p);
}
