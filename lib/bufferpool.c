#include "bufferpool.h"
#include <glib.h>
#include <stdbool.h>
#include "obj.h"

static_assert((BUFFERPOOL_SHARD_SIZE & (BUFFERPOOL_SHARD_SIZE - 1)) == 0,
		"BUFFERPOOL_SHARD_SIZE is not a power of two");

struct bufferpool {
	void *(*alloc)(void);
	void (*dealloc)(void *);
	mutex_t lock;
	GQueue empty_shards;
	GQueue full_shards;
	bool destroy;
};

struct bpool_shard {
	struct bufferpool *bp;
	unsigned int refs;
	void *buf; // actual head of buffer, given to free()
	void *empty; // head of usable buffer, head == empty if empty
	void *end;
	void *head;
	bool full;
	unsigned int (*recycle)(void *);
	void *arg;
};

// sorted list of all shards for quick bsearch
static rwlock_t bpool_shards_lock = RWLOCK_STATIC_INIT;
static GPtrArray *bpool_shards;

struct bufferpool *bufferpool_new(void *(*alloc)(void), void (*dealloc)(void *)) {
	struct bufferpool *ret = g_new0(__typeof(*ret), 1);
	ret->alloc = alloc;
	mutex_init(&ret->lock);
	g_queue_init(&ret->empty_shards);
	g_queue_init(&ret->full_shards);
	ret->dealloc = dealloc;
	return ret;
}

// bufferpool is locked and shard is in "full" list but with zero refs
static void bufferpool_recycle(struct bpool_shard *shard) {
	struct bufferpool *bp = shard->bp;
	shard->head = shard->empty;

	if (shard->recycle)
		shard->refs += shard->recycle(shard->arg);

	if (shard->refs == 0) {
		shard->full = false;
		GList *link = g_queue_find(&bp->full_shards, shard); // XXX avoid this
		g_queue_delete_link(&bp->full_shards, link);
		g_queue_push_tail(&bp->empty_shards, shard);
	}
}

static void bufferpool_dealloc(struct bpool_shard *shard) {
	struct bufferpool *bp = shard->bp;
	bp->dealloc(shard->buf);
}

// bufferpool is locked
static void shard_check_full(struct bpool_shard *shard) {
	if (shard->refs != 0 || !shard->full)
		return;

	bufferpool_recycle(shard);
}

static int bpool_shards_sort(const void *A, const void *B) {
	const struct bpool_shard * const * const Ap = A, * const * const Bp = B;
	if ((*Ap)->buf < (*Bp)->buf)
		return -1;
	if ((*Ap)->buf > (*Bp)->buf)
		return 1;
	return 0;
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

	RWLOCK_W(&bpool_shards_lock);

	g_ptr_array_add(bpool_shards, ret);
	g_ptr_array_sort(bpool_shards, bpool_shards_sort);

	return ret;
}

void *bufferpool_alloc(struct bufferpool *bp, size_t len) {
	if (len > BUFFERPOOL_SHARD_SIZE)
		return NULL;

	LOCK(&bp->lock);

	// check existing shards if one has enough room. if not, create a new one

	struct bpool_shard *shard;

	while (true) {
		if (!bp->empty_shards.length) {
			shard = bufferpool_new_shard(bp);
			g_queue_push_tail(&bp->empty_shards, shard);
			break;
		}
		shard = bp->empty_shards.head->data;
		if (shard->head + len <= shard->end)
			break;

		g_queue_pop_head(&bp->empty_shards);
		g_queue_push_tail(&bp->full_shards, shard);

		shard->full = true;
		shard_check_full(shard);
	}

	// allocate buffer from shard

	void *ret = shard->head;
	shard->refs++;
	shard->head += BUFFERPOOL_ALIGN(len);
	return ret;
}

void *bufferpool_reserve(struct bufferpool *bp, unsigned int refs, unsigned int (*recycle)(void *), void *arg) {
	LOCK(&bp->lock);

	// get a completely empty shard. create one if needed

	struct bpool_shard *shard = g_queue_peek_head(&bp->empty_shards);
	if (shard && shard->head == shard->empty && shard->refs == 0)
		g_queue_pop_head(&bp->empty_shards);
	else
		shard = bufferpool_new_shard(bp);

	// set references, set recycle callback, move to full list
	shard->refs = refs;
	shard->full = true;
	g_queue_push_tail(&bp->full_shards, shard);
	shard->recycle = recycle;
	shard->arg = arg;

	return shard->empty;
}

static int bpool_shard_cmp(const void *buf, const void *ptr) {
	struct bpool_shard *const *sptr = ptr;
	struct bpool_shard *shard = *sptr;
	if (buf < shard->buf)
		return -1;
	if (buf >= shard->end)
		return 1;
	return 0;
}

// bpool_shards_lock must be held
static struct bpool_shard **bpool_find_shard_ptr(void *p) {
	return bsearch(p, bpool_shards->pdata, bpool_shards->len,
			sizeof(*bpool_shards->pdata), bpool_shard_cmp);
}

static struct bpool_shard *bpool_find_shard(void *p) {
	struct bpool_shard **head = (struct bpool_shard **) ((size_t) p & BUFFERPOOL_TOP_MASK);
	return *head;
}

static void bpool_shard_destroy(struct bpool_shard *shard) {
	{
		RWLOCK_W(&bpool_shards_lock);
		struct bpool_shard **ele = bpool_find_shard_ptr(shard->buf);
		size_t idx = (void **) ele - bpool_shards->pdata;
		g_ptr_array_remove_index(bpool_shards, idx);
	}
	bufferpool_dealloc(shard);
	g_free(shard);
}

static void bpool_shard_delayed_destroy(struct bufferpool *bp, struct bpool_shard *shard) {
	if (shard->full) {
		GList *link = g_queue_find(&bp->full_shards, shard);
		g_queue_delete_link(&bp->full_shards, link);
	}
	else {
		GList *link = g_queue_find(&bp->empty_shards, shard);
		g_queue_delete_link(&bp->empty_shards, link);
	}
	bpool_shard_destroy(shard);
}

void bufferpool_unref(void *p) {
	if (!p)
		return;
	struct bpool_shard *shard;
	struct bufferpool *bpool;
	{
		RWLOCK_R(&bpool_shards_lock);
		shard = bpool_find_shard(p);
		if (!shard) // should only happen during shutdown
			return;
		bpool = shard->bp;
	}
	{
		LOCK(&bpool->lock);
		assert(shard->refs != 0);
		shard->refs--;
		// handle delayed destruction
		if (!bpool->destroy) {
			shard_check_full(shard);
			return;
		}
		// wait for refs to drop to zero, then remove/free shard, and destroy pool if no shards left
		if (shard->refs > 0)
			return;
		bpool_shard_delayed_destroy(bpool, shard);
		if (bpool->full_shards.length || bpool->empty_shards.length)
			return; // still some left
	}
	// no shards left, can destroy now
	bufferpool_destroy(bpool);
}

void bufferpool_release(void *p) {
	if (!p)
		return;
	struct bpool_shard *shard;
	struct bufferpool *bpool;
	{
		RWLOCK_R(&bpool_shards_lock);
		shard = bpool_find_shard(p);
		bpool = shard->bp;
	}
	LOCK(&bpool->lock);
	assert(shard->refs != 0);
	shard->refs = 0;
}

void *bufferpool_ref(void *p) {
	if (!p)
		return NULL;
	struct bpool_shard *shard;
	struct bufferpool *bpool;
	{
		RWLOCK_R(&bpool_shards_lock);
		shard = bpool_find_shard(p);
		bpool = shard->bp;
	}
	LOCK(&bpool->lock);
	assert(shard->refs != 0);
	shard->refs++;
	return p;
}

static void bpool_destroy_shards(GQueue *q) {
	GList *l = q->head;
	while (l) {
		GList *n = l->next;
		struct bpool_shard *shard = l->data;
		if (shard->refs == 0) {
			bpool_shard_destroy(shard);
			g_queue_delete_link(q, l);
		}
		l = n;
	}
}

void bufferpool_destroy(struct bufferpool *bp) {
	{
		LOCK(&bp->lock);
		bpool_destroy_shards(&bp->full_shards);
		bpool_destroy_shards(&bp->empty_shards);
		if (bp->full_shards.length || bp->empty_shards.length) {
			// deferred destruction
			bp->destroy = true;
			return;
		}
	}
	g_free(bp);
}

void bufferpool_init(void) {
	bpool_shards = g_ptr_array_new();
}

void bufferpool_cleanup(void) {
	assert(bpool_shards->len == 0);
	g_ptr_array_free(bpool_shards, true);
}

void *bufferpool_aligned_alloc(void) {
	void *m = aligned_alloc(BUFFERPOOL_SHARD_SIZE, BUFFERPOOL_SHARD_SIZE);
	assert(m != NULL);
	return m;
}

void bufferpool_aligned_free(void *p) {
	free(p);
}
