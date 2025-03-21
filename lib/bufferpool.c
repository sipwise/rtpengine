#include "bufferpool.h"
#include <glib.h>
#include <stdbool.h>
#include "obj.h"

static_assert((BUFFERPOOL_SHARD_SIZE & (BUFFERPOOL_SHARD_SIZE - 1)) == 0,
		"BUFFERPOOL_SHARD_SIZE is not a power of two");

TYPED_GQUEUE(shard, struct bpool_shard)

struct bufferpool {
	void *(*alloc)(void);
	void (*dealloc)(void *);
	mutex_t lock;
	shard_q empty_shards;
	shard_q full_shards;
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
	shard_list link;
	unsigned int (*recycle)(void *);
	void *arg;
};

struct bufferpool *bufferpool_new(void *(*alloc)(void), void (*dealloc)(void *)) {
	struct bufferpool *ret = g_new0(__typeof(*ret), 1);
	ret->alloc = alloc;
	mutex_init(&ret->lock);
	t_queue_init(&ret->empty_shards);
	t_queue_init(&ret->full_shards);
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
		t_queue_unlink(&bp->full_shards, &shard->link);
		t_queue_push_tail_link(&bp->empty_shards, &shard->link);
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
	ret->link.data = ret;

	struct bpool_shard **head = buf;
	*head = ret;

	static_assert(BUFFERPOOL_ALIGN(sizeof(void *)) == BUFFERPOOL_OVERHEAD,
			"wrong BUFFERPOOL_OVERHEAD size");
	buf += BUFFERPOOL_ALIGN(sizeof(void *));

	ret->empty = buf;
	ret->head = buf;

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
			t_queue_push_tail_link(&bp->empty_shards, &shard->link);
			break;
		}
		shard = bp->empty_shards.head->data;
		if (shard->head + len <= shard->end)
			break;

		t_queue_unlink(&bp->empty_shards, &shard->link);
		t_queue_push_tail_link(&bp->full_shards, &shard->link);

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

	struct bpool_shard *shard = t_queue_peek_head(&bp->empty_shards);
	if (shard && shard->head == shard->empty && shard->refs == 0)
		t_queue_unlink(&bp->empty_shards, &shard->link);
	else
		shard = bufferpool_new_shard(bp);

	// set references, set recycle callback, move to full list
	shard->refs = refs;
	shard->full = true;
	t_queue_push_tail_link(&bp->full_shards, &shard->link);
	shard->recycle = recycle;
	shard->arg = arg;

	return shard->empty;
}

static struct bpool_shard *bpool_find_shard(void *p) {
	struct bpool_shard **head = (struct bpool_shard **) ((size_t) p & BUFFERPOOL_TOP_MASK);
	return *head;
}

static void bpool_shard_destroy(struct bpool_shard *shard) {
	bufferpool_dealloc(shard);
	g_free(shard);
}

static void bpool_shard_delayed_destroy(struct bufferpool *bp, struct bpool_shard *shard) {
	if (shard->full) {
		shard_list *link = t_queue_find(&bp->full_shards, shard);
		t_queue_unlink(&bp->full_shards, link);
	}
	else {
		shard_list *link = t_queue_find(&bp->empty_shards, shard);
		t_queue_unlink(&bp->empty_shards, link);
	}
	bpool_shard_destroy(shard);
}

void bufferpool_unref(void *p) {
	if (!p)
		return;

	struct bpool_shard *shard = bpool_find_shard(p);
	if (!shard) // should only happen during shutdown
		return;
	struct bufferpool *bpool = shard->bp;

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

	struct bpool_shard *shard = bpool_find_shard(p);
	struct bufferpool *bpool = shard->bp;

	LOCK(&bpool->lock);
	assert(shard->refs != 0);
	shard->refs = 0;
}

void *bufferpool_ref(void *p) {
	if (!p)
		return NULL;

	struct bpool_shard *shard = bpool_find_shard(p);
	struct bufferpool *bpool = shard->bp;

	LOCK(&bpool->lock);
	assert(shard->refs != 0);
	shard->refs++;
	return p;
}

static void bpool_destroy_shards(shard_q *q) {
	shard_list *l = q->head;
	while (l) {
		shard_list *n = l->next;
		struct bpool_shard *shard = l->data;
		if (shard->refs == 0) {
			t_queue_unlink(q, l);
			bpool_shard_destroy(shard);
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
