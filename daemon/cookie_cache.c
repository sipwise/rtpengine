#include <time.h>
#include <glib.h>
#include "cookie_cache.h"
#include "aux.h"
#include "poller.h"

static const char *cookie_in_use = "MAGIC";

static inline void cookie_cache_state_init(struct cookie_cache_state *s) {
	s->cookies = g_hash_table_new(g_str_hash, g_str_equal);
	s->chunks = g_string_chunk_new(4 * 1024);
}

void cookie_cache_init(struct cookie_cache *c) {
	cookie_cache_state_init(&c->current);
	cookie_cache_state_init(&c->old);
	c->swap_time = poller_now;
	mutex_init(&c->lock);
	cond_init(&c->cond);
}

/* lock must be held */
static void __cookie_cache_check_swap(struct cookie_cache *c) {
	if (poller_now - c->swap_time >= 30) {
		g_hash_table_remove_all(c->old.cookies);
#if GLIB_CHECK_VERSION(2,14,0)
		g_string_chunk_clear(c->old.chunks);
		swap_ptrs(&c->old.chunks, &c->current.chunks);
#else
		g_string_chunk_free(c->old.chunks);
		c->old.chunks = c->current.chunks;
		c->current.chunks = g_string_chunk_new(4 * 1024);
#endif
		swap_ptrs(&c->old.cookies, &c->current.cookies);
		c->swap_time = poller_now;
	}
}

char *cookie_cache_lookup(struct cookie_cache *c, const char *s) {
	char *ret;

	mutex_lock(&c->lock);

	__cookie_cache_check_swap(c);

restart:
	/* XXX better hashing */
	ret = g_hash_table_lookup(c->current.cookies, s);
	if (!ret)
		ret = g_hash_table_lookup(c->old.cookies, s);
	if (ret) {
		if (ret == cookie_in_use) {
			/* another thread is working on this right now */
			cond_wait(&c->cond, &c->lock);
			goto restart;
		}
		mutex_unlock(&c->lock);
		return ret;
	}
	g_hash_table_replace(c->current.cookies, (void *) s, (void *) cookie_in_use);
	mutex_unlock(&c->lock);
	return NULL;
}

void cookie_cache_insert(struct cookie_cache *c, const char *s, const char *r, int len) {
	mutex_lock(&c->lock);
	g_hash_table_replace(c->current.cookies, g_string_chunk_insert(c->current.chunks, s),
		g_string_chunk_insert_len(c->current.chunks, r, (len >= 0) ? len : strlen(r)));
	g_hash_table_remove(c->old.cookies, s);
	cond_broadcast(&c->cond);
	mutex_unlock(&c->lock);
}

void cookie_cache_remove(struct cookie_cache *c, const char *s) {
	mutex_lock(&c->lock);
	g_hash_table_remove(c->current.cookies, s);
	g_hash_table_remove(c->old.cookies, s);
	cond_broadcast(&c->cond);
	mutex_unlock(&c->lock);
}
