#include "cookie_cache.h"

#include <time.h>
#include <glib.h>

#include "compat.h"
#include "helpers.h"
#include "poller.h"
#include "str.h"

INLINE void cookie_cache_state_init(struct cookie_cache_state *s) {
	s->in_use = g_hash_table_new(str_hash, str_equal);
	s->cookies = g_hash_table_new_full(str_hash, str_equal, free, cache_entry_free);
}
INLINE void cookie_cache_state_cleanup(struct cookie_cache_state *s) {
	g_hash_table_destroy(s->cookies);
	g_hash_table_destroy(s->in_use);
}

void cookie_cache_init(struct cookie_cache *c) {
	cookie_cache_state_init(&c->current);
	cookie_cache_state_init(&c->old);
	c->swap_time = rtpe_now.tv_sec;
	mutex_init(&c->lock);
	cond_init(&c->cond);
}

/* lock must be held */
static void __cookie_cache_check_swap(struct cookie_cache *c) {
	if (rtpe_now.tv_sec - c->swap_time >= 30) {
		g_hash_table_remove_all(c->old.cookies);
		swap_ptrs(&c->old.cookies, &c->current.cookies);
		c->swap_time = rtpe_now.tv_sec;
	}
}

cache_entry *cookie_cache_lookup(struct cookie_cache *c, const str *s) {
	cache_entry *ret;

	mutex_lock(&c->lock);

	__cookie_cache_check_swap(c);

restart:
	ret = g_hash_table_lookup(c->current.cookies, s);
	if (!ret)
		ret = g_hash_table_lookup(c->old.cookies, s);
	if (ret) {
		ret = cache_entry_dup(ret);
		mutex_unlock(&c->lock);
		return ret;
	}

	// is it being worked on right now by another thread?
	void *p = g_hash_table_lookup(c->current.in_use, s);
	if (!p)
		p = g_hash_table_lookup(c->old.in_use, s);
	if (p) {
		cond_wait(&c->cond, &c->lock);
		goto restart;
	}

	// caller is required to call cookie_cache_insert or cookie_cache_remove
	// before `s` runs out of scope
	g_hash_table_replace(c->current.in_use, (void *) s, (void *) 0x1);
	mutex_unlock(&c->lock);
	return NULL;
}

void cookie_cache_insert(struct cookie_cache *c, const str *s, const struct cache_entry *entry) {
	mutex_lock(&c->lock);
	g_hash_table_remove(c->current.in_use, s);
	g_hash_table_remove(c->old.in_use, s);
	g_hash_table_replace(c->current.cookies, str_dup(s), cache_entry_dup(entry));
	g_hash_table_remove(c->old.cookies, s);
	cond_broadcast(&c->cond);
	mutex_unlock(&c->lock);
}

void cookie_cache_remove(struct cookie_cache *c, const str *s) {
	mutex_lock(&c->lock);
	g_hash_table_remove(c->current.in_use, s);
	g_hash_table_remove(c->old.in_use, s);
	g_hash_table_remove(c->current.cookies, s);
	g_hash_table_remove(c->old.cookies, s);
	cond_broadcast(&c->cond);
	mutex_unlock(&c->lock);
}

void cookie_cache_cleanup(struct cookie_cache *c) {
	cookie_cache_state_cleanup(&c->current);
	cookie_cache_state_cleanup(&c->old);
}
