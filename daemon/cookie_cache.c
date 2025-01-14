#include "cookie_cache.h"

#include <time.h>
#include <glib.h>

#include "compat.h"
#include "helpers.h"
#include "poller.h"
#include "str.h"

INLINE void cookie_cache_state_init(struct cookie_cache_state *s) {
	bencode_buffer_init(&s->buffer);
	s->in_use = g_hash_table_new((GHashFunc) str_hash, (GEqualFunc) str_equal);
	s->cookies = g_hash_table_new((GHashFunc) str_hash, (GEqualFunc) str_equal);
}
INLINE void cookie_cache_state_cleanup(struct cookie_cache_state *s) {
	g_hash_table_destroy(s->cookies);
	g_hash_table_destroy(s->in_use);
	bencode_buffer_free(&s->buffer);
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
		bencode_buffer_free(&c->old.buffer);
		swap_ptrs(&c->old.cookies, &c->current.cookies);
		c->old.buffer = c->current.buffer;
		bencode_buffer_init(&c->current.buffer);
		c->swap_time = rtpe_now.tv_sec;
	}
}

static cache_entry *__cache_entry_dup(struct cookie_cache_state *c, const cache_entry *s) {
	if (!s)
		return NULL;
	cache_entry *r;
	r = bencode_buffer_alloc(&c->buffer, sizeof(*r));
	r->reply = bencode_str_strdup(&c->buffer, &s->reply);
	r->command = s->command;
	r->callid = bencode_str_strdup(&c->buffer, &s->callid);
	return r;
}

cache_entry *cookie_cache_lookup(struct cookie_cache *c, const str *s) {
	cache_entry *ret;

	LOCK(&c->lock);

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
	return NULL;
}

void cookie_cache_insert(struct cookie_cache *c, const str *s, const struct cache_entry *entry) {
	LOCK(&c->lock);
	g_hash_table_remove(c->current.in_use, s);
	g_hash_table_remove(c->old.in_use, s);
	g_hash_table_replace(c->current.cookies, bencode_str_str_dup(&c->current.buffer, s),
			__cache_entry_dup(&c->current, entry));
	g_hash_table_remove(c->old.cookies, s);
	cond_broadcast(&c->cond);
}

void cookie_cache_remove(struct cookie_cache *c, const str *s) {
	LOCK(&c->lock);
	g_hash_table_remove(c->current.in_use, s);
	g_hash_table_remove(c->old.in_use, s);
	g_hash_table_remove(c->current.cookies, s);
	g_hash_table_remove(c->old.cookies, s);
	cond_broadcast(&c->cond);
}

void cookie_cache_cleanup(struct cookie_cache *c) {
	cookie_cache_state_cleanup(&c->current);
	cookie_cache_state_cleanup(&c->old);
}
