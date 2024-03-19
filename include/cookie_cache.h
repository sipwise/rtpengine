#ifndef _COOKIE_CACHE_H_
#define _COOKIE_CACHE_H_

#include <time.h>
#include <glib.h>

#include "helpers.h"
#include "str.h"

struct cookie_cache_state {
	GHashTable *in_use;
	GHashTable *cookies;
};

typedef struct cache_entry {
	str *reply;
	str *command;
	str *callid;
} cache_entry;

INLINE cache_entry *cache_entry_dup(const cache_entry *s) {
	if (!s)
		return NULL;
	cache_entry *r;
	r = malloc(sizeof(*r));
	r->reply = str_dup(s->reply);
	r->command = str_dup(s->command);
	r->callid = str_dup(s->callid);
	return r;
}
INLINE void cache_entry_free(void *p) {
	cache_entry *s = p;
	if (!s)
		return;
	free(s->reply);
	free(s->command);
	free(s->callid);
}
struct cookie_cache {
	mutex_t lock;
	cond_t cond;
	struct cookie_cache_state current, old;
	time_t swap_time;
};

void cookie_cache_init(struct cookie_cache *);
cache_entry *cookie_cache_lookup(struct cookie_cache *, const str *);
void cookie_cache_insert(struct cookie_cache *, const str *, const struct cache_entry *);
void cookie_cache_remove(struct cookie_cache *, const str *);
void cookie_cache_cleanup(struct cookie_cache *);

#endif
