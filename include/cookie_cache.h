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

struct cookie_cache {
	mutex_t lock;
	cond_t cond;
	struct cookie_cache_state current, old;
	time_t swap_time;
};

void cookie_cache_init(struct cookie_cache *);
str *cookie_cache_lookup(struct cookie_cache *, const str *);
void cookie_cache_insert(struct cookie_cache *, const str *, const str *);
void cookie_cache_remove(struct cookie_cache *, const str *);
void cookie_cache_cleanup(struct cookie_cache *);

#endif
