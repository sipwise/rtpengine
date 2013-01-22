#ifndef _COOKIE_CACHE_H_
#define _COOKIE_CACHE_H_

#include <time.h>
#include <glib.h>
#include "aux.h"

struct cookie_cache_state {
	GHashTable *cookies;
	GStringChunk *chunks;
};

struct cookie_cache {
	mutex_t lock;
	cond_t cond;
	struct cookie_cache_state current, old;
	time_t swap_time;
};

void cookie_cache_init(struct cookie_cache *);
char *cookie_cache_lookup(struct cookie_cache *, const char *);
void cookie_cache_insert(struct cookie_cache *, const char *, const char *, int);
void cookie_cache_remove(struct cookie_cache *, const char *);

#endif
