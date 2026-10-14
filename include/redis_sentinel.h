#ifndef __REDIS_SENTINEL_H__
#define __REDIS_SENTINEL_H__

#include <stdbool.h>
#include <stdint.h>

#include "socket.h"

/*
 * A thread asks the Redis Sentinels for the master and publishes it with a
 * generation number; the connections that use it compare the generation (one
 * atomic read) and reconnect when it changes. All Sentinel I/O is done in
 * that thread.
 */

struct redis_sentinel;

extern struct redis_sentinel *rtpe_redis_sentinel;

struct redis_sentinel *redis_sentinel_new(const char *list, const char *master_name,
		const char *auth_env);
void redis_sentinel_set_probe_auth(struct redis_sentinel *, const char *auth);
bool redis_sentinel_discover(struct redis_sentinel *);
void redis_sentinel_loop(struct redis_sentinel *);
void redis_sentinel_free(struct redis_sentinel *);

uint64_t redis_sentinel_gen(struct redis_sentinel *);
uint64_t redis_sentinel_get(struct redis_sentinel *, endpoint_t *);
void redis_sentinel_wake(struct redis_sentinel *, bool limited);
const char *redis_sentinel_master_name(const struct redis_sentinel *);

#endif
