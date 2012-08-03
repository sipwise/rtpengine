#include "redis.h"

struct redis *(*redis_new)(u_int32_t, u_int16_t, int);
int (*redis_restore)(struct callmaster *, struct redis *);
void (*redis_update)(struct call *, struct redis *);
void (*redis_delete)(struct call *, struct redis *);
void (*redis_wipe)(struct redis *);
