#include "redis.h"

struct redis *(*redis_new)(u_int32_t, u_int16_t, int);
int (*redis_restore)(struct callmaster *);
void (*redis_update)(struct call *);
void (*redis_delete)(struct call *);
void (*redis_wipe)(struct callmaster *);
