#include "redis.h"

struct redis *(*redis_new_mod)(u_int32_t, u_int16_t, int);
int (*redis_restore_mod)(struct callmaster *, struct redis *);
void (*redis_update_mod)(struct call *, struct redis *);
void (*redis_delete_mod)(struct call *, struct redis *);
void (*redis_wipe_mod)(struct redis *);
