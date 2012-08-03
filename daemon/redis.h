#ifndef __REDIS_H__
#define __REDIS_H__




#include <sys/types.h>




struct callmaster;
struct call;
struct redis;



extern struct redis *(*redis_new)(u_int32_t, u_int16_t, int);
extern int (*redis_restore)(struct callmaster *, struct redis *);
extern void (*redis_update)(struct call *, struct redis *);
extern void (*redis_delete)(struct call *, struct redis *);
extern void (*redis_wipe)(struct redis *);




#endif
