#ifndef __REDIS_H__
#define __REDIS_H__




#include <sys/types.h>
#include "compat.h"




struct callmaster;
struct call;
struct redis;



extern struct redis *(*redis_new_mod)(u_int32_t, u_int16_t, int);
extern int (*redis_restore_mod)(struct callmaster *, struct redis *);
extern void (*redis_update_mod)(struct call *, struct redis *);
extern void (*redis_delete_mod)(struct call *, struct redis *);
extern void (*redis_wipe_mod)(struct redis *);




INLINE void redis_update(struct call *c, struct redis *r) {
	if (!redis_update_mod)
		return;
	redis_update_mod(c, r);
}
INLINE void redis_delete(struct call *c, struct redis *r) {
	if (!redis_delete_mod)
		return;
	redis_delete_mod(c, r);
}
INLINE int redis_restore(struct callmaster *m, struct redis *r) {
	if (!redis_restore_mod)
		return 0;
	return redis_restore_mod(m, r);
}




#endif
