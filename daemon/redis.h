#ifndef __REDIS_H__
#define __REDIS_H__




#include <sys/types.h>
#include <hiredis.h>




struct callmaster;



struct redis {
	char		host[32];
	int		port;

	redisContext	*ctx;
	int		db;
};




struct redis *redis_new(u_int32_t, u_int16_t, int);
int redis_restore(struct callmaster *);




#endif
