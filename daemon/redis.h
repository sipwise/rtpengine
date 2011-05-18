#ifndef __REDIS_H__
#define __REDIS_H__




#include <sys/types.h>
#include <hiredis.h>




struct redis {
	char		host[32];
	int		port;

	redisContext	*ctx;
	char		*key;
	int		active:1;
};




struct redis *redis_new(u_int32_t, u_int16_t, char *);




#endif
