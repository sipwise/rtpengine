#include <stdio.h>
#include <hiredis.h>
#include <sys/types.h>
#include <sys/time.h>

#include "redis.h"
#include "aux.h"
#include "log.h"





struct redis *redis_new(u_int32_t ip, u_int16_t port, char *key) {
	struct redis *r;
	struct timeval tv;
	redisReply *rp;

	r = malloc(sizeof(*r));
	ZERO(*r);

	sprintf(r->host, IPF, IPP(ip));
	r->port = port;
	r->key = key;

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	r->ctx = redisConnectWithTimeout(r->host, r->port, tv);

	if (!r->ctx)
		goto err;
	if (r->ctx->err)
		goto err;

	rp = redisCommand(r->ctx, "PING");
	if (!rp)
		goto err;
	freeReplyObject(rp);

	return r;

err:
	if (r->ctx && r->ctx->errstr)
		mylog(LOG_CRIT, "Redis error: %s\n", r->ctx->errstr);
	if (r->ctx)
		redisFree(r->ctx);
	free(r);
	return NULL;
}
