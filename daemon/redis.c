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
	char *s;

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

	rp = redisCommand(r->ctx, "INFO");
	if (!rp)
		goto err;
	s = strstr(rp->str, "role:");
	if (!s) {
		freeReplyObject(rp);
		goto err;
	}
	if (!memcmp(s, "role:master", 9))
		r->active = 1;
	else if (!memcmp(s, "role:slave", 8))
		;	/* it's already 0 */
	else {
		mylog(LOG_ERR, "Unable to determine Redis master/slave state\n");
		freeReplyObject(rp);
		goto err;
	}
	freeReplyObject(rp);

	return r;

err:
	if (r->ctx && r->ctx->err && r->ctx->errstr)
		mylog(LOG_CRIT, "Redis error: %s\n", r->ctx->errstr);
	if (r->ctx)
		redisFree(r->ctx);
	free(r);
	return NULL;
}
