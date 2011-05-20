#include <stdio.h>
#include <hiredis.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#include "redis.h"
#include "aux.h"
#include "call.h"
#include "log.h"





#define redisCommandNR(a...) (int)({ void *__tmp; __tmp = redisCommand(a); if (__tmp) freeReplyObject(__tmp); __tmp ? 0 : -1;})





static int redis_connect(struct redis *r, int wait) {
	struct timeval tv;
	redisReply *rp;
	char *s;

	if (r->ctx)
		redisFree(r->ctx);
	r->ctx = NULL;

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	r->ctx = redisConnectWithTimeout(r->host, r->port, tv);

	if (!r->ctx)
		goto err;
	if (r->ctx->err)
		goto err2;

	if (redisCommandNR(r->ctx, "PING"))
		goto err2;

	if (redisCommandNR(r->ctx, "SELECT %i", r->db))
		goto err2;

	while (wait-- >= 0) {
		mylog(LOG_INFO, "Asking Redis whether it's master or slave...\n");
		rp = redisCommand(r->ctx, "INFO");
		if (!rp)
			goto err2;

		s = strstr(rp->str, "role:");
		if (!s)
			goto err3;
		if (!memcmp(s, "role:master", 9))
			goto done;
		else if (!memcmp(s, "role:slave", 8))
			goto next;
		else
			goto err3;

next:
		freeReplyObject(rp);
		mylog(LOG_INFO, "Connected to Redis, but it's in slave mode\n");
		sleep(1);
	}

	goto err2;

done:
	freeReplyObject(rp);
	mylog(LOG_INFO, "Connected to Redis\n");
	return 0;

err3:
	freeReplyObject(rp);
err2:
	if (r->ctx->err)
		mylog(LOG_ERR, "Redis error: %s\n", r->ctx->errstr);
	redisFree(r->ctx);
	r->ctx = NULL;
err:
	mylog(LOG_ERR, "Failed to connect to master Redis database\n");
	return -1;
}




struct redis *redis_new(u_int32_t ip, u_int16_t port, int db) {
	struct redis *r;

	r = malloc(sizeof(*r));
	ZERO(*r);

	sprintf(r->host, IPF, IPP(ip));
	r->port = port;
	r->db = db;

	if (redis_connect(r, 10))
		goto err;

	return r;

err:
	free(r);
	return NULL;
}




int redis_restore(struct callmaster *m) {
	struct redis *r = m->redis;
	redisReply *rp, *rp2, *rp3;
	int i;

	rp = redisCommand(r->ctx, "SMEMBERS calls");
	if (!rp || rp->type != REDIS_REPLY_ARRAY) {
		mylog(LOG_ERR, "Could not retrieve call list from Redis: %s\n", r->ctx->errstr);
		goto err;
	}

	for (i = 0; i < rp->elements; i++) {
		rp2 = rp->element[i];
		if (rp2->type != REDIS_REPLY_STRING)
			continue;

		rp3 = redisCommand(r->ctx, "HMGET %s callid created", rp2->str);

		if (!rp3)
			goto del;
		if (rp3->type != REDIS_REPLY_ARRAY)
			goto del2;
		if (rp3->elements != 2)
			goto del2;
		if (rp3->element[0]->type != REDIS_REPLY_STRING)
			goto del2;
		if (rp3->element[1]->type != REDIS_REPLY_INTEGER)
			goto del2;

		continue;

del2:
		freeReplyObject(rp3);
del:
		redisCommandNR(r->ctx, "DEL %s", rp2->str);
		redisCommandNR(r->ctx, "SREM calls %s", rp2->str);
	}

	freeReplyObject(rp);

	return 0;

err:
	return -1;
}
