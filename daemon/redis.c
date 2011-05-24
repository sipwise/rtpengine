#include <stdio.h>
#include <hiredis.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "redis.h"
#include "aux.h"
#include "call.h"
#include "log.h"





#define redisCommandNR(a...) (int)({ void *__tmp; __tmp = redisCommand(a); if (__tmp) freeReplyObject(__tmp); __tmp ? 0 : -1;})





static int redis_check_type(struct redis *r, char *key, char *suffix, char *type) {
	redisReply *rp;

	rp = redisCommand(r->ctx, "TYPE %s%s", key, suffix ? : "");
	if (!rp || rp->type != REDIS_REPLY_STATUS)
		return -1;
	if (strcmp(rp->str, type) && strcmp(rp->str, "none"))
		redisCommandNR(r->ctx, "DEL %s%s", key, suffix ? : "");
	return 0;
}




static void redis_consume(struct redis *r, int count) {
	redisReply *rp;

	while (count-- > 0) {
		redisGetReply(r->ctx, (void **) &rp);
		freeReplyObject(rp);
	}
}




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




static void redis_delete_uuid(char *uuid, struct callmaster *m) {
	struct redis *r = m->redis;
	redisReply *rp, *rp2;
	int i, count = 0;

	if (!r)
		return;

	rp = redisCommand(r->ctx, "LRANGE %s-streams 0 -1", uuid);
	if (!rp || rp->type != REDIS_REPLY_ARRAY)
		return;

	for (i = 0; i < rp->elements; i++) {
		rp2 = rp->element[i];
		if (rp2->type != REDIS_REPLY_STRING)
			continue;

		redisAppendCommand(r->ctx, "DEL %s:0 %s:1", rp2->str, rp2->str);
		count++;
	}

	redisAppendCommand(r->ctx, "DEL %s-streams %s", uuid, uuid);
	redisAppendCommand(r->ctx, "SREM calls %s", uuid);
	count += 2;

	redis_consume(r, count);
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
		if (rp3->element[1]->type != REDIS_REPLY_STRING)
			goto del2;

		continue;

del2:
		freeReplyObject(rp3);
del:
		redis_delete_uuid(rp2->str, m);
	}

	freeReplyObject(rp);

	return 0;

err:
	return -1;
}




void redis_update(struct call *c) {
	struct callmaster *cm = c->callmaster;
	struct redis *r = cm->redis;
	char uuid[37];
	GList *l;
	struct callstream *cs;
	int i;
	struct peer *p;

	if (!r)
		return;

	if (!c->redis_uuid[0])
		uuid_str_generate(c->redis_uuid);

	redis_check_type(r, c->redis_uuid, NULL, "hash");
	redisCommandNR(r->ctx, "HMSET %s callid %s created %i", c->redis_uuid, c->callid, c->created);
	redisCommandNR(r->ctx, "DEL %s-streams-temp", c->redis_uuid);

	for (l = c->callstreams->head; l; l = l->next) {
		cs = l->data;
		uuid_str_generate(uuid);

		for (i = 0; i < 2; i++) {
			p = &cs->peers[i];

			redisCommandNR(r->ctx, "DEL %s:%i", uuid, i);
			redisCommandNR(r->ctx, "HMSET %s:%i ip " IPF " port %i localport %i last-rtp %i last-rtcp %i kernel %i filled %i confirmed %i", uuid, i, IPP(p->rtps[0].peer.ip), p->rtps[0].peer.port, p->rtps[0].localport, p->rtps[0].last, p->rtps[1].last, p->kernelized, p->filled, p->confirmed);
			redisCommandNR(r->ctx, "EXPIRE %s:%i 86400", uuid, i);
		}

		redisCommandNR(r->ctx, "RPUSH %s-streams-temp %s", c->redis_uuid, uuid);
	}

	redisCommandNR(r->ctx, "RENAME %s-streams-temp %s-streams", c->redis_uuid, c->redis_uuid);	/* XXX causes orphaned keys */
	redisCommandNR(r->ctx, "EXPIRE %s-streams 86400", c->redis_uuid);
	redisCommandNR(r->ctx, "EXPIRE %s 86400", c->redis_uuid);
	redisCommandNR(r->ctx, "SADD calls %s", c->redis_uuid);
}





void redis_delete(struct call *c) {
	redis_delete_uuid(c->redis_uuid, c->callmaster);
}
