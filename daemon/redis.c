#include "redis.h"

#include <stdio.h>
#include <hiredis/hiredis.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <glib.h>
#include <stdarg.h>
#include <ctype.h>
#include <glib.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libevent.h>
#include <event2/thread.h>
#include <stdlib.h>
#include <glib-object.h>
#include <json-glib/json-glib.h>
#include <inttypes.h>
#include <stdbool.h>

#include "compat.h"
#include "aux.h"
#include "call.h"
#include "log.h"
#include "log_funcs.h"
#include "str.h"
#include "crypto.h"
#include "dtls.h"
#include "recording.h"
#include "rtplib.h"
#include "str.h"
#include "ssrc.h"
#include "main.h"
#include "codec.h"

struct redis		*rtpe_redis;
struct redis		*rtpe_redis_write;
struct redis		*rtpe_redis_notify;


INLINE redisReply *redis_expect(int type, redisReply *r) {
	if (!r)
		return NULL;
	if (r->type != type) {
		freeReplyObject(r);
		return NULL;
	}
	return r;
}

#if __YCM

/* format checking in YCM editor */

INLINE void redis_pipe(struct redis *r, const char *fmt, ...)
	__attribute__((format(printf,2,3)));
INLINE redisReply *redis_get(struct redis *r, int type, const char *fmt, ...)
	__attribute__((format(printf,3,4)));
static int redisCommandNR(redisContext *r, const char *fmt, ...)
	__attribute__((format(printf,2,3)));

#define PB "%.*s"
#define STR(x) (int) (x)->len, (x)->s
#define STR_R(x) (int) (x)->len, (x)->str
#define S_LEN(s,l) (int) (l), (s)

#else

#define PB "%b"
#define STR(x) (x)->s, (size_t) (x)->len
#define STR_R(x) (x)->str, (size_t) (x)->len
#define S_LEN(s,l) (s), (size_t) (l)

#endif

#define REDIS_FMT(x) (int) (x)->len, (x)->str

static int redis_check_conn(struct redis *r);
static void json_restore_call(struct redis *r, const str *id, bool foreign);
static int redis_connect(struct redis *r, int wait);
static int json_build_ssrc(struct call_monologue *ml, JsonReader *root_reader);

static void redis_pipe(struct redis *r, const char *fmt, ...) {
	va_list ap;

	if (!r->ctx) {
		ilog(LOG_ERROR, "Unable to pipe redis command. No redis context");
		return;
	}
	va_start(ap, fmt);
	redisvAppendCommand(r->ctx, fmt, ap);
	va_end(ap);
	r->pipeline++;
}
static redisReply *redis_get(struct redis *r, int type, const char *fmt, ...) {
	va_list ap;
	redisReply *ret;

	if (!r->ctx) {
		ilog(LOG_ERROR, "Unable to get redis reply. No redis context");
		return NULL;
	}
	va_start(ap, fmt);
	ret = redis_expect(type, redisvCommand(r->ctx, fmt, ap));
	va_end(ap);

	return ret;
}
static int redisCommandNR(redisContext *r, const char *fmt, ...) {
	va_list ap;
	redisReply *ret;
	int i = 0;

	if (!r) {
		ilog(LOG_ERROR, "Unable to send redis command. No redis context");
		return -1;
	}
	va_start(ap, fmt);
	ret = redisvCommand(r, fmt, ap);
	va_end(ap);

	if (!ret)
		return -1;

	if (ret->type == REDIS_REPLY_ERROR) {
		i = -1;
		ilog(LOG_WARNING, "Redis returned error to command '%s': %s", fmt, ret->str);
	}

	freeReplyObject(ret);
	return i;
}


/* called with r->lock held */
static int redis_check_type(struct redis *r, char *key, char *suffix, char *type) {
	redisReply *rp;

	if (!r->ctx) {
		ilog(LOG_ERROR, "Unable to check redis reply type. No redis context");
		return -1;
	}

	rp = redisCommand(r->ctx, "TYPE %s%s", key, suffix ? : "");
	if (!rp)
		return -1;
	if (rp->type != REDIS_REPLY_STATUS) {
		freeReplyObject(rp);
		return -1;
	}
	if (strcmp(rp->str, type) && strcmp(rp->str, "none"))
		redisCommandNR(r->ctx, "DEL %s%s", key, suffix ? : "");
	freeReplyObject(rp);
	return 0;
}


/* called with r->lock held */
static void redis_consume(struct redis *r) {
	redisReply *rp;

	if (!r->ctx) {
		ilog(LOG_ERROR, "Unable to consume pipelined replies. No redis context");
		r->pipeline = 0;
		return;
	}
	while (r->pipeline) {
		if (redisGetReply(r->ctx, (void **) &rp) == REDIS_OK)
			freeReplyObject(rp);
		r->pipeline--;
	}
}

int redis_set_timeout(struct redis* r, int timeout) {
	struct timeval tv_cmd;

	if (!timeout)
		return 0;
	tv_cmd.tv_sec = (int) timeout / 1000;
	tv_cmd.tv_usec = (int) (timeout % 1000) * 1000;
	if (redisSetTimeout(r->ctx, tv_cmd))
		return -1;
	ilog(LOG_INFO, "Setting timeout for Redis commands to %d milliseconds",timeout);
	return 0;
}

int redis_reconnect(struct redis* r) {
	int rval;
	mutex_lock(&r->lock);
	rval = redis_connect(r,1);
	if (rval)
		r->state = REDIS_STATE_DISCONNECTED;
	mutex_unlock(&r->lock);
	return rval;
}

// struct must be locked or single thread
static int redis_select_db(struct redis *r, int db) {
	if (db == r->current_db)
		return 0;
	if (redisCommandNR(r->ctx, "SELECT %i", db))
		return -1;
	r->current_db = db;
	return 0;
}

/* called with r->lock held if necessary */
static int redis_connect(struct redis *r, int wait) {
	struct timeval tv;
	redisReply *rp;
	char *s;
	int cmd_timeout, connect_timeout;

	if (r->ctx)
		redisFree(r->ctx);
	r->ctx = NULL;
	r->current_db = -1;

	rwlock_lock_r(&rtpe_config.config_lock);
	connect_timeout = rtpe_config.redis_connect_timeout;
	cmd_timeout = rtpe_config.redis_cmd_timeout;
	rwlock_unlock_r(&rtpe_config.config_lock);

	tv.tv_sec = (int) connect_timeout / 1000;
	tv.tv_usec = (int) (connect_timeout % 1000) * 1000;
	r->ctx = redisConnectWithTimeout(r->host, r->endpoint.port, tv);

	if (!r->ctx)
		goto err;
	if (r->ctx->err)
		goto err2;

	if (redis_set_timeout(r,cmd_timeout))
		goto err2;

	if (r->auth) {
		if (redisCommandNR(r->ctx, "AUTH %s", r->auth))
			goto err2;
	}
	else {
		if (redisCommandNR(r->ctx, "PING"))
			goto err2;
	}

	if (redis_select_db(r, r->db))
		goto err2;

	while (wait-- >= 0) {
		ilog(LOG_INFO, "Asking Redis whether it's master or slave...");
		rp = redisCommand(r->ctx, "INFO");
		if (!rp) {
			goto err2;
		}

		s = strstr(rp->str, "role:");
		if (!s) {
			goto err3;
		}

		if (!memcmp(s, "role:master", 11) || !memcmp(s, "role:active-replica", 19)) {
			if (r->role == MASTER_REDIS_ROLE || r->role == ANY_REDIS_ROLE) {
				ilog(LOG_INFO, "Connected to Redis %s in master mode", 
					endpoint_print_buf(&r->endpoint));
				goto done;
			} else if (r->role == SLAVE_REDIS_ROLE) {
				ilog(LOG_INFO, "Connected to Redis %s in master mode, but wanted mode is slave; retrying...",
					endpoint_print_buf(&r->endpoint));
				goto next;
			}
		} else if (!memcmp(s, "role:slave", 10)) {
			if (r->role == SLAVE_REDIS_ROLE || r->role == ANY_REDIS_ROLE) {
				ilog(LOG_INFO, "Connected to Redis %s in slave mode",
					endpoint_print_buf(&r->endpoint));
				goto done;
			} else if (r->role == MASTER_REDIS_ROLE) {
				ilog(LOG_INFO, "Connected to Redis %s in slave mode, but wanted mode is master; retrying...",
					endpoint_print_buf(&r->endpoint));
				goto next;
			}
		} else {
			goto err3;
		}

next:
		freeReplyObject(rp);
		usleep(1000000);
	}

	goto err2;

done:
	freeReplyObject(rp);
	redis_check_type(r, "calls", NULL, "set");
	return 0;

err3:
	freeReplyObject(rp);
err2:
	if (r->ctx->err) {
		rlog(LOG_ERR, "Failed to connect to Redis %s, error: %s",
			endpoint_print_buf(&r->endpoint), r->ctx->errstr);
		return -1;
	}
	redisFree(r->ctx);
	r->ctx = NULL;
err:
	rlog(LOG_ERR, "Failed to connect to Redis %s",
		endpoint_print_buf(&r->endpoint));
	return -1;
}


void on_redis_notification(redisAsyncContext *actx, void *reply, void *privdata) {
	struct redis *r = 0;
	struct call *c = NULL;
	str callid;
	str keyspace_id;

	if (!rtpe_redis_notify) {
		rlog(LOG_ERROR, "A redis notification has been received but no redis_notify database found");
		return;
	}

	r = rtpe_redis_notify;

	mutex_lock(&r->lock);

	redisReply *rr = (redisReply*)reply;

	if (reply == NULL || rr->type != REDIS_REPLY_ARRAY)
		goto err;

	for (int j = 0; j < rr->elements; j++) {
		rlog(LOG_DEBUG, "Redis-Notify: %u) %s%s%s\n", j, FMT_M(rr->element[j]->str));
	}

	if (rr->elements != 4)
		goto err;

	// format: __keyspace@<db>__:<key>
	str_init_len(&keyspace_id, rr->element[2]->str, rr->element[2]->len);

	if (str_shift_cmp(&keyspace_id, "__keyspace@"))
		goto err;

	// extract <db>
	char *endp;
	r->db = strtoul(keyspace_id.s, &endp, 10);
	if (endp == keyspace_id.s || *endp != '_')
		goto err;
	if (str_shift(&keyspace_id, endp - keyspace_id.s + 3))
		goto err;
	if (keyspace_id.s[-1] != ':')
		goto err;

	// now at <key>
	callid = keyspace_id;

	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED)
		goto err;

	// select the right db for restoring the call
	if (redis_select_db(r, r->db)) {
		if (r->ctx && r->ctx->err)
			rlog(LOG_ERROR, "Redis error: %s", r->ctx->errstr);
		redisFree(r->ctx);
		r->ctx = NULL;
		goto err;
	}

	if (strncmp(rr->element[3]->str,"set",3)==0) {
		c = call_get(&callid);
		if (c) {
			rwlock_unlock_w(&c->master_lock);
			if (IS_FOREIGN_CALL(c)) {
				c->redis_hosted_db = rtpe_redis_write->db; // don't delete from foreign DB
				call_destroy(c);
			}
			else {
				rlog(LOG_WARN, "Redis-Notifier: Ignoring SET received for OWN call: " STR_FORMAT "\n", STR_FMT(&callid));
				goto err;
			}
		}

		redis_select_db(r, r->db);
	        mutex_unlock(&r->lock);

		// unlock before restoring calls to avoid deadlock in case err happens
		json_restore_call(r, &callid, true);

	        mutex_lock(&r->lock);
	}

	if (strncmp(rr->element[3]->str,"del",3)==0) {
		c = call_get(&callid);
		if (!c) {
			rlog(LOG_NOTICE, "Redis-Notifier: DEL did not find call with callid: " STR_FORMAT "\n", STR_FMT(&callid));
			goto err;
		}
		rwlock_unlock_w(&c->master_lock);
		if (!IS_FOREIGN_CALL(c)) {
			rlog(LOG_WARN, "Redis-Notifier: Ignoring DEL received for an OWN call: " STR_FORMAT "\n", STR_FMT(&callid));
			goto err;
		}
		call_destroy(c);
	}

err:
	if (c) {
		// because of call_get(..)
		obj_put(c);
		log_info_clear();
	}

	mutex_unlock(&r->lock);
}

void redis_delete_async_context_connect(const redisAsyncContext *redis_delete_async_context, int status) {
	if (status == REDIS_ERR) {
		rtpe_redis_write->async_ctx = NULL;
		if (redis_delete_async_context->errstr) {
			rlog(LOG_ERROR, "redis_delete_async_context_connect error %d: %s",
				redis_delete_async_context->err, redis_delete_async_context->errstr);
		} else {
			rlog(LOG_ERROR, "redis_delete_async_context_connect error %d: no errstr",
				redis_delete_async_context->err);
		}
	} else if (status == REDIS_OK) {
		rlog(LOG_NOTICE, "redis_delete_async_context_connect initiated by user");
	} else {
		rlog(LOG_ERROR, "redis_delete_async_context_connect invalid status code %d", status);
	}
}

void redis_delete_async_context_disconnect(const redisAsyncContext *redis_delete_async_context, int status) {
	rtpe_redis_write->async_ctx = NULL;
	if (status == REDIS_ERR) {
		if (redis_delete_async_context->errstr) {
			rlog(LOG_ERROR, "redis_delete_async_context_disconnect error %d: %s",
				redis_delete_async_context->err, redis_delete_async_context->errstr);
		} else {
			rlog(LOG_ERROR, "redis_delete_async_context_disconnect error %d: no errstr",
				redis_delete_async_context->err);
		}
	} else if (status == REDIS_OK) {
		rlog(LOG_NOTICE, "redis_delete_async_context_disconnect initiated by user");
	} else {
		rlog(LOG_ERROR, "redis_delete_async_context_disconnect invalid status code %d", status);
	}
}

void redis_notify_async_context_disconnect(const redisAsyncContext *redis_notify_async_context, int status) {
	if (status == REDIS_ERR) {
		if (redis_notify_async_context->errstr) {
			rlog(LOG_ERROR, "redis_notify_async_context_disconnect error %d on context free: %s",
				redis_notify_async_context->err, redis_notify_async_context->errstr);
		} else {
			rlog(LOG_ERROR, "redis_notify_async_context_disconnect error %d on context free: no errstr",
				redis_notify_async_context->err);
		}
	} else if (status == REDIS_OK) {
		rlog(LOG_NOTICE, "redis_notify_async_context_disconnect initiated by user");
	} else {
		rlog(LOG_ERROR, "redis_notify_async_context_disconnect invalid status code %d", status);
	}
}

// connect_cb = connect callback, disconnect_cb = disconnect callback
int redis_async_context_alloc(struct redis *r, void *connect_cb, void *disconnect_cb) {
	// sanity checks
	if (!r) {
		rlog(LOG_ERROR, "redis_async_context_alloc: NULL r");
		return -1;
	} else {
		rlog(LOG_DEBUG, "redis_async_context_alloc: Use Redis %s", endpoint_print_buf(&r->endpoint));
	}

	// alloc async context
	r->async_ctx = redisAsyncConnect(r->host, r->endpoint.port);
	if (!r->async_ctx) {
		rlog(LOG_ERROR, "redis_async_context_alloc: can't create new");
		return -1;
	}

	if (r->async_ctx->err) {
		rlog(LOG_ERROR, "redis_async_context_alloc: can't create new error: %s", r->async_ctx->errstr);
		return -1;
	}

	// callbacks async context
	if (redisAsyncSetConnectCallback(r->async_ctx, connect_cb) != REDIS_OK) {
		rlog(LOG_ERROR, "redis_async_context_alloc: can't set connect callback");
		return -1;
	}

	if (redisAsyncSetDisconnectCallback(r->async_ctx, disconnect_cb) != REDIS_OK) {
		rlog(LOG_ERROR, "redis_async_context_alloc: can't set disconnect callback");
		return -1;
	}

	rlog(LOG_DEBUG, "redis_async_context_alloc: Success");

	return 0;
}

int redis_async_event_base_action(struct redis *r, enum event_base_action action) {
	// sanity checks
	if (!r) {
		rlog(LOG_ERR, "redis_async_event_base_action: NULL r");
		return -1;
	} else {
		rlog(LOG_DEBUG, "redis_async_event_base_action: Use Redis %s", endpoint_print_buf(&r->endpoint));
	}

	if (!r->async_ev && action != EVENT_BASE_ALLOC) {
		rlog(LOG_NOTICE, "redis_async_event_base_action: async_ev is NULL on event base action %d", action);
		return -1;
	}

	// exec event base action
	switch (action) {
		case EVENT_BASE_ALLOC:
			r->async_ev = event_base_new();
			if (!r->async_ev) {
				rlog(LOG_ERROR, "redis_async_event_base_action: Fail alloc async_ev");
				return -1;
			} else {
				rlog(LOG_DEBUG, "redis_async_event_base_action: Success alloc async_ev");
			}
			break;

		case EVENT_BASE_FREE:
			event_base_free(r->async_ev);
			rlog(LOG_DEBUG, "redis_async_event_base_action: Success free async_ev");
			break;

		case EVENT_BASE_LOOPBREAK:
			if (event_base_loopbreak(r->async_ev)) {
				rlog(LOG_ERROR, "redis_async_event_base_action: Fail loopbreak async_ev");
				return -1;
			} else {
				rlog(LOG_DEBUG, "redis_async_event_base_action: Success loopbreak async_ev");
			}
			break;

		default:
			rlog(LOG_ERROR, "redis_async_event_base_action: No event base action found: %d", action);
			return -1;
	}

	return 0;
}

int redis_notify_subscribe_action(struct redis *r, enum subscribe_action action, int keyspace) {
	if (!r->async_ctx) {
		rlog(LOG_ERROR, "redis_notify_async_context is NULL on subscribe action");
		return -1;
	}

	if (r->async_ctx->err) {
		rlog(LOG_ERROR, "redis_notify_async_context error on subscribe action: %s", r->async_ctx->errstr);
		return -1;
	}

	switch (action) {
	case SUBSCRIBE_KEYSPACE:
		if (redisAsyncCommand(r->async_ctx, on_redis_notification, NULL, "psubscribe __keyspace@%i__:*", keyspace) != REDIS_OK) {
			rlog(LOG_ERROR, "Fail redisAsyncCommand on JSON SUBSCRIBE_KEYSPACE");
			return -1;
		}
		break;
	case UNSUBSCRIBE_KEYSPACE:
		if (redisAsyncCommand(r->async_ctx, on_redis_notification, NULL, "punsubscribe __keyspace@%i__:*", keyspace) != REDIS_OK) {
			rlog(LOG_ERROR, "Fail redisAsyncCommand on JSON UNSUBSCRIBE_KEYSPACE");
			return -1;
		}
		break;
	case UNSUBSCRIBE_ALL:
		if (redisAsyncCommand(r->async_ctx, on_redis_notification, NULL, "punsubscribe") != REDIS_OK) {
			rlog(LOG_ERROR, "Fail redisAsyncCommand on JSON UNSUBSCRIBE_ALL");
			return -1;
		}
		break;
	default:
		rlog(LOG_ERROR, "No subscribe action found: %d", action);
		return -1;
	}

	return 0;
}

static int redis_delete_async(struct redis *r) {
	// sanity checks
	if (!r) {
		rlog(LOG_ERROR, "redis_delete_async: Don't use Redis async deletions beacause no redis/redis_write.");
		return -1 ;
	}

	// alloc new redis async context
	if (r->async_ctx == NULL && redis_async_context_alloc(r, redis_delete_async_context_connect, redis_delete_async_context_disconnect) < 0) {
		r->async_ctx = NULL;
		rlog(LOG_ERROR, "redis_delete_async: Failed to alloc async_ctx");
		return -1;
	}

	// attach event base
	if (redisLibeventAttach(r->async_ctx, r->async_ev) == REDIS_ERR) {
		if (r->async_ctx->err) {
			rlog(LOG_ERROR, "redis_delete_async: redis_delete_async_context can't attach event base error: %s", r->async_ctx->errstr);
		} else {
			rlog(LOG_ERROR, "redis_delete_async: redis_delete_async_context can't attach event base");

		}
		return -1;
	}

	// commands
	if (r->auth) {
		if (redisAsyncCommand(r->async_ctx, NULL, NULL, "AUTH %s", r->auth) != REDIS_OK) {
			rlog(LOG_ERROR, "redis_delete_async: Fail redisAsyncCommand on AUTH");
			return -1;
		}
	} else {
		if (redisAsyncCommand(r->async_ctx, NULL, NULL, "PING") != REDIS_OK) {
			rlog(LOG_ERROR, "redis_delete_async: Fail redisAsyncCommand on PING");
			return -1;
		}
	}

	// delete commands
	gchar *redis_command;
	gint redis_command_total = 0;

	mutex_lock(&r->async_lock);
	while (!g_queue_is_empty(&r->async_queue)) {
		redis_command_total++;
		redis_command = g_queue_pop_head(&r->async_queue);

		if (redisAsyncCommand(r->async_ctx, NULL, NULL, redis_command) != REDIS_OK) {
			rlog(LOG_ERROR, "redis_delete_async: Fail redisAsyncCommand on DELETE");
		}

		g_free(redis_command);
	}
	mutex_unlock(&r->async_lock);

	rlog(LOG_NOTICE, "redis_delete_async: Queued DELETE redisAsyncCommand total: %d", redis_command_total);

	// dispatch event base => thread blocks here
	if (event_base_dispatch(r->async_ev) < 0) {
		rlog(LOG_ERROR, "redis_delete_async: Fail event_base_dispatch()");
		return -1;
	}

	// loopbreak
	redisAsyncDisconnect(r->async_ctx);
	r->async_ctx = NULL;

	return 0;
}

static int redis_notify(struct redis *r) {
	GList *l;

	if (!r) {
		rlog(LOG_ERROR, "redis_notify database is NULL on redis_notify()");
		return -1;
	}

	if (!r->async_ctx) {
		rlog(LOG_ERROR, "redis_notify_async_context is NULL on redis_notify()");
		return -1;
	}

	if (!r->async_ev) {
		rlog(LOG_ERROR, "redis_notify_event_base is NULL on redis_notify()");
		return -1;
	}

	// get redis_notify database
	rlog(LOG_INFO, "Use Redis %s to subscribe to notifications", endpoint_print_buf(&r->endpoint));

	// attach event base
	if (redisLibeventAttach(r->async_ctx, r->async_ev) == REDIS_ERR) {
		if (r->async_ctx->err) {
			rlog(LOG_ERROR, "redis_notify_async_context can't attach event base error: %s", r->async_ctx->errstr);
		} else {
			rlog(LOG_ERROR, "redis_notify_async_context can't attach event base");

		}
		return -1;
	}

	if (r->auth) {
		if (redisAsyncCommand(r->async_ctx, on_redis_notification, NULL, "AUTH %s", r->auth) != REDIS_OK) {
			rlog(LOG_ERROR, "Fail redisAsyncCommand on AUTH");
			return -1;
		}
	}

	// subscribe to the values in the configured keyspaces
	rwlock_lock_r(&rtpe_config.config_lock);
	for (l = rtpe_config.redis_subscribed_keyspaces.head; l; l = l->next) {
		redis_notify_subscribe_action(r, SUBSCRIBE_KEYSPACE, GPOINTER_TO_INT(l->data));
	}
	rwlock_unlock_r(&rtpe_config.config_lock);

	// dispatch event base => thread blocks here
	if (event_base_dispatch(r->async_ev) < 0) {
		rlog(LOG_ERROR, "Fail event_base_dispatch()");
		return -1;
	}

	return 0;
}

void redis_delete_async_loop(void *d) {
	struct redis *r = NULL;

	// sanity checks
	r = rtpe_redis_write;
	if (!r) {
		rlog(LOG_ERROR, "redis_delete_async_loop: Don't use Redis async deletions beacause no redis/redis_write.");
		return ;
	}

	r->async_last = rtpe_now.tv_sec;

	// init libevent for pthread usage
	if (evthread_use_pthreads() < 0) {
		ilog(LOG_ERROR, "redis_delete_async_loop: evthread_use_pthreads failed.");
		return ;
	}

	// alloc libevent base
	if (redis_async_event_base_action(r, EVENT_BASE_ALLOC) < 0) {
		rlog(LOG_ERROR, "redis_delete_async_loop: Failed to EVENT_BASE_ALLOC.");
		return ;
	}

	// loop (almost) forever
	while (!rtpe_shutdown) {
		redis_delete_async(r);
		sleep(1);
	}
}

void redis_notify_loop(void *d) {
	int seconds = 1, redis_notify_return = 0;
	time_t next_run = rtpe_now.tv_sec;
	struct redis *r;

	r = rtpe_redis_notify;
	if (!r) {
		rlog(LOG_ERROR, "Don't use Redis notifications. See --redis-notifications parameter.");
		return ;
	}

	// init libevent for pthread usage
	if (evthread_use_pthreads() < 0) {
		ilog(LOG_ERROR, "evthread_use_pthreads failed");
		return ;
	}

	// alloc redis async context 
	if (redis_async_context_alloc(r, NULL, redis_notify_async_context_disconnect) < 0) {
		return ;
	}

	// alloc event base
	if (redis_async_event_base_action(r, EVENT_BASE_ALLOC) < 0) {
		return ;
	}

	// initial redis_notify
	if (redis_check_conn(r) == REDIS_STATE_CONNECTED) {
		redis_notify_return = redis_notify(r);
	}

	// loop redis_notify => in case of lost connection
	while (!rtpe_shutdown) {
		gettimeofday(&rtpe_now, NULL);
		if (rtpe_now.tv_sec < next_run) {
			usleep(100000);
			continue;
		}

		next_run = rtpe_now.tv_sec + seconds;

		if (redis_check_conn(r) == REDIS_STATE_CONNECTED || redis_notify_return < 0) {
			r->async_ctx = NULL;
			// alloc new redis async context upon redis breakdown
			if (redis_async_context_alloc(r, NULL, redis_notify_async_context_disconnect) < 0) {
				continue;
			}

			// prepare notifications
			redis_notify_return = redis_notify(r);
		}
	}

	// unsubscribe notifications
	redis_notify_subscribe_action(r, UNSUBSCRIBE_ALL, 0);

	// free async context
	redisAsyncDisconnect(r->async_ctx);
	r->async_ctx = NULL;
}

struct redis *redis_new(const endpoint_t *ep, int db, const char *auth,
		enum redis_role role, int no_redis_required) {
	struct redis *r;
	r = g_slice_alloc0(sizeof(*r));

	r->endpoint = *ep;
	sockaddr_print(&ep->address, r->host, sizeof(r->host));
	r->db = db;
	r->auth = auth;
	r->role = role;
	r->state = REDIS_STATE_DISCONNECTED;
	r->no_redis_required = no_redis_required;
	r->restore_tick = 0;
	r->consecutive_errors = 0;
	mutex_init(&r->lock);

	if (redis_connect(r, 10)) {
		if (r->no_redis_required) {
			rlog(LOG_WARN, "Starting with no initial connection to Redis %s !",
				endpoint_print_buf(&r->endpoint));
			return r;
		}
		goto err;
	}

	// redis is connected
	rlog(LOG_INFO, "Established initial connection to Redis %s",
		endpoint_print_buf(&r->endpoint));
	r->state = REDIS_STATE_CONNECTED;
	return r;

err:
	mutex_destroy(&r->lock);
	g_slice_free1(sizeof(*r), r);
	return NULL;
}


void redis_close(struct redis *r) {
	if (!r)
		return;
	if (r->ctx)
		redisFree(r->ctx);
	r->ctx = NULL;
	mutex_destroy(&r->lock);
	g_slice_free1(sizeof(*r), r);
}

static void redis_count_err_and_disable(struct redis *r)
{
	int allowed_errors;
	int disable_time;

	rwlock_lock_r(&rtpe_config.config_lock);
	allowed_errors = rtpe_config.redis_allowed_errors;
	disable_time = rtpe_config.redis_disable_time;
	rwlock_unlock_r(&rtpe_config.config_lock);

	if (allowed_errors < 0) {
		return;
	}

	r->consecutive_errors++;
	if (r->consecutive_errors > allowed_errors) {
		r->restore_tick = rtpe_now.tv_sec + disable_time;
		ilog(LOG_WARNING, "Redis server %s disabled for %d seconds",
				endpoint_print_buf(&r->endpoint),
				disable_time);
	}
}

/* must be called with r->lock held */
static int redis_check_conn(struct redis *r) {
	gettimeofday(&rtpe_now, NULL);

	if ((r->state == REDIS_STATE_DISCONNECTED) && (r->restore_tick > rtpe_now.tv_sec)) {
		ilog(LOG_WARNING, "Redis server %s is disabled. Don't try RE-Establishing for %" TIME_T_INT_FMT " more seconds",
				endpoint_print_buf(&r->endpoint),r->restore_tick - rtpe_now.tv_sec);
		return REDIS_STATE_DISCONNECTED;
	}

	if (r->state == REDIS_STATE_DISCONNECTED)
		ilog(LOG_INFO, "RE-Establishing connection for Redis server %s",endpoint_print_buf(&r->endpoint));

	// try redis connection
	if (r->ctx && redisCommandNR(r->ctx, "PING") == 0) {
		// redis is connected
		if (r->state == REDIS_STATE_DISCONNECTED) {
			rlog(LOG_INFO, "RE-Established connection to Redis %s; PING works",
				endpoint_print_buf(&r->endpoint));
			r->state = REDIS_STATE_CONNECTED;
		}
		return REDIS_STATE_CONNECTED;
	}

	// redis is disconnected
	if (r->state == REDIS_STATE_CONNECTED) {
		rlog(LOG_ERR, "Lost connection to Redis %s",
			endpoint_print_buf(&r->endpoint));
		r->state = REDIS_STATE_DISCONNECTED;
	}

	// try redis reconnect => will free current r->ctx
	if (redis_connect(r, 1)) {
		// redis is disconnected
		redis_count_err_and_disable(r);
		return REDIS_STATE_DISCONNECTED;
	}

	r->consecutive_errors = 0;

	// redis is connected
	if (r->state == REDIS_STATE_DISCONNECTED) {
		rlog(LOG_INFO, "RE-Established connection to Redis %s",
			endpoint_print_buf(&r->endpoint));
		r->state = REDIS_STATE_CONNECTED;
	}

	// redis is re-connected
	return REDIS_STATE_CONNECTED;
}

/* called with r->lock held and c->master_lock held */
static void redis_delete_call_json(struct call *c, struct redis *r) {
	redis_pipe(r, "DEL "PB"", STR(&c->callid));
	redis_consume(r);
}

static void redis_delete_async_call_json(struct call *c, struct redis *r) {
	gchar *redis_command;

	redis_command = g_strdup_printf("SELECT %i", c->redis_hosted_db);
	g_queue_push_tail(&r->async_queue, redis_command);

	redis_command = g_strdup_printf("DEL " STR_FORMAT, STR_FMT(&c->callid));
	g_queue_push_tail(&r->async_queue, redis_command);
}

INLINE void json_builder_add_string_value_uri_enc(JsonBuilder *builder, const char* tmp, int len) {
	char enc[len * 3 + 1];
	str_uri_encode_len(enc, tmp, len);
	json_builder_add_string_value(builder,enc);
}
INLINE str *json_reader_get_string_value_uri_enc(JsonReader *root_reader) {
	const char *s = json_reader_get_string_value(root_reader);
	if (!s)
		return NULL;
	str *out = str_uri_decode_len(s, strlen(s));
	return out; // must be free'd
}
// XXX rework restore procedure to use functions like this everywhere and eliminate the GHashTable
INLINE long long json_reader_get_ll(JsonReader *root_reader, const char *key) {
	if (!json_reader_read_member(root_reader, key))
		return -1;
	str *ret = json_reader_get_string_value_uri_enc(root_reader);
	long long r = strtoll(ret->s, NULL, 10);
	free(ret);
	json_reader_end_member(root_reader);
	return r;
}

static int json_get_hash(struct redis_hash *out,
		const char *key, unsigned int id, JsonReader *root_reader)
{
	static unsigned int MAXKEYLENGTH = 512;
	char key_concatted[MAXKEYLENGTH];
	int rc=0;
	AUTO_CLEANUP_GVBUF(orig_members);

	if (id == -1) {
		rc = snprintf(key_concatted, MAXKEYLENGTH, "%s",key);
	} else {
		rc = snprintf(key_concatted, MAXKEYLENGTH, "%s-%u",key,id);
	}
	if (rc>=MAXKEYLENGTH) {
		rlog(LOG_ERROR,"Json key too long.");
		goto err;
	}

	if (!json_reader_read_member(root_reader, key_concatted)) {
		rlog(LOG_ERROR, "Could not read json member: %s",key_concatted);
		goto err;
	}

	out->ht = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
	if (!out->ht)
		goto err;

	gchar **members = json_reader_list_members(root_reader);
	orig_members = members;
	int nmemb = json_reader_count_members (root_reader);

	for (int i=0; i < nmemb; ++i) {

		if (!json_reader_read_member(root_reader, *members)) {
			rlog(LOG_ERROR, "Could not read json member: %s",*members);
			goto err3;
		}
		str *val = json_reader_get_string_value_uri_enc(root_reader);
		char* tmp = strdup(*members);

		if (g_hash_table_insert_check(out->ht, tmp, val) != TRUE) {
			rlog(LOG_WARNING,"Key %s already exists", tmp);
			goto err3;
		}

		json_reader_end_member(root_reader);

		++members;
	} // for
	json_reader_end_member (root_reader);

	return 0;

err3:
	g_hash_table_destroy(out->ht);
err:
	return -1;
}

static void json_destroy_hash(struct redis_hash *rh) {
        g_hash_table_destroy(rh->ht);
}

static void json_destroy_list(struct redis_list *rl) {
        unsigned int i;

        for (i = 0; i < rl->len; i++) {
                json_destroy_hash(&rl->rh[i]);
        }
        free(rl->rh);
        free(rl->ptrs);
}

static int redis_hash_get_str(str *out, const struct redis_hash *h, const char *k) {
	str *r;

	r = g_hash_table_lookup(h->ht, k);
	if (!r) {
		out->s = NULL;
		out->len = 0;
		return -1;
	}
	*out = *r;
	return 0;
}

/* we can do this because this happens during startup in a single thread */
static atomic64 strtoa64(const char *c, char **endp, int base) {
	uint64_t u;
	atomic64 ret;

	u = strtoull(c, endp, base);
	atomic64_set_na(&ret, u);
	return ret;
}
static struct timeval strtotimeval(const char *c, char **endp, int base) {
	long long ll = strtoll(c, endp, base);
	struct timeval ret;
	timeval_from_us(&ret, ll);
	return ret;
}

define_get_int_type(time_t, time_t, strtoull);
define_get_int_type(timeval, struct timeval, strtotimeval);
define_get_int_type(int, int, strtol);
define_get_int_type(unsigned, unsigned int, strtol);
//define_get_int_type(u16, uint16_t, strtol);
//define_get_int_type(u64, uint64_t, strtoull);
define_get_int_type(a64, atomic64, strtoa64);

define_get_type_format(str, str);
define_get_type_format(int, int);
//define_get_type_format(unsigned, unsigned int);
//define_get_type_format(u16, uint16_t);
//define_get_type_format(u64, uint64_t);
define_get_type_format(a64, atomic64);

static int redis_hash_get_c_buf_fn(unsigned char *out, size_t len, const struct redis_hash *h,
		const char *k, ...)
{
	va_list ap;
	str s;
	int ret;

	va_start(ap, k);
	ret = redis_hash_get_str_v(&s, h, k, ap);
	va_end(ap);
	if (ret)
		return -1;
	if (s.len > len)
		return -1;

	memcpy(out, s.s, s.len);

	return 0;
}

#define redis_hash_get_c_buf_f(o, h, f...) \
		redis_hash_get_c_buf_fn(o, sizeof(o), h, f)

static int redis_hash_get_bool_flag(const struct redis_hash *h, const char *k) {
	int i;

	if (redis_hash_get_int(&i, h, k))
		return 0;
	if (i)
		return -1;
	return 0;
}

static int redis_hash_get_endpoint(struct endpoint *out, const struct redis_hash *h, const char *k) {
	str s;

	if (redis_hash_get_str(&s, h, k))
		return -1;
	if (endpoint_parse_any(out, s.s))
		return -1;

	return 0;
}
static int redis_hash_get_stats(struct stream_stats *out, const struct redis_hash *h, const char *k) {
	if (redis_hash_get_a64_f(&out->packets, h, "%s-packets", k))
		return -1;
	if (redis_hash_get_a64_f(&out->bytes, h, "%s-bytes", k))
		return -1;
	if (redis_hash_get_a64_f(&out->errors, h, "%s-errors", k))
		return -1;
	return 0;
}
static void *redis_list_get_idx_ptr(struct redis_list *list, unsigned int idx) {
	if (idx >= list->len)
		return NULL;
	return list->ptrs[idx];
}
static void *redis_list_get_ptr(struct redis_list *list, struct redis_hash *rh, const char *key) {
	unsigned int idx;
	if (redis_hash_get_unsigned(&idx, rh, key))
		return NULL;
	return redis_list_get_idx_ptr(list, idx);
}

static int json_build_list_cb(GQueue *q, struct call *c, const char *key,
		unsigned int idx, struct redis_list *list,
		int (*cb)(str *, GQueue *, struct redis_list *, void *), void *ptr, JsonReader *root_reader)
{
	char key_concatted[256];

	snprintf(key_concatted, 256, "%s-%u", key, idx);

	if (!json_reader_read_member(root_reader, key_concatted)) {
		rlog(LOG_ERROR,"Key in json not found:%s",key_concatted);
		return -1;
	}
	int nmemb = json_reader_count_elements(root_reader);
	for (int jidx=0; jidx < nmemb; ++jidx) {
		if (!json_reader_read_element(root_reader,jidx)) {
			rlog(LOG_ERROR,"Element in array not found.");
			return -1;
		}
		str *s = json_reader_get_string_value_uri_enc(root_reader);
		if (!s) {
			rlog(LOG_ERROR,"String in json not found.");
			return -1;
		}
		if (cb(s, q, list, ptr)) {
			free(s);
			return -1;
		}
		free(s);
		json_reader_end_element(root_reader);
	}
	json_reader_end_member (root_reader);

	return 0;
}

static int rbl_cb_simple(str *s, GQueue *q, struct redis_list *list, void *ptr) {
	int j;
	j = str_to_i(s, 0);
	g_queue_push_tail(q, redis_list_get_idx_ptr(list, (unsigned) j));
	return 0;
}

static int json_build_list(GQueue *q, struct call *c, const char *key, const str *callid,
		unsigned int idx, struct redis_list *list, JsonReader *root_reader)
{
	return json_build_list_cb(q, c, key, idx, list, rbl_cb_simple, NULL, root_reader);
}

static int json_get_list_hash(struct redis_list *out,
		const char *key,
		const struct redis_hash *rh, const char *rh_num_key, JsonReader *root_reader)
{
	unsigned int i;

	if (redis_hash_get_unsigned(&out->len, rh, rh_num_key))
		return -1;
	out->rh = malloc(sizeof(*out->rh) * out->len);
	if (!out->rh)
		return -1;
	out->ptrs = malloc(sizeof(*out->ptrs) * out->len);
	if (!out->ptrs)
		goto err1;

	for (i = 0; i < out->len; i++) {
		if (json_get_hash(&out->rh[i], key, i, root_reader))
			goto err2;
	}

	return 0;

err2:
	free(out->ptrs);
	while (i) {
		i--;
		json_destroy_hash(&out->rh[i]);
	}
err1:
	free(out->rh);
	return -1;
}

/* can return 1, 0 or -1 */
static int redis_hash_get_sdes_params1(struct crypto_params *out, const struct redis_hash *h, const char *k) {
	str s;
	int i;
	const char *err;

	if (redis_hash_get_str_f(&s, h, "%s-crypto_suite", k))
		return 1;
	out->crypto_suite = crypto_find_suite(&s);
	err = "crypto suite not known";
	if (!out->crypto_suite)
		goto err;

	err = "master_key";
	if (redis_hash_get_c_buf_f(out->master_key, h, "%s-master_key", k))
		goto err;
	err = "master_salt";
	if (redis_hash_get_c_buf_f(out->master_salt, h, "%s-master_salt", k))
		goto err;

	if (!redis_hash_get_str_f(&s, h, "%s-mki", k)) {
		err = "mki too long";
		if (s.len > 255)
			return -1;
		out->mki = malloc(s.len);
		memcpy(out->mki, s.s, s.len);
		out->mki_len = s.len;
	}

	if (!redis_hash_get_int_f(&i, h, "%s-unenc-srtp", k))
		out->session_params.unencrypted_srtp = i;
	if (!redis_hash_get_int_f(&i, h, "%s-unenc-srtcp", k))
		out->session_params.unencrypted_srtcp = i;
	if (!redis_hash_get_int_f(&i, h, "%s-unauth-srtp", k))
		out->session_params.unauthenticated_srtp = i;

	return 0;

err:
	rlog(LOG_ERR, "Crypto params error: %s", err);
	return -1;
}
static int redis_hash_get_sdes_params(GQueue *out, const struct redis_hash *h, const char *k) {
	char key[32], tagkey[64];
	const char *kk = k;
	unsigned int tag;
	unsigned int iter = 0;

	while (1) {
		snprintf(tagkey, sizeof(tagkey), "%s_tag", kk);
		if (redis_hash_get_unsigned(&tag, h, tagkey))
			break;
		struct crypto_params_sdes *cps = g_slice_alloc0(sizeof(*cps));
		cps->tag = tag;
		int ret = redis_hash_get_sdes_params1(&cps->params, h, kk);
		if (ret) {
			g_slice_free1(sizeof(*cps), cps);
			if (ret == 1)
				return 0;
			return -1;
		}

		g_queue_push_tail(out, cps);
		snprintf(key, sizeof(key), "%s-%u", k, iter++);
		kk = key;
	}
	return 0;
}

static int redis_sfds(struct call *c, struct redis_list *sfds) {
	unsigned int i;
	str family, intf_name;
	struct redis_hash *rh;
	sockfamily_t *fam;
	struct logical_intf *lif;
	struct local_intf *loc;
	GQueue q = G_QUEUE_INIT;
	unsigned int loc_uid;
	struct stream_fd *sfd;
	socket_t *sock;
	int port;
	const char *err;

	for (i = 0; i < sfds->len; i++) {
		rh = &sfds->rh[i];

		err = "'localport' key not present";
		if (redis_hash_get_int(&port, rh, "localport"))
			goto err;
		err = "'pref_family' key not present";
		if (redis_hash_get_str(&family, rh, "pref_family"))
			goto err;
		err = "'logical_intf' key not present";
		if (redis_hash_get_str(&intf_name, rh, "logical_intf"))
			goto err;
		err = "'local_intf_uid' key not present";
		if (redis_hash_get_unsigned(&loc_uid, rh, "local_intf_uid"))
			goto err;

		err = "socket family not known";
		fam = get_socket_family_rfc(&family);
		if (!fam)
			goto err;
		err = "logical interface not known";
		lif = get_logical_interface(&intf_name, fam, 0);
		if (!lif)
			goto err;
		err = "not enough local interfaces";
		loc = g_queue_peek_nth(&lif->list, loc_uid);
		if (!loc)
			goto err;

		err = "failed to open ports";
		if (__get_consecutive_ports(&q, 1, port, loc->spec, &c->callid))
			goto err;
		err = "no port returned";
		sock = g_queue_pop_head(&q);
		if (!sock)
			goto err;
		set_tos(sock, c->tos);
		sfd = stream_fd_new(sock, c, loc);

		if (redis_hash_get_sdes_params1(&sfd->crypto.params, rh, "") == -1)
			return -1;

		sfds->ptrs[i] = sfd;
	}
	return 0;

err:
	rlog(LOG_ERR, "Error creating sfd: %s", err);
	return -1;
}

static int redis_streams(struct call *c, struct redis_list *streams) {
	unsigned int i;
	struct redis_hash *rh;
	struct packet_stream *ps;

	for (i = 0; i < streams->len; i++) {
		rh = &streams->rh[i];

		ps = __packet_stream_new(c);
		if (!ps)
			return -1;

		atomic64_set_na(&ps->last_packet, time(NULL));
		if (redis_hash_get_unsigned((unsigned int *) &ps->ps_flags, rh, "ps_flags"))
			return -1;
		if (redis_hash_get_unsigned((unsigned int *) &ps->component, rh, "component"))
			return -1;
		if (redis_hash_get_endpoint(&ps->endpoint, rh, "endpoint"))
			return -1;
		if (redis_hash_get_endpoint(&ps->advertised_endpoint, rh, "advertised_endpoint"))
			return -1;
		if (redis_hash_get_stats(&ps->stats, rh, "stats"))
			return -1;
		if (redis_hash_get_sdes_params1(&ps->crypto.params, rh, "") == -1)
			return -1;

		streams->ptrs[i] = ps;

		PS_CLEAR(ps, KERNELIZED);
	}
	return 0;
}

static int redis_tags(struct call *c, struct redis_list *tags, JsonReader *root_reader) {
	unsigned int i;
	int ii;
	struct redis_hash *rh;
	struct call_monologue *ml;
	str s;

	for (i = 0; i < tags->len; i++) {
		rh = &tags->rh[i];

		ml = __monologue_create(c);
		if (!ml)
			return -1;

		if (redis_hash_get_time_t(&ml->created, rh, "created"))
			return -1;
		if (!redis_hash_get_str(&s, rh, "tag"))
			__monologue_tag(ml, &s);
		if (!redis_hash_get_str(&s, rh, "via-branch"))
			__monologue_viabranch(ml, &s);
		if (!redis_hash_get_str(&s, rh, "label"))
			call_str_cpy(c, &ml->label, &s);
		redis_hash_get_time_t(&ml->deleted, rh, "deleted");
		if (!redis_hash_get_int(&ii, rh, "block_dtmf"))
			ml->block_dtmf = ii ? 1 : 0;
		if (!redis_hash_get_int(&ii, rh, "block_media"))
			ml->block_media = ii ? 1 : 0;

		if (redis_hash_get_str(&s, rh, "logical_intf")
				|| !(ml->logical_intf = get_logical_interface(&s, NULL, 0)))
		{
			rlog(LOG_ERR, "unable to find specified local interface");
			ml->logical_intf = get_logical_interface(NULL, NULL, 0);
		}

		if (json_build_ssrc(ml, root_reader))
			return -1;

		tags->ptrs[i] = ml;
	}

	return 0;
}

static struct rtp_payload_type *rbl_cb_plts_g(str *s, GQueue *q, struct redis_list *list, void *ptr) {
	str ptype;
	struct call_media *med = ptr;

	if (str_token(&ptype, s, '/'))
		return NULL;

	struct rtp_payload_type *pt = codec_make_payload_type(s, med->type_id);
	if (!pt)
		return NULL;

	pt->payload_type = str_to_i(&ptype, 0);

	return pt;
}
static int rbl_cb_plts_r(str *s, GQueue *q, struct redis_list *list, void *ptr) {
	struct call_media *med = ptr;
	codec_store_add_raw(&med->codecs, rbl_cb_plts_g(s, q, list, ptr));
	return 0;
}
static int json_medias(struct call *c, struct redis_list *medias, JsonReader *root_reader) {
	unsigned int i;
	struct redis_hash *rh;
	struct call_media *med;
	str s;

	for (i = 0; i < medias->len; i++) {
		rh = &medias->rh[i];

		/* from call.c:__get_media() */
		med = call_media_new(c);

		if (redis_hash_get_unsigned(&med->index, rh, "index"))
			return -1;
		if (redis_hash_get_str(&s, rh, "type"))
			return -1;
		call_str_cpy(c, &med->type, &s);
		med->type_id = codec_get_type(&med->type);
		if (!redis_hash_get_str(&s, rh, "format_str"))
			call_str_cpy(c, &med->format_str, &s);
		if (!redis_hash_get_str(&s, rh, "media_id"))
			call_str_cpy(c, &med->media_id, &s);

		if (redis_hash_get_str(&s, rh, "protocol"))
			return -1;
		med->protocol = transport_protocol(&s);

		if (redis_hash_get_str(&s, rh, "desired_family"))
			return -1;
		med->desired_family = get_socket_family_rfc(&s);

		if (redis_hash_get_str(&s, rh, "logical_intf")
				|| !(med->logical_intf = get_logical_interface(&s, med->desired_family, 0)))
		{
			rlog(LOG_ERR, "unable to find specified local interface");
			med->logical_intf = get_logical_interface(NULL, med->desired_family, 0);
		}

		if (redis_hash_get_unsigned((unsigned int *) &med->media_flags, rh,
					"media_flags"))
			return -1;

		if (redis_hash_get_sdes_params(&med->sdes_in, rh, "sdes_in") < 0)
			return -1;
		if (redis_hash_get_sdes_params(&med->sdes_out, rh, "sdes_out") < 0)
			return -1;

		json_build_list_cb(NULL, c, "payload_types", i, NULL, rbl_cb_plts_r, med, root_reader);
		/* XXX dtls */

		medias->ptrs[i] = med;
	}

	return 0;
}

static int redis_maps(struct call *c, struct redis_list *maps) {
	unsigned int i;
	struct redis_hash *rh;
	struct endpoint_map *em;
	str s, t;
	sockfamily_t *fam;

	for (i = 0; i < maps->len; i++) {
		rh = &maps->rh[i];

		/* from call.c:__get_endpoint_map() */
		em = uid_slice_alloc0(em, &c->endpoint_maps);
		g_queue_init(&em->intf_sfds);

		em->wildcard = redis_hash_get_bool_flag(rh, "wildcard");
		if (redis_hash_get_unsigned(&em->num_ports, rh, "num_ports"))
			return -1;
		if (redis_hash_get_str(&t, rh, "intf_preferred_family"))
			return -1;
		fam = get_socket_family_rfc(&t);
		if (!fam)
			return -1;
		if (redis_hash_get_str(&s, rh, "logical_intf")
				|| !(em->logical_intf = get_logical_interface(&s, fam, 0)))
		{
			rlog(LOG_ERR, "unable to find specified local interface");
			em->logical_intf = get_logical_interface(NULL, fam, 0);
		}
		if (redis_hash_get_endpoint(&em->endpoint, rh, "endpoint"))
			return -1;

		maps->ptrs[i] = em;
	}

	return 0;
}

static int redis_link_sfds(struct redis_list *sfds, struct redis_list *streams) {
	unsigned int i;
	struct stream_fd *sfd;

	for (i = 0; i < sfds->len; i++) {
		sfd = sfds->ptrs[i];

		sfd->stream = redis_list_get_ptr(streams, &sfds->rh[i], "stream");
		if (!sfd->stream)
			return -1;
	}

	return 0;
}

static int json_link_tags(struct call *c, struct redis_list *tags, struct redis_list *medias, JsonReader *root_reader)
{
	unsigned int i;
	struct call_monologue *ml, *other_ml;
	GQueue q = G_QUEUE_INIT;
	GList *l;

	for (i = 0; i < tags->len; i++) {
		ml = tags->ptrs[i];

		if (json_build_list(&q, c, "subscriptions-oa", &c->callid, i, tags, root_reader))
			return -1;
		for (l = q.head; l; l = l->next) {
			other_ml = l->data;
			if (!other_ml)
			    return -1;
			__add_subscription(ml, other_ml, true);
		}
		g_queue_clear(&q);

		if (json_build_list(&q, c, "subscriptions-noa", &c->callid, i, tags, root_reader))
			return -1;
		for (l = q.head; l; l = l->next) {
			other_ml = l->data;
			if (!other_ml)
			    return -1;
			__add_subscription(ml, other_ml, false);
		}
		g_queue_clear(&q);

		// backwards compatibility
		if (!ml->subscriptions.length) {
			other_ml = redis_list_get_ptr(tags, &tags->rh[i], "active");
			if (other_ml)
				__add_subscription(ml, other_ml, true);
		}

		if (json_build_list(&q, c, "other_tags", &c->callid, i, tags, root_reader))
			return -1;
		for (l = q.head; l; l = l->next) {
			other_ml = l->data;
			if (!other_ml)
			    return -1;
			g_hash_table_insert(ml->other_tags, &other_ml->tag, other_ml);
		}
		g_queue_clear(&q);

		if (json_build_list(&q, c, "branches", &c->callid, i, tags, root_reader))
			return -1;
		for (l = q.head; l; l = l->next) {
			other_ml = l->data;
			if (!other_ml)
			    return -1;
			g_hash_table_insert(ml->branches, &other_ml->viabranch, other_ml);
		}
		g_queue_clear(&q);

		if (json_build_list(&ml->medias, c, "medias", &c->callid, i, medias, root_reader))
			return -1;
	}

	return 0;
}

static int json_link_streams(struct call *c, struct redis_list *streams,
		struct redis_list *sfds, struct redis_list *medias, JsonReader *root_reader)
{
	unsigned int i;
	struct packet_stream *ps;
	GQueue q = G_QUEUE_INIT;
	GList *l;

	for (i = 0; i < streams->len; i++) {
		ps = streams->ptrs[i];

		ps->media = redis_list_get_ptr(medias, &streams->rh[i], "media");
		ps->selected_sfd = redis_list_get_ptr(sfds, &streams->rh[i], "sfd");
		ps->rtcp_sibling = redis_list_get_ptr(streams, &streams->rh[i], "rtcp_sibling");

		if (json_build_list(&ps->sfds, c, "stream_sfds", &c->callid, i, sfds, root_reader))
			return -1;

		if (json_build_list(&q, c, "rtp_sinks", &c->callid, i, streams, root_reader))
			return -1;
		for (l = q.head; l; l = l->next) {
			struct packet_stream *sink = l->data;
			if (!sink)
				return -1;
			__add_sink_handler(&ps->rtp_sinks, sink);
		}
		g_queue_clear(&q);

		// backwards compatibility
		if (!ps->rtp_sinks.length) {
			struct packet_stream *sink = redis_list_get_ptr(streams, &streams->rh[i], "rtp_sink");
			if (sink)
				__add_sink_handler(&ps->rtp_sinks, sink);
		}

		if (json_build_list(&q, c, "rtcp_sinks", &c->callid, i, streams, root_reader))
			return -1;
		for (l = q.head; l; l = l->next) {
			struct packet_stream *sink = l->data;
			if (!sink)
				return -1;
			__add_sink_handler(&ps->rtcp_sinks, sink);
		}
		g_queue_clear(&q);

		// backwards compatibility
		if (!ps->rtcp_sinks.length) {
			struct packet_stream *sink = redis_list_get_ptr(streams, &streams->rh[i], "rtcp_sink");
			if (sink)
				__add_sink_handler(&ps->rtcp_sinks, sink);
		}

		if (ps->media)
			__rtp_stats_update(ps->rtp_stats, &ps->media->codecs);

		__init_stream(ps);
	}

	return 0;
}

static int json_link_medias(struct call *c, struct redis_list *medias,
		struct redis_list *streams, struct redis_list *maps, struct redis_list *tags, JsonReader *root_reader)
{
	unsigned int i;
	struct call_media *med;

	for (i = 0; i < medias->len; i++) {
		med = medias->ptrs[i];

		med->monologue = redis_list_get_ptr(tags, &medias->rh[i], "tag");
		if (!med->monologue)
			return -1;
		if (json_build_list(&med->streams, c, "streams", &c->callid, i, streams, root_reader))
			return -1;
		if (json_build_list(&med->endpoint_maps, c, "maps", &c->callid, i, maps, root_reader))
			return -1;

		if (med->media_id.s)
			g_hash_table_insert(med->monologue->media_ids, &med->media_id, med);

		// find the pair media
		struct call_monologue *ml = med->monologue;
		for (GList *sub = ml->subscriptions.head; sub; sub = sub->next) {
			struct call_subscription *cs = sub->data;
			struct call_monologue *other_ml = cs->monologue;
			for (GList *l = other_ml->medias.head; l; l = l->next) {
				struct call_media *other_m = l->data;
				other_m->monologue = other_ml;
				if (other_m->index == med->index) {
					codec_handlers_update(med, other_m, NULL, NULL);
					break;
				}
			}
		}
	}
	return 0;
}

static int rbl_cb_intf_sfds(str *s, GQueue *q, struct redis_list *list, void *ptr) {
	int i;
	struct intf_list *il;
	struct endpoint_map *em;
	void *sfd;

	if (!strncmp(s->s, "loc-", 4)) {
		il = g_slice_alloc0(sizeof(*il));
		em = ptr;
		i = atoi(s->s+4);
		il->local_intf = g_queue_peek_nth((GQueue*) &em->logical_intf->list, i);
		if (!il->local_intf)
			return -1;
		g_queue_push_tail(q, il);
		return 0;
	}

	il = g_queue_peek_tail(q);
	if (!il)
		return -1;

	sfd = redis_list_get_idx_ptr(list, atoi(s->s));
	if (G_UNLIKELY(!sfd))
	    return -1;

	g_queue_push_tail(&il->list, sfd);
	return 0;
}

static int json_link_maps(struct call *c, struct redis_list *maps,
		struct redis_list *sfds, JsonReader *root_reader)
{
	unsigned int i;
	struct endpoint_map *em;

	for (i = 0; i < maps->len; i++) {
		em = maps->ptrs[i];

		if (json_build_list_cb(&em->intf_sfds, c, "map_sfds", em->unique_id, sfds,
				rbl_cb_intf_sfds, em, root_reader))
			return -1;
	}
	return 0;
}

static int json_build_ssrc(struct call_monologue *ml, JsonReader *root_reader) {
	char tmp[2048];
	snprintf(tmp, sizeof(tmp), "ssrc_table-%u", ml->unique_id);
	if (!json_reader_read_member(root_reader, "ssrc_table")) {
		// non-fatal for backwards compatibility
		json_reader_end_member(root_reader);
		return 0;
	}
	int nmemb = json_reader_count_elements(root_reader);
	for (int jidx=0; jidx < nmemb; ++jidx) {
		if (!json_reader_read_element(root_reader, jidx))
			return -1;

		uint32_t ssrc = json_reader_get_ll(root_reader, "ssrc");
		struct ssrc_entry_call *se = get_ssrc(ssrc, ml->ssrc_hash);
		if (!se)
			goto next;
		se->input_ctx.srtp_index = json_reader_get_ll(root_reader, "in_srtp_index");
		se->input_ctx.srtcp_index = json_reader_get_ll(root_reader, "in_srtcp_index");
		payload_tracker_add(&se->input_ctx.tracker, json_reader_get_ll(root_reader, "in_payload_type"));
		se->output_ctx.srtp_index = json_reader_get_ll(root_reader, "out_srtp_index");
		se->output_ctx.srtcp_index = json_reader_get_ll(root_reader, "out_srtcp_index");
		payload_tracker_add(&se->output_ctx.tracker, json_reader_get_ll(root_reader, "out_payload_type"));

		obj_put(&se->h);
next:
		json_reader_end_element(root_reader);
	}
	json_reader_end_member (root_reader);
	return 0;
}

static void json_restore_call(struct redis *r, const str *callid, bool foreign) {
	redisReply* rr_jsonStr;
	struct redis_hash call;
	struct redis_list tags, sfds, streams, medias, maps;
	struct call *c = NULL;
	str s, id, meta;
	time_t last_signal;

	const char *err = 0;
	int i;
	JsonReader *root_reader =0;
	JsonParser *parser =0;

	mutex_lock(&r->lock);
	rr_jsonStr = redis_get(r, REDIS_REPLY_STRING, "GET " PB, STR(callid));
	mutex_unlock(&r->lock);

	err = "could not retrieve JSON data from redis";
	if (!rr_jsonStr)
		goto err1;

	parser = json_parser_new();
	err = "could not parse JSON data";
	if (!json_parser_load_from_data (parser, rr_jsonStr->str, -1, NULL))
		goto err1;
	root_reader = json_reader_new (json_parser_get_root (parser));
	err = "could not read JSON data";
	if (!root_reader)
		goto err1;

	c = call_get_or_create(callid, foreign, false);
	err = "failed to create call struct";
	if (!c)
		goto err1;

	err = "'call' data incomplete";
	if (json_get_hash(&call, "json", -1, root_reader))
		goto err2;

	err = "missing 'last signal' timestamp";
	if (redis_hash_get_time_t(&last_signal, &call, "last_signal"))
		goto err3;

	if (c->last_signal) {
		err = NULL;
		// is the call we're loading newer than the one we have?
		if (last_signal > c->last_signal) {
			// switch ownership
			call_make_own_foreign(c, foreign);
			c->last_signal = last_signal;
		}
		goto err3; // no error, just bail
	}

	err = "'tags' incomplete";
	if (json_get_list_hash(&tags, "tag", &call, "num_tags", root_reader))
		goto err3;
	err = "'sfds' incomplete";
	if (json_get_list_hash(&sfds, "sfd", &call, "num_sfds", root_reader))
		goto err4;
	err = "'streams' incomplete";
	if (json_get_list_hash(&streams, "stream", &call, "num_streams", root_reader))
		goto err5;
	err = "'medias' incomplete";
	if (json_get_list_hash(&medias, "media", &call, "num_medias", root_reader))
		goto err6;
	err = "'maps' incomplete";
	if (json_get_list_hash(&maps, "map", &call, "num_maps", root_reader))
		goto err7;

	err = "missing 'created' timestamp";
	if (redis_hash_get_timeval(&c->created, &call, "created"))
		goto err8;
	c->last_signal = last_signal;
	if (redis_hash_get_int(&i, &call, "tos"))
		c->tos = 184;
	else
		c->tos = i;
	redis_hash_get_time_t(&c->deleted, &call, "deleted");
	redis_hash_get_time_t(&c->ml_deleted, &call, "ml_deleted");
	if (!redis_hash_get_str(&id, &call, "created_from"))
		c->created_from = call_strdup(c, id.s);
	if (!redis_hash_get_str(&id, &call, "created_from_addr"))
		sockaddr_parse_any_str(&c->created_from_addr, &id);
	if (!redis_hash_get_int(&i, &call, "block_dtmf"))
		c->block_dtmf = i ? 1 : 0;
	if (!redis_hash_get_int(&i, &call, "block_media"))
		c->block_media = i ? 1 : 0;

	err = "missing 'redis_hosted_db' value";
	if (redis_hash_get_unsigned((unsigned int *) &c->redis_hosted_db, &call, "redis_hosted_db"))
		goto err8;

	err = "failed to create sfds";
	if (redis_sfds(c, &sfds))
		goto err8;
	err = "failed to create streams";
	if (redis_streams(c, &streams))
		goto err8;
	err = "failed to create tags";
	if (redis_tags(c, &tags, root_reader))
		goto err8;
	err = "failed to create medias";
	if (json_medias(c, &medias, root_reader))
		goto err8;
	err = "failed to create maps";
	if (redis_maps(c, &maps))
		goto err8;

	err = "failed to link sfds";
	if (redis_link_sfds(&sfds, &streams))
		goto err8;
	err = "failed to link streams";
	if (json_link_streams(c, &streams, &sfds, &medias, root_reader))
		goto err8;
	err = "failed to link tags";
	if (json_link_tags(c, &tags, &medias, root_reader))
		goto err8;
	err = "failed to link medias";
	if (json_link_medias(c, &medias, &streams, &maps, &tags, root_reader))
		goto err8;
	err = "failed to link maps";
	if (json_link_maps(c, &maps, &sfds, root_reader))
		goto err8;

	// presence of this key determines whether we were recording at all
	if (!redis_hash_get_str(&s, &call, "recording_meta_prefix")) {
		// coverity[check_return : FALSE]
		redis_hash_get_str(&meta, &call, "recording_metadata");
		recording_start(c, s.s, &meta, NULL);
	}

	err = NULL;

err8:
	json_destroy_list(&maps);
err7:
	json_destroy_list(&medias);
err6:
	json_destroy_list(&streams);
err5:
	json_destroy_list(&sfds);
err4:
	json_destroy_list(&tags);
err3:
	json_destroy_hash(&call);
err2:
	rwlock_unlock_w(&c->master_lock);
err1:
	if (root_reader)
		g_object_unref (root_reader);
	if (parser)
		g_object_unref (parser);
	if (rr_jsonStr)
		freeReplyObject(rr_jsonStr);	
	if (err) {
		mutex_lock(&r->lock);
		if (r->ctx && r->ctx->err)
			rlog(LOG_WARNING, "Failed to restore call ID '" STR_FORMAT_M "' from Redis: %s (%s)",
					STR_FMT_M(callid),
					err, r->ctx->errstr);
		else
			rlog(LOG_WARNING, "Failed to restore call ID '" STR_FORMAT_M "' from Redis: %s",
					STR_FMT_M(callid),
					err);
		mutex_unlock(&r->lock);
		if (c) 
			call_destroy(c);

		mutex_lock(&rtpe_redis_write->lock);
		redisCommandNR(rtpe_redis_write->ctx, "DEL " PB, STR(callid));
		mutex_unlock(&rtpe_redis_write->lock);

		if (rtpe_redis_notify) {
			mutex_lock(&rtpe_redis_notify->lock);
			redisCommandNR(rtpe_redis_notify->ctx, "DEL " PB, STR(callid));
			mutex_unlock(&rtpe_redis_notify->lock);
		}
	}
	if (c)
		obj_put(c);
	log_info_clear();
}

struct thread_ctx {
	GQueue r_q;
	mutex_t r_m;
	bool foreign;
};

static void restore_thread(void *call_p, void *ctx_p) {
	struct thread_ctx *ctx = ctx_p;
	redisReply *call = call_p;
	struct redis *r;
	str callid;
	str_init_len(&callid, call->str, call->len);

	rlog(LOG_DEBUG, "Processing call ID '%s%.*s%s' from Redis", FMT_M(REDIS_FMT(call)));

	mutex_lock(&ctx->r_m);
	r = g_queue_pop_head(&ctx->r_q);
	mutex_unlock(&ctx->r_m);

	gettimeofday(&rtpe_now, NULL);
	json_restore_call(r, &callid, ctx->foreign);

	mutex_lock(&ctx->r_m);
	g_queue_push_tail(&ctx->r_q, r);
	mutex_unlock(&ctx->r_m);
}

int redis_restore(struct redis *r, bool foreign, int db) {
	redisReply *calls = NULL, *call;
	int i, ret = -1;
	GThreadPool *gtp;
	struct thread_ctx ctx;

	if (!r)
		return 0;

	for (unsigned int i = 0; i < num_log_levels; i++)
		rtpe_config.common.log_levels[i] |= LOG_FLAG_RESTORE;

	rlog(LOG_DEBUG, "Restoring calls from Redis...");

	mutex_lock(&r->lock);
	// coverity[sleep : FALSE]
	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED) {
		mutex_unlock(&r->lock);
		ret = 0;
		goto err;
	}
	if (db != -1)
		redis_select_db(r, db);

	calls = redis_get(r, REDIS_REPLY_ARRAY, "KEYS *");

	if (db != -1)
		redis_select_db(r, r->db);
	else
		db = r->db;

	mutex_unlock(&r->lock);

	if (!calls) {
		rlog(LOG_ERR, "Could not retrieve call list from Redis: %s",
				r->ctx ? r->ctx->errstr : "No redis context");
		goto err;
	}

	mutex_init(&ctx.r_m);
	g_queue_init(&ctx.r_q);
	ctx.foreign = foreign;
	for (i = 0; i < rtpe_config.redis_num_threads; i++)
		g_queue_push_tail(&ctx.r_q,
				redis_new(&r->endpoint, db, r->auth, r->role, r->no_redis_required));
	gtp = g_thread_pool_new(restore_thread, &ctx, rtpe_config.redis_num_threads, TRUE, NULL);

	for (i = 0; i < calls->elements; i++) {
		call = calls->element[i];
		if (call->type != REDIS_REPLY_STRING)
			continue;

		g_thread_pool_push(gtp, call, NULL);
	}

	g_thread_pool_stop_unused_threads();
	g_thread_pool_set_max_unused_threads(0);

	g_thread_pool_free(gtp, FALSE, TRUE);
	while ((r = g_queue_pop_head(&ctx.r_q)))
		redis_close(r);
	ret = 0;

	freeReplyObject(calls);

err:
	for (unsigned int i = 0; i < num_log_levels; i++)
		if (rtpe_config.common.log_levels[i] > 0)
			rtpe_config.common.log_levels[i] &= ~LOG_FLAG_RESTORE;
	return ret;
}

#define JSON_ADD_STRING(f...) do { \
		int len = snprintf(tmp,sizeof(tmp), f); \
		json_builder_add_string_value_uri_enc(builder, tmp, len); \
	} while (0)
#define JSON_SET_NSTRING(a,b,c,d) do { \
		snprintf(tmp,sizeof(tmp), a,b); \
		json_builder_set_member_name(builder, tmp); \
		JSON_ADD_STRING(c, d); \
	} while (0)
#define JSON_SET_NSTRING_CSTR(a,b,d) JSON_SET_NSTRING_LEN(a, b, strlen(d), d)
#define JSON_SET_NSTRING_LEN(a,b,l,d) do { \
		snprintf(tmp,sizeof(tmp), a,b); \
		json_builder_set_member_name(builder, tmp); \
		json_builder_add_string_value_uri_enc(builder, d, l); \
	} while (0)
#define JSON_SET_SIMPLE(a,c,d) do { \
		json_builder_set_member_name(builder, a); \
		JSON_ADD_STRING(c, d); \
	} while (0)
#define JSON_SET_SIMPLE_LEN(a,l,d) do { \
		json_builder_set_member_name(builder, a); \
		json_builder_add_string_value_uri_enc(builder, d, l); \
	} while (0)
#define JSON_SET_SIMPLE_CSTR(a,d) JSON_SET_SIMPLE_LEN(a, (d) ? strlen(d) : 0, (d) ? : "")
#define JSON_SET_SIMPLE_STR(a,d) JSON_SET_SIMPLE_LEN(a, (d)->len, (d)->s)

static void json_update_crypto_params(JsonBuilder *builder, const char *key, struct crypto_params *p) {
	char tmp[2048];

	if (!p->crypto_suite)
		return;

	JSON_SET_NSTRING_CSTR("%s-crypto_suite", key, p->crypto_suite->name);
	JSON_SET_NSTRING_LEN("%s-master_key", key, sizeof(p->master_key), (char *) p->master_key);
	JSON_SET_NSTRING_LEN("%s-master_salt", key, sizeof(p->master_salt), (char *) p->master_salt);

	JSON_SET_NSTRING("%s-unenc-srtp", key, "%i", p->session_params.unencrypted_srtp);
	JSON_SET_NSTRING("%s-unenc-srtcp", key, "%i", p->session_params.unencrypted_srtcp);
	JSON_SET_NSTRING("%s-unauth-srtp", key, "%i", p->session_params.unauthenticated_srtp);

	if (p->mki)
		JSON_SET_NSTRING_LEN("%s-mki", key, p->mki_len, (char *) p->mki);
}

static int json_update_sdes_params(JsonBuilder *builder, const char *pref,
		unsigned int unique_id,
		const char *k, GQueue *q)
{
	char tmp[2048];
	unsigned int iter = 0;
	char keybuf[32];
	const char *key = k;

	for (GList *l = q->head; l; l = l->next) {
		struct crypto_params_sdes *cps = l->data;
		struct crypto_params *p = &cps->params;

		if (!p->crypto_suite)
			return -1;

		JSON_SET_NSTRING("%s_tag", key, "%u", cps->tag);
		json_update_crypto_params(builder, key, p);

		snprintf(keybuf, sizeof(keybuf), "%s-%u", k, iter++);
		key = keybuf;
	}

	return 0;
}

static void json_update_dtls_fingerprint(JsonBuilder *builder, const char *pref,
		unsigned int unique_id,
		const struct dtls_fingerprint *f)
{
	if (!f->hash_func)
		return;

	JSON_SET_SIMPLE_CSTR("hash_func",f->hash_func->name);
	JSON_SET_SIMPLE_LEN("fingerprint", sizeof(f->digest), (char *) f->digest);
}

/**
 * encodes the few (k,v) pairs for one call under one json structure
 */

char* redis_encode_json(struct call *c) {

	GList *l=0,*k=0, *m=0, *n=0;
	struct endpoint_map *ep;
	struct call_media *media;
	struct rtp_payload_type *pt;
	struct stream_fd *sfd;
	struct packet_stream *ps;
	struct intf_list *il;
	struct call_monologue *ml, *ml2;
	JsonBuilder *builder = json_builder_new ();
	struct recording *rec = 0;

	char tmp[2048];

	json_builder_begin_object (builder);
	{
		json_builder_set_member_name(builder, "json");

		json_builder_begin_object (builder);

		{
			JSON_SET_SIMPLE("created","%lli", timeval_us(&c->created));
			JSON_SET_SIMPLE("last_signal","%ld",(long int) c->last_signal);
			JSON_SET_SIMPLE("tos","%u",(int) c->tos);
			JSON_SET_SIMPLE("deleted","%ld",(long int) c->deleted);
			JSON_SET_SIMPLE("num_sfds","%u",g_queue_get_length(&c->stream_fds));
			JSON_SET_SIMPLE("num_streams","%u",g_queue_get_length(&c->streams));
			JSON_SET_SIMPLE("num_medias","%u",g_queue_get_length(&c->medias));
			JSON_SET_SIMPLE("num_tags","%u",g_queue_get_length(&c->monologues));
			JSON_SET_SIMPLE("num_maps","%u",g_queue_get_length(&c->endpoint_maps));
			JSON_SET_SIMPLE("ml_deleted","%ld",(long int) c->ml_deleted);
			JSON_SET_SIMPLE_CSTR("created_from",c->created_from);
			JSON_SET_SIMPLE_CSTR("created_from_addr",sockaddr_print_buf(&c->created_from_addr));
			JSON_SET_SIMPLE("redis_hosted_db","%u",c->redis_hosted_db);
			JSON_SET_SIMPLE_STR("recording_metadata",&c->metadata);
			JSON_SET_SIMPLE("block_dtmf","%i",c->block_dtmf ? 1 : 0);
			JSON_SET_SIMPLE("block_media","%i",c->block_media ? 1 : 0);

			if ((rec = c->recording)) {
				JSON_SET_SIMPLE_CSTR("recording_meta_prefix",rec->meta_prefix);
			}
		}

		json_builder_end_object (builder);

		for (l = c->stream_fds.head; l; l = l->next) {
			sfd = l->data;

			snprintf(tmp, sizeof(tmp), "sfd-%u", sfd->unique_id);
			json_builder_set_member_name(builder, tmp);

			json_builder_begin_object (builder);

			{
				JSON_SET_SIMPLE_CSTR("pref_family",sfd->local_intf->logical->preferred_family->rfc_name);
				JSON_SET_SIMPLE("localport","%u",sfd->socket.local.port);
				JSON_SET_SIMPLE_STR("logical_intf",&sfd->local_intf->logical->name);
				JSON_SET_SIMPLE("local_intf_uid","%u",sfd->local_intf->unique_id);
				JSON_SET_SIMPLE("stream","%u",sfd->stream->unique_id);

				json_update_crypto_params(builder, "", &sfd->crypto.params);

			}
			json_builder_end_object (builder);

		} // --- for

		for (l = c->streams.head; l; l = l->next) {
			ps = l->data;

			mutex_lock(&ps->in_lock);
			mutex_lock(&ps->out_lock);

			snprintf(tmp, sizeof(tmp), "stream-%u", ps->unique_id);
			json_builder_set_member_name(builder, tmp);

			json_builder_begin_object (builder);

			{
				JSON_SET_SIMPLE("media","%u",ps->media->unique_id);
				JSON_SET_SIMPLE("sfd","%u",ps->selected_sfd ? ps->selected_sfd->unique_id : -1);
				JSON_SET_SIMPLE("rtcp_sibling","%u",ps->rtcp_sibling ? ps->rtcp_sibling->unique_id : -1);
				JSON_SET_SIMPLE("last_packet",UINT64F,atomic64_get(&ps->last_packet));
				JSON_SET_SIMPLE("ps_flags","%u",ps->ps_flags);
				JSON_SET_SIMPLE("component","%u",ps->component);
				JSON_SET_SIMPLE_CSTR("endpoint",endpoint_print_buf(&ps->endpoint));
				JSON_SET_SIMPLE_CSTR("advertised_endpoint",endpoint_print_buf(&ps->advertised_endpoint));
				JSON_SET_SIMPLE("stats-packets","%" PRIu64, atomic64_get(&ps->stats.packets));
				JSON_SET_SIMPLE("stats-bytes","%" PRIu64, atomic64_get(&ps->stats.bytes));
				JSON_SET_SIMPLE("stats-errors","%" PRIu64, atomic64_get(&ps->stats.errors));

				json_update_crypto_params(builder, "", &ps->crypto.params);
			}

			json_builder_end_object (builder);

			// stream_sfds was here before
			mutex_unlock(&ps->in_lock);
			mutex_unlock(&ps->out_lock);

		} // --- for streams.head


		for (l = c->streams.head; l; l = l->next) {
			ps = l->data;
			// XXX these should all go into the above loop

			mutex_lock(&ps->in_lock);
			mutex_lock(&ps->out_lock);

			snprintf(tmp, sizeof(tmp), "stream_sfds-%u", ps->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array (builder);
			for (k = ps->sfds.head; k; k = k->next) {
				sfd = k->data;
				JSON_ADD_STRING("%u",sfd->unique_id);
			}
			json_builder_end_array (builder);

			snprintf(tmp, sizeof(tmp), "rtp_sinks-%u", ps->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array(builder);
			for (k = ps->rtp_sinks.head; k; k = k->next) {
				struct sink_handler *sh = k->data;
				struct packet_stream *sink = sh->sink;
				JSON_ADD_STRING("%u", sink->unique_id);
			}
			json_builder_end_array (builder);

			snprintf(tmp, sizeof(tmp), "rtcp_sinks-%u", ps->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array(builder);
			for (k = ps->rtcp_sinks.head; k; k = k->next) {
				struct sink_handler *sh = k->data;
				struct packet_stream *sink = sh->sink;
				JSON_ADD_STRING("%u", sink->unique_id);
			}
			json_builder_end_array (builder);

			mutex_unlock(&ps->in_lock);
			mutex_unlock(&ps->out_lock);
		}


		for (l = c->monologues.head; l; l = l->next) {
			ml = l->data;

			snprintf(tmp, sizeof(tmp), "tag-%u", ml->unique_id);
			json_builder_set_member_name(builder, tmp);

			json_builder_begin_object (builder);
			{

				JSON_SET_SIMPLE("created","%llu",(long long unsigned) ml->created);
				JSON_SET_SIMPLE("deleted","%llu",(long long unsigned) ml->deleted);
				JSON_SET_SIMPLE("block_dtmf","%i",ml->block_dtmf ? 1 : 0);
				JSON_SET_SIMPLE("block_media","%i",ml->block_media ? 1 : 0);
				if (ml->logical_intf)
					JSON_SET_SIMPLE_STR("logical_intf", &ml->logical_intf->name);

				if (ml->tag.s)
					JSON_SET_SIMPLE_STR("tag",&ml->tag);
				if (ml->viabranch.s)
					JSON_SET_SIMPLE_STR("via-branch",&ml->viabranch);
				if (ml->label.s)
					JSON_SET_SIMPLE_STR("label",&ml->label);
			}
			json_builder_end_object (builder);

			// other_tags and medias- was here before

		} // --- for monologues.head

		for (l = c->monologues.head; l; l = l->next) {
			ml = l->data;
			// -- we do it again here since the jsonbuilder is linear straight forward
			// XXX these should all go into the above loop
			k = g_hash_table_get_values(ml->other_tags);
			snprintf(tmp, sizeof(tmp), "other_tags-%u", ml->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array (builder);
			for (m = k; m; m = m->next) {
				ml2 = m->data;
				JSON_ADD_STRING("%u",ml2->unique_id);
			}
			json_builder_end_array (builder);

			g_list_free(k);

			k = g_hash_table_get_values(ml->branches);
			snprintf(tmp, sizeof(tmp), "branches-%u", ml->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array (builder);
			for (m = k; m; m = m->next) {
				ml2 = m->data;
				JSON_ADD_STRING("%u",ml2->unique_id);
			}
			json_builder_end_array (builder);

			g_list_free(k);

			snprintf(tmp, sizeof(tmp), "medias-%u", ml->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array (builder);
			for (k = ml->medias.head; k; k = k->next) {
				media = k->data;
				JSON_ADD_STRING("%u",media->unique_id);
			}
			json_builder_end_array (builder);

			// SSRC table dump
			rwlock_lock_r(&ml->ssrc_hash->lock);
			k = g_hash_table_get_values(ml->ssrc_hash->ht);
			snprintf(tmp, sizeof(tmp), "ssrc_table-%u", ml->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array (builder);
			for (m = k; m; m = m->next) {
				struct ssrc_entry_call *se = m->data;
				json_builder_begin_object (builder);

				JSON_SET_SIMPLE("ssrc","%" PRIu32, se->h.ssrc);
				// XXX use function for in/out
				JSON_SET_SIMPLE("in_srtp_index","%" PRIu64, se->input_ctx.srtp_index);
				JSON_SET_SIMPLE("in_srtcp_index","%" PRIu64, se->input_ctx.srtcp_index);
				JSON_SET_SIMPLE("in_payload_type","%i", se->input_ctx.tracker.most[0]);
				JSON_SET_SIMPLE("out_srtp_index","%" PRIu64, se->output_ctx.srtp_index);
				JSON_SET_SIMPLE("out_srtcp_index","%" PRIu64, se->output_ctx.srtcp_index);
				JSON_SET_SIMPLE("out_payload_type","%i", se->output_ctx.tracker.most[0]);
				// XXX add rest of info

				json_builder_end_object (builder);
			}
			json_builder_end_array (builder);

			g_list_free(k);
			rwlock_unlock_r(&ml->ssrc_hash->lock);

			snprintf(tmp, sizeof(tmp), "subscriptions-oa-%u", ml->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array(builder);
			for (k = ml->subscriptions.head; k; k = k->next) {
				struct call_subscription *cs = k->data;
				if (!cs->offer_answer)
					continue;
				JSON_ADD_STRING("%u", cs->monologue->unique_id);
			}
			json_builder_end_array(builder);

			snprintf(tmp, sizeof(tmp), "subscriptions-noa-%u", ml->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array(builder);
			for (k = ml->subscriptions.head; k; k = k->next) {
				struct call_subscription *cs = k->data;
				if (cs->offer_answer)
					continue;
				JSON_ADD_STRING("%u", cs->monologue->unique_id);
			}
			json_builder_end_array(builder);
		}


		for (l = c->medias.head; l; l = l->next) {
			media = l->data;

			snprintf(tmp, sizeof(tmp), "media-%u", media->unique_id);
			json_builder_set_member_name(builder, tmp);

			json_builder_begin_object (builder);
			{
				JSON_SET_SIMPLE("tag","%u",media->monologue->unique_id);
				JSON_SET_SIMPLE("index","%u",media->index);
				JSON_SET_SIMPLE_STR("type",&media->type);
				if (media->format_str.s)
					JSON_SET_SIMPLE_STR("format_str",&media->format_str);
				if (media->media_id.s)
					JSON_SET_SIMPLE_STR("media_id",&media->media_id);
				JSON_SET_SIMPLE_CSTR("protocol",media->protocol ? media->protocol->name : "");
				JSON_SET_SIMPLE_CSTR("desired_family",media->desired_family ? media->desired_family->rfc_name : "");
				JSON_SET_SIMPLE_STR("logical_intf",&media->logical_intf->name);
				JSON_SET_SIMPLE("ptime","%i",media->ptime);
				JSON_SET_SIMPLE("media_flags","%u",media->media_flags);

				json_update_sdes_params(builder, "media", media->unique_id, "sdes_in",
						&media->sdes_in);
				json_update_sdes_params(builder, "media", media->unique_id, "sdes_out",
						&media->sdes_out);
				json_update_dtls_fingerprint(builder, "media", media->unique_id, &media->fingerprint);
			}
			json_builder_end_object (builder);

		} // --- for medias.head

		// -- we do it again here since the jsonbuilder is linear straight forward
		// XXX can this be moved into the above json object?
		for (l = c->medias.head; l; l = l->next) {
			media = l->data;

			snprintf(tmp, sizeof(tmp), "streams-%u", media->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array (builder);
			for (m = media->streams.head; m; m = m->next) {
				ps = m->data;
				JSON_ADD_STRING("%u",ps->unique_id);
			}
			json_builder_end_array (builder);

			snprintf(tmp, sizeof(tmp), "maps-%u", media->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array (builder);
			for (m = media->endpoint_maps.head; m; m = m->next) {
				ep = m->data;
				JSON_ADD_STRING("%u",ep->unique_id);
			}
			json_builder_end_array (builder);

			snprintf(tmp, sizeof(tmp), "payload_types-%u", media->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array (builder);
			for (m = media->codecs.codec_prefs.head; m; m = m->next) {
				pt = m->data;
				JSON_ADD_STRING("%u/" STR_FORMAT "/%u/" STR_FORMAT "/" STR_FORMAT "/%i/%i",
						pt->payload_type, STR_FMT(&pt->encoding),
						pt->clock_rate, STR_FMT(&pt->encoding_parameters),
						STR_FMT(&pt->format_parameters), pt->bitrate, pt->ptime);
			}
			json_builder_end_array (builder);
		}

		for (l = c->endpoint_maps.head; l; l = l->next) {
			ep = l->data;

			snprintf(tmp, sizeof(tmp), "map-%u", ep->unique_id);
			json_builder_set_member_name(builder, tmp);

			json_builder_begin_object (builder);
			{
				JSON_SET_SIMPLE("wildcard","%i",ep->wildcard);
				JSON_SET_SIMPLE("num_ports","%u",ep->num_ports);
				JSON_SET_SIMPLE_CSTR("intf_preferred_family",ep->logical_intf->preferred_family->rfc_name);
				JSON_SET_SIMPLE_STR("logical_intf",&ep->logical_intf->name);
				JSON_SET_SIMPLE_CSTR("endpoint",endpoint_print_buf(&ep->endpoint));

			}
			json_builder_end_object (builder);

		} // --- for c->endpoint_maps.head

		// -- we do it again here since the jsonbuilder is linear straight forward
		for (l = c->endpoint_maps.head; l; l = l->next) {
			ep = l->data;

			snprintf(tmp, sizeof(tmp), "map_sfds-%u", ep->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array (builder);
			for (m = ep->intf_sfds.head; m; m = m->next) {
				il = m->data;
				JSON_ADD_STRING("loc-%u",il->local_intf->unique_id);
				for (n = il->list.head; n; n = n->next) {
					sfd = n->data;
					JSON_ADD_STRING("%u",sfd->unique_id);
				}
			}
			json_builder_end_array (builder);
		}

	}
	json_builder_end_object (builder);

	JsonGenerator *gen = json_generator_new ();
	JsonNode * root = json_builder_get_root (builder);
	json_generator_set_root (gen, root);
	char* result = json_generator_to_data (gen, NULL);

	json_node_free (root);
	g_object_unref (gen);
	g_object_unref (builder);

	return result;

}


void redis_update_onekey(struct call *c, struct redis *r) {
	unsigned int redis_expires_s;

	if (!r)
		return;
	if (c->foreign_call)
		return;

	mutex_lock(&r->lock);
	// coverity[sleep : FALSE]
	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED) {
		mutex_unlock(&r->lock);
		return ;
	}

	rwlock_lock_r(&c->master_lock);

	redis_expires_s = rtpe_config.redis_expires_secs;

	c->redis_hosted_db = r->db;
	if (redis_select_db(r, c->redis_hosted_db)) {
		rlog(LOG_ERR, " >>>>>>>>>>>>>>>>> Redis error.");
		goto err;
	}

	char* result = redis_encode_json(c);
	if (!result)
		goto err;

	redis_pipe(r, "SET "PB" %s", STR(&c->callid), result);
	redis_pipe(r, "EXPIRE "PB" %i", STR(&c->callid), redis_expires_s);

	redis_consume(r);

	if (result)
		free(result);
	mutex_unlock(&r->lock);
	rwlock_unlock_r(&c->master_lock);

	return;
err:
	if (r->ctx && r->ctx->err)
		rlog(LOG_ERR, "Redis error: %s", r->ctx->errstr);
	redisFree(r->ctx);
	r->ctx = NULL;

	mutex_unlock(&r->lock);
	rwlock_unlock_r(&c->master_lock);
}

/* must be called lock-free */
void redis_delete(struct call *c, struct redis *r) {
	int delete_async = rtpe_config.redis_delete_async;
	rlog(LOG_DEBUG, "Redis delete_async=%d", delete_async);

	if (!r)
		return;

	if (delete_async) {
		mutex_lock(&r->async_lock);
		rwlock_lock_r(&c->master_lock);
		redis_delete_async_call_json(c, r);
		rwlock_unlock_r(&c->master_lock);
		mutex_unlock(&r->async_lock);
		return;
	}

	mutex_lock(&r->lock);
	// coverity[sleep : FALSE]
	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED) {
		mutex_unlock(&r->lock);
		return ;
	}
	rwlock_lock_r(&c->master_lock);

	if (redis_select_db(r, c->redis_hosted_db))
		goto err;

	redis_delete_call_json(c, r);

	rwlock_unlock_r(&c->master_lock);
	mutex_unlock(&r->lock);
	return;

err:
	if (r->ctx && r->ctx->err)
		rlog(LOG_ERR, "Redis error: %s", r->ctx->errstr);
	redisFree(r->ctx);
	r->ctx = NULL;

	rwlock_unlock_r(&c->master_lock);
	mutex_unlock(&r->lock);
}





void redis_wipe(struct redis *r) {
	if (!r)
		return;

	mutex_lock(&r->lock);
	// coverity[sleep : FALSE]
	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED) {
		mutex_unlock(&r->lock);
		return ;
	}
	redisCommandNR(r->ctx, "DEL calls");
	mutex_unlock(&r->lock);
}
