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
#include "helpers.h"
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

typedef union {
	GQueue *q;
	stream_fd_q *sfds_q;
	medias_arr *ma;
	sfd_intf_list_q *siq;
	packet_stream_q *psq;
	endpoint_map_q *emq;
} callback_arg_t __attribute__ ((__transparent_union__));


struct redis		*rtpe_redis;
struct redis		*rtpe_redis_write;
struct redis		*rtpe_redis_write_disabled;
struct redis		*rtpe_redis_notify;


static __thread const ng_parser_t *redis_parser = &ng_parser_json;
static const ng_parser_t *const redis_format_parsers[__REDIS_FORMAT_MAX] = {
	&ng_parser_native,
	&ng_parser_json,
};


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
#define PBSTR(x) (int) (x)->len, (x)->s
#define STR_R(x) (int) (x)->len, (x)->str
#define S_LEN(s,l) (int) (l), (s)

#else

#define PB "%b"
#define PBSTR(x) (x)->s, (size_t) (x)->len
#define STR_R(x) (x)->str, (size_t) (x)->len
#define S_LEN(s,l) (s), (size_t) (l)

#endif

#define REDIS_FMT(x) (int) (x)->len, (x)->str

// To protect against a restore race condition: Keyspace notifications are set up
// before existing calls are restored (restore_thread). Therefore the following
// scenario is possible:
// NOTIF THREAD:   receives SET, creates call
// RESTORE THREAD: executes KEYS *
// NOTIF THREAD:   receives another SET:
// NOTIF THREAD:      does call_destroy(), which:
//                       adds ports to late-release list
// RESTORE THREAD: comes across call ID, does GET
// RESTORE THREAD: creates new call
// RESTORE THREAD: wants to allocate ports, but they're still in use
// NOTIF THREAD:   now does release_closed_sockets()
static mutex_t redis_ports_release_lock = MUTEX_STATIC_INIT;
static cond_t redis_ports_release_cond = COND_STATIC_INIT;
static int redis_ports_release_balance = 0; // negative = releasers, positive = allocators

static int redis_check_conn(struct redis *r);
static void json_restore_call(struct redis *r, const str *id, bool foreign);
static int redis_connect(struct redis *r, int wait, bool resolve);
static int json_build_ssrc(struct call_monologue *ml, parser_arg arg);


// mutually exclusive multi-A multi-B lock
// careful with deadlocks against redis->lock
static void redis_ports_release_push(bool inc) {
	LOCK(&redis_ports_release_lock);
	if (inc) {
		while (redis_ports_release_balance < 0)
			cond_wait(&redis_ports_release_cond, &redis_ports_release_lock);
	}
	else {
		while (redis_ports_release_balance > 0)
			cond_wait(&redis_ports_release_cond, &redis_ports_release_lock);
	}
	redis_ports_release_balance += (inc ? 1 : -1);
}
static void redis_ports_release_pop(bool inc) {
	LOCK(&redis_ports_release_lock);
	redis_ports_release_balance -= (inc ? 1 : -1);
	if (redis_ports_release_balance == 0)
		cond_broadcast(&redis_ports_release_cond);
}

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
	LOCK(&r->lock);

	rval = redis_connect(r, 1, r->update_resolve);
	if (rval)
		r->state = REDIS_STATE_DISCONNECTED;
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
static int redis_connect(struct redis *r, int wait, bool resolve) {
	struct timeval tv;
	redisReply *rp;
	char *s;
	int cmd_timeout, connect_timeout;
	sockaddr_t a;

	if (r->ctx)
		redisFree(r->ctx);
	r->ctx = NULL;
	r->current_db = -1;

	connect_timeout = atomic_get_na(&rtpe_config.redis_connect_timeout);
	cmd_timeout = atomic_get_na(&rtpe_config.redis_cmd_timeout);

	tv.tv_sec = (int) connect_timeout / 1000;
	tv.tv_usec = (int) (connect_timeout % 1000) * 1000;

	/* re-resolve if asked */
	if (resolve && r->hostname) {
		if (sockaddr_getaddrinfo(&a, r->hostname))
			ilog(LOG_WARN, "Failed to re-resolve remote server hostname: '%s'. Just use older one: '%s'.",
					r->hostname, r->host);
		else {
			sockaddr_print(&a, r->host, sizeof(r->host));
			r->endpoint.address = a;
		}
	}

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
	call_t *c = NULL;
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
	keyspace_id = STR_LEN(rr->element[2]->str, rr->element[2]->len);

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
				// redis_notify->lock is held
				redis_ports_release_push(true);
				call_destroy(c);
				release_closed_sockets();
				redis_ports_release_pop(true);
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
		// redis_notify->lock is held
		redis_ports_release_push(true);
		call_destroy(c);
		release_closed_sockets();
		redis_ports_release_pop(true);
	}

err:
	if (c) // because of call_get(..)
		obj_put(c);

	mutex_unlock(&r->lock);
	release_closed_sockets();
	log_info_reset();
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
		rlog(LOG_ERROR, "redis_delete_async: Don't use Redis async deletions because no redis/redis_write.");
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
	rwlock_lock_r(&rtpe_config.keyspaces_lock);
	for (l = rtpe_config.redis_subscribed_keyspaces.head; l; l = l->next) {
		int id = GPOINTER_TO_INT(l->data);
		if (id < 0)
			continue;
		redis_notify_subscribe_action(r, SUBSCRIBE_KEYSPACE, id);
	}
	rwlock_unlock_r(&rtpe_config.keyspaces_lock);

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
		rlog(LOG_ERROR, "redis_delete_async_loop: Don't use Redis async deletions because no redis/redis_write.");
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

struct redis *redis_new(const endpoint_t *ep, int db, const char *hostname, const char *auth,
		enum redis_role role, int no_redis_required, bool update_resolve) {
	struct redis *r;
	r = g_slice_alloc0(sizeof(*r));

	r->endpoint = *ep;
	sockaddr_print(&ep->address, r->host, sizeof(r->host));
	r->db = db;
	r->auth = auth;
	r->hostname = hostname;
	r->role = role;
	r->state = REDIS_STATE_DISCONNECTED;
	r->no_redis_required = no_redis_required;
	r->restore_tick = 0;
	r->consecutive_errors = 0;
	r->update_resolve = update_resolve;
	mutex_init(&r->lock);

	if (redis_connect(r, 10, false)) {
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

struct redis *redis_dup(const struct redis *r, int db) {
	return redis_new(&r->endpoint,
				(db >= 0 ? db : r->db),
				r->hostname,
				r->auth,
				r->role,
				r->no_redis_required,
				r->update_resolve);
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

	allowed_errors = atomic_get_na(&rtpe_config.redis_allowed_errors);
	disable_time = atomic_get_na(&rtpe_config.redis_disable_time);

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
		ilog(LOG_WARNING, "Redis server '%s' is disabled. Don't try RE-Establishing for %" TIME_T_INT_FMT " more seconds",
				r->hostname, r->restore_tick - rtpe_now.tv_sec);
		return REDIS_STATE_DISCONNECTED;
	}

	if (r->state == REDIS_STATE_DISCONNECTED)
		ilog(LOG_INFO, "RE-Establishing connection for Redis server '%s'", r->hostname);

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
		rlog(LOG_ERR, "Lost connection to Redis '%s'",
			r->hostname);
		r->state = REDIS_STATE_DISCONNECTED;
	}

	// try redis reconnect => will free current r->ctx
	if (redis_connect(r, 1, r->update_resolve)) {
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
static void redis_delete_call_json(call_t *c, struct redis *r) {
	redis_pipe(r, "DEL "PB"", PBSTR(&c->callid));
	redis_consume(r);
}

static void redis_delete_async_call_json(call_t *c, struct redis *r) {
	gchar *redis_command;

	redis_command = g_strdup_printf("SELECT %i", c->redis_hosted_db);
	g_queue_push_tail(&r->async_queue, redis_command);

	redis_command = g_strdup_printf("DEL " STR_FORMAT, STR_FMT(&c->callid));
	g_queue_push_tail(&r->async_queue, redis_command);
}

// XXX rework restore procedure to use functions like this everywhere and eliminate the GHashTable
INLINE long long parser_get_ll(parser_arg arg, const char *key) {
	return redis_parser->dict_get_int_str(arg, key, -1);
}

static void json_get_hash_iter(const ng_parser_t *parser, str *key, parser_arg val_a, helper_arg arg) {
	str val;
	if (!parser->get_str(val_a, &val)) {
		rlog(LOG_ERROR, "Could not read json member: " STR_FORMAT, STR_FMT(key));
		return;
	}

	// XXX convert to proper str ht
	char *tmp = __g_memdup(key->s, key->len + 1);
	tmp[key->len] = '\0';
	// XXX eliminate string dup? eliminate URI decode?
	if (g_hash_table_insert(arg.ht, tmp, parser->unescape(val.s, val.len)) != TRUE)
		rlog(LOG_WARNING,"Key %s already exists", tmp);
}

static int json_get_hash(struct redis_hash *out,
		const char *key, unsigned int id, parser_arg root)
{
	static unsigned int MAXKEYLENGTH = 512;
	char key_concatted[MAXKEYLENGTH];
	int rc=0;

	if (id == -1) {
		rc = snprintf(key_concatted, MAXKEYLENGTH, "%s",key);
	} else {
		rc = snprintf(key_concatted, MAXKEYLENGTH, "%s-%u",key,id);
	}
	if (rc>=MAXKEYLENGTH) {
		rlog(LOG_ERROR,"Json key too long.");
		return -1;
	}

	parser_arg dict = redis_parser->dict_get_expect(root, key_concatted, BENCODE_DICTIONARY);
	if (!dict.gen) {
		rlog(LOG_ERROR, "Could not read json member: %s",key_concatted);
		return -1;
	}

	out->ht = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
	if (!out->ht)
		return -1;

	redis_parser->dict_iter(redis_parser, dict, json_get_hash_iter, out->ht);

	return 0;
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
define_get_int_type(llu, unsigned long long, strtoll);
define_get_int_type(ld, long, strtoll);
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

struct cb_iter_ptrs { // XXX remove this?
	int (*cb)(str *, callback_arg_t, struct redis_list *, void *);
	callback_arg_t cb_arg;
	struct redis_list *list;
	void *ptr;
};

static void json_build_list_cb_iter(str *val, unsigned int i, helper_arg arg) {
	struct cb_iter_ptrs *args = arg.generic;
	str *s = redis_parser->unescape(val->s, val->len);
	args->cb(s, args->cb_arg, args->list, args->ptr);
	g_free(s);
}

static int json_build_list_cb(callback_arg_t q, call_t *c, const char *key,
		unsigned int idx, struct redis_list *list,
		int (*cb)(str *, callback_arg_t, struct redis_list *, void *), void *ptr, parser_arg arg)
{
	char key_concatted[256];

	snprintf(key_concatted, 256, "%s-%u", key, idx);

	parser_arg r_list = redis_parser->dict_get_expect(arg, key_concatted, BENCODE_LIST);
	if (!r_list.gen) {
		rlog(LOG_ERROR,"Key in json not found:%s",key_concatted);
		return -1;
	}
	struct cb_iter_ptrs args = {
		.cb = cb,
		.cb_arg = q,
		.list = list,
		.ptr = ptr,
	};
	redis_parser->list_iter(redis_parser, r_list, json_build_list_cb_iter, NULL, &args);
	return 0;
}

static int rbl_cb_simple(str *s, callback_arg_t qp, struct redis_list *list, void *ptr) {
	GQueue *q = qp.q;
	int j;
	j = str_to_i(s, 0);
	g_queue_push_tail(q, redis_list_get_idx_ptr(list, (unsigned) j));
	return 0;
}

static int rbpa_cb_simple(str *s, callback_arg_t pap, struct redis_list *list, void *ptr) {
	medias_arr *pa = pap.ma;
	int j;
	j = str_to_i(s, 0);
	t_ptr_array_add(pa, redis_list_get_idx_ptr(list, (unsigned) j));
	return 0;
}

static int json_build_list(callback_arg_t q, call_t *c, const char *key,
		unsigned int idx, struct redis_list *list, parser_arg arg)
{
	return json_build_list_cb(q, c, key, idx, list, rbl_cb_simple, NULL, arg);
}

static int json_build_ptra(medias_arr *q, call_t *c, const char *key,
		unsigned int idx, struct redis_list *list, parser_arg arg)
{
	return json_build_list_cb(q, c, key, idx, list, rbpa_cb_simple, NULL, arg);
}

static int json_get_list_hash(struct redis_list *out,
		const char *key,
		const struct redis_hash *rh, const char *rh_num_key, parser_arg arg)
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
		if (json_get_hash(&out->rh[i], key, i, arg))
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
static int redis_hash_get_sdes_params(sdes_q *out, const struct redis_hash *h, const char *k) {
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

		t_queue_push_tail(out, cps);
		snprintf(key, sizeof(key), "%s-%u", k, iter++);
		kk = key;
	}
	return 0;
}

static int redis_sfds(call_t *c, struct redis_list *sfds) {
	unsigned int i;
	str family, intf_name;
	struct redis_hash *rh;
	sockfamily_t *fam;
	struct logical_intf *lif;
	struct local_intf *loc;
	socket_q q = TYPED_GQUEUE_INIT;
	unsigned int loc_uid;
	stream_fd *sfd;
	socket_t *sock;
	int port, fd;
	const char *err;

	for (i = 0; i < sfds->len; i++) {
		rh = &sfds->rh[i];

		if (redis_hash_get_int(&fd, rh, "fd"))
			fd = 0;
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

		if (fd != -1) {
			err = "failed to open ports";
			if (__get_consecutive_ports(&q, 1, port, loc->spec, &c->callid))
				goto err;
			err = "no port returned";
			sock = t_queue_pop_head(&q);
			if (!sock)
				goto err;
			set_tos(sock, c->tos);
		}
		else {
			sock = g_slice_alloc(sizeof(*sock));
			dummy_socket(sock, &loc->spec->local_address.addr);
		}
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

static int redis_streams(call_t *c, struct redis_list *streams) {
	unsigned int i;
	struct redis_hash *rh;
	struct packet_stream *ps;

	for (i = 0; i < streams->len; i++) {
		rh = &streams->rh[i];

		ps = __packet_stream_new(c);
		if (!ps)
			return -1;

		atomic64_set_na(&ps->last_packet, time(NULL));
		if (redis_hash_get_a64(&ps->ps_flags, rh, "ps_flags"))
			return -1;
		if (redis_hash_get_unsigned((unsigned int *) &ps->component, rh, "component"))
			return -1;
		if (redis_hash_get_endpoint(&ps->endpoint, rh, "endpoint"))
			return -1;
		if (redis_hash_get_endpoint(&ps->advertised_endpoint, rh, "advertised_endpoint"))
			return -1;
		if (redis_hash_get_stats(ps->stats_in, rh, "stats"))
			return -1;
		if (redis_hash_get_sdes_params1(&ps->crypto.params, rh, "") == -1)
			return -1;

		streams->ptrs[i] = ps;

		PS_CLEAR(ps, KERNELIZED);
	}
	return 0;
}

static int redis_tags(call_t *c, struct redis_list *tags, parser_arg arg) {
	unsigned int i;
	int ii;
	long il;
	atomic64 a64;
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
			ml->label = call_str_cpy(&s);
		if (!redis_hash_get_str(&s, rh, "metadata"))
			c->metadata = call_str_cpy(&s);
		redis_hash_get_time_t(&ml->deleted, rh, "deleted");
		if (!redis_hash_get_int(&ii, rh, "block_dtmf"))
			ml->block_dtmf = ii;
		if (!redis_hash_get_a64(&a64, rh, "ml_flags"))
			ml->ml_flags = a64;

		/* s= */
		if (!redis_hash_get_str(&s, rh, "sdp_session_name"))
			ml->sdp_session_name = call_str_cpy(&s);
		/* t= */
		if (!redis_hash_get_str(&s, rh, "sdp_session_timing"))
			ml->sdp_session_timing = call_str_cpy(&s);
		/* o= */
		if (!redis_hash_get_str(&s, rh, "sdp_orig_parsed")) {
			ml->session_sdp_orig = g_slice_alloc0(sizeof(*ml->session_sdp_orig));
			ml->session_sdp_orig->parsed = 1;
			redis_hash_get_llu(&ml->session_sdp_orig->version_num, rh, "sdp_orig_version_num");
			if (!redis_hash_get_str(&s, rh, "sdp_orig_username"))
				ml->session_sdp_orig->username = str_dup_str(&s);
			if (!redis_hash_get_str(&s, rh, "sdp_orig_session_id"))
				ml->session_sdp_orig->session_id = str_dup_str(&s);
			if (!redis_hash_get_str(&s, rh, "sdp_orig_version_str"))
				ml->session_sdp_orig->version_str = str_dup_str(&s);
			if (!redis_hash_get_str(&s, rh, "sdp_orig_address_network_type"))
				ml->session_sdp_orig->address.network_type = str_dup_str(&s);
			if (!redis_hash_get_str(&s, rh, "sdp_orig_address_address_type"))
				ml->session_sdp_orig->address.address_type = str_dup_str(&s);
			if (!redis_hash_get_str(&s, rh, "sdp_orig_address_address"))
				ml->session_sdp_orig->address.address = str_dup_str(&s);
		}
		/* o= last used of the other side*/
		if (!redis_hash_get_str(&s, rh, "last_sdp_orig_parsed")) {
			ml->session_last_sdp_orig = g_slice_alloc0(sizeof(*ml->session_last_sdp_orig));
			ml->session_last_sdp_orig->parsed = 1;
			redis_hash_get_llu(&ml->session_last_sdp_orig->version_num, rh, "last_sdp_orig_version_num");
			if (!redis_hash_get_str(&s, rh, "last_sdp_orig_username"))
				ml->session_last_sdp_orig->username = str_dup_str(&s);
			if (!redis_hash_get_str(&s, rh, "last_sdp_orig_session_id"))
				ml->session_last_sdp_orig->session_id = str_dup_str(&s);
			if (!redis_hash_get_str(&s, rh, "last_sdp_orig_version_str"))
				ml->session_last_sdp_orig->version_str = str_dup_str(&s);
			if (!redis_hash_get_str(&s, rh, "last_sdp_orig_address_network_type"))
				ml->session_last_sdp_orig->address.network_type = str_dup_str(&s);
			if (!redis_hash_get_str(&s, rh, "last_sdp_orig_address_address_type"))
				ml->session_last_sdp_orig->address.address_type = str_dup_str(&s);
			if (!redis_hash_get_str(&s, rh, "last_sdp_orig_address_address"))
				ml->session_last_sdp_orig->address.address = str_dup_str(&s);
		}

		ml->sdp_session_bandwidth.as = (!redis_hash_get_ld(&il, rh, "sdp_session_as")) ? il : -1;
		ml->sdp_session_bandwidth.ct = (!redis_hash_get_ld(&il, rh, "sdp_session_ct")) ? il : -1;
		ml->sdp_session_bandwidth.rr = (!redis_hash_get_ld(&il, rh, "sdp_session_rr")) ? il : -1;
		ml->sdp_session_bandwidth.rs = (!redis_hash_get_ld(&il, rh, "sdp_session_rs")) ? il : -1;

		if (redis_hash_get_str(&s, rh, "desired_family"))
			return -1;
		ml->desired_family = get_socket_family_rfc(&s);

		if (redis_hash_get_str(&s, rh, "logical_intf")
				|| !(ml->logical_intf = get_logical_interface(&s, ml->desired_family, 0)))
		{
			rlog(LOG_ERR, "unable to find specified local interface");
			ml->logical_intf = get_logical_interface(NULL, ml->desired_family, 0);
		}

		if (json_build_ssrc(ml, arg))
			return -1;

		tags->ptrs[i] = ml;
	}

	return 0;
}

static rtp_payload_type *rbl_cb_plts_g(str *s, struct redis_list *list, void *ptr) {
	str ptype;
	struct call_media *med = ptr;

	if (!str_token(&ptype, s, '/'))
		return NULL;

	rtp_payload_type *pt = codec_make_payload_type(s, med->type_id);
	if (!pt)
		return NULL;

	pt->payload_type = str_to_i(&ptype, 0);

	return pt;
}
static int rbl_cb_plts_r(str *s, callback_arg_t dummy, struct redis_list *list, void *ptr) {
	struct call_media *med = ptr;
	codec_store_add_raw(&med->codecs, rbl_cb_plts_g(s, list, ptr));
	return 0;
}
static int json_medias(call_t *c, struct redis_list *medias, struct redis_list *tags,
		parser_arg arg)
{
	unsigned int i;
	long il;
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
		med->type = call_str_cpy(&s);
		med->type_id = codec_get_type(&med->type);
		if (!redis_hash_get_str(&s, rh, "format_str"))
			med->format_str = call_str_cpy(&s);
		if (!redis_hash_get_str(&s, rh, "media_id"))
			med->media_id = call_str_cpy(&s);

		if (redis_hash_get_int(&med->ptime, rh, "ptime"))
			return -1;
		if (redis_hash_get_int(&med->maxptime, rh, "maxptime"))
			return -1;

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

		if (redis_hash_get_a64(&med->media_flags, rh,
					"media_flags"))
			return -1;

		if (redis_hash_get_sdes_params(&med->sdes_in, rh, "sdes_in") < 0)
			return -1;
		if (redis_hash_get_sdes_params(&med->sdes_out, rh, "sdes_out") < 0)
			return -1;

		/* bandwidth data is not critical */
		med->sdp_media_bandwidth.as = (!redis_hash_get_ld(&il, rh, "bandwidth_as")) ? il : -1;
		med->sdp_media_bandwidth.rr = (!redis_hash_get_ld(&il, rh, "bandwidth_rr")) ? il : -1;
		med->sdp_media_bandwidth.rs = (!redis_hash_get_ld(&il, rh, "bandwidth_rs")) ? il : -1;

		json_build_list_cb(NULL, c, "payload_types", i, NULL, rbl_cb_plts_r, med, arg);
		/* XXX dtls */

		/* link monologue */
		med->monologue = redis_list_get_ptr(tags, &medias->rh[i], "tag");

		medias->ptrs[i] = med;
	}

	return 0;
}

static int redis_maps(call_t *c, struct redis_list *maps) {
	unsigned int i;
	struct redis_hash *rh;
	struct endpoint_map *em;
	str s, t;
	sockfamily_t *fam;

	for (i = 0; i < maps->len; i++) {
		rh = &maps->rh[i];

		/* from call.c:__get_endpoint_map() */
		em = uid_slice_alloc0(em, &c->endpoint_maps.q);
		t_queue_init(&em->intf_sfds);

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
	stream_fd *sfd;

	for (i = 0; i < sfds->len; i++) {
		sfd = sfds->ptrs[i];

		sfd->stream = redis_list_get_ptr(streams, &sfds->rh[i], "stream");
		if (!sfd->stream)
			return -1;
	}

	return 0;
}

/**
 * Supports only `media-subscriptions-*` structures.
 * Restores media subscriptions based on:
 * `unique_id`, `offer_answer`, `rtcp_only`, `egress`
 */
static int rbl_subs_cb(str *s, callback_arg_t dummy, struct redis_list *list, void *ptr) {
	str token;

	if (!str_token_sep(&token, s, '/'))
		return -1;

	unsigned int media_unique_id = str_to_i(&token, 0);

	bool offer_answer = false;
	bool rtcp_only = false;
	bool egress = false;

	if (str_token_sep(&token, s, '/')) {
		offer_answer = str_to_i(&token, 0) ? true : false;
		if (str_token_sep(&token, s, '/')) {
			rtcp_only = str_to_i(&token, 0) ? true : false;
			if (str_token_sep(&token, s, '/'))
				egress = str_to_i(&token, 0) ? true : false;
		}
	}

	struct call_media *media = ptr;
	struct call_media *other_media = redis_list_get_idx_ptr(list, media_unique_id);
	if (!other_media)
		return -1;

	__add_media_subscription(media, other_media,
						&(struct sink_attrs) {
						.offer_answer = offer_answer,
						.rtcp_only = rtcp_only,
						.egress = egress,
					});

	codec_handlers_update(other_media, media, .reset_transcoding = true);

	return 0;
}

static int cb_tag_aliases(str *s, callback_arg_t dummy, struct redis_list *list, void *ptr) {
	struct call_monologue *ml = ptr;
	t_queue_push_tail(&ml->tag_aliases, call_str_dup(s));
	return 0;
}

static int json_link_tags(call_t *c, struct redis_list *tags, struct redis_list *medias, parser_arg arg)
{
	unsigned int i;
	struct call_monologue *ml, *other_ml;
	GQueue q = G_QUEUE_INIT;
	GList *l;

	for (i = 0; i < tags->len; i++)
	{
		ml = tags->ptrs[i];

		char key_subscriptions[256], key_subscriptions_oa[256], key_subscriptions_noa[256];
		snprintf(key_subscriptions, 256, "subscriptions-%u", i);
		snprintf(key_subscriptions_oa, 256, "subscriptions-oa-%u", i);
		snprintf(key_subscriptions_noa, 256, "subscriptions-noa-%u", i);

		/* Legacy */
		if (redis_parser->dict_contains(arg, key_subscriptions))
			rlog(LOG_DEBUG, "Outdated format used to restore subscriptions (older rtpengine ver.), will be dropped.");

		if (redis_parser->dict_contains(arg, key_subscriptions_oa))
			rlog(LOG_DEBUG, "Outdated format used to restore subscriptions (older rtpengine ver.), will be dropped.");

		if (redis_parser->dict_contains(arg, key_subscriptions_noa))
			rlog(LOG_DEBUG, "Outdated format used to restore subscriptions (older rtpengine ver.), will be dropped.");

		/* associated tags */
		if (json_build_list(&q, c, "associated_tags", i, tags, arg))
			return -1;
		for (l = q.head; l; l = l->next)
		{
			other_ml = l->data;
			if (!other_ml)
			    return -1;
			g_hash_table_insert(ml->associated_tags, other_ml, other_ml);
		}
		g_queue_clear(&q);

		json_build_list_cb(NULL, c, "tag_aliases", i, NULL, cb_tag_aliases, ml, arg);

		if (json_build_ptra(ml->medias, c, "medias", i, medias, arg))
			return -1;
	}

	return 0;
}

static struct media_subscription *__find_media_subscriber(struct call_media *media, struct packet_stream *sink) {
	if (!media || !sink || !sink->media)
		return NULL;

	struct call_monologue * find_ml = sink->media->monologue;

	for (__auto_type subscriber = media->media_subscribers.head;
			subscriber;
			subscriber = subscriber->next)
	{
		struct media_subscription * ms = subscriber->data;
		if (find_ml == ms->monologue)
			return ms;
	}

	return NULL;
}

static int json_link_streams(call_t *c, struct redis_list *streams,
		struct redis_list *sfds, struct redis_list *medias, parser_arg arg)
{
	unsigned int i;
	struct packet_stream *ps;
	GQueue q = G_QUEUE_INIT;
	GList *l;

	for (i = 0; i < streams->len; i++) {
		ps = streams->ptrs[i];
		struct call_media *media = ps->media;

		ps->media = redis_list_get_ptr(medias, &streams->rh[i], "media");
		ps->selected_sfd = redis_list_get_ptr(sfds, &streams->rh[i], "sfd");
		ps->rtcp_sibling = redis_list_get_ptr(streams, &streams->rh[i], "rtcp_sibling");

		if (json_build_list(&ps->sfds, c, "stream_sfds", i, sfds, arg))
			return -1;

		if (json_build_list(&q, c, "rtp_sinks", i, streams, arg))
			return -1;
		for (l = q.head; l; l = l->next) {
			struct packet_stream *sink = l->data;
			if (!sink)
				return -1;
			struct media_subscription *ms = __find_media_subscriber(media, sink);
			if (ms && ms->attrs.egress)
				continue;
			struct sink_attrs attrs = { .rtcp_only = (ms && ms->attrs.rtcp_only) ? 1 : 0 };
			__add_sink_handler(&ps->rtp_sinks, sink, &attrs);
		}
		g_queue_clear(&q);

		// backwards compatibility
		if (!ps->rtp_sinks.length) {
			struct packet_stream *sink = redis_list_get_ptr(streams, &streams->rh[i], "rtp_sink");
			if (sink)
				__add_sink_handler(&ps->rtp_sinks, sink, NULL);
		}

		if (json_build_list(&q, c, "rtcp_sinks", i, streams, arg))
			return -1;
		for (l = q.head; l; l = l->next) {
			struct packet_stream *sink = l->data;
			if (!sink)
				return -1;
			__add_sink_handler(&ps->rtcp_sinks, sink, NULL);
		}
		g_queue_clear(&q);

		// backwards compatibility
		if (!ps->rtcp_sinks.length) {
			struct packet_stream *sink = redis_list_get_ptr(streams, &streams->rh[i], "rtcp_sink");
			if (sink)
				__add_sink_handler(&ps->rtcp_sinks, sink, NULL);
		}

		if (ps->media)
			__rtp_stats_update(ps->rtp_stats, &ps->media->codecs);

		__init_stream(ps);
	}

	return 0;
}

static int json_link_medias(call_t *c, struct redis_list *medias,
		struct redis_list *streams, struct redis_list *maps, parser_arg arg)
{
	for (unsigned int i = 0; i < medias->len; i++)
	{
		struct call_media *med = medias->ptrs[i];
		if (!med || !med->monologue)
			continue;
		if (json_build_list(&med->streams, c, "streams", i, streams, arg))
			return -1;
		if (json_build_list(&med->endpoint_maps, c, "maps", i, maps, arg))
			return -1;

		if (med->media_id.s)
			t_hash_table_insert(med->monologue->media_ids, &med->media_id, med);

		/* find the pair media to subscribe */
		if (!json_build_list_cb(NULL, c, "media-subscriptions", med->unique_id,
					medias, rbl_subs_cb, med, arg))
		{
			rlog(LOG_DEBUG, "Restored media subscriptions for: '" STR_FORMAT_M "'", STR_FMT_M(&med->monologue->tag));
		}
	}
	return 0;
}

static int rbl_cb_intf_sfds(str *s, callback_arg_t qp, struct redis_list *list, void *ptr) {
	sfd_intf_list_q *q = qp.siq;
	int i;
	struct sfd_intf_list *il;
	struct endpoint_map *em;
	void *sfd;

	if (!strncmp(s->s, "loc-", 4)) {
		il = g_slice_alloc0(sizeof(*il));
		em = ptr;
		i = atoi(s->s+4);
		il->local_intf = g_queue_peek_nth((GQueue*) &em->logical_intf->list, i);
		if (!il->local_intf)
			return -1;
		t_queue_push_tail(q, il);
		return 0;
	}

	il = t_queue_peek_tail(q);
	if (!il)
		return -1;

	sfd = redis_list_get_idx_ptr(list, atoi(s->s));
	if (G_UNLIKELY(!sfd))
	    return -1;

	t_queue_push_tail(&il->list, sfd);
	return 0;
}

static int json_link_maps(call_t *c, struct redis_list *maps,
		struct redis_list *sfds, parser_arg arg)
{
	unsigned int i;
	struct endpoint_map *em;

	for (i = 0; i < maps->len; i++) {
		em = maps->ptrs[i];

		if (json_build_list_cb(&em->intf_sfds, c, "map_sfds", em->unique_id, sfds,
				rbl_cb_intf_sfds, em, arg))
			return -1;
	}
	return 0;
}

static void json_build_ssrc_iter(const ng_parser_t *parser, parser_arg dict, helper_arg arg) {
	struct call_monologue *ml = arg.ml;

	uint32_t ssrc = parser_get_ll(dict, "ssrc");
	struct ssrc_entry_call *se = get_ssrc(ssrc, ml->ssrc_hash);
	if (!se)
		return;

	atomic_set_na(&se->input_ctx.stats->ext_seq, parser_get_ll(dict, "in_srtp_index"));
	atomic_set_na(&se->input_ctx.stats->rtcp_seq, parser_get_ll(dict, "in_srtcp_index"));
	payload_tracker_add(&se->input_ctx.tracker, parser_get_ll(dict, "in_payload_type"));
	atomic_set_na(&se->output_ctx.stats->ext_seq, parser_get_ll(dict, "out_srtp_index"));
	atomic_set_na(&se->output_ctx.stats->rtcp_seq, parser_get_ll(dict, "out_srtcp_index"));
	payload_tracker_add(&se->output_ctx.tracker, parser_get_ll(dict, "out_payload_type"));

	obj_put(&se->h);
}

static int json_build_ssrc(struct call_monologue *ml, parser_arg arg) {
	char tmp[2048];
	snprintf(tmp, sizeof(tmp), "ssrc_table-%u", ml->unique_id);
	parser_arg list = redis_parser->dict_get_expect(arg, tmp, BENCODE_LIST);
	if (!list.gen) {
		// non-fatal for backwards compatibility
		return 0;
	}
	redis_parser->list_iter(redis_parser, list, NULL, json_build_ssrc_iter, ml);
	return 0;
}

static void json_restore_call(struct redis *r, const str *callid, bool foreign) {
	redisReply* rr_jsonStr;
	struct redis_hash call;
	struct redis_list tags, sfds, streams, medias, maps;
	call_t *c = NULL;
	str s, id;
	time_t last_signal;

	const char *err = 0;
	int i;
	atomic64 a64;
	JsonNode *json_root = NULL;
	JsonParser *parser = NULL;
	bencode_item_t *benc_root = NULL;
	bencode_buffer_t buf = {0};

	mutex_lock(&r->lock);
	rr_jsonStr = redis_get(r, REDIS_REPLY_STRING, "GET " PB, PBSTR(callid));
	mutex_unlock(&r->lock);

	bool must_release_pop = true;
	redis_ports_release_push(false);

	err = "could not retrieve JSON data from redis";
	if (!rr_jsonStr)
		goto err1;

	parser_arg root = {0};

	if (rr_jsonStr->str[0] == '{') {
		parser = json_parser_new();
		err = "could not parse JSON data";
		if (!json_parser_load_from_data (parser, rr_jsonStr->str, -1, NULL))
			goto err1;
		json_root = json_parser_get_root(parser);
		err = "could not read JSON data";
		if (!json_root)
			goto err1;
		root.json = json_root;
		redis_parser = &ng_parser_json;
	}
	else if (rr_jsonStr->str[0] == 'd') {
		int ret = bencode_buffer_init(&buf);
		err = "failed to initialise bencode buffer";
		if (ret)
			goto err1;
		err = "failed to decode bencode dictionary";
		benc_root = bencode_decode_expect_str(&buf, &STR_LEN(rr_jsonStr->str, rr_jsonStr->len),
				BENCODE_DICTIONARY);
		if (!benc_root)
			goto err1;
		redis_parser = &ng_parser_native;
		root.benc = benc_root;
	}
	else {
		err = "Unrecognised serial format";
		goto err1;
	}

	c = call_get_or_create(callid, false);
	err = "failed to create call struct";
	if (!c)
		goto err1;

	err = "'call' data incomplete";
	if (json_get_hash(&call, "json", -1, root))
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
	if (json_get_list_hash(&tags, "tag", &call, "num_tags", root))
		goto err3;
	err = "'sfds' incomplete";
	if (json_get_list_hash(&sfds, "sfd", &call, "num_sfds", root))
		goto err4;
	err = "'streams' incomplete";
	if (json_get_list_hash(&streams, "stream", &call, "num_streams", root))
		goto err5;
	err = "'medias' incomplete";
	if (json_get_list_hash(&medias, "media", &call, "num_medias", root))
		goto err6;
	err = "'maps' incomplete";
	if (json_get_list_hash(&maps, "map", &call, "num_maps", root))
		goto err7;

	err = "missing 'created' timestamp";
	if (redis_hash_get_timeval(&c->created, &call, "created"))
		goto err8;
	redis_hash_get_timeval(&c->destroyed, &call, "destroyed");
	c->last_signal = last_signal;
	if (redis_hash_get_int(&i, &call, "tos"))
		c->tos = 184;
	else
		c->tos = i;
	redis_hash_get_time_t(&c->deleted, &call, "deleted");
	redis_hash_get_time_t(&c->ml_deleted, &call, "ml_deleted");
	if (!redis_hash_get_str(&id, &call, "created_from"))
		c->created_from = call_strdup_str(&id);
	if (!redis_hash_get_str(&id, &call, "created_from_addr")) {
		err = "failed to parse 'created_from_addr'";
		if (sockaddr_parse_any_str(&c->created_from_addr, &id))
			goto err8;
	}
	if (!redis_hash_get_int(&i, &call, "block_dtmf"))
		c->block_dtmf = i;
	if (!redis_hash_get_a64(&a64, &call, "call_flags"))
		c->call_flags = a64;

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
	if (redis_tags(c, &tags, root))
		goto err8;
	err = "failed to create medias";
	if (json_medias(c, &medias, &tags, root))
		goto err8;
	err = "failed to create maps";
	if (redis_maps(c, &maps))
		goto err8;

	err = "failed to link sfds";
	if (redis_link_sfds(&sfds, &streams))
		goto err8;
	err = "failed to link streams";
	if (json_link_streams(c, &streams, &sfds, &medias, root))
		goto err8;
	err = "failed to link tags";
	if (json_link_tags(c, &tags, &medias, root))
		goto err8;
	err = "failed to link medias";
	if (json_link_medias(c, &medias, &streams, &maps, root))
		goto err8;
	err = "failed to link maps";
	if (json_link_maps(c, &maps, &sfds, root))
		goto err8;

	// presence of this key determines whether we were recording at all
	if (!redis_hash_get_str(&s, &call, "recording_meta_prefix")) {
		c->recording_meta_prefix = call_str_cpy(&s);
		// coverity[check_return : FALSE]
		redis_hash_get_str(&s, &call, "recording_metadata");
		c->metadata = call_str_cpy(&s);
		redis_hash_get_str(&s, &call, "recording_file");
		c->recording_file = call_str_cpy(&s);
		redis_hash_get_str(&s, &call, "recording_path");
		c->recording_path = call_str_cpy(&s);
		redis_hash_get_str(&s, &call, "recording_pattern");
		c->recording_pattern = call_str_cpy(&s);
		redis_hash_get_str(&s, &call, "recording_random_tag");
		c->recording_random_tag = call_str_cpy(&s);
		recording_start_daemon(c);
	}

	// force-clear foreign flag (could have been set through call_flags), then
	// set it to what we want, updating the statistics if needed
	CALL_CLEAR(c, FOREIGN);
	call_make_own_foreign(c, foreign);
	bf_set_clear(&c->call_flags, CALL_FLAG_MEDIA_COUNTED, false);
	statistics_update_ip46_inc_dec(c, CMC_INCREMENT);

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
	if (parser)
		g_object_unref (parser);
	if (rr_jsonStr)
		freeReplyObject(rr_jsonStr);	
	bencode_buffer_free(&buf);
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
		release_closed_sockets();
		if (must_release_pop) // avoid deadlock with redis_notify->lock below
			redis_ports_release_pop(false);
		must_release_pop = false;

		mutex_lock(&rtpe_redis_write->lock);

		redis_select_db(rtpe_redis_write, rtpe_redis_write->db);

		redisCommandNR(rtpe_redis_write->ctx, "DEL " PB, PBSTR(callid));
		mutex_unlock(&rtpe_redis_write->lock);

		if (rtpe_redis_notify) {
			mutex_lock(&rtpe_redis_notify->lock);
			redisCommandNR(rtpe_redis_notify->ctx, "DEL " PB, PBSTR(callid));
			mutex_unlock(&rtpe_redis_notify->lock);
		}
	}
	if (c)
		obj_put(c);
	release_closed_sockets();
	if (must_release_pop)
		redis_ports_release_pop(false);
	log_info_reset();
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
	str callid = STR_LEN(call->str, call->len);

	rlog(LOG_DEBUG, "Processing call ID '%s%.*s%s' from Redis", FMT_M(REDIS_FMT(call)));

	mutex_lock(&ctx->r_m);
	r = g_queue_pop_head(&ctx->r_q);
	mutex_unlock(&ctx->r_m);

	gettimeofday(&rtpe_now, NULL);
	json_restore_call(r, &callid, ctx->foreign);

	mutex_lock(&ctx->r_m);
	g_queue_push_tail(&ctx->r_q, r);
	mutex_unlock(&ctx->r_m);
	release_closed_sockets();
}

int redis_restore(struct redis *r, bool foreign, int db) {
	redisReply *calls = NULL, *call;
	int ret = -1;
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

	if (calls->elements == 0)
		goto out;

	mutex_init(&ctx.r_m);
	g_queue_init(&ctx.r_q);
	ctx.foreign = foreign;
	for (int i = 0; i < rtpe_config.redis_num_threads; i++) {
		struct redis *dup = redis_dup(r, db);
		if (!dup) {
			rlog(LOG_ERR, "Failed to create thread connection to Redis");
			goto err;
		}
		g_queue_push_tail(&ctx.r_q, dup);
	}
	gtp = g_thread_pool_new(restore_thread, &ctx, rtpe_config.redis_num_threads, TRUE, NULL);

	for (int i = 0; i < calls->elements; i++) {
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

out:
	ret = 0;

	freeReplyObject(calls);

err:
	for (unsigned int i = 0; i < num_log_levels; i++)
		if (rtpe_config.common.log_levels[i] > 0)
			rtpe_config.common.log_levels[i] &= ~LOG_FLAG_RESTORE;
	return ret;
}

#define JSON_ADD_LIST_STRING(f,...) do { \
		int len = snprintf(tmp,sizeof(tmp), f, __VA_ARGS__); \
		char enc[len * 3 + 1]; \
		str encstr = parser->escape(enc, tmp, len); \
		parser->list_add_str_dup(inner, &encstr); \
	} while (0)
#define JSON_SET_NSTRING(a,b,c,...) do { \
		int len = snprintf(tmp,sizeof(tmp), c, __VA_ARGS__); \
		char enc[len * 3 + 1]; \
		str encstr = parser->escape(enc, tmp, len); \
		snprintf(tmp,sizeof(tmp), a,b); \
		parser->dict_add_str_dup(inner, tmp, &encstr); \
	} while (0)
#define JSON_SET_NSTRING_CSTR(a,b,d) JSON_SET_NSTRING_LEN(a, b, strlen(d), d)
#define JSON_SET_NSTRING_LEN(a,b,l,d) do { \
		char enc[l * 3 + 1]; \
		str encstr = parser->escape(enc, d, l); \
		snprintf(tmp,sizeof(tmp), a,b); \
		parser->dict_add_str_dup(inner, tmp, &encstr); \
	} while (0)
#define JSON_SET_SIMPLE(a,c,...) do { \
		int len = snprintf(tmp,sizeof(tmp), c, __VA_ARGS__); \
		char enc[len * 3 + 1]; \
		str encstr = parser->escape(enc, tmp, len); \
		parser->dict_add_str_dup(inner, a, &encstr); \
	} while (0)
#define JSON_SET_SIMPLE_LEN(a,l,d) do { \
		char enc[l * 3 + 1]; \
		str encstr = parser->escape(enc, d, l); \
		parser->dict_add_str_dup(inner, a, &encstr); \
	} while (0)
#define JSON_SET_SIMPLE_CSTR(a,d) parser->dict_add_str_dup(inner, a, STR_PTR(d))
#define JSON_SET_SIMPLE_STR(a,d) parser->dict_add_str_dup(inner, a, d)

static void json_update_crypto_params(const ng_parser_t *parser, parser_arg inner, const char *key, struct crypto_params *p) {
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

static int json_update_sdes_params(const ng_parser_t *parser, parser_arg inner, const char *pref,
		unsigned int unique_id,
		const char *k, sdes_q *q)
{
	char tmp[2048];
	unsigned int iter = 0;
	char keybuf[32];
	const char *key = k;

	for (__auto_type l = q->head; l; l = l->next) {
		struct crypto_params_sdes *cps = l->data;
		struct crypto_params *p = &cps->params;

		if (!p->crypto_suite)
			return -1;

		JSON_SET_NSTRING("%s_tag", key, "%u", cps->tag);
		json_update_crypto_params(parser, inner, key, p);

		snprintf(keybuf, sizeof(keybuf), "%s-%u", k, iter++);
		key = keybuf;
	}

	return 0;
}

static void json_update_dtls_fingerprint(const ng_parser_t *parser, parser_arg inner, const char *pref,
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

static str redis_encode_json(ng_parser_ctx_t *ctx, call_t *c, void **to_free) {

	char tmp[2048];
	const ng_parser_t *parser = ctx->parser;

	parser_arg root = parser->dict(ctx);

	{
		parser_arg inner = parser->dict_add_dict(root, "json");

		{
			JSON_SET_SIMPLE("created","%lli", timeval_us(&c->created));
			JSON_SET_SIMPLE("destroyed","%lli", timeval_us(&c->destroyed));
			JSON_SET_SIMPLE("last_signal","%ld", (long int) c->last_signal);
			JSON_SET_SIMPLE("tos","%u", (int) c->tos);
			JSON_SET_SIMPLE("deleted","%ld", (long int) c->deleted);
			JSON_SET_SIMPLE("num_sfds","%u", t_queue_get_length(&c->stream_fds));
			JSON_SET_SIMPLE("num_streams","%u", t_queue_get_length(&c->streams));
			JSON_SET_SIMPLE("num_medias","%u", t_queue_get_length(&c->medias));
			JSON_SET_SIMPLE("num_tags","%u", t_queue_get_length(&c->monologues));
			JSON_SET_SIMPLE("num_maps","%u", t_queue_get_length(&c->endpoint_maps));
			JSON_SET_SIMPLE("ml_deleted","%ld", (long int) c->ml_deleted);
			JSON_SET_SIMPLE_CSTR("created_from", c->created_from);
			JSON_SET_SIMPLE_CSTR("created_from_addr", sockaddr_print_buf(&c->created_from_addr));
			JSON_SET_SIMPLE("redis_hosted_db","%u", c->redis_hosted_db);
			JSON_SET_SIMPLE_STR("recording_metadata", &c->metadata);
			JSON_SET_SIMPLE("block_dtmf","%i", c->block_dtmf);
			JSON_SET_SIMPLE("call_flags", "%" PRIu64, atomic64_get_na(&c->call_flags));

			if (c->recording_meta_prefix.len)
				JSON_SET_SIMPLE_STR("recording_meta_prefix", &c->recording_meta_prefix);
			if (c->recording_file.len)
				JSON_SET_SIMPLE_STR("recording_file", &c->recording_file);
			if (c->recording_path.len)
				JSON_SET_SIMPLE_STR("recording_path", &c->recording_path);
			if (c->recording_pattern.len)
				JSON_SET_SIMPLE_STR("recording_pattern", &c->recording_pattern);
			if (c->recording_random_tag.len)
				JSON_SET_SIMPLE_STR("recording_random_tag", &c->recording_random_tag);
		}

		for (__auto_type l = c->stream_fds.head; l; l = l->next) {
			stream_fd *sfd = l->data;

			snprintf(tmp, sizeof(tmp), "sfd-%u", sfd->unique_id);
			inner = parser->dict_add_dict_dup(root, tmp);

			{
				JSON_SET_SIMPLE_CSTR("pref_family", sfd->local_intf->logical->preferred_family->rfc_name);
				JSON_SET_SIMPLE("localport","%u", sfd->socket.local.port);
				JSON_SET_SIMPLE("fd", "%i", sfd->socket.fd);
				JSON_SET_SIMPLE_STR("logical_intf", &sfd->local_intf->logical->name);
				JSON_SET_SIMPLE("local_intf_uid","%u", sfd->local_intf->unique_id);
				JSON_SET_SIMPLE("stream","%u", sfd->stream->unique_id);

				json_update_crypto_params(parser, inner, "", &sfd->crypto.params);
			}

		} // --- for

		for (__auto_type l = c->streams.head; l; l = l->next) {
			struct packet_stream *ps = l->data;

			LOCK(&ps->in_lock);
			LOCK(&ps->out_lock);

			snprintf(tmp, sizeof(tmp), "stream-%u", ps->unique_id);
			inner = parser->dict_add_dict_dup(root, tmp);

			{
				JSON_SET_SIMPLE("media","%u",ps->media->unique_id);
				JSON_SET_SIMPLE("sfd","%u",ps->selected_sfd ? ps->selected_sfd->unique_id : -1);
				JSON_SET_SIMPLE("rtcp_sibling","%u",ps->rtcp_sibling ? ps->rtcp_sibling->unique_id : -1);
				JSON_SET_SIMPLE("last_packet",UINT64F,atomic64_get(&ps->last_packet));
				JSON_SET_SIMPLE("ps_flags", "%" PRIu64, atomic64_get_na(&ps->ps_flags));
				JSON_SET_SIMPLE("component","%u",ps->component);
				JSON_SET_SIMPLE_CSTR("endpoint",endpoint_print_buf(&ps->endpoint));
				JSON_SET_SIMPLE_CSTR("advertised_endpoint",endpoint_print_buf(&ps->advertised_endpoint));
				JSON_SET_SIMPLE("stats-packets","%" PRIu64, atomic64_get_na(&ps->stats_in->packets));
				JSON_SET_SIMPLE("stats-bytes","%" PRIu64, atomic64_get_na(&ps->stats_in->bytes));
				JSON_SET_SIMPLE("stats-errors","%" PRIu64, atomic64_get_na(&ps->stats_in->errors));

				json_update_crypto_params(parser, inner, "", &ps->crypto.params);
			}

			snprintf(tmp, sizeof(tmp), "stream_sfds-%u", ps->unique_id);
			inner = parser->dict_add_list_dup(root, tmp);
			for (__auto_type k = ps->sfds.head; k; k = k->next) {
				stream_fd *sfd = k->data;
				JSON_ADD_LIST_STRING("%u", sfd->unique_id);
			}

			snprintf(tmp, sizeof(tmp), "rtp_sinks-%u", ps->unique_id);
			inner = parser->dict_add_list_dup(root, tmp);
			for (__auto_type k = ps->rtp_sinks.head; k; k = k->next) {
				struct sink_handler *sh = k->data;
				struct packet_stream *sink = sh->sink;
				JSON_ADD_LIST_STRING("%u", sink->unique_id);
			}

			snprintf(tmp, sizeof(tmp), "rtcp_sinks-%u", ps->unique_id);
			inner = parser->dict_add_list_dup(root, tmp);
			for (__auto_type k = ps->rtcp_sinks.head; k; k = k->next) {
				struct sink_handler *sh = k->data;
				struct packet_stream *sink = sh->sink;
				JSON_ADD_LIST_STRING("%u", sink->unique_id);
			}
		} // --- for streams.head

		for (__auto_type l = c->monologues.head; l; l = l->next) {
			struct call_monologue *ml = l->data;

			snprintf(tmp, sizeof(tmp), "tag-%u", ml->unique_id);
			inner = parser->dict_add_dict_dup(root, tmp);

			{

				JSON_SET_SIMPLE("created", "%llu", (long long unsigned) ml->created);
				JSON_SET_SIMPLE("deleted", "%llu", (long long unsigned) ml->deleted);
				JSON_SET_SIMPLE("block_dtmf", "%i", ml->block_dtmf);
				JSON_SET_SIMPLE("ml_flags", "%" PRIu64, atomic64_get_na(&ml->ml_flags));
				JSON_SET_SIMPLE_CSTR("desired_family", ml->desired_family ? ml->desired_family->rfc_name : "");
				if (ml->logical_intf)
					JSON_SET_SIMPLE_STR("logical_intf", &ml->logical_intf->name);

				if (ml->tag.s)
					JSON_SET_SIMPLE_STR("tag", &ml->tag);
				if (ml->viabranch.s)
					JSON_SET_SIMPLE_STR("via-branch", &ml->viabranch);
				if (ml->label.s)
					JSON_SET_SIMPLE_STR("label", &ml->label);
				if (ml->metadata.s)
					JSON_SET_SIMPLE_STR("metadata", &ml->metadata);

				JSON_SET_SIMPLE_STR("sdp_session_name", &ml->sdp_session_name);
				JSON_SET_SIMPLE_STR("sdp_session_timing", &ml->sdp_session_timing);

				if (ml->session_sdp_orig) {
					JSON_SET_SIMPLE_STR("sdp_orig_username", &ml->session_sdp_orig->username);
					JSON_SET_SIMPLE_STR("sdp_orig_session_id", &ml->session_sdp_orig->session_id);
					JSON_SET_SIMPLE_STR("sdp_orig_version_str", &ml->session_sdp_orig->version_str);
					JSON_SET_SIMPLE("sdp_orig_version_num", "%llu", (long long unsigned) ml->session_sdp_orig->version_num);
					JSON_SET_SIMPLE("sdp_orig_parsed", "%u", (unsigned int) ml->session_sdp_orig->parsed);
					JSON_SET_SIMPLE_STR("sdp_orig_address_network_type", &ml->session_sdp_orig->address.network_type);
					JSON_SET_SIMPLE_STR("sdp_orig_address_address_type", &ml->session_sdp_orig->address.address_type);
					JSON_SET_SIMPLE_STR("sdp_orig_address_address", &ml->session_sdp_orig->address.address);
				}
				if (ml->session_last_sdp_orig) {
					JSON_SET_SIMPLE_STR("last_sdp_orig_username", &ml->session_last_sdp_orig->username);
					JSON_SET_SIMPLE_STR("last_sdp_orig_session_id", &ml->session_last_sdp_orig->session_id);
					JSON_SET_SIMPLE_STR("last_sdp_orig_version_str", &ml->session_last_sdp_orig->version_str);
					JSON_SET_SIMPLE("last_sdp_orig_version_num", "%llu", (long long unsigned) ml->session_last_sdp_orig->version_num);
					JSON_SET_SIMPLE("last_sdp_orig_parsed", "%u", (unsigned int) ml->session_last_sdp_orig->parsed);
					JSON_SET_SIMPLE_STR("last_sdp_orig_address_network_type", &ml->session_last_sdp_orig->address.network_type);
					JSON_SET_SIMPLE_STR("last_sdp_orig_address_address_type", &ml->session_last_sdp_orig->address.address_type);
					JSON_SET_SIMPLE_STR("last_sdp_orig_address_address", &ml->session_last_sdp_orig->address.address);
				}

				if (ml->sdp_session_bandwidth.as >= 0)
					JSON_SET_SIMPLE("sdp_session_as", "%ld", ml->sdp_session_bandwidth.as);
				if (ml->sdp_session_bandwidth.ct >= 0)
					JSON_SET_SIMPLE("sdp_session_ct", "%ld", ml->sdp_session_bandwidth.ct);
				if (ml->sdp_session_bandwidth.rr >= 0)
					JSON_SET_SIMPLE("sdp_session_rr", "%ld", ml->sdp_session_bandwidth.rr);
				if (ml->sdp_session_bandwidth.rs >= 0)
					JSON_SET_SIMPLE("sdp_session_rs", "%ld", ml->sdp_session_bandwidth.rs);
			}

			GList *k = g_hash_table_get_values(ml->associated_tags);
			snprintf(tmp, sizeof(tmp), "associated_tags-%u", ml->unique_id);
			inner = parser->dict_add_list_dup(root, tmp);
			for (GList *m = k; m; m = m->next) {
				struct call_monologue *ml2 = m->data;
				JSON_ADD_LIST_STRING("%u", ml2->unique_id);
			}

			g_list_free(k);

			snprintf(tmp, sizeof(tmp), "tag_aliases-%u", ml->unique_id);
			inner = parser->dict_add_list_dup(root, tmp);
			for (__auto_type alias = ml->tag_aliases.head; alias; alias = alias->next)
				JSON_ADD_LIST_STRING(STR_FORMAT, STR_FMT(alias->data));

			snprintf(tmp, sizeof(tmp), "medias-%u", ml->unique_id);
			inner = parser->dict_add_list_dup(root, tmp);
			for (unsigned int j = 0; j < ml->medias->len; j++) {
				struct call_media *media = ml->medias->pdata[j];
				JSON_ADD_LIST_STRING("%u", media ? media->unique_id : -1);
			}

			// SSRC table dump
			rwlock_lock_r(&ml->ssrc_hash->lock);
			k = g_hash_table_get_values(ml->ssrc_hash->ht);
			snprintf(tmp, sizeof(tmp), "ssrc_table-%u", ml->unique_id);
			parser_arg list = parser->dict_add_list_dup(root, tmp);
			for (GList *m = k; m; m = m->next) {
				struct ssrc_entry_call *se = m->data;
				inner = parser->list_add_dict(list);

				JSON_SET_SIMPLE("ssrc", "%" PRIu32, se->h.ssrc);
				// XXX use function for in/out
				JSON_SET_SIMPLE("in_srtp_index", "%u", atomic_get_na(&se->input_ctx.stats->ext_seq));
				JSON_SET_SIMPLE("in_srtcp_index", "%u", atomic_get_na(&se->input_ctx.stats->rtcp_seq));
				JSON_SET_SIMPLE("in_payload_type", "%i", se->input_ctx.tracker.most[0]);
				JSON_SET_SIMPLE("out_srtp_index", "%u", atomic_get_na(&se->output_ctx.stats->ext_seq));
				JSON_SET_SIMPLE("out_srtcp_index", "%u", atomic_get_na(&se->output_ctx.stats->rtcp_seq));
				JSON_SET_SIMPLE("out_payload_type", "%i", se->output_ctx.tracker.most[0]);
				// XXX add rest of info
			}

			g_list_free(k);
			rwlock_unlock_r(&ml->ssrc_hash->lock);
		} // --- for monologues.head

		for (__auto_type l = c->medias.head; l; l = l->next) {
			struct call_media *media = l->data;

			if (!media)
				continue;

			/* store media subscriptions */
			snprintf(tmp, sizeof(tmp), "media-subscriptions-%u", media->unique_id);
			inner = parser->dict_add_list_dup(root, tmp);

			for (__auto_type sub = media->media_subscriptions.head; sub; sub = sub->next)
			{
				struct media_subscription * ms = sub->data;
				JSON_ADD_LIST_STRING("%u/%u/%u/%u",
						ms->media->unique_id,
						ms->attrs.offer_answer,
						ms->attrs.rtcp_only,
						ms->attrs.egress);
			}

			snprintf(tmp, sizeof(tmp), "media-%u", media->unique_id);
			inner = parser->dict_add_dict_dup(root, tmp);

			{
				JSON_SET_SIMPLE("tag","%u", media->monologue->unique_id);
				JSON_SET_SIMPLE("index","%u", media->index);
				JSON_SET_SIMPLE_STR("type", &media->type);
				if (media->format_str.s)
					JSON_SET_SIMPLE_STR("format_str", &media->format_str);
				if (media->media_id.s)
					JSON_SET_SIMPLE_STR("media_id", &media->media_id);
				JSON_SET_SIMPLE_CSTR("protocol", media->protocol ? media->protocol->name : "");
				JSON_SET_SIMPLE_CSTR("desired_family", media->desired_family ? media->desired_family->rfc_name : "");
				JSON_SET_SIMPLE_STR("logical_intf", &media->logical_intf->name);
				JSON_SET_SIMPLE("ptime","%i", media->ptime);
				JSON_SET_SIMPLE("maxptime","%i", media->maxptime);
				JSON_SET_SIMPLE("media_flags", "%" PRIu64, atomic64_get_na(&media->media_flags));

				if (media->sdp_media_bandwidth.as >= 0)
					JSON_SET_SIMPLE("bandwidth_as","%ld", media->sdp_media_bandwidth.as);
				if (media->sdp_media_bandwidth.rr >= 0)
					JSON_SET_SIMPLE("bandwidth_rr","%ld", media->sdp_media_bandwidth.rr);
				if (media->sdp_media_bandwidth.rs >= 0)
					JSON_SET_SIMPLE("bandwidth_rs","%ld", media->sdp_media_bandwidth.rs);

				json_update_sdes_params(parser, inner, "media", media->unique_id, "sdes_in",
						&media->sdes_in);
				json_update_sdes_params(parser, inner, "media", media->unique_id, "sdes_out",
						&media->sdes_out);
				json_update_dtls_fingerprint(parser, inner, "media", media->unique_id, &media->fingerprint);
			}

			snprintf(tmp, sizeof(tmp), "streams-%u", media->unique_id);
			inner = parser->dict_add_list_dup(root, tmp);
			for (__auto_type m = media->streams.head; m; m = m->next) {
				struct packet_stream *ps = m->data;
				JSON_ADD_LIST_STRING("%u", ps->unique_id);
			}

			snprintf(tmp, sizeof(tmp), "maps-%u", media->unique_id);
			inner = parser->dict_add_list_dup(root, tmp);
			for (__auto_type m = media->endpoint_maps.head; m; m = m->next) {
				struct endpoint_map *ep = m->data;
				JSON_ADD_LIST_STRING("%u", ep->unique_id);
			}

			snprintf(tmp, sizeof(tmp), "payload_types-%u", media->unique_id);
			inner = parser->dict_add_list_dup(root, tmp);
			for (__auto_type m = media->codecs.codec_prefs.head; m; m = m->next) {
				rtp_payload_type *pt = m->data;
				JSON_ADD_LIST_STRING("%u/" STR_FORMAT "/%u/" STR_FORMAT "/" STR_FORMAT "/%i/%i",
						pt->payload_type, STR_FMT(&pt->encoding),
						pt->clock_rate, STR_FMT(&pt->encoding_parameters),
						STR_FMT(&pt->format_parameters), pt->bitrate, pt->ptime);
			}
		} // --- for medias.head

		for (__auto_type l = c->endpoint_maps.head; l; l = l->next) {
			struct endpoint_map *ep = l->data;

			snprintf(tmp, sizeof(tmp), "map-%u", ep->unique_id);
			inner = parser->dict_add_dict_dup(root, tmp);

			{
				JSON_SET_SIMPLE("wildcard","%i", ep->wildcard);
				JSON_SET_SIMPLE("num_ports","%u", ep->num_ports);
				JSON_SET_SIMPLE_CSTR("intf_preferred_family", ep->logical_intf->preferred_family->rfc_name);
				JSON_SET_SIMPLE_STR("logical_intf", &ep->logical_intf->name);
				JSON_SET_SIMPLE_CSTR("endpoint", endpoint_print_buf(&ep->endpoint));

			}

			snprintf(tmp, sizeof(tmp), "map_sfds-%u", ep->unique_id);
			inner = parser->dict_add_list_dup(root, tmp);
			for (__auto_type m = ep->intf_sfds.head; m; m = m->next) {
				struct sfd_intf_list *il = m->data;
				JSON_ADD_LIST_STRING("loc-%u", il->local_intf->unique_id);
				for (__auto_type n = il->list.head; n; n = n->next) {
					stream_fd *sfd = n->data;
					JSON_ADD_LIST_STRING("%u", sfd->unique_id);
				}
			}
		} // --- for c->endpoint_maps.head

	}

	return parser->collapse(ctx, root, to_free);
}


void redis_update_onekey(call_t *c, struct redis *r) {
	unsigned int redis_expires_s;

	if (!r)
		return;
	if (IS_FOREIGN_CALL(c))
		return;

	LOCK(&r->lock);
	// coverity[sleep : FALSE]
	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED)
		return;

	atomic64_set_na(&c->last_redis_update, rtpe_now.tv_sec);

	rwlock_lock_r(&c->master_lock);

	redis_expires_s = rtpe_config.redis_expires_secs;

	c->redis_hosted_db = r->db;
	if (redis_select_db(r, c->redis_hosted_db)) {
		rlog(LOG_ERR, " >>>>>>>>>>>>>>>>> Redis error.");
		goto err;
	}

	ng_parser_ctx_t ctx;
	bencode_buffer_t bbuf;
	redis_format_parsers[rtpe_config.redis_format]->init(&ctx, &bbuf);

	void *to_free = NULL;
	str result = redis_encode_json(&ctx, c, &to_free);
	if (!result.len)
		goto err;

	redis_pipe(r, "SET " PB " " PB " EX %i", PBSTR(&c->callid), PBSTR(&result), redis_expires_s);

	redis_consume(r);

	rwlock_unlock_r(&c->master_lock);

	g_free(to_free);
	bencode_buffer_free(ctx.buffer);

	return;
err:
	if (r->ctx && r->ctx->err)
		rlog(LOG_ERR, "Redis error: %s", r->ctx->errstr);
	redisFree(r->ctx);
	r->ctx = NULL;

	rwlock_unlock_r(&c->master_lock);
}

/* must be called lock-free */
void redis_delete(call_t *c, struct redis *r) {
	int delete_async = rtpe_config.redis_delete_async;
	rlog(LOG_DEBUG, "Redis delete_async=%d", delete_async);

	if (!r)
		return;

	if (IS_FOREIGN_CALL(c))
		return;

	if (delete_async) {
		LOCK(&r->async_lock);
		rwlock_lock_r(&c->master_lock);
		redis_delete_async_call_json(c, r);
		rwlock_unlock_r(&c->master_lock);
		return;
	}

	LOCK(&r->lock);
	// coverity[sleep : FALSE]
	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED)
		return;
	rwlock_lock_r(&c->master_lock);

	if (redis_select_db(r, c->redis_hosted_db))
		goto err;

	redis_delete_call_json(c, r);

	rwlock_unlock_r(&c->master_lock);
	return;

err:
	if (r->ctx && r->ctx->err)
		rlog(LOG_ERR, "Redis error: %s", r->ctx->errstr);
	redisFree(r->ctx);
	r->ctx = NULL;

	rwlock_unlock_r(&c->master_lock);
}





void redis_wipe(struct redis *r) {
	if (!r)
		return;

	LOCK(&r->lock);
	// coverity[sleep : FALSE]
	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED)
		return;
	redisCommandNR(r->ctx, "DEL calls");
}
