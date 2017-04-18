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

#define REDIS_FMT(x) (x)->len, (x)->str

static int redis_check_conn(struct redis *r);
static void json_restore_call(struct redis *r, struct callmaster *m, const str *id, enum call_type type);

static void redis_pipe(struct redis *r, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	redisvAppendCommand(r->ctx, fmt, ap);
	va_end(ap);
	r->pipeline++;
}
static redisReply *redis_get(struct redis *r, int type, const char *fmt, ...) {
	va_list ap;
	redisReply *ret;

	va_start(ap, fmt);
	ret = redis_expect(type, redisvCommand(r->ctx, fmt, ap));
	va_end(ap);

	return ret;
}
static int redisCommandNR(redisContext *r, const char *fmt, ...) {
	va_list ap;
	redisReply *ret;
	int i = 0;

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

	while (r->pipeline) {
		if (redisGetReply(r->ctx, (void **) &rp) == REDIS_OK)
			freeReplyObject(rp);
		r->pipeline--;
	}
}


/* called with r->lock held if necessary */
static int redis_connect(struct redis *r, int wait) {
	struct timeval tv;
	redisReply *rp;
	char *s;

	if (r->ctx)
		redisFree(r->ctx);
	r->ctx = NULL;

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	r->ctx = redisConnectWithTimeout(r->host, r->endpoint.port, tv);

	if (!r->ctx)
		goto err;
	if (r->ctx->err)
		goto err2;

	if (r->auth) {
		if (redisCommandNR(r->ctx, "AUTH %s", r->auth))
			goto err2;
	}
	else {
		if (redisCommandNR(r->ctx, "PING"))
			goto err2;
	}

	if (redisCommandNR(r->ctx, "SELECT %i", r->db))
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

		if (!memcmp(s, "role:master", 9)) {
			if (r->role == MASTER_REDIS_ROLE || r->role == ANY_REDIS_ROLE) {
				ilog(LOG_INFO, "Connected to Redis %s in master mode", 
					endpoint_print_buf(&r->endpoint));
				goto done;
			} else if (r->role == SLAVE_REDIS_ROLE) {
				ilog(LOG_INFO, "Connected to Redis %s in master mode, but wanted mode is slave; retrying...",
					endpoint_print_buf(&r->endpoint));
				goto next;
			}
		} else if (!memcmp(s, "role:slave", 8)) {
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
err:
	rlog(LOG_ERR, "Failed to connect to Redis %s",
		endpoint_print_buf(&r->endpoint));
	return -1;
}


void on_redis_notification(redisAsyncContext *actx, void *reply, void *privdata) {

	struct callmaster *cm = privdata;
	struct redis *r = 0;
	struct call *c = NULL;
	str callid;
	str keyspace_id;

	// sanity checks
	if (!cm) {
		rlog(LOG_ERROR, "Struct callmaster is NULL on on_redis_notification");
		return;
	}

	if (!cm->conf.redis_notify) {
		rlog(LOG_ERROR, "A redis notification has been received but no redis_notify database found");
		return;
	}

	r = cm->conf.redis_notify;

	mutex_lock(&r->lock);

	redisReply *rr = (redisReply*)reply;

	if (reply == NULL || rr->type != REDIS_REPLY_ARRAY)
		goto err;

	for (int j = 0; j < rr->elements; j++) {
		rlog(LOG_DEBUG, "Redis-Notify: %u) %s\n", j, rr->element[j]->str);
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

	// select the right db for restoring the call
	if (redisCommandNR(r->ctx, "SELECT %i", r->db)) {
		if (r->ctx->err)
			rlog(LOG_ERROR, "Redis error: %s", r->ctx->errstr);
		redisFree(r->ctx);
		r->ctx = NULL;
		goto err;
	}

	if (strncmp(rr->element[3]->str,"set",3)==0) {
		c = call_get(&callid, cm);
		if (c) {
			rwlock_unlock_w(&c->master_lock);
			if (IS_FOREIGN_CALL(c))
				call_destroy(c);
			else {
				rlog(LOG_WARN, "Redis-Notifier: Ignoring SET received for OWN call: %s\n", rr->element[2]->str);
				goto err;
			}
		}
		json_restore_call(r, cm, &callid, CT_FOREIGN_CALL);
	}

	if (strncmp(rr->element[3]->str,"del",3)==0) {
		c = call_get(&callid, cm);
		if (!c) {
			rlog(LOG_NOTICE, "Redis-Notifier: DEL did not find call with callid: %s\n", rr->element[2]->str);
			goto err;
		}
		rwlock_unlock_w(&c->master_lock);
		if (!IS_FOREIGN_CALL(c)) {
			rlog(LOG_WARN, "Redis-Notifier: Ignoring DEL received for an OWN call: %s\n", rr->element[2]->str);
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

void redis_async_context_disconnect(const redisAsyncContext *redis_notify_async_context, int status) {
	if (status == REDIS_ERR) {
		if (redis_notify_async_context->errstr) {
			rlog(LOG_ERROR, "redis_async_context_disconnect error %d on context free: %s",
				redis_notify_async_context->err, redis_notify_async_context->errstr);
		} else {
			rlog(LOG_ERROR, "redis_async_context_disconnect error %d on context free: no errstr",
				redis_notify_async_context->err);
		}
	} else if (status == REDIS_OK) {
		rlog(LOG_ERROR, "redis_async_context_disconnect initiated by user");
	} else {
		rlog(LOG_ERROR, "redis_async_context_disconnect invalid status code %d", status);
	}
}

int redis_async_context_alloc(struct callmaster *cm) {
	struct redis *r = 0;

	// sanity checks
	if (!cm) {
		rlog(LOG_ERROR, "Struct callmaster is NULL on context free");
		return -1;
	}

	if (!cm->conf.redis_notify) {
		rlog(LOG_INFO, "redis_notify database is NULL.");
		return -1;
	}

	// get redis_notify database
	r = cm->conf.redis_notify;
	rlog(LOG_INFO, "Use Redis %s for notifications", endpoint_print_buf(&r->endpoint));

	// alloc async context
	cm->conf.redis_notify_async_context = redisAsyncConnect(r->host, r->endpoint.port);
	if (!cm->conf.redis_notify_async_context) {
		rlog(LOG_ERROR, "redis_notify_async_context can't create new");
		return -1;
	}
	if (cm->conf.redis_notify_async_context->err) {
		rlog(LOG_ERROR, "redis_notify_async_context can't create new error: %s", cm->conf.redis_notify_async_context->errstr);
		return -1;
	}

	if (redisAsyncSetDisconnectCallback(cm->conf.redis_notify_async_context, redis_async_context_disconnect) != REDIS_OK) {
		rlog(LOG_ERROR, "redis_notify_async_context can't set disconnect callback");
		return -1;
	}

	return 0;
}

int redis_notify_event_base_action(struct callmaster *cm, enum event_base_action action) {
	// sanity checks
	if (!cm) {
		rlog(LOG_ERROR, "Struct callmaster is NULL on event base action %d", action);
		return -1;
	}

	if (!cm->conf.redis_notify_event_base && action!=EVENT_BASE_ALLOC) {
		rlog(LOG_ERROR, "redis_notify_event_base is NULL on event base action %d", action);
		return -1;
	}

	// exec event base action
	switch (action) {
		case EVENT_BASE_ALLOC:
			cm->conf.redis_notify_event_base = event_base_new();
			if (!cm->conf.redis_notify_event_base) {
				rlog(LOG_ERROR, "Fail alloc redis_notify_event_base");
				return -1;
			} else {
				rlog(LOG_DEBUG, "Success alloc redis_notify_event_base");
			}
			break;

		case EVENT_BASE_FREE:
			event_base_free(cm->conf.redis_notify_event_base);
			rlog(LOG_DEBUG, "Success free redis_notify_event_base");
			break;

		case EVENT_BASE_LOOPBREAK:
			if (event_base_loopbreak(cm->conf.redis_notify_event_base)) {
				rlog(LOG_ERROR, "Fail loopbreak redis_notify_event_base");
				return -1;
			} else {
				rlog(LOG_DEBUG, "Success loopbreak redis_notify_event_base");
			}
			break;

		default:
			rlog(LOG_ERROR, "No event base action found: %d", action);
			return -1;
	}

	return 0;
}

int redis_notify_subscribe_action(struct callmaster *cm, enum subscribe_action action, int keyspace) {
	// sanity checks
	if (!cm) {
		rlog(LOG_ERROR, "Struct callmaster is NULL on subscribe action");
		return -1;
	}

	if (!cm->conf.redis_notify_async_context) {
		rlog(LOG_ERROR, "redis_notify_async_context is NULL on subscribe action");
		return -1;
	}

	if (cm->conf.redis_notify_async_context->err) {
		rlog(LOG_ERROR, "redis_notify_async_context error on subscribe action: %s", cm->conf.redis_notify_async_context->errstr);
		return -1;
	}

	switch (action) {
	case SUBSCRIBE_KEYSPACE:
		if (redisAsyncCommand(cm->conf.redis_notify_async_context, on_redis_notification, (void*)cm, "psubscribe __keyspace@%i__:*", keyspace) != REDIS_OK) {
			rlog(LOG_ERROR, "Fail redisAsyncCommand on JSON SUBSCRIBE_KEYSPACE");
			return -1;
		}
		break;
	case UNSUBSCRIBE_KEYSPACE:
		if (redisAsyncCommand(cm->conf.redis_notify_async_context, on_redis_notification, (void*)cm, "punsubscribe __keyspace@%i__:*", keyspace) != REDIS_OK) {
			rlog(LOG_ERROR, "Fail redisAsyncCommand on JSON UNSUBSCRIBE_KEYSPACE");
			return -1;
		}
		break;
	case UNSUBSCRIBE_ALL:
		if (redisAsyncCommand(cm->conf.redis_notify_async_context, on_redis_notification, (void *) cm, "punsubscribe") != REDIS_OK) {
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

static int redis_notify(struct callmaster *cm) {
	struct redis *r = 0;
	GList *l;

	// sanity checks
	if (!cm) {
		rlog(LOG_ERROR, "Struct callmaster is NULL on redis_notify()");
		return -1;
	}

	if (!cm->conf.redis_notify) {
		rlog(LOG_ERROR, "redis_notify database is NULL on redis_notify()");
		return -1;
	}

	if (!cm->conf.redis_notify_async_context) {
		rlog(LOG_ERROR, "redis_notify_async_context is NULL on redis_notify()");
		return -1;
	}

	if (!cm->conf.redis_notify_event_base) {
		rlog(LOG_ERROR, "redis_notify_event_base is NULL on redis_notify()");
		return -1;
	}

	// get redis_notify database
	r = cm->conf.redis_notify;
	rlog(LOG_INFO, "Use Redis %s to subscribe to notifications", endpoint_print_buf(&r->endpoint));

	// attach event base
	if (redisLibeventAttach(cm->conf.redis_notify_async_context, cm->conf.redis_notify_event_base) == REDIS_ERR) {
		if (cm->conf.redis_notify_async_context->err) {
			rlog(LOG_ERROR, "redis_notify_async_context can't attach event base error: %s", cm->conf.redis_notify_async_context->errstr);
		} else {
			rlog(LOG_ERROR, "redis_notify_async_context can't attach event base");

		}
		return -1;
	}

	// subscribe to the values in the configured keyspaces
	rwlock_lock_r(&cm->conf.config_lock);
	for (l = cm->conf.redis_subscribed_keyspaces->head; l; l = l->next) {
		redis_notify_subscribe_action(cm, SUBSCRIBE_KEYSPACE, GPOINTER_TO_UINT(l->data));
	}
	rwlock_unlock_r(&cm->conf.config_lock);

	// dispatch event base => thread blocks here
	if (event_base_dispatch(cm->conf.redis_notify_event_base) < 0) {
		rlog(LOG_ERROR, "Fail event_base_dispatch()");
		return -1;
	}

	return 0;
}

void redis_notify_loop(void *d) {
	int seconds = 1, redis_notify_return = 0;
	time_t next_run = g_now.tv_sec;
	struct callmaster *cm = (struct callmaster *)d;
	struct redis *r;

	// sanity checks
	if (!cm) {
		ilog(LOG_ERROR, "NULL callmaster");
		return ;
	}

	r = cm->conf.redis_notify;
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
	if (redis_async_context_alloc(cm) < 0) {
		return ;
	}

	// alloc event base
	if (redis_notify_event_base_action(cm, EVENT_BASE_ALLOC) < 0) {
		return ;
	}

	// initial redis_notify
	if (redis_check_conn(r) == REDIS_STATE_CONNECTED) {
		redis_notify_return = redis_notify(cm);
	}

	// loop redis_notify => in case of lost connection
	while (!g_shutdown) {
		gettimeofday(&g_now, NULL);
		if (g_now.tv_sec < next_run) {
			usleep(100000);
			continue;
		}

		next_run = g_now.tv_sec + seconds;

		if (redis_check_conn(r) == REDIS_STATE_RECONNECTED || redis_notify_return < 0) {
			// alloc new redis async context upon redis breakdown
			if (redis_async_context_alloc(cm) < 0) {
				continue;
			}

			// prepare notifications
			redis_notify_return = redis_notify(cm);
		}
	}

	// unsubscribe notifications
	redis_notify_subscribe_action(cm, UNSUBSCRIBE_ALL, 0);

	// free async context
	redisAsyncDisconnect(cm->conf.redis_notify_async_context);

	// free event base
	redis_notify_event_base_action(cm, EVENT_BASE_FREE);
}

struct redis *redis_new(const endpoint_t *ep, int db, const char *auth, enum redis_role role, int no_redis_required) {
	struct redis *r;

	r = g_slice_alloc0(sizeof(*r));

	r->endpoint = *ep;
	sockaddr_print(&ep->address, r->host, sizeof(r->host));
	r->db = db;
	r->auth = auth;
	r->role = role;
	r->state = REDIS_STATE_DISCONNECTED;
	r->no_redis_required = no_redis_required;
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


static void redis_close(struct redis *r) {
	if (r->ctx)
		redisFree(r->ctx);
	mutex_destroy(&r->lock);
	g_slice_free1(sizeof(*r), r);
}


/* must be called with r->lock held */
static int redis_check_conn(struct redis *r) {
	// try redis connection
	if (redisCommandNR(r->ctx, "PING") == 0) {
		// redis is connected
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
		return REDIS_STATE_DISCONNECTED;
	}

	// redis is connected
	if (r->state == REDIS_STATE_DISCONNECTED) {
		rlog(LOG_INFO, "RE-Established connection to Redis %s",
			endpoint_print_buf(&r->endpoint));
		r->state = REDIS_STATE_CONNECTED;
	}

	// redis is re-connected
	return REDIS_STATE_RECONNECTED;
}

/* called with r->lock held and c->master_lock held */
static void redis_delete_call_json(struct call *c, struct redis *r) {
	redis_pipe(r, "DEL "PB"", STR(&c->callid));
	redis_consume(r);
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
	gchar **orig_members = members;
	int nmemb = json_reader_count_members (root_reader);

	for (int i=0; i < nmemb; ++i) {

		if (!json_reader_read_member(root_reader, *members)) {
			rlog(LOG_ERROR, "Could not read json member: %s",*members);
			goto err3;
		}
		str *val = json_reader_get_string_value_uri_enc(root_reader);
		char* tmp = strdup(*members);

		if (g_hash_table_insert_check(out->ht, tmp, val) != TRUE) {
			ilog(LOG_WARNING,"Key %s already exists", tmp);
			goto err3;
		}

		json_reader_end_member(root_reader);

		++members;
	} // for
	g_strfreev(orig_members);
	json_reader_end_member (root_reader);

	return 0;

err3:
	g_strfreev(members);
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
	u_int64_t u;
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
//define_get_int_type(u16, u_int16_t, strtol);
//define_get_int_type(u64, u_int64_t, strtoull);
define_get_int_type(a64, atomic64, strtoa64);

define_get_type_format(str, str);
define_get_type_format(int, int);
//define_get_type_format(unsigned, unsigned int);
//define_get_type_format(u16, u_int16_t);
//define_get_type_format(u64, u_int64_t);
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
static int redis_hash_get_stats(struct stats *out, const struct redis_hash *h, const char *k) {
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
static int redis_hash_get_crypto_params(struct crypto_params *out, const struct redis_hash *h, const char *k) {
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
		if (__get_consecutive_ports(&q, 1, port, loc->spec))
			goto err;
		err = "no port returned";
		sock = g_queue_pop_head(&q);
		if (!sock)
			goto err;
		sfd = stream_fd_new(sock, c, loc);
		// XXX tos

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

		streams->ptrs[i] = ps;

		PS_CLEAR(ps, KERNELIZED);
	}
	return 0;
}

static int redis_tags(struct call *c, struct redis_list *tags) {
	unsigned int i;
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

		tags->ptrs[i] = ml;
	}

	return 0;
}

static int rbl_cb_plts(str *s, GQueue *q, struct redis_list *list, void *ptr) {
	struct rtp_payload_type *pt;
	str ptype, enc, clock, parms;
	struct call_media *med = ptr;
	struct call *call = med->call;

	if (str_token(&ptype, s, '/'))
		return -1;
	if (str_token(&enc, s, '/'))
		return -1;
	if (str_token(&clock, s, '/'))
		return -1;
	parms = *s;

	// from call.c
	// XXX remove all the duplicate code
	pt = g_slice_alloc0(sizeof(*pt));
	pt->payload_type = str_to_ui(&ptype, 0);
	call_str_cpy(call, &pt->encoding, &enc);
	pt->clock_rate = str_to_ui(&clock, 0);
	call_str_cpy(call, &pt->encoding_parameters, &parms);
	g_hash_table_replace(med->rtp_payload_types, &pt->payload_type, pt);
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
		med = uid_slice_alloc0(med, &c->medias);
		med->call = c;
		med->rtp_payload_types = g_hash_table_new_full(g_int_hash, g_int_equal, NULL,
				__payload_type_free);

		if (redis_hash_get_unsigned(&med->index, rh, "index"))
			return -1;
		if (redis_hash_get_str(&s, rh, "type"))
			return -1;
		call_str_cpy(c, &med->type, &s);

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

		if (redis_hash_get_unsigned(&med->sdes_in.tag, rh, "sdes_in_tag"))
			return -1;
		if (redis_hash_get_unsigned(&med->sdes_out.tag, rh, "sdes_out_tag"))
			return -1;
		if (redis_hash_get_unsigned((unsigned int *) &med->media_flags, rh,
					"media_flags"))
			return -1;
		if (redis_hash_get_crypto_params(&med->sdes_in.params, rh, "sdes_in") < 0)
			return -1;
		if (redis_hash_get_crypto_params(&med->sdes_out.params, rh, "sdes_out") < 0)
			return -1;

		json_build_list_cb(NULL, c, "payload_types", i, NULL, rbl_cb_plts, med, root_reader);
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

		ml->active_dialogue = redis_list_get_ptr(tags, &tags->rh[i], "active");

		if (json_build_list(&q, c, "other_tags", &c->callid, i, tags, root_reader))
			return -1;
		for (l = q.head; l; l = l->next) {
			other_ml = l->data;
			if (!other_ml)
			    return -1;
			g_hash_table_insert(ml->other_tags, &other_ml->tag, other_ml);
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

	for (i = 0; i < streams->len; i++) {
		ps = streams->ptrs[i];

		ps->media = redis_list_get_ptr(medias, &streams->rh[i], "media");
		ps->selected_sfd = redis_list_get_ptr(sfds, &streams->rh[i], "sfd");
		ps->rtp_sink = redis_list_get_ptr(streams, &streams->rh[i], "rtp_sink");
		ps->rtcp_sink = redis_list_get_ptr(streams, &streams->rh[i], "rtcp_sink");
		ps->rtcp_sibling = redis_list_get_ptr(streams, &streams->rh[i], "rtcp_sibling");

		if (json_build_list(&ps->sfds, c, "stream_sfds", &c->callid, i, sfds, root_reader))
			return -1;

		if (ps->media)
			__rtp_stats_update(ps->rtp_stats, ps->media->rtp_payload_types);
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

static int json_build_ssrc(struct call *c, JsonReader *root_reader) {
	if (!json_reader_read_member(root_reader, "ssrc_table"))
		return -1;
	int nmemb = json_reader_count_elements(root_reader);
	for (int jidx=0; jidx < nmemb; ++jidx) {
		if (!json_reader_read_element(root_reader, jidx))
			return -1;

		u_int32_t ssrc = json_reader_get_ll(root_reader, "ssrc");
		struct ssrc_entry *se = get_ssrc(ssrc, c->ssrc_hash);
		se->input_ctx.srtp_index = json_reader_get_ll(root_reader, "in_srtp_index");
		se->input_ctx.srtcp_index = json_reader_get_ll(root_reader, "in_srtcp_index");
		se->output_ctx.srtp_index = json_reader_get_ll(root_reader, "out_srtp_index");
		se->output_ctx.srtcp_index = json_reader_get_ll(root_reader, "out_srtcp_index");
		se->payload_type = json_reader_get_ll(root_reader, "payload_type");

		json_reader_end_element(root_reader);
	}
	json_reader_end_member (root_reader);
	return 0;
}

static void json_restore_call(struct redis *r, struct callmaster *m, const str *callid, enum call_type type) {
	redisReply* rr_jsonStr;
	struct redis_hash call;
	struct redis_list tags, sfds, streams, medias, maps;
	struct call *c = NULL;
	str s, id;

	const char *err = 0;
	int i;
	JsonReader *root_reader =0;
	JsonParser *parser =0;

	rr_jsonStr = redis_get(r, REDIS_REPLY_STRING, "GET " PB, STR(callid));
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

	c = call_get_or_create(callid, m, type);
	err = "failed to create call struct";
	if (!c)
		goto err1;

	err = "call already exists";
	if (c->last_signal)
		goto err2;
	err = "'call' data incomplete";

	if (json_get_hash(&call, "json", -1, root_reader))
		goto err2;
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
	err = "missing 'last signal' timestamp";
	if (redis_hash_get_time_t(&c->last_signal, &call, "last_signal"))
		goto err8;
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
	if (redis_tags(c, &tags))
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
	err = "failed to restore SSRC table";
	if (json_build_ssrc(c, root_reader))
		goto err8;

	// presence of this key determines whether we were recording at all
	if (!redis_hash_get_str(&s, &call, "recording_meta_prefix")) {
		recording_start(c, s.s);

		if (!redis_hash_get_str(&s, &call, "recording_metadata"))
			call_str_cpy(c, &c->recording->metadata, &s);
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
	log_info_clear();
	if (err) {
		rlog(LOG_WARNING, "Failed to restore call ID '" STR_FORMAT "' from Redis: %s", STR_FMT(callid),
				err);
		if (c) 
			call_destroy(c);
		else {
			mutex_lock(&m->conf.redis_write->lock);
			redisCommandNR(m->conf.redis_write->ctx, "DEL " PB, STR(callid));
			mutex_unlock(&m->conf.redis_write->lock);
		}
	}
	if (c)
		obj_put(c);
}

struct thread_ctx {
	struct callmaster *m;
	GQueue r_q;
	mutex_t r_m;
};

static void restore_thread(void *call_p, void *ctx_p) {
	struct thread_ctx *ctx = ctx_p;
	redisReply *call = call_p;
	struct redis *r;
	str callid;
	str_init_len(&callid, call->str, call->len);

	rlog(LOG_DEBUG, "Processing call ID '%.*s' from Redis", REDIS_FMT(call));

	mutex_lock(&ctx->r_m);
	r = g_queue_pop_head(&ctx->r_q);
	mutex_unlock(&ctx->r_m);

	json_restore_call(r, ctx->m, &callid, CT_OWN_CALL);

	mutex_lock(&ctx->r_m);
	g_queue_push_tail(&ctx->r_q, r);
	mutex_unlock(&ctx->r_m);
}

int redis_restore(struct callmaster *m, struct redis *r) {
	redisReply *calls = NULL, *call;
	int i, ret = -1;
	GThreadPool *gtp;
	struct thread_ctx ctx;

	if (!r)
		return 0;

	log_level |= LOG_FLAG_RESTORE;

	rlog(LOG_DEBUG, "Restoring calls from Redis...");

	mutex_lock(&r->lock);
	// coverity[sleep : FALSE]
	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED) {
		mutex_unlock(&r->lock);
		ret = 0;
		goto err;
	}
	mutex_unlock(&r->lock);

	calls = redis_get(r, REDIS_REPLY_ARRAY, "KEYS *");

	if (!calls) {
		rlog(LOG_ERR, "Could not retrieve call list from Redis: %s", r->ctx->errstr);
		goto err;
	}

	ctx.m = m;
	mutex_init(&ctx.r_m);
	g_queue_init(&ctx.r_q);
	for (i = 0; i < m->conf.redis_num_threads; i++)
		g_queue_push_tail(&ctx.r_q, redis_new(&r->endpoint, r->db, r->auth, r->role, r->no_redis_required));
	gtp = g_thread_pool_new(restore_thread, &ctx, m->conf.redis_num_threads, TRUE, NULL);

	for (i = 0; i < calls->elements; i++) {
		call = calls->element[i];
		if (call->type != REDIS_REPLY_STRING)
			continue;

		g_thread_pool_push(gtp, call, NULL);
	}

	g_thread_pool_free(gtp, FALSE, TRUE);
	while ((r = g_queue_pop_head(&ctx.r_q)))
		redis_close(r);
	ret = 0;

	freeReplyObject(calls);

err:
	log_level &= ~LOG_FLAG_RESTORE;
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
#define JSON_SET_SIMPLE_CSTR(a,d) JSON_SET_SIMPLE_LEN(a, strlen(d), d)
#define JSON_SET_SIMPLE_STR(a,d) JSON_SET_SIMPLE_LEN(a, (d)->len, (d)->s)

static int json_update_crypto_params(JsonBuilder *builder, const char *pref,
		unsigned int unique_id,
		const char *key, const struct crypto_params *p)
{
	char tmp[2048];

	if (!p->crypto_suite)
		return -1;

	JSON_SET_NSTRING_CSTR("%s-crypto_suite",key,p->crypto_suite->name);
	JSON_SET_NSTRING_LEN("%s-master_key",key, sizeof(p->master_key), (char *) p->master_key);
	JSON_SET_NSTRING_LEN("%s-master_salt",key, sizeof(p->master_salt), (char *) p->master_salt);

	JSON_SET_NSTRING("%s-unenc-srtp",key,"%i",p->session_params.unencrypted_srtp);
	JSON_SET_NSTRING("%s-unenc-srtcp",key,"%i",p->session_params.unencrypted_srtcp);
	JSON_SET_NSTRING("%s-unauth-srtp",key,"%i",p->session_params.unauthenticated_srtp);

	if (p->mki) {
		JSON_SET_NSTRING_LEN("%s-mki",key, p->mki_len, (char *) p->mki);
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

			if ((rec = c->recording)) {
				JSON_SET_SIMPLE_STR("recording_metadata",&rec->metadata);
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
				JSON_SET_SIMPLE("rtp_sink","%u",ps->rtp_sink ? ps->rtp_sink->unique_id : -1);
				JSON_SET_SIMPLE("rtcp_sink","%u",ps->rtcp_sink ? ps->rtcp_sink->unique_id : -1);
				JSON_SET_SIMPLE("rtcp_sibling","%u",ps->rtcp_sibling ? ps->rtcp_sibling->unique_id : -1);
				JSON_SET_SIMPLE("last_packet",UINT64F,atomic64_get(&ps->last_packet));
				JSON_SET_SIMPLE("ps_flags","%u",ps->ps_flags);
				JSON_SET_SIMPLE("component","%u",ps->component);
				JSON_SET_SIMPLE_CSTR("endpoint",endpoint_print_buf(&ps->endpoint));
				JSON_SET_SIMPLE_CSTR("advertised_endpoint",endpoint_print_buf(&ps->advertised_endpoint));
				JSON_SET_SIMPLE("stats-packets","%" PRIu64, atomic64_get(&ps->stats.packets));
				JSON_SET_SIMPLE("stats-bytes","%" PRIu64, atomic64_get(&ps->stats.bytes));
				JSON_SET_SIMPLE("stats-errors","%" PRIu64, atomic64_get(&ps->stats.errors));

			}

			json_builder_end_object (builder);

			// stream_sfds was here before
			mutex_unlock(&ps->in_lock);
			mutex_unlock(&ps->out_lock);

		} // --- for streams.head


		for (l = c->streams.head; l; l = l->next) {
			ps = l->data;

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
				JSON_SET_SIMPLE("active","%u",ml->active_dialogue ? ml->active_dialogue->unique_id : -1);
				JSON_SET_SIMPLE("deleted","%llu",(long long unsigned) ml->deleted);

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

			snprintf(tmp, sizeof(tmp), "medias-%u", ml->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array (builder);
			for (k = ml->medias.head; k; k = k->next) {
				media = k->data;
				JSON_ADD_STRING("%u",media->unique_id);
			}
			json_builder_end_array (builder);
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
				JSON_SET_SIMPLE_CSTR("protocol",media->protocol ? media->protocol->name : "");
				JSON_SET_SIMPLE_CSTR("desired_family",media->desired_family ? media->desired_family->rfc_name : "");
				JSON_SET_SIMPLE("sdes_in_tag","%u",media->sdes_in.tag);
				JSON_SET_SIMPLE("sdes_out_tag","%u",media->sdes_out.tag);
				JSON_SET_SIMPLE_STR("logical_intf",&media->logical_intf->name);
				JSON_SET_SIMPLE("media_flags","%u",media->media_flags);

				json_update_crypto_params(builder, "media", media->unique_id, "sdes_in",
						&media->sdes_in.params);
				json_update_crypto_params(builder, "media", media->unique_id, "sdes_out",
						&media->sdes_out.params);
				json_update_dtls_fingerprint(builder, "media", media->unique_id, &media->fingerprint);

				// streams and maps- and payload_types- was here before

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

			k = g_hash_table_get_values(media->rtp_payload_types);
			snprintf(tmp, sizeof(tmp), "payload_types-%u", media->unique_id);
			json_builder_set_member_name(builder, tmp);
			json_builder_begin_array (builder);
			for (m = k; m; m = m->next) {
				pt = m->data;
				JSON_ADD_STRING("%u/" STR_FORMAT "/%u/" STR_FORMAT, 
						pt->payload_type, STR_FMT(&pt->encoding),
						pt->clock_rate, STR_FMT(&pt->encoding_parameters));
			}
			json_builder_end_array (builder);

			g_list_free(k);
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

		// SSRC table dump
		k = g_hash_table_get_values(c->ssrc_hash->ht);
		json_builder_set_member_name(builder, "ssrc_table");
		json_builder_begin_array (builder);
		for (m = k; m; m = m->next) {
			struct ssrc_entry *se = m->data;
			json_builder_begin_object (builder);

			JSON_SET_SIMPLE("ssrc","%" PRIu32, se->ssrc);
			// XXX use function for in/out
			JSON_SET_SIMPLE("in_srtp_index","%" PRIu64, se->input_ctx.srtp_index);
			JSON_SET_SIMPLE("in_srtcp_index","%" PRIu64, se->input_ctx.srtcp_index);
			JSON_SET_SIMPLE("out_srtp_index","%" PRIu64, se->output_ctx.srtp_index);
			JSON_SET_SIMPLE("out_srtcp_index","%" PRIu64, se->output_ctx.srtcp_index);
			JSON_SET_SIMPLE("payload_type","%i", se->payload_type);
			// XXX add rest of info

			json_builder_end_object (builder);
		}
		json_builder_end_array (builder);

		g_list_free(k);
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

	mutex_lock(&r->lock);
	// coverity[sleep : FALSE]
	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED) {
		mutex_unlock(&r->lock);
		return ;
	}

	rwlock_lock_r(&c->master_lock);

	redis_expires_s = c->callmaster->conf.redis_expires_secs;

	c->redis_hosted_db = r->db;
	if (redisCommandNR(r->ctx, "SELECT %i", c->redis_hosted_db)) {
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

	mutex_unlock(&r->lock);
	rwlock_unlock_r(&c->master_lock);
	if (r->ctx->err)
		rlog(LOG_ERR, "Redis error: %s", r->ctx->errstr);
	redisFree(r->ctx);
	r->ctx = NULL;

}

/* must be called lock-free */
void redis_delete(struct call *c, struct redis *r) {
	if (!r)
		return;

	mutex_lock(&r->lock);
	// coverity[sleep : FALSE]
	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED) {
		mutex_unlock(&r->lock);
		return ;
	}
	rwlock_lock_r(&c->master_lock);

	if (redisCommandNR(r->ctx, "SELECT %i", c->redis_hosted_db))
		goto err;

	redis_delete_call_json(c, r);

	rwlock_unlock_r(&c->master_lock);
	mutex_unlock(&r->lock);
	return;

err:
	rwlock_unlock_r(&c->master_lock);
	mutex_unlock(&r->lock);

	if (r->ctx->err)
		rlog(LOG_ERR, "Redis error: %s", r->ctx->errstr);
	redisFree(r->ctx);
	r->ctx = NULL;
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
