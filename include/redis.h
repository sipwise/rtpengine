#ifndef __REDIS_MOD_H__
#define __REDIS_MOD_H__




#include <sys/types.h>
#include "compat.h"
#include "socket.h"
#include "aux.h"

#include <glib.h>
#include <sys/types.h>
#include <hiredis/hiredis.h>
#include "call.h"
#include "str.h"


#define REDIS_RESTORE_NUM_THREADS 4


enum redis_role {
	MASTER_REDIS_ROLE = 0,
	SLAVE_REDIS_ROLE = 1,
	ANY_REDIS_ROLE = 2,
};

enum redis_state {
	REDIS_STATE_DISCONNECTED = 0,
	REDIS_STATE_CONNECTED,
};

enum event_base_action {
	EVENT_BASE_ALLOC = 0,
	EVENT_BASE_FREE,
	EVENT_BASE_LOOPBREAK,
};

enum subscribe_action {
	SUBSCRIBE_KEYSPACE = 0,
	UNSUBSCRIBE_KEYSPACE,
	UNSUBSCRIBE_ALL,
};

struct call;



struct redis {
	endpoint_t	endpoint;
	char		host[64];
	enum redis_role	role;

	redisContext	*ctx;
	int		db;
	const char	*auth;
	mutex_t		lock;
	unsigned int	pipeline;

	int		state;
	int		no_redis_required;
	int		consecutive_errors;
	time_t	restore_tick;

	struct event_base        *async_ev;
	struct redisAsyncContext *async_ctx;
	mutex_t                   async_lock;
	GQueue                    async_queue;
	int                       async_last;
};

struct redis_hash {
	GHashTable *ht;
};

struct redis_list {
	unsigned int len;
	struct redis_hash *rh;
	void **ptrs;
};


extern struct redis		*rtpe_redis;
extern struct redis		*rtpe_redis_write;
extern struct redis		*rtpe_redis_notify;



#if !GLIB_CHECK_VERSION(2,40,0)
INLINE gboolean g_hash_table_insert_check(GHashTable *h, gpointer k, gpointer v) {
	gboolean ret = TRUE;
	if (g_hash_table_contains(h, k))
		ret = FALSE;
	g_hash_table_insert(h, k, v);
	return ret;
}
#else
# define g_hash_table_insert_check g_hash_table_insert
#endif


#define rlog(l, x...) ilog(l | LOG_FLAG_RESTORE, x)

void redis_notify_loop(void *d);
void redis_delete_async_loop(void *d);


struct redis *redis_new(const endpoint_t *, int, const char *, enum redis_role, int);
void redis_close(struct redis *r);
int redis_restore(struct redis *, int foreign);
void redis_update(struct call *, struct redis *);
void redis_update_onekey(struct call *c, struct redis *r);
void redis_delete(struct call *, struct redis *);
void redis_wipe(struct redis *);
int redis_async_event_base_action(struct redis *r, enum event_base_action);
int redis_notify_subscribe_action(struct redis *r, enum subscribe_action action, int keyspace);
int redis_set_timeout(struct redis* r, int timeout);
int redis_reconnect(struct redis* r);



#define define_get_type_format(name, type)									\
	static int redis_hash_get_ ## name ## _v(type *out, const struct redis_hash *h, const char *f,		\
			va_list ap)										\
	{													\
		char key[64];											\
														\
		vsnprintf(key, sizeof(key), f, ap);								\
		return redis_hash_get_ ## name(out, h, key);							\
	}													\
	static int redis_hash_get_ ## name ## _f(type *out, const struct redis_hash *h, const char *f, ...) {	\
		va_list ap;											\
		int ret;											\
														\
		va_start(ap, f);										\
		ret = redis_hash_get_ ## name ## _v(out, h, f, ap);						\
		va_end(ap);											\
		return ret;											\
	}

#define define_get_int_type(name, type, func)								\
	static int redis_hash_get_ ## name(type *out, const struct redis_hash *h, const char *k) {	\
		str* s;										\
													\
		s = g_hash_table_lookup(h->ht, k);							\
		if (!s)											\
			return -1;									\
		*out = func(s->s, NULL, 10);								\
		return 0;										\
	}








#endif
