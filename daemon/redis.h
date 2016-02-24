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


#define REDIS_RESTORE_NUM_THREADS 4


enum redis_role {
	MASTER_REDIS_ROLE = 0,
	SLAVE_REDIS_ROLE = 1,
	ANY_REDIS_ROLE = 2,
};

enum redis_state {
	REDIS_STATE_DISCONNECTED = 0,	// DISCONNECTED -> DISCONNECTED
	REDIS_STATE_CONNECTED,		// CONNECTED -> CONNECTED
	REDIS_STATE_RECONNECTED,	// DISCONNECTED -> CONNECTED
};

struct callmaster;
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
};
struct redis_hash {
	redisReply *rr;
	GHashTable *ht;
};
struct redis_list {
	unsigned int len;
	struct redis_hash *rh;
	void **ptrs;
};








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



#define REDIS_FMT(x) (x)->len, (x)->str


void redis_notify_loop(void *d);


struct redis *redis_new(const endpoint_t *, int, const char *, enum redis_role, int no_redis_required);
int redis_restore(struct callmaster *, struct redis *);
void redis_update(struct call *, struct redis *);
void redis_delete(struct call *, struct redis *);
void redis_wipe(struct redis *);
void redis_notify_event_base_loopbreak(struct callmaster *cm);
void redis_notify_subscribe_keyspace(struct callmaster *cm, int keyspace);
void redis_notify_unsubscribe_keyspace(struct callmaster *cm, int keyspace);




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
		redisReply *r;										\
													\
		r = g_hash_table_lookup(h->ht, k);							\
		if (!r)											\
			return -1;									\
		*out = func(r->str, NULL, 10);								\
		return 0;										\
	}








#endif
