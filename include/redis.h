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
	REDIS_STATE_DISCONNECTED = 0,	// DISCONNECTED -> DISCONNECTED
	REDIS_STATE_CONNECTED,		// CONNECTED -> CONNECTED
	REDIS_STATE_RECONNECTED,	// DISCONNECTED -> CONNECTED
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

extern struct event_base	*rtpe_redis_notify_event_base;
extern struct redisAsyncContext *rtpe_redis_notify_async_context;



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


struct redis *redis_new(const endpoint_t *, int, const char *, enum redis_role, int);
int redis_restore(struct redis *);
void redis_update(struct call *, struct redis *);
void redis_update_onekey(struct call *c, struct redis *r);
void redis_delete(struct call *, struct redis *);
void redis_wipe(struct redis *);
int redis_notify_event_base_action(enum event_base_action);
int redis_notify_subscribe_action(enum subscribe_action action, int keyspace);
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


/* New mode JSON parsing support. Use with care */

typedef struct redis_call_media_stream_fd {
	struct obj		obj;
	unsigned		unique_id;
	unsigned		stream_unique_id;
	str*			pref_family;
	unsigned		localport;
	str*			logical_intf;
	unsigned		logical_intf_uid;
} redis_call_media_stream_fd_t;

typedef struct redis_call_media_stream {
	struct obj		obj;
	unsigned		unique_id;
	unsigned		media_unique_id;
	unsigned		selected_sfd;
	int			rtp_sink;
	int			rtcp_sink;
	int			rtcp_sibling;
	unsigned		last_packet;
	unsigned		ps_flags;
	unsigned		component;
	str*			endpoint;
	str*			advertised_endpoint;
	unsigned 		stats_packets;
	unsigned		stats_bytes;
	unsigned		stats_errors;
	GQueue*			fds;
} redis_call_media_stream_t;

struct redis_call_media_tag;

typedef struct redis_call_media_tag {
	struct obj		obj;
	unsigned		unique_id;
	unsigned long		created;
	gboolean		active;
	gboolean		deleted;
	gboolean		block_dtmf;
	gboolean		block_media;
	str*			tag;
	str*			viabranch;
	str*			label;
	struct redis_call_media_tag*	other_tag;
} redis_call_media_tag_t;

typedef struct redis_call_media {
	struct obj		obj;
	unsigned		index;
	unsigned		unique_id;
	str*			type;
	str*			protocol;
	str*			desired_family;
	str*			logical_intf;
	unsigned		ptime;
	unsigned		media_flags;
	str*			rtpe_addr;
	redis_call_media_tag_t*	tag;
	GQueue*			streams;
} redis_call_media_t;

typedef struct redis_call {
	struct obj		obj;
	str*			call_id;
	unsigned long long	created;
	unsigned long		last_signal;
	unsigned		tos;
	gboolean		deleted;
	gboolean		ml_deleted;
	str*			created_from;
	str*			created_from_addr;
	unsigned		redis_hosted_db;
	str*			recording_metadata;
	gboolean		block_dtmf;
	gboolean		block_media;
	GQueue*			media;
} redis_call_t;

#endif
