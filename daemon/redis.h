#ifndef __REDIS_MOD_H__
#define __REDIS_MOD_H__




#include "aux.h"

#include <glib.h>
#include <sys/types.h>
#include <hiredis/hiredis.h>



struct callmaster;
struct call;



struct redis {
	u_int32_t	ip;
	char		host[32];
	int		port;

	redisContext	*ctx;
	int		db;
	mutex_t		lock;
	unsigned int	pipeline;
};
struct redis_hash {
	redisReply *rr;
	GHashTable *ht;
};
struct redis_list {
	GQueue q;
	struct redis_hash rh;
};
struct list_item {
	redisReply *id;
	struct redis_hash rh;
	void *ptr;
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




struct redis *redis_new(u_int32_t, u_int16_t, int);
int redis_restore(struct callmaster *, struct redis *);
void redis_update(struct call *, struct redis *);
void redis_delete(struct call *, struct redis *);
void redis_wipe(struct redis *);






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
