#ifndef _OBJ_H_
#define _OBJ_H_



#include <glib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "log.h"




#ifdef __DEBUG
#define OBJ_DEBUG 1
#else
#define OBJ_DEBUG 0
#endif




struct obj {
#if OBJ_DEBUG
	u_int32_t		magic;
	char			*type;
#endif
	volatile gint		ref;
	void			(*free_func)(void *);
	unsigned int		size;
};





#if OBJ_DEBUG

#define OBJ_MAGIC 0xf1eef1ee

#define obj_alloc(t,a,b)	__obj_alloc(a,b,t,__FILE__,__LINE__)
#define obj_alloc0(t,a,b)	__obj_alloc0(a,b,t,__FILE__,__LINE__)
#define obj_hold(a)		__obj_hold(a,__FILE__,__LINE__)
#define obj_get(a)		__obj_get(a,__FILE__,__LINE__)
#define obj_put(a)		__obj_put(a,__FILE__,__LINE__)

#else

#define obj_alloc(t,a,b)	__obj_alloc(a,b)
#define obj_alloc0(t,a,b)	__obj_alloc0(a,b)
#define obj_hold(a)		__obj_hold(a)
#define obj_get(a)		__obj_get(a)
#define obj_put(a)		__obj_put(a)

#endif

static inline void __obj_init(struct obj *o, unsigned int size, void (*free_func)(void *)
#if OBJ_DEBUG
, const char *type, const char *file, unsigned int line
#endif
) {
#if OBJ_DEBUG
	o->magic = OBJ_MAGIC;
	o->type = strdup(type);
	mylog(LOG_DEBUG, "obj_allocX(\"%s\") -> %p [%s:%u]", type, o, file, line);
#endif
	o->ref = 1;
	o->free_func = free_func;
	o->size = size;
}

static inline void *__obj_alloc(unsigned int size, void (*free_func)(void *)
#if OBJ_DEBUG
, const char *type, const char *file, unsigned int line
#endif
) {
	struct obj *r;

	r = g_slice_alloc(size);
	__obj_init(r, size, free_func
#if OBJ_DEBUG
	, type, file, line
#endif
	);
	return r;
}

static inline void *__obj_alloc0(unsigned int size, void (*free_func)(void *)
#if OBJ_DEBUG
, const char *type, const char *file, unsigned int line
#endif
) {
	struct obj *r;

	r = g_slice_alloc0(size);
	__obj_init(r, size, free_func
#if OBJ_DEBUG
	, type, file, line
#endif
	);
	return r;
}

static inline struct obj *__obj_hold(void *p
#if OBJ_DEBUG
, const char *file, unsigned int line
#endif
) {
	struct obj *o = p;
#if OBJ_DEBUG
	assert(o->magic == OBJ_MAGIC);
	mylog(LOG_DEBUG, "obj_hold(%p, \"%s\"), refcnt before %u [%s:%u]",
		o, o->type, g_atomic_int_get(&o->ref), file, line);
#endif
	g_atomic_int_inc(&o->ref);
#if OBJ_DEBUG
	mylog(LOG_DEBUG, "obj_hold(%p, \"%s\"), refcnt after %u [%s:%u]",
		o, o->type, g_atomic_int_get(&o->ref), file, line);
#endif
	return o;
}

static inline void *__obj_get(void *p
#if OBJ_DEBUG
, const char *file, unsigned int line
#endif
) {
	return __obj_hold(p
#if OBJ_DEBUG
	, file, line
#endif
	);
}

static inline void __obj_put(void *p
#if OBJ_DEBUG
, const char *file, unsigned int line
#endif
) {
	struct obj *o = p;
#if OBJ_DEBUG
	assert(o->magic == OBJ_MAGIC);
	mylog(LOG_DEBUG, "obj_put(%p, \"%s\"), refcnt before %u [%s:%u]",
		o, o->type, g_atomic_int_get(&o->ref), file, line);
#endif
	if (!g_atomic_int_dec_and_test(&o->ref))
		return;
#if OBJ_DEBUG
	mylog(LOG_DEBUG, "obj_put(%p, \"%s\"), refcnt after %u [%s:%u]",
		o, o->type, g_atomic_int_get(&o->ref), file, line);
	free(o->type);
#endif
	if (o->free_func)
		o->free_func(o);
#if OBJ_DEBUG
	o->magic = 0;
#endif
	g_slice_free1(o->size, o);
}



#endif
