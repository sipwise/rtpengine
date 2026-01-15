#ifndef _OBJ_H_
#define _OBJ_H_



#include <glib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include "compat.h"
#include "auxlib.h"





#if 0 && defined(__DEBUG)
#define OBJ_DEBUG 1
#else
#define OBJ_DEBUG 0
#endif


#if OBJ_DEBUG
#define OBJ_BACKTRACE 1
#else
#define OBJ_BACKTRACE 0
#endif

#if OBJ_BACKTRACE
#include <execinfo.h>
#endif


struct obj {
#if OBJ_DEBUG
	uint32_t		magic;
	char			*type;
#endif
	int			ref;
	void			(*clear_func)(void *);
	void			(*free_func)(void *);
};







#if OBJ_DEBUG

#define OBJ_MAGIC 0xf1eef1ee

#define obj_alloc_full(t,f,a,d)		({ \
		void (*__ff)(t *) = (f); \
		void (*__df)(t *) = (d); \
		void *__r = __obj_alloc(sizeof(t), (void (*)(void *)) __ff, #t, __FILE__, __func__, __LINE__, \
				a, (void (*)(void *)) __df); \
		(t *) __r; \
	})

#define obj_alloc0_gen(t,a,b)	__obj_alloc(a,b,t,__FILE__,__func__,__LINE__, g_malloc0, g_free)
#define obj_hold(a)		__obj_hold(&(a)->obj,__FILE__,__func__,__LINE__)
#define obj_get(a)		((__typeof__(a)) (__obj_get(&(a)->obj,__FILE__,__func__,__LINE__)))
#define obj_put(a)		__obj_put(&(a)->obj,__FILE__,__func__,__LINE__)
#define obj_hold_o(a)		__obj_hold(a,__FILE__,__func__,__LINE__)
#define obj_get_o(a)		__obj_get(a,__FILE__,__func__,__LINE__)
#define obj_put_o(a)		__obj_put(a,__FILE__,__func__,__LINE__)

INLINE void *__obj_alloc(size_t size, void (*clear_func)(void *),
		const char *type, const char *file, const char *func, unsigned int line,
		void *(*alloc_func)(size_t), void (*free_func)(void *));
INLINE struct obj *__obj_hold(struct obj *o,
		const char *file, const char *func, unsigned int line);
INLINE void *__obj_get(struct obj *o,
		const char *file, const char *func, unsigned int line);
INLINE void __obj_put(struct obj *o,
		const char *file, const char *func, unsigned int line);

#else

#define obj_alloc_full(t,f,a,d)		({ \
		void (*__ff)(t *) = (f); \
		void (*__df)(t *) = (d); \
		void *__r = __obj_alloc(sizeof(t), (void (*)(void *)) __ff, a, (void (*)(void *)) __df); \
		(t *) __r; \
	})

#define obj_alloc0_gen(t,a,b)	__obj_alloc(a,b, g_malloc0, g_free)
#define obj_hold(a)		__obj_hold(&(a)->obj)
#define obj_get(a)		((__typeof__(a)) (__obj_get(&(a)->obj)))
#define obj_put(a)		__obj_put(&(a)->obj)
#define obj_hold_o(a)		__obj_hold(a)
#define obj_get_o(a)		__obj_get(a)
#define obj_put_o(a)		__obj_put(a)

INLINE void *__obj_alloc(size_t size, void (*clear_func)(void *),
		void *(*alloc_func)(size_t), void (*free_func)(void *));
INLINE struct obj *__obj_hold(struct obj *o);
INLINE void *__obj_get(struct obj *o);
INLINE void __obj_put(struct obj *o);

#endif


#define obj_alloc(t,f) obj_alloc_full(t, f, g_malloc, (void (*)(t *)) g_free)
#define obj_alloc0(t,f) obj_alloc_full(t, f, g_malloc0, (void (*)(t *)) g_free)

#define obj_release_o(op) do { if (op) obj_put_o((struct obj *) op); op = NULL; } while (0)
#define obj_release(op) do { if (op) obj_put(op); op = NULL; } while (0)

INLINE void obj_put_gen(struct obj *o) {
	obj_put_o(o);
}



#include "log.h"



INLINE void *__obj_alloc(size_t size, void (*clear_func)(void *),
#if OBJ_DEBUG
		const char *type, const char *file, const char *func, unsigned int line,
#endif
		void *(*alloc_func)(size_t), void (*free_func)(void *))
{
	struct obj *r;

	r = alloc_func(size);

#if OBJ_DEBUG
	r->magic = OBJ_MAGIC;
	r->type = strdup(type);
	write_log(LOG_DEBUG, "obj_allocX(\"%s\") -> %p [%s:%s:%u]", type, r, file, func, line);
#if OBJ_BACKTRACE
	void *bt[4];
	int addrs = backtrace(bt, 4);
	char **syms = backtrace_symbols(bt, addrs);
	if (syms) {
		for (int i = 0; i < addrs; i++)
			write_log(LOG_DEBUG, "    obj_allocX caller %i: %s", i, syms[i]);
	}
	free(syms);
#endif
#endif
	r->ref = 1;
	r->clear_func = clear_func;
	r->free_func = free_func;

	return r;
}

INLINE struct obj *__obj_hold(struct obj *o
#if OBJ_DEBUG
, const char *file, const char *func, unsigned int line
#endif
) {
#if OBJ_DEBUG
	assert(o->magic == OBJ_MAGIC);
	write_log(LOG_DEBUG, "obj_hold(%p, \"%s\"), refcnt inc %u -> %u [%s:%s:%u]",
		o, o->type, atomic_get_na(&o->ref), atomic_get_na(&o->ref) + 1, file, func, line);
#if OBJ_BACKTRACE
	void *bt[4];
	int addrs = backtrace(bt, 4);
	char **syms = backtrace_symbols(bt, addrs);
	if (syms) {
		for (int i = 0; i < addrs; i++)
			write_log(LOG_DEBUG, "    obj_hold caller %i: %s", i, syms[i]);
	}
	free(syms);
#endif
#endif
	atomic_inc(&o->ref);
	return o;
}

INLINE void *__obj_get(struct obj *o
#if OBJ_DEBUG
, const char *file, const char *func, unsigned int line
#endif
) {
	return __obj_hold(o
#if OBJ_DEBUG
	, file, func, line
#endif
	);
}

INLINE void __obj_put(struct obj *o
#if OBJ_DEBUG
, const char *file, const char *func, unsigned int line
#endif
) {
#if OBJ_DEBUG
	assert(o->magic == OBJ_MAGIC);
	write_log(LOG_DEBUG, "obj_put(%p, \"%s\"), refcnt dec %u -> %u [%s:%s:%u]",
		o, o->type, atomic_get_na(&o->ref), atomic_get_na(&o->ref) - 1, file, func, line);
#if OBJ_BACKTRACE
	void *bt[4];
	int addrs = backtrace(bt, 4);
	char **syms = backtrace_symbols(bt, addrs);
	if (syms) {
		for (int i = 0; i < addrs; i++)
			write_log(LOG_DEBUG, "    obj_put caller %i: %s", i, syms[i]);
	}
	free(syms);
#endif
#endif
	if (atomic_dec(&o->ref) != 1)
		return;
	if (o->clear_func)
		o->clear_func(o);
#if OBJ_DEBUG
	o->magic = 0;
	if (o->type)
		free(o->type);
#endif
	o->free_func(o);
}



#endif
