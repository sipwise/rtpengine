#ifndef _OBJ_H_
#define _OBJ_H_



#include <glib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include "compat.h"





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
	volatile gint		ref;
	void			(*free_func)(void *);
	size_t			size;
};







#if OBJ_DEBUG

#define OBJ_MAGIC 0xf1eef1ee

#define obj_alloc(t,f)		({ \
		void (*__ff)(t *) = (f); \
		void *__r = __obj_alloc(sizeof(t), (void (*)(void *)) __ff, #t, __FILE__, __func__, __LINE__); \
		(t *) __r; \
	})
#define obj_alloc0(t,f)		({ \
		void (*__ff)(t *) = (f); \
		void *__r = __obj_alloc0(sizeof(t), (void (*)(void *)) __ff, #t, __FILE__, __func__, __LINE__); \
		(t *) __r; \
	})
#define obj_alloc0_gen(t,a,b)	__obj_alloc0(a,b,t,__FILE__,__func__,__LINE__)
#define obj_hold(a)		__obj_hold(&(a)->obj,__FILE__,__func__,__LINE__)
#define obj_get(a)		((__typeof__(a)) (__obj_get(&(a)->obj,__FILE__,__func__,__LINE__)))
#define obj_put(a)		__obj_put(&(a)->obj,__FILE__,__func__,__LINE__)
#define obj_hold_o(a)		__obj_hold(a,__FILE__,__func__,__LINE__)
#define obj_get_o(a)		__obj_get(a,__FILE__,__func__,__LINE__)
#define obj_put_o(a)		__obj_put(a,__FILE__,__func__,__LINE__)

INLINE void __obj_init(struct obj *o, size_t size, void (*free_func)(void *),
		const char *type, const char *file, const char *func, unsigned int line);
INLINE void *__obj_alloc(size_t size, void (*free_func)(void *),
		const char *type, const char *file, const char *func, unsigned int line);
INLINE void *__obj_alloc0(size_t size, void (*free_func)(void *),
		const char *type, const char *file, const char *func, unsigned int line);
INLINE struct obj *__obj_hold(struct obj *o,
		const char *file, const char *func, unsigned int line);
INLINE void *__obj_get(struct obj *o,
		const char *file, const char *func, unsigned int line);
INLINE void __obj_put(struct obj *o,
		const char *file, const char *func, unsigned int line);

#else

#define obj_alloc(t,f)		({ \
		void (*__ff)(t *) = (f); \
		void *__r = __obj_alloc(sizeof(t), (void (*)(void *)) __ff); \
		(t *) __r; \
	})
#define obj_alloc0(t,f)		({ \
		void (*__ff)(t *) = (f); \
		void *__r = __obj_alloc0(sizeof(t), (void (*)(void *)) __ff); \
		(t *) __r; \
	})
#define obj_alloc0_gen(t,a,b)	__obj_alloc0(a,b)
#define obj_hold(a)		__obj_hold(&(a)->obj)
#define obj_get(a)		((__typeof__(a)) (__obj_get(&(a)->obj)))
#define obj_put(a)		__obj_put(&(a)->obj)
#define obj_hold_o(a)		__obj_hold(a)
#define obj_get_o(a)		__obj_get(a)
#define obj_put_o(a)		__obj_put(a)

INLINE void __obj_init(struct obj *o, size_t size, void (*free_func)(void *));
INLINE void *__obj_alloc(size_t size, void (*free_func)(void *));
INLINE void *__obj_alloc0(size_t size, void (*free_func)(void *));
INLINE struct obj *__obj_hold(struct obj *o);
INLINE void *__obj_get(struct obj *o);
INLINE void __obj_put(struct obj *o);

#endif


#define obj_release(op) do { if (op) obj_put_o((struct obj *) op); op = NULL; } while (0)



#include "log.h"



INLINE void __obj_init(struct obj *o, size_t size, void (*free_func)(void *)
#if OBJ_DEBUG
, const char *type, const char *file, const char *func, unsigned int line
#endif
) {
#if OBJ_DEBUG
	o->magic = OBJ_MAGIC;
	o->type = strdup(type);
	write_log(LOG_DEBUG, "obj_allocX(\"%s\") -> %p [%s:%s:%u]", type, o, file, func, line);
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
	o->ref = 1;
	o->free_func = free_func;
	o->size = size;
}

INLINE void *__obj_alloc(size_t size, void (*free_func)(void *)
#if OBJ_DEBUG
, const char *type, const char *file, const char *func, unsigned int line
#endif
) {
	struct obj *r;

	r = g_slice_alloc(size);
	__obj_init(r, size, free_func
#if OBJ_DEBUG
	, type, file, func, line
#endif
	);
	return r;
}

INLINE void *__obj_alloc0(size_t size, void (*free_func)(void *)
#if OBJ_DEBUG
, const char *type, const char *file, const char *func, unsigned int line
#endif
) {
	struct obj *r;

	r = g_slice_alloc0(size);
	__obj_init(r, size, free_func
#if OBJ_DEBUG
	, type, file, func, line
#endif
	);
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
		o, o->type, g_atomic_int_get(&o->ref), g_atomic_int_get(&o->ref) + 1, file, func, line);
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
	g_atomic_int_inc(&o->ref);
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
		o, o->type, g_atomic_int_get(&o->ref), g_atomic_int_get(&o->ref) - 1, file, func, line);
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
	if (!g_atomic_int_dec_and_test(&o->ref))
		return;
	if (o->free_func)
		o->free_func(o);
#if OBJ_DEBUG
	o->magic = 0;
	if (o->type)
		free(o->type);
#endif
	if (o->size != -1)
		g_slice_free1(o->size, o);
}



#endif
