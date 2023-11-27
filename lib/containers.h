#ifndef __CONTAINERS_H__
#define __CONTAINERS_H__

#include <stdbool.h>
#include <glib.h>
#include <assert.h>


#define TYPED_GHASHTABLE_PROTO(type_name, key_type, value_type) \
	typedef union { \
		GHashTable *ht; \
		/* unused members to store the contained types */ \
		key_type *__key; \
		const key_type *__ckey; \
		value_type *__value; \
	} type_name; \
	typedef union { \
		GHashTableIter it; \
		/* unused members to store the contained types */ \
		type_name __ht; \
	} type_name##_iter; \
	static inline type_name type_name##_null(void) { \
		return (type_name) { NULL }; \
	} \
	static inline void type_name##_destroy_ptr(type_name *h) { \
		if (h->ht) \
			g_hash_table_destroy(h->ht); \
		h->ht = NULL; \
	}


#define t_hash_table_is_set(h) ({ \
		bool __ret = (h).ht != NULL; \
		__ret; \
	})

#define t_hash_table_insert(h, k, v) ({ \
		__typeof__((h).__key) __k = k; \
		__typeof__((h).__value) __v = v; \
		g_hash_table_insert((h).ht, __k, __v); \
	})

#define t_hash_table_replace(h, k, v) ({ \
		__typeof__((h).__key) __k = k; \
		__typeof__((h).__value) __v = v; \
		g_hash_table_replace((h).ht, __k, __v); \
	})

#define t_hash_table_lookup(h, k) ({ \
		__typeof__((h).__ckey) __k = k; \
		__typeof__((h).__value) __r = g_hash_table_lookup((h).ht, __k); \
		__r; \
	})

#define t_hash_table_remove(h, k) ({ \
		__typeof__((h).__key) __k = k; \
		bool __r = g_hash_table_remove((h).ht, __k); \
		__r; \
	})

#define t_hash_table_steal_extended(h, k, kp, vp) ({ \
		__typeof__((h).__key) __k = k; \
		__typeof__(&(h).__key) __kp = kp; \
		__typeof__(&(h).__value) __vp = vp; \
		bool __r = g_hash_table_steal_extended((h).ht, __k, (void **) __kp, (void **) __vp); \
		__r; \
	})

#define t_hash_table_destroy(h) ({ \
		g_hash_table_destroy((h).ht); \
	})

#define t_hash_table_destroy_ptr(h) ({ \
		if ((h)->ht) \
			g_hash_table_destroy((h)->ht); \
		(h)->ht = NULL; \
	})

#define t_hash_table_size(h) ({ \
		unsigned int __ret = g_hash_table_size((h).ht); \
		__ret; \
	})

#define t_hash_table_foreach_remove(h, f, p) ({ \
		gboolean (*__f)(__typeof__((h).__key), __typeof__((h).__value), void *) = f; \
		bool __ret = g_hash_table_foreach_remove((h).ht, (GHRFunc) __f, p); \
		__ret; \
	})

#define t_hash_table_iter_init(i, h) ({ \
		__typeof__((i)->__ht) *__h = &(h); \
		g_hash_table_iter_init(&(i)->it, __h->ht); \
	})

#define t_hash_table_iter_next(i, kp, vp) ({ \
		__typeof__(&((i)->__ht).__key) __kp = kp; \
		__typeof__(&((i)->__ht).__value) __vp = vp; \
		bool __ret = g_hash_table_iter_next(&(i)->it, (void **) __kp, (void **) __vp); \
		__ret; \
	})


#define TYPED_GHASHTABLE_IMPL(type_name, hash_func, eq_func, key_free_func, value_free_func) \
	static inline type_name type_name##_new(void) { \
		GHashTable *ht = g_hash_table_new_full(hash_func, eq_func, \
				(GDestroyNotify) key_free_func, \
				(GDestroyNotify) value_free_func); \
		return (type_name) { ht }; \
	} \

#define TYPED_GHASHTABLE(type_name, key_type, value_type, hash_func, eq_func, key_free_func, value_free_func) \
	TYPED_GHASHTABLE_PROTO(type_name, key_type, value_type) \
	TYPED_GHASHTABLE_IMPL(type_name, hash_func, eq_func, key_free_func, value_free_func) \
	G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(type_name, type_name##_destroy_ptr)

#define TYPED_GHASHTABLE_LOOKUP_INSERT(type_name, key_free_func, value_new_func) \
	static inline __typeof__(((type_name *)0)->__value) type_name##_lookup_insert(type_name h, \
			__typeof__(((type_name *)0)->__key) k) { \
		__typeof__((h).__value) r = t_hash_table_lookup(h, k); \
		if (r) { \
			void (*free_func)(__typeof__((h).__key)) = key_free_func; \
			if (free_func) \
				free_func(k); \
			return r; \
		} \
		r = value_new_func(); \
		t_hash_table_insert(h, k, r); \
		return r; \
	}


#endif
