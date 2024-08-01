#ifndef __CONTAINERS_H__
#define __CONTAINERS_H__

#include <stdbool.h>
#include <glib.h>
#include <assert.h>

#if !(GLIB_CHECK_VERSION(2,60,0))
static inline void g_queue_clear_full(GQueue *q, GDestroyNotify free_func) {
	void *p;
	while ((p = g_queue_pop_head(q)))
		free_func(p);
}
#endif

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

#define t_hash_table_remove_all(h) ({ \
		g_hash_table_remove_all((h).ht); \
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
		unsigned int (*__hash_func)(__typeof__(((type_name *)0)->__ckey)) = hash_func; \
		gboolean (*__eq_func)(__typeof__(((type_name *)0)->__ckey), __typeof__(((type_name *)0)->__ckey)) = eq_func; \
		GHashTable *ht = g_hash_table_new_full((GHashFunc) __hash_func, (GEqualFunc) __eq_func, \
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

#define TYPED_DIRECT_FUNCS(hash_name, eq_name, type) \
	static inline unsigned int hash_name(const type *a) { \
		return g_direct_hash(a); \
	} \
	static inline gboolean eq_name(const type *a, const type *b) { \
		return a == b; \
	}


#define TYPED_GQUEUE(type_name, contained_type) \
	typedef union type_name##_slist type_name##_slist; \
	union type_name##_slist { \
		GSList l; \
		struct { \
			contained_type *data; \
			type_name##_slist *next; \
		}; \
	}; \
	/* ensure that our union overlaps the original struct perfectly */ \
	static_assert(sizeof(GSList) == sizeof(type_name##_slist), "sizeof slist type mismatch"); \
	static_assert(G_STRUCT_OFFSET(GSList, data) == G_STRUCT_OFFSET(type_name##_slist, data), \
			"data offset mismatch"); \
	static_assert(G_STRUCT_OFFSET(GSList, next) == G_STRUCT_OFFSET(type_name##_slist, next), \
			"next offset mismatch"); \
	typedef union type_name##_list type_name##_list; \
	union type_name##_list { \
		GList l; \
		struct { \
			union { \
				contained_type *data; \
				const contained_type *__ct; \
			}; \
			type_name##_list *next; \
			type_name##_list *prev; \
		}; \
	}; \
	/* ensure that our union overlaps the original struct perfectly */ \
	static_assert(sizeof(GList) == sizeof(type_name##_list), "sizeof list type mismatch"); \
	static_assert(G_STRUCT_OFFSET(GList, data) == G_STRUCT_OFFSET(type_name##_list, data), \
			"data offset mismatch"); \
	static_assert(G_STRUCT_OFFSET(GList, next) == G_STRUCT_OFFSET(type_name##_list, next), \
			"next offset mismatch"); \
	static_assert(G_STRUCT_OFFSET(GList, prev) == G_STRUCT_OFFSET(type_name##_list, prev), \
			"prev offset mismatch"); \
	typedef union { \
		GQueue q; \
		struct { \
			type_name##_list *head; \
			type_name##_list *tail; \
			unsigned int length; \
		}; \
		/* unused members to store the contained types */ \
		contained_type *__t; \
		const contained_type *__ct; \
	} type_name##_q; \
	/* ensure that our union overlaps the original struct perfectly */ \
	static_assert(sizeof(GQueue) == sizeof(type_name##_q), "sizeof queue type mismatch"); \
	static_assert(G_STRUCT_OFFSET(GQueue, head) == G_STRUCT_OFFSET(type_name##_q, head), \
			"head offset mismatch"); \
	static_assert(G_STRUCT_OFFSET(GQueue, tail) == G_STRUCT_OFFSET(type_name##_q, tail), \
			"tail offset mismatch"); \
	static_assert(G_STRUCT_OFFSET(GQueue, length) == G_STRUCT_OFFSET(type_name##_q, length), \
			"length offset mismatch"); \
	static inline type_name##_q *type_name##_q_new(void) { \
		GQueue *q = g_queue_new(); \
		return (type_name##_q *) q; \
	} \
	static inline void type_name##_q_clear(type_name##_q *q) { \
		g_queue_clear(&q->q); \
	}

#define TYPED_GQUEUE_INIT { .q = G_QUEUE_INIT }

#define t_queue_init(Q) ({ \
		(Q)->q = (GQueue) G_QUEUE_INIT; \
	})

#define t_queue_pop_head(Q) ({ \
		__typeof__((Q)->__t) __ret = g_queue_pop_head(&(Q)->q); \
		__ret; \
	})

#define t_queue_pop_tail(Q) ({ \
		__typeof__((Q)->__t) __ret = g_queue_pop_tail(&(Q)->q); \
		__ret; \
	})

#define t_queue_peek_head(Q) ({ \
		__typeof__((Q)->__t) __ret = g_queue_peek_head(&(Q)->q); \
		__ret; \
	})

#define t_queue_peek_tail(Q) ({ \
		__typeof__((Q)->__t) __ret = g_queue_peek_tail(&(Q)->q); \
		__ret; \
	})

#define t_queue_peek_nth(Q, n) ({ \
		__typeof__((Q)->__t) __ret = g_queue_peek_nth(&(Q)->q, n); \
		__ret; \
	})

#define t_queue_push_head(Q, e) ({ \
		__typeof__((Q)->__t) __e = e; \
		g_queue_push_head(&(Q)->q, __e); \
	})

#define t_queue_push_tail(Q, e) ({ \
		__typeof__((Q)->__t) __e = e; \
		g_queue_push_tail(&(Q)->q, __e); \
	})

#define t_queue_insert_before(Q, l, e) ({ \
		__typeof__((Q)->__t) __e = e; \
		__typeof__((Q)->head) __l = l; \
		g_queue_insert_before(&(Q)->q, (GList *) __l, __e); \
	})

#define t_queue_sort(Q, f, d) ({ \
		int (*__f)(__typeof__((Q)->__ct), __typeof__((Q)->__ct), void *) = f; \
		g_queue_sort(&(Q)->q, (GCompareDataFunc) __f, d); \
	})

#define t_queue_insert_sorted(Q, e, f, d) ({ \
		__typeof__((Q)->__t) __e = e; \
		int (*__f)(__typeof__((Q)->__ct), __typeof__((Q)->__ct), void *) = f; \
		g_queue_insert_sorted(&(Q)->q, __e, (GCompareDataFunc) __f, d); \
	})

#define t_queue_truncate(Q, n) ({ \
		unsigned int __n = n; \
		while ((Q)->length > __n) \
			t_queue_pop_tail(Q); \
	})

#define t_queue_find(Q, e) ({ \
		__typeof__((Q)->__t) __e = e; \
		GList *__l = g_queue_find(&(Q)->q, __e); \
		__typeof__((Q)->head) __ret = (__typeof__((Q)->head)) __l; \
		__ret; \
	})

#define t_queue_remove(Q, e) ({ \
		__typeof__((Q)->__t) __e = e; \
		bool __ret = g_queue_remove(&(Q)->q, __e); \
		__ret; \
	})

#define t_queue_delete_link(Q, L) ({ \
		__typeof__((Q)->head) __l = L; \
		g_queue_delete_link(&(Q)->q, &(__l)->l); \
	})

#define t_queue_find_custom(Q, e, f) ({ \
		int (*__f)(__typeof__((Q)->__ct), const void *) = f; \
		GList *__l = g_queue_find_custom(&(Q)->q, e, (GCompareFunc) __f); \
		__typeof__((Q)->head) __ret = (__typeof__((Q)->head)) __l; \
		__ret; \
	})

#define t_list_find_custom(L, e, f) ({ \
		int (*__f)(__typeof__((L)->__ct), const void *) = f; \
		GList *__l = g_list_find_custom(&(L)->l, e, (GCompareFunc) __f); \
		__typeof__(L) __ret = (__typeof__(L)) __l; \
		__ret; \
	})

#define t_queue_clear(Q) ({ \
		g_queue_clear(&(Q)->q); \
	})

#define t_queue_clear_full(Q, f) ({ \
		void (*__f)(__typeof__((Q)->__t)) = f; \
		g_queue_clear_full(&(Q)->q, (GDestroyNotify) __f); \
	})

#define t_queue_free(Q) ({ \
		g_queue_free(&(Q)->q); \
	})

#define t_queue_free_full(Q, f) ({ \
		void (*__f)(__typeof__((Q)->__t)) = f; \
		g_queue_free_full(&(Q)->q, (GDestroyNotify) __f); \
	})

#define t_queue_move(dst, src) ({ \
		__typeof__(dst) __dst = dst; \
		__typeof__(src) __src = src; \
		if (!__src->length) \
			; \
		else if (!__dst->length) { \
			*__dst = *__src; \
			t_queue_init(__src); \
		} \
		else { \
			__dst->tail->next = __src->head; \
			__src->head->prev = __dst->tail; \
			__dst->tail = __src->tail; \
			__dst->length += __src->length; \
			t_queue_init(__src); \
		} \
	})

#define t_queue_append(dst, src) ({ \
		__typeof__(dst) __dst = dst; \
		__typeof__(src) __src = src; \
		if (__dst && __src) \
			for (__auto_type __l = __src->head; __l; __l = __l->next) \
				t_queue_push_tail(__dst, __l->data); \
	})

#define t_queue_get_length(Q) ((Q)->length)

#define t_list_prepend(L, e) ({ \
		__typeof__((L)->data) __e = e; \
		GList *__r = g_list_prepend(&(L)->l, __e); \
		__typeof__(L) __ret = (__typeof__(L)) __r; \
		__ret; \
	})

#define t_list_insert_before_link(a, b, c) ({ \
		GList *__r = g_list_insert_before_link(&(a)->l, &(b)->l, &(c)->l); \
		__typeof__(a) __ret = (__typeof__(a)) __r; \
		__ret; \
	})

#define t_slist_prepend(L, e) ({ \
		__typeof__((L)->data) __e = e; \
		GSList *__r = g_slist_prepend(&(L)->l, __e); \
		__typeof__(L) __ret = (__typeof__(L)) __r; \
		__ret; \
	})

#define t_list_delete_link(L, k) ({ \
		GList *__r = g_list_delete_link(&(L)->l, &(k)->l); \
		__typeof__(L) __ret = (__typeof__(L)) __r; \
		__ret; \
	})

#define t_list_remove_link(L, k) ({ \
		GList *__r = g_list_remove_link(&(L)->l, &(k)->l); \
		__typeof__(L) __ret = (__typeof__(L)) __r; \
		__ret; \
	})

#define t_slist_delete_link(L, k) ({ \
		GSList *__r = g_slist_delete_link(&(L)->l, &(k)->l); \
		__typeof__(L) __ret = (__typeof__(L)) __r; \
		__ret; \
	})


#define TYPED_GPTRARRAY_FULL(type_name, contained_type, free_func) \
	typedef union { \
		GPtrArray a; \
		struct { \
			contained_type **pdata; \
			unsigned int len; \
		}; \
	} type_name; \
	static_assert(sizeof(GPtrArray) == sizeof(type_name), "sizeof ptrarray type mismatch"); \
	static_assert(G_STRUCT_OFFSET(GPtrArray, pdata) == G_STRUCT_OFFSET(type_name, pdata), \
			"pdata offset mismatch"); \
	static_assert(G_STRUCT_OFFSET(GPtrArray, len) == G_STRUCT_OFFSET(type_name, len), \
			"len offset mismatch"); \
	static inline type_name *type_name##_new_sized(unsigned int len) { \
		void (*func)(contained_type *) = free_func; \
		return (type_name *) g_ptr_array_new_full(len, (GDestroyNotify) func); \
	} \
	static inline type_name *type_name##_new(void) { \
		return type_name##_new_sized(0); \
	}

#define TYPED_GPTRARRAY(type_name, contained_type) \
	TYPED_GPTRARRAY_FULL(type_name, contained_type, NULL)

#define t_ptr_array_set_size(A, l) ({ \
		g_ptr_array_set_size(&(A)->a, l); \
	})

#define t_ptr_array_free(A, fd) ({ \
		g_ptr_array_free(&(A)->a, fd); \
	})

#define t_ptr_array_add(A, e) ({ \
		__typeof__(*(A)->pdata) __e = e; \
		g_ptr_array_add(&(A)->a, __e); \
	})


#endif
