#ifndef __IQUEUE_H__
#define __IQUEUE_H__


#include <stddef.h>


#define IQUEUE_LINK \
	struct { \
		void *prev; \
		void *next; \
	}


#define IQUEUE_TYPE(ele_type, link_name) \
	struct { \
		union { \
			struct { \
				ele_type *head; \
				ele_type *tail; \
				unsigned int length; \
			}; \
			struct { \
				char dummy[offsetof(ele_type, link_name)]; \
				struct { \
					ele_type *prev; \
					ele_type *next; \
				} link; \
			} *offset; \
			const ele_type *const_ele; \
		}; \
	}


#define IQUEUE(ele_type, link_name, queue_name) \
	IQUEUE_TYPE(ele_type, link_name) queue_name


#define i_queue_init(list) do { \
	(list)->head = NULL; \
	(list)->tail = NULL; \
	(list)->length = 0; \
} while (0)


#define IQUEUE_INIT { 0 }


#define i_queue_peek_head(list) ({ \
	__auto_type __ret = (list)->head; \
	__ret; \
})


#define i_queue_pop_head(list) ({ \
	__auto_type __ret = (list)->head; \
	if (__ret) { \
		__auto_type __link = (__typeof((list)->offset)) __ret; \
		(list)->head = __link->link.next; \
		__link->link.next = NULL; \
		(list)->length--; \
		if (!(list)->head) \
			(list)->tail = NULL; \
	} \
	__ret; \
})


#define i_queue_push_tail(list, ele) do { \
	if ((list)->tail) { \
		__auto_type __link = (__typeof((list)->offset)) (list)->tail; \
		__link->link.next = ele; \
	} \
	__auto_type __link = (__typeof((list)->offset)) ele; \
	__link->link.prev = (list)->tail; \
	(list)->tail = ele; \
	if (!(list)->head) \
		(list)->head = ele; \
	(list)->length++; \
} while (0)


#define i_queue_push_head(list, ele) do { \
	if ((list)->head) { \
		__auto_type __link = (__typeof((list)->offset)) (list)->head; \
		__link->link.prev = ele; \
	} \
	__auto_type __link = (__typeof((list)->offset)) ele; \
	__link->link.next = (list)->head; \
	(list)->head = ele; \
	if (!(list)->tail) \
		(list)->tail = ele; \
	(list)->length++; \
} while (0)


#define i_queue_delete(list, ele) do { \
	__auto_type __link = (__typeof((list)->offset)) ele; \
	if (__link->link.next) { \
		__auto_type __next_link = (__typeof((list)->offset)) __link->link.next; \
		__next_link->link.prev = __link->link.prev; \
	} \
	else \
		(list)->tail = __link->link.prev; \
	if (__link->link.prev) { \
		__auto_type __prev_link = (__typeof((list)->offset)) __link->link.prev; \
		__prev_link->link.next = __link->link.next; \
	} \
	else \
		(list)->head = __link->link.next; \
} while (0)


#define IQUEUE_FOREACH(list, var) \
	for (__typeof__ ( ({ __typeof__ (*(list)->head) __t; &__t; }) ) var = (list)->head; \
			var; var = ((__typeof((list)->offset)) var)->link.next)


#define IQUEUE_FOREACH_SAFE_DECL(list, var) \
	__typeof__ ( ({ __typeof__ (*(list)->head) __t; &__t; }) ) var, __next ## var \


#define IQUEUE_FOREACH_SAFE(list, var) \
	for (var = (list)->head, \
				__next ## var = var ? ((__typeof((list)->offset)) var)->link.next : NULL; \
			var; \
			var = __next ## var, \
				__next ## var = var ? ((__typeof((list)->offset)) var)->link.next : NULL)


#define i_queue_clear_full(list, fn) do { \
	IQUEUE_FOREACH_SAFE_DECL(list, __ele); \
	IQUEUE_FOREACH_SAFE(list, __ele) \
		(fn)(__ele); \
	i_queue_init(list); \
} while (0)


#define i_queue_find(list, fn) ({ \
	 __typeof__ ((list)->head) __ret = NULL; \
	 bool (*__fn)(__typeof__ ((list)->const_ele)) = (fn); \
	 IQUEUE_FOREACH(list, __ele) { \
	 	if (__fn(__ele)) { \
			__ret = __ele; \
			break; \
		} \
	} \
	__ret; \
})


#endif
