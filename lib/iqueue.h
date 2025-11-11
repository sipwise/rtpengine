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


#define IQUEUE_FOREACH(list, var) \
	for (__typeof__ ( ({ __typeof__ (*(list)->head) __t; &__t; }) ) var = (list)->head; \
			var; var = ((__typeof((list)->offset)) var)->link.next)


#endif
