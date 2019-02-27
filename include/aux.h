#ifndef __AUX_H__
#define __AUX_H__



#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <glib.h>
#include <pcre.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "compat.h"
#include "auxlib.h"

#if !(GLIB_CHECK_VERSION(2,30,0))
#define g_atomic_int_and(atomic, val) \
(G_GNUC_EXTENSION ({                                                          \
G_STATIC_ASSERT (sizeof *(atomic) == sizeof (gint));                     \
(void) (0 ? *(atomic) ^ (val) : 0);                                      \
(guint) __sync_fetch_and_and ((atomic), (val));                          \
}))
#define g_atomic_int_or(atomic, val) \
(G_GNUC_EXTENSION ({                                                          \
G_STATIC_ASSERT (sizeof *(atomic) == sizeof (gint));                     \
(void) (0 ? *(atomic) ^ (val) : 0);                                      \
(guint) __sync_fetch_and_or ((atomic), (val));                           \
}))
#define g_atomic_pointer_add(atomic, val) \
(G_GNUC_EXTENSION ({                                                          \
    G_STATIC_ASSERT (sizeof *(atomic) == sizeof (gpointer));            \
    (void) (0 ? (gpointer) *(atomic) : 0);                              \
    (void) (0 ? (val) ^ (val) : 0);                                     \
    (gssize) __sync_fetch_and_add ((atomic), (val));                    \
}))
#endif

#if 0 && defined(__DEBUG)
#define __THREAD_DEBUG 1
#endif




/*** GLOBALS ***/

extern volatile int rtpe_shutdown;




/*** PROTOTYPES ***/

typedef int (*parse_func)(char **, void **, void *);

int pcre_multi_match(pcre *, pcre_extra *, const char *, unsigned int, parse_func, void *, GQueue *);
INLINE void strmove(char **, char **);
INLINE void strdupfree(char **, const char *);



/*** GLIB HELPERS ***/

GList *g_list_link(GList *, GList *);

#if !GLIB_CHECK_VERSION(2,32,0)
INLINE int g_hash_table_contains(GHashTable *h, const void *k) {
	return g_hash_table_lookup(h, k) ? 1 : 0;
}
INLINE void g_queue_free_full(GQueue *q, GDestroyNotify free_func) {
       void *d;
       while ((d = g_queue_pop_head(q)))
               free_func(d);
       g_queue_free(q);
}
#endif



/* GQUEUE */

INLINE void g_queue_move(GQueue *dst, GQueue *src) {
	GList *l;
	while ((l = g_queue_pop_head_link(src)))
		g_queue_push_tail_link(dst, l);
}
INLINE void g_queue_truncate(GQueue *q, unsigned int len) {
	while (q->length > len)
		g_queue_pop_tail(q);
}
#if !(GLIB_CHECK_VERSION(2,60,0))
INLINE void g_queue_clear_full(GQueue *q, GDestroyNotify free_func) {
	void *p;
	while ((p = g_queue_pop_head(q)))
		free_func(p);
}
#endif
INLINE void g_queue_append(GQueue *dst, const GQueue *src) {
	GList *l;
	if (!src || !dst)
		return;
	for (l = src->head; l; l = l->next)
		g_queue_push_tail(dst, l->data);
}


/* GTREE */

int g_tree_find_first_cmp(void *, void *, void *);
int g_tree_find_all_cmp(void *, void *, void *);
INLINE void *g_tree_find_first(GTree *t, GEqualFunc f, void *data) {
	void *p[3];
	p[0] = data;
	p[1] = f;
	p[2] = NULL;
	g_tree_foreach(t, g_tree_find_first_cmp, p);
	return p[2];
}
INLINE void g_tree_find_all(GQueue *out, GTree *t, GEqualFunc f, void *data) {
	void *p[3];
	p[0] = data;
	p[1] = f;
	p[2] = out;
	g_tree_foreach(t, g_tree_find_all_cmp, p);
}
INLINE void g_tree_get_values(GQueue *out, GTree *t) {
	g_tree_find_all(out, t, NULL, NULL);
}
INLINE void g_tree_remove_all(GQueue *out, GTree *t) {
	GList *l;
	g_queue_init(out);
	g_tree_find_all(out, t, NULL, NULL);
	for (l = out->head; l; l = l->next)
		g_tree_remove(t, l->data);
}
INLINE void g_tree_add_all(GTree *t, GQueue *q) {
	GList *l;
	for (l = q->head; l; l = l->next)
		g_tree_insert(t, l->data, l->data);
	g_queue_clear(q);
}



/* GHASHTABLE */

INLINE GQueue *g_hash_table_lookup_queue_new(GHashTable *ht, void *key) {
	GQueue *ret = g_hash_table_lookup(ht, key);
	if (ret)
		return ret;
	ret = g_queue_new();
	g_hash_table_insert(ht, key, ret);
	return ret;
}



/*** STRING HELPERS ***/

INLINE void strmove(char **d, char **s) {
	if (*d)
		free(*d);
	*d = *s;
	*s = strdup("");
}

INLINE void strdupfree(char **d, const char *s) {
	if (*d)
		free(*d);
	*d = strdup(s);
}

INLINE int strmemcmp(const void *mem, int len, const char *str) {
	int l = strlen(str);
	if (l < len)
		return -1;
	if (l > len)
		return 1;
	return memcmp(mem, str, len);
}

INLINE long unsigned int ssl_random(void) {
	long unsigned int ret;
	random_string((void *) &ret, sizeof(ret));
	return ret;
}

INLINE const char *__get_enum_array_text(const char * const *array, unsigned int idx,
		unsigned int len, const char *deflt)
{
	const char *ret;
	if (idx >= len)
		return deflt;
	ret = array[idx];
	return ret ? : deflt;
}
#define get_enum_array_text(array, idx, deflt) \
	__get_enum_array_text(array, idx, G_N_ELEMENTS(array), deflt)





/*** GENERIC HELPERS ***/

INLINE char chrtoupper(char x) {
	return x & 0xdf;
}

INLINE void swap_ptrs(void *a, void *b) {
	void *t, **aa, **bb;
	aa = a;
	bb = b;
	t = *aa;
	*aa = *bb;
	*bb = t;
}

INLINE int rlim(int res, rlim_t val) {
	struct rlimit rlim;

	ZERO(rlim);
	rlim.rlim_cur = rlim.rlim_max = val;
	return setrlimit(res, &rlim);
}

void free_buf(char **);



/*** INET ADDRESS HELPERS ***/

#define IPF			"%u.%u.%u.%u"
#define IPP(x)			((unsigned char *) (&(x)))[0], ((unsigned char *) (&(x)))[1], ((unsigned char *) (&(x)))[2], ((unsigned char *) (&(x)))[3]
#define IP6F			"%x:%x:%x:%x:%x:%x:%x:%x"
#define IP6P(x)			ntohs(((u_int16_t *) (x))[0]), \
				ntohs(((u_int16_t *) (x))[1]), \
				ntohs(((u_int16_t *) (x))[2]), \
				ntohs(((u_int16_t *) (x))[3]), \
				ntohs(((u_int16_t *) (x))[4]), \
				ntohs(((u_int16_t *) (x))[5]), \
				ntohs(((u_int16_t *) (x))[6]), \
				ntohs(((u_int16_t *) (x))[7])
#define D6F			"["IP6F"]:%u"
#define D6P(x)			IP6P((x).sin6_addr.s6_addr), ntohs((x).sin6_port)
#define DF			IPF ":%u"
#define DP(x)			IPP((x).sin_addr.s_addr), ntohs((x).sin_port)





/*** THREAD HELPERS ***/

void threads_join_all(int);
void thread_create_detach_prio(void (*)(void *), void *, const char *, int);
INLINE void thread_create_detach(void (*f)(void *), void *a) {
	thread_create_detach_prio(f, a, NULL, 0);
}




/*** ATOMIC BITFIELD OPERATIONS ***/

/* checks if at least one of the flags is set */
INLINE int bf_isset(const volatile unsigned int *u, unsigned int f) {
	if ((g_atomic_int_get(u) & f))
		return -1;
	return 0;
}
/* checks if all of the flags are set */
INLINE int bf_areset(const volatile unsigned int *u, unsigned int f) {
	if ((g_atomic_int_get(u) & f) == f)
		return -1;
	return 0;
}
/* returns true if at least one of the flags was set already */
INLINE int bf_set(volatile unsigned int *u, unsigned int f) {
	return (g_atomic_int_or(u, f) & f) ? -1 : 0;
}
/* returns true if at least one of the flags was set */
INLINE int bf_clear(volatile unsigned int *u, unsigned int f) {
	return (g_atomic_int_and(u, ~f) & f) ? -1 : 0;
}
INLINE void bf_set_clear(volatile unsigned int *u, unsigned int f, int cond) {
	if (cond)
		bf_set(u, f);
	else
		bf_clear(u, f);
}
/* works only for single flags */
INLINE void bf_copy(volatile unsigned int *u, unsigned int f,
		const volatile unsigned int *s, unsigned int g)
{
	bf_set_clear(u, f, bf_isset(s, g));
}
/* works for multiple flags */
INLINE void bf_copy_same(volatile unsigned int *u, const volatile unsigned int *s, unsigned int g) {
	unsigned int old, set, clear;
	old = g_atomic_int_get(s);
	set = old & g;
	clear = ~old & g;
	bf_set(u, set);
	bf_clear(u, clear);
}



/*** BIT ARRAY FUNCTIONS ***/

#define BIT_ARRAY_DECLARE(name, size)	\
	volatile unsigned int name[((size) + sizeof(int) * 8 - 1) / (sizeof(int) * 8)]

INLINE int bit_array_isset(const volatile unsigned int *name, unsigned int bit) {
	return bf_isset(&name[bit / (sizeof(int) * 8)], 1U << (bit % (sizeof(int) * 8)));
}
INLINE int bit_array_set(volatile unsigned int *name, unsigned int bit) {
	return bf_set(&name[bit / (sizeof(int) * 8)], 1U << (bit % (sizeof(int) * 8)));
}
INLINE int bit_array_clear(volatile unsigned int *name, unsigned int bit) {
	return bf_clear(&name[bit / (sizeof(int) * 8)], 1U << (bit % (sizeof(int) * 8)));
}




/*** ATOMIC64 ***/

#if GLIB_SIZEOF_VOID_P >= 8

typedef struct {
	volatile void *p;
} atomic64;

INLINE u_int64_t atomic64_get(const atomic64 *u) {
	return (u_int64_t) g_atomic_pointer_get(&u->p);
}
INLINE u_int64_t atomic64_get_na(const atomic64 *u) {
	return (u_int64_t) u->p;
}
INLINE void atomic64_set(atomic64 *u, u_int64_t a) {
	g_atomic_pointer_set(&u->p, (void *) a);
}
INLINE void atomic64_set_na(atomic64 *u, u_int64_t a) {
	u->p = (void *) a;
}
INLINE void atomic64_add(atomic64 *u, u_int64_t a) {
	g_atomic_pointer_add(&u->p, a);
}
INLINE void atomic64_add_na(atomic64 *u, u_int64_t a) {
	u->p = (void *) (((u_int64_t) u->p) + a);
}
INLINE u_int64_t atomic64_get_set(atomic64 *u, u_int64_t a) {
	u_int64_t old;
	do {
		old = atomic64_get(u);
		if (g_atomic_pointer_compare_and_exchange(&u->p, (void *) old, (void *) a))
			return old;
	} while (1);
}

#else

/* Simulate atomic u64 with a global mutex on non-64-bit platforms.
 * Bad performance possible, thus not recommended. */

typedef struct {
	u_int64_t u;
} atomic64;

#define NEED_ATOMIC64_MUTEX
extern mutex_t __atomic64_mutex;

INLINE u_int64_t atomic64_get(const atomic64 *u) {
	u_int64_t ret;
	mutex_lock(&__atomic64_mutex);
	ret = u->u;
	mutex_unlock(&__atomic64_mutex);
	return ret;
}
INLINE u_int64_t atomic64_get_na(const atomic64 *u) {
	return u->u;
}
INLINE void atomic64_set(atomic64 *u, u_int64_t a) {
	mutex_lock(&__atomic64_mutex);
	u->u = a;
	mutex_unlock(&__atomic64_mutex);
}
INLINE void atomic64_set_na(atomic64 *u, u_int64_t a) {
	u->u = a;
}
INLINE void atomic64_add(atomic64 *u, u_int64_t a) {
	mutex_lock(&__atomic64_mutex);
	u->u += a;
	mutex_unlock(&__atomic64_mutex);
}
INLINE void atomic64_add_na(atomic64 *u, u_int64_t a) {
	u->u += a;
}
INLINE u_int64_t atomic64_get_set(atomic64 *u, u_int64_t a) {
	u_int64_t old;
	mutex_lock(&__atomic64_mutex);
	old = u->u;
	u->u = a;
	mutex_unlock(&__atomic64_mutex);
	return old;
}

#endif

INLINE void atomic64_inc(atomic64 *u) {
	atomic64_add(u, 1);
}
INLINE void atomic64_dec(atomic64 *u) {
	atomic64_add(u, -1);
}
INLINE void atomic64_local_copy_zero(atomic64 *dst, atomic64 *src) {
	atomic64_set_na(dst, atomic64_get_set(src, 0));
}
#define atomic64_local_copy_zero_struct(d, s, member) \
	atomic64_local_copy_zero(&((d)->member), &((s)->member))





/*** ALLOC WITH UNIQUE ID HELPERS ***/

#define uid_slice_alloc(ptr, q) __uid_slice_alloc(sizeof(*(ptr)), q, \
		G_STRUCT_OFFSET(__typeof__(*(ptr)), unique_id))
#define uid_slice_alloc0(ptr, q) __uid_slice_alloc0(sizeof(*(ptr)), q, \
		G_STRUCT_OFFSET(__typeof__(*(ptr)), unique_id))
INLINE void __uid_slice_alloc_fill(void *ptr, GQueue *q, unsigned int offset) {
	unsigned int *id;
	id = G_STRUCT_MEMBER_P(ptr, offset);
	*id = g_queue_get_length(q);
	g_queue_push_tail(q, ptr);
}
INLINE void *__uid_slice_alloc(unsigned int size, GQueue *q, unsigned int offset) {
	void *ret;
	ret = g_slice_alloc(size);
	__uid_slice_alloc_fill(ret, q, offset);
	return ret;
}
INLINE void *__uid_slice_alloc0(unsigned int size, GQueue *q, unsigned int offset) {
	void *ret;
	ret = g_slice_alloc0(size);
	__uid_slice_alloc_fill(ret, q, offset);
	return ret;
}

#define TRUNCATED " ... Output truncated. Increase Output Buffer ...                                    \n"

#define truncate_output(x) strcpy(x - strlen(TRUNCATED) - 1, TRUNCATED)

#define ADJUSTLEN(printlen,outbufend,replybuffer) do { \
               replybuffer += (printlen>=outbufend-replybuffer)?outbufend-replybuffer:printlen; \
               if (replybuffer == outbufend) \
                       truncate_output(replybuffer); \
       } while (0);


#endif
