#ifndef __HELPERS_H__
#define __HELPERS_H__



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
#include <stdbool.h>
#include <json-glib/json-glib.h>
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
#if !GLIB_CHECK_VERSION(2,62,0)

// from https://github.com/GNOME/glib/blob/master/glib/glist.c

INLINE GList *
g_list_insert_before_link (GList *list,
                           GList *sibling,
                           GList *link_)
{
  g_return_val_if_fail (link_ != NULL, list);
  g_return_val_if_fail (link_->prev == NULL, list);
  g_return_val_if_fail (link_->next == NULL, list);

  if (list == NULL)
    {
      g_return_val_if_fail (sibling == NULL, list);
      return link_;
    }
  else if (sibling != NULL)
    {
      link_->prev = sibling->prev;
      link_->next = sibling;
      sibling->prev = link_;
      if (link_->prev != NULL)
        {
          link_->prev->next = link_;
          return list;
        }
      else
        {
          g_return_val_if_fail (sibling == list, link_);
          return link_;
        }
    }
  else
    {
      GList *last;

      for (last = list; last->next != NULL; last = last->next) {}

      last->next = link_;
      last->next->prev = last;
      last->next->next = NULL;

      return list;
    }
}

#endif


/* GLIB-JSON */

// frees 'builder', returns g_malloc'd string
INLINE char *glib_json_print(JsonBuilder *builder) {
	JsonGenerator *gen = json_generator_new();
	JsonNode *root = json_builder_get_root(builder);
	json_generator_set_root(gen, root);
	char *result = json_generator_to_data(gen, NULL);

	json_node_free(root);
	g_object_unref(gen);
	g_object_unref(builder);

	return result;
}


/* GQUEUE */

// appends `src` to the end of `dst` and clears out `src`
INLINE void g_queue_move(GQueue *dst, GQueue *src) {
	if (!src->length)
		return;
	if (!dst->length) {
		*dst = *src;
		g_queue_init(src);
		return;
	}
	dst->tail->next = src->head;
	src->head->prev = dst->tail;
	dst->length += src->length;
	g_queue_init(src);
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


/* GHASHTABLE */

INLINE GQueue *g_hash_table_lookup_queue_new(GHashTable *ht, void *key, GDestroyNotify free_func) {
	GQueue *ret = g_hash_table_lookup(ht, key);
	if (ret) {
		if (free_func)
			free_func(key);
		return ret;
	}
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

INLINE int strmemcmp(const void *mem, int len, const char *s) {
	int l = strlen(s);
	if (l < len)
		return -1;
	if (l > len)
		return 1;
	return memcmp(mem, s, len);
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



/*** TAINT FUNCTIONS ***/

#if __has_attribute(__error__)
/* This is not supported in clang, and on gcc it might become inert if the
 * symbol gets remapped to a builtin or stack protected function, but it
 * otherwise gives better diagnostics. */
#define taint_func(symbol, reason) \
	__typeof__(symbol) symbol __attribute__((__error__(reason)))
#else
#define taint_pragma(str) _Pragma(#str)
#define taint_pragma_expand(str) taint_pragma(str)
#define taint_func(symbol, reason) taint_pragma_expand(GCC poison symbol)
#endif

taint_func(rand, "use ssl_random() instead");
taint_func(random, "use ssl_random() instead");
taint_func(srandom, "use RAND_seed() instead");



/*** INET ADDRESS HELPERS ***/

#define IPF			"%u.%u.%u.%u"
#define IPP(x)			((unsigned char *) (&(x)))[0], ((unsigned char *) (&(x)))[1], ((unsigned char *) (&(x)))[2], ((unsigned char *) (&(x)))[3]
#define IP6F			"%x:%x:%x:%x:%x:%x:%x:%x"
#define IP6P(x)			ntohs(((uint16_t *) (x))[0]), \
				ntohs(((uint16_t *) (x))[1]), \
				ntohs(((uint16_t *) (x))[2]), \
				ntohs(((uint16_t *) (x))[3]), \
				ntohs(((uint16_t *) (x))[4]), \
				ntohs(((uint16_t *) (x))[5]), \
				ntohs(((uint16_t *) (x))[6]), \
				ntohs(((uint16_t *) (x))[7])
#define D6F			"["IP6F"]:%u"
#define D6P(x)			IP6P((x).sin6_addr.s6_addr), ntohs((x).sin6_port)
#define DF			IPF ":%u"
#define DP(x)			IPP((x).sin_addr.s_addr), ntohs((x).sin_port)





/*** THREAD HELPERS ***/

struct thread_waker {
	mutex_t *lock;
	cond_t *cond;
};
enum thread_looper_action {
	TLA_CONTINUE,
	TLA_BREAK,
};

void thread_waker_add(struct thread_waker *);
void thread_waker_del(struct thread_waker *);
void threads_join_all(bool cancel);
void thread_create_detach_prio(void (*)(void *), void *, const char *, int, const char *);
void thread_create_looper(enum thread_looper_action (*f)(void), const char *scheduler, int priority,
		const char *name, long long);
INLINE void thread_create_detach(void (*f)(void *), void *a, const char *name) {
	thread_create_detach_prio(f, a, NULL, 0, name);
}

#ifndef ASAN_BUILD
#define thread_cancel_enable() pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)
#define thread_cancel_disable() pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)
#define thread_sleep_time 10000 /* ms */
#else
#define thread_cancel_enable() ((void)0)
#define thread_cancel_disable() ((void)0)
#define thread_sleep_time 100 /* ms */
#endif




/*** ATOMIC BITFIELD OPERATIONS ***/

/* checks if at least one of the flags is set */
INLINE bool bf_isset(const volatile unsigned int *u, unsigned int f) {
	if ((g_atomic_int_get(u) & f))
		return true;
	return false;
}
/* checks if all of the flags are set */
INLINE bool bf_areset(const volatile unsigned int *u, unsigned int f) {
	if ((g_atomic_int_get(u) & f) == f)
		return true;
	return false;
}
/* returns true if at least one of the flags was set already */
INLINE bool bf_set(volatile unsigned int *u, unsigned int f) {
	return (g_atomic_int_or(u, f) & f) ? true : false;
}
/* returns true if at least one of the flags was set */
INLINE bool bf_clear(volatile unsigned int *u, unsigned int f) {
	return (g_atomic_int_and(u, ~f) & f) ? true : false;
}
INLINE void bf_set_clear(volatile unsigned int *u, unsigned int f, bool cond) {
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

INLINE bool bit_array_isset(const volatile unsigned int *name, unsigned int bit) {
	return bf_isset(&name[bit / (sizeof(int) * 8)], 1U << (bit % (sizeof(int) * 8)));
}
INLINE bool bit_array_set(volatile unsigned int *name, unsigned int bit) {
	return bf_set(&name[bit / (sizeof(int) * 8)], 1U << (bit % (sizeof(int) * 8)));
}
INLINE bool bit_array_clear(volatile unsigned int *name, unsigned int bit) {
	return bf_clear(&name[bit / (sizeof(int) * 8)], 1U << (bit % (sizeof(int) * 8)));
}




/*** ATOMIC64 ***/

#if GLIB_SIZEOF_VOID_P >= 8

typedef struct {
	void *p;
} atomic64;

INLINE uint64_t atomic64_get(const atomic64 *u) {
	void **p = (void *) &u->p;
	return (uint64_t) g_atomic_pointer_get(p);
}
INLINE uint64_t atomic64_get_na(const atomic64 *u) {
	void **p = (void *) &u->p;
	return (uint64_t) *p;
}
INLINE void atomic64_set(atomic64 *u, uint64_t a) {
	g_atomic_pointer_set(&u->p, (void *) a);
}
INLINE gboolean atomic64_set_if(atomic64 *u, uint64_t a, uint64_t i) {
	return g_atomic_pointer_compare_and_exchange(&u->p, (void *) i, (void *) a);
}
INLINE void atomic64_set_na(atomic64 *u, uint64_t a) {
	u->p = (void *) a;
}
INLINE uint64_t atomic64_add(atomic64 *u, uint64_t a) {
	return g_atomic_pointer_add(&u->p, a);
}
INLINE uint64_t atomic64_add_na(atomic64 *u, uint64_t a) {
	uint64_t old = (uint64_t) u->p;
	u->p = (void *) (((uint64_t) u->p) + a);
	return old;
}
INLINE uint64_t atomic64_get_set(atomic64 *u, uint64_t a) {
	uint64_t old;
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
	uint64_t u;
} atomic64;

#define NEED_ATOMIC64_MUTEX
extern mutex_t __atomic64_mutex;

INLINE uint64_t atomic64_get(const atomic64 *u) {
	uint64_t ret;
	mutex_lock(&__atomic64_mutex);
	ret = u->u;
	mutex_unlock(&__atomic64_mutex);
	return ret;
}
INLINE uint64_t atomic64_get_na(const atomic64 *u) {
	return u->u;
}
INLINE void atomic64_set(atomic64 *u, uint64_t a) {
	mutex_lock(&__atomic64_mutex);
	u->u = a;
	mutex_unlock(&__atomic64_mutex);
}
INLINE gboolean atomic64_set_if(atomic64 *u, uint64_t a, uint64_t i) {
	gboolean done = TRUE;
	mutex_lock(&__atomic64_mutex);
	if (u->u == i)
		u->u = a;
	else
		done = FALSE;
	mutex_unlock(&__atomic64_mutex);
	return done;
}
INLINE void atomic64_set_na(atomic64 *u, uint64_t a) {
	u->u = a;
}
INLINE uint64_t atomic64_add(atomic64 *u, uint64_t a) {
	mutex_lock(&__atomic64_mutex);
	uint64_t old = u->u;
	u->u += a;
	mutex_unlock(&__atomic64_mutex);
	return old;
}
INLINE uint64_t atomic64_add_na(atomic64 *u, uint64_t a) {
	uint64_t old = u->u;
	u->u += a;
	return old;
}
INLINE uint64_t atomic64_get_set(atomic64 *u, uint64_t a) {
	uint64_t old;
	mutex_lock(&__atomic64_mutex);
	old = u->u;
	u->u = a;
	mutex_unlock(&__atomic64_mutex);
	return old;
}

#endif

INLINE uint64_t atomic64_inc(atomic64 *u) {
	return atomic64_add(u, 1);
}
INLINE uint64_t atomic64_dec(atomic64 *u) {
	return atomic64_add(u, -1);
}
INLINE void atomic64_local_copy_zero(atomic64 *dst, atomic64 *src) {
	atomic64_set_na(dst, atomic64_get_set(src, 0));
}
#define atomic64_local_copy_zero_struct(d, s, member) \
	atomic64_local_copy_zero(&((d)->member), &((s)->member))

INLINE void atomic64_min(atomic64 *min, uint64_t val) {
	do {
		uint64_t old = atomic64_get(min);
		if (old && old <= val)
			break;
		if (atomic64_set_if(min, val, old))
			break;
	} while (1);
}
INLINE void atomic64_max(atomic64 *max, uint64_t val) {
	do {
		uint64_t old = atomic64_get(max);
		if (old && old >= val)
			break;
		if (atomic64_set_if(max, val, old))
			break;
	} while (1);
}

INLINE void atomic64_calc_rate_from_diff(long long run_diff_us, uint64_t diff, atomic64 *rate_var) {
	atomic64_set(rate_var, run_diff_us ? diff * 1000000LL / run_diff_us : 0);
}
INLINE void atomic64_calc_rate(const atomic64 *ax_var, long long run_diff_us,
		atomic64 *intv_var, atomic64 *rate_var)
{
	uint64_t ax = atomic64_get(ax_var);
	uint64_t old_intv = atomic64_get(intv_var);
	atomic64_set(intv_var, ax);
	atomic64_calc_rate_from_diff(run_diff_us, ax - old_intv, rate_var);
}
INLINE void atomic64_calc_diff(const atomic64 *ax_var, atomic64 *intv_var, atomic64 *diff_var) {
	uint64_t ax = atomic64_get(ax_var);
	uint64_t old_intv = atomic64_get(intv_var);
	atomic64_set(intv_var, ax);
	atomic64_set(diff_var, ax - old_intv);
}
INLINE void atomic64_mina(atomic64 *min, atomic64 *inp) {
	atomic64_min(min, atomic64_get(inp));
}
INLINE void atomic64_maxa(atomic64 *max, atomic64 *inp) {
	atomic64_max(max, atomic64_get(inp));
}
INLINE double atomic64_div(const atomic64 *n, const atomic64 *d) {
	int64_t dd = atomic64_get(d);
	if (!dd)
		return 0.;
	return (double) atomic64_get(n) / (double) dd;
}



/*** STATS HELPERS ***/

#define STAT_MIN_MAX_RESET_ZERO(x, mm, loc) \
	atomic64_set(&loc->min.x, atomic64_get_set(&mm->min.x, 0)); \
	atomic64_set(&loc->max.x, atomic64_get_set(&mm->max.x, 0));

#define STAT_MIN_MAX(x, loc, mm, cur) \
	atomic64_set(&loc->min.x, atomic64_get_set(&mm->min.x, atomic64_get(&cur->x))); \
	atomic64_set(&loc->max.x, atomic64_get_set(&mm->max.x, atomic64_get(&cur->x)));

#define STAT_MIN_MAX_AVG(x, mm, loc, run_diff_us, counter_diff) \
	atomic64_set(&loc->min.x, atomic64_get_set(&mm->min.x, 0)); \
	atomic64_set(&loc->max.x, atomic64_get_set(&mm->max.x, 0)); \
	atomic64_set(&loc->avg.x, run_diff_us ? atomic64_get(&counter_diff->x) * 1000000LL / run_diff_us : 0);

#define STAT_SAMPLED_CALC_DIFF(x, stats, intv, diff) \
	atomic64_calc_diff(&stats->sums.x, &intv->sums.x, &diff->sums.x); \
	atomic64_calc_diff(&stats->sums_squared.x, &intv->sums_squared.x, &diff->sums_squared.x); \
	atomic64_calc_diff(&stats->counts.x, &intv->counts.x, &diff->counts.x);

#define STAT_SAMPLED_AVG_STDDEV(x, loc, diff) { \
	double __mean = atomic64_div(&diff->sums.x, &diff->counts.x); \
	atomic64_set(&loc->avg.x, __mean); \
	atomic64_set(&loc->stddev.x, sqrt(fabs(atomic64_div(&diff->sums_squared.x, &diff->counts.x) \
					- __mean * __mean))); \
	}



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


#endif
