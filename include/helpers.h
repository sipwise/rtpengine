#ifndef __HELPERS_H__
#define __HELPERS_H__

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <glib.h>
#include <pcre2.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <json-glib/json-glib.h>

#include "compat.h"
#include "auxlib.h"

#if 0 && defined(__DEBUG)
#define __THREAD_DEBUG 1
#endif

/*** PROTOTYPES ***/

typedef bool (*parse_func)(char **, void **, void *);

int pcre2_multi_match(pcre2_code *, const char *, unsigned int, parse_func, void *, GQueue *);

#if PCRE2_MAJOR > 10 || (PCRE2_MAJOR == 10 && PCRE2_MINOR >= 43)
#define SUBSTRING_FREE_ARG PCRE2_UCHAR **
#else
#define SUBSTRING_FREE_ARG PCRE2_SPTR *
#endif



/*** GLIB HELPERS ***/

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
INLINE void glib_json_builder_add_str(JsonBuilder *builder, str *s) {
	char ori = s->s[s->len];
	s->s[s->len] = '\0';
	json_builder_add_string_value(builder, s->s);
	s->s[s->len] = ori;
}


/* GQUEUE */

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
	void (*func)(struct thread_waker *);
	mutex_t *lock;
	cond_t *cond;
	void *arg;
};
enum thread_looper_action {
	TLA_CONTINUE,
	TLA_BREAK,
};

void thread_waker_add(struct thread_waker *);
void thread_waker_add_generic(struct thread_waker *);
void thread_waker_del(struct thread_waker *);
void threads_join_all(bool cancel);
void thread_create_detach_prio(void (*)(void *), void *, const char *, int, const char *);
void thread_create_looper(enum thread_looper_action (*f)(void), const char *scheduler, int priority,
		const char *name, long long);
INLINE void thread_create_detach(void (*f)(void *), void *a, const char *name) {
	thread_create_detach_prio(f, a, NULL, 0, name);
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
