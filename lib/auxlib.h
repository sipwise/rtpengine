#ifndef _AUXLIB_H_
#define _AUXLIB_H_

#include <glib.h>
#include <assert.h>
#include "compat.h"
#include <openssl/rand.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/syscall.h>


#define THREAD_BUF_SIZE		64
#define NUM_THREAD_BUFS		8
#define MAX_LOG_LEVELS		32


struct rtpengine_common_config {
	char *config_file;
	char *config_section;
	char *log_facility;
	int default_log_level;
	int log_levels[MAX_LOG_LEVELS];
	gboolean log_stderr;
	gboolean split_logs;
	gboolean no_log_timestamps;
	char *log_name;
	char *log_mark_prefix;
	char *log_mark_suffix;
	char *pidfile;
	gboolean foreground;
	int thread_stack;
	int poller_size;
	gboolean io_uring;
	int io_uring_buffers;
	int max_log_line_length;
	int mos_type;				// enum in codec_def_t
	char *evs_lib_path;
	char *codec_chain_lib_path;
	int codec_chain_runners;
	int codec_chain_concurrency;
	int codec_chain_async;
	int codec_chain_opus_application;
	int codec_chain_opus_complexity;
};

extern struct rtpengine_common_config *rtpe_common_config_ptr;



/*** GLOBALS ***/

extern __thread struct timeval rtpe_now;
extern volatile bool rtpe_shutdown;




/*** PROTOTYPES ***/

void daemonize(void);
void resources(void);
void wpidfile(void);
void service_notify(const char *message);
void config_load_free(struct rtpengine_common_config *);
void config_load_ext(int *argc, char ***argv, GOptionEntry *entries, const char *description,
		char *default_config, char *default_section,
		struct rtpengine_common_config *,
		char * const *template_section, GHashTable *templates);
INLINE void config_load(int *argc, char ***argv, GOptionEntry *entries, const char *description,
		char *default_config, char *default_section,
		struct rtpengine_common_config *cc)
{
	config_load_ext(argc, argv, entries, description, default_config, default_section, cc, NULL, NULL);
}

char *get_thread_buf(void);
int thread_create(void *(*func)(void *), void *arg, bool joinable, pthread_t *handle, const char *name);

unsigned int in6_addr_hash(const void *p);
int in6_addr_eq(const void *a, const void *b);
unsigned int uint32_hash(const void *p);
int uint32_eq(const void *a, const void *b);
int num_cpu_cores(int);


/*** HELPER MACROS ***/

#define ZERO(x)			memset(&(x), 0, sizeof(x))

#define UINT64F			"%" G_GUINT64_FORMAT

G_DEFINE_AUTOPTR_CLEANUP_FUNC(char, g_free)
typedef char *char_p;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(char_p, g_strfreev)
#define auto_iter(v, l) __typeof__ ( ({ __typeof__ (*l) __t; &__t; }) ) v = (l) /* for gcc <12 */


/*** STRING HELPERS ***/

INLINE void random_string(unsigned char *buf, int len) {
	int ret = RAND_bytes(buf, len);
	assert(ret == 1);
	(void) ret;
}

INLINE unsigned int c_str_hash(const char *s) {
	return g_str_hash(s);
}
INLINE gboolean c_str_equal(const char *a, const char *b) {
	return g_str_equal(a, b);
}


/*** MUTEX ABSTRACTION ***/

typedef pthread_mutex_t mutex_t;
typedef pthread_rwlock_t rwlock_t;
typedef pthread_cond_t cond_t;

#define mutex_init(m) __debug_mutex_init(m, __FILE__, __LINE__)
#define mutex_destroy(m) __debug_mutex_destroy(m, __FILE__, __LINE__)
#define mutex_lock(m) __debug_mutex_lock(m, __FILE__, __LINE__)
#define mutex_trylock(m) __debug_mutex_trylock(m, __FILE__, __LINE__)
#define mutex_unlock(m) __debug_mutex_unlock(m, __FILE__, __LINE__)
#define MUTEX_STATIC_INIT PTHREAD_MUTEX_INITIALIZER

#define rwlock_init(l) __debug_rwlock_init(l, __FILE__, __LINE__)
#define rwlock_destroy(l) __debug_rwlock_destroy(l, __FILE__, __LINE__)
#define rwlock_lock_r(l) __debug_rwlock_lock_r(l, __FILE__, __LINE__)
#define rwlock_unlock_r(l) __debug_rwlock_unlock_r(l, __FILE__, __LINE__)
#define rwlock_lock_w(l) __debug_rwlock_lock_w(l, __FILE__, __LINE__)
#define rwlock_trylock_w(l) __debug_rwlock_trylock_w(l, __FILE__, __LINE__)
#define rwlock_unlock_w(l) __debug_rwlock_unlock_w(l, __FILE__, __LINE__)
#define RWLOCK_STATIC_INIT PTHREAD_RWLOCK_INITIALIZER

#define cond_init(c) __debug_cond_init(c, __FILE__, __LINE__)
#define cond_wait(c,m) __debug_cond_wait(c,m, __FILE__, __LINE__)
#define cond_timedwait(c,m,t) __debug_cond_timedwait(c,m,t, __FILE__, __LINE__)
#define cond_signal(c) __debug_cond_signal(c, __FILE__, __LINE__)
#define cond_broadcast(c) __debug_cond_broadcast(c, __FILE__, __LINE__)
#define COND_STATIC_INIT PTHREAD_COND_INITIALIZER

INLINE int __cond_timedwait_tv(cond_t *c, mutex_t *m, const struct timeval *tv) {
	struct timespec ts;
	ts.tv_sec = tv->tv_sec;
	ts.tv_nsec = tv->tv_usec * 1000;
	return pthread_cond_timedwait(c, m, &ts);
}


#ifndef ASAN_BUILD
#define thread_cancel_enable() pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)
#define thread_cancel_disable() pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)
#define thread_sleep_time 10000 /* ms */
#define thread_cleanup_push pthread_cleanup_push
#define thread_cleanup_pop pthread_cleanup_pop
#else
#define thread_cancel_enable() ((void)0)
#define thread_cancel_disable() ((void)0)
#define thread_sleep_time 100 /* ms */
#define thread_cleanup_push(f,a) void (*_cfn)(void *) = f; void *_cfa = a
#define thread_cleanup_pop(exe) assert(exe != false); _cfn(_cfa)
#endif



#ifndef __THREAD_DEBUG

#define __debug_mutex_init(m, F, L) pthread_mutex_init(m, NULL)
#define __debug_mutex_destroy(m, F, L) pthread_mutex_destroy(m)
#define __debug_mutex_lock(m, F, L) pthread_mutex_lock(m)
#define __debug_mutex_trylock(m, F, L) pthread_mutex_trylock(m)
#define __debug_mutex_unlock(m, F, L) pthread_mutex_unlock(m)

#define __debug_rwlock_init(l, F, L) pthread_rwlock_init(l, NULL)
#define __debug_rwlock_destroy(l, F, L) pthread_rwlock_destroy(l)
#define __debug_rwlock_lock_r(l, F, L) pthread_rwlock_rdlock(l)
#define __debug_rwlock_unlock_r(l, F, L) pthread_rwlock_unlock(l)
#define __debug_rwlock_lock_w(l, F, L) pthread_rwlock_wrlock(l)
#define __debug_rwlock_trylock_w(l, F, L) pthread_rwlock_trywrlock(l)
#define __debug_rwlock_unlock_w(l, F, L) pthread_rwlock_unlock(l)

#define __debug_cond_init(c, F, L) pthread_cond_init(c, NULL)
#define __debug_cond_wait(c, m, F, L) pthread_cond_wait(c,m)
#define __debug_cond_timedwait(c, m, t, F, L) __cond_timedwait_tv(c,m,t)
#define __debug_cond_signal(c, F, L) pthread_cond_signal(c)
#define __debug_cond_broadcast(c, F, L) pthread_cond_broadcast(c)

#else


#include "log.h"



INLINE int __debug_mutex_init(mutex_t *m, const char *file, unsigned int line) {
	write_log(LOG_DEBUG, "mutex_init(%p) at %s:%u", m, file, line);
	return pthread_mutex_init(m, NULL);
}
INLINE int __debug_mutex_destroy(mutex_t *m, const char *file, unsigned int line) {
	write_log(LOG_DEBUG, "mutex_destroy(%p) at %s:%u", m, file, line);
	return pthread_mutex_destroy(m);
}
INLINE int __debug_mutex_lock(mutex_t *m, const char *file, unsigned int line) {
	int ret;
	write_log(LOG_DEBUG, "mutex_lock(%p) at %s:%u ...", m, file, line);
	ret = pthread_mutex_lock(m);
	write_log(LOG_DEBUG, "mutex_lock(%p) at %s:%u returning %i", m, file, line, ret);
	return ret;
}
INLINE int __debug_mutex_trylock(mutex_t *m, const char *file, unsigned int line) {
	int ret;
	write_log(LOG_DEBUG, "mutex_trylock(%p) at %s:%u ...", m, file, line);
	ret = pthread_mutex_trylock(m);
	write_log(LOG_DEBUG, "mutex_trylock(%p) at %s:%u returning %i", m, file, line, ret);
	return ret;
}
INLINE int __debug_mutex_unlock(mutex_t *m, const char *file, unsigned int line) {
	write_log(LOG_DEBUG, "mutex_unlock(%p) at %s:%u", m, file, line);
	return pthread_mutex_unlock(m);
}

INLINE int __debug_rwlock_init(rwlock_t *m, const char *file, unsigned int line) {
	write_log(LOG_DEBUG, "rwlock_init(%p) at %s:%u", m, file, line);
	return pthread_rwlock_init(m, NULL);
}
INLINE int __debug_rwlock_destroy(rwlock_t *m, const char *file, unsigned int line) {
	write_log(LOG_DEBUG, "rwlock_destroy(%p) at %s:%u", m, file, line);
	return pthread_rwlock_destroy(m);
}
INLINE int __debug_rwlock_lock_r(rwlock_t *m, const char *file, unsigned int line) {
	int ret;
	write_log(LOG_DEBUG, "rwlock_lock_r(%p) at %s:%u ...", m, file, line);
	ret = pthread_rwlock_rdlock(m);
	write_log(LOG_DEBUG, "rwlock_lock_r(%p) at %s:%u returning %i", m, file, line, ret);
	return ret;
}
INLINE int __debug_rwlock_lock_w(rwlock_t *m, const char *file, unsigned int line) {
	int ret;
	write_log(LOG_DEBUG, "rwlock_lock_w(%p) at %s:%u ...", m, file, line);
	ret = pthread_rwlock_wrlock(m);
	write_log(LOG_DEBUG, "rwlock_lock_w(%p) at %s:%u returning %i", m, file, line, ret);
	return ret;
}
INLINE int __debug_rwlock_trylock_w(rwlock_t *m, const char *file, unsigned int line) {
	int ret;
	write_log(LOG_DEBUG, "rwlock_trylock_w(%p) at %s:%u ...", m, file, line);
	ret = pthread_rwlock_trywrlock(m);
	write_log(LOG_DEBUG, "rwlock_trylock_w(%p) at %s:%u returning %i", m, file, line, ret);
	return ret;
}
INLINE int __debug_rwlock_unlock_r(rwlock_t *m, const char *file, unsigned int line) {
	write_log(LOG_DEBUG, "rwlock_unlock_r(%p) at %s:%u", m, file, line);
	return pthread_rwlock_unlock(m);
}
INLINE int __debug_rwlock_unlock_w(rwlock_t *m, const char *file, unsigned int line) {
	write_log(LOG_DEBUG, "rwlock_unlock_w(%p) at %s:%u", m, file, line);
	return pthread_rwlock_unlock(m);
}

#define __debug_cond_init(c, F, L) pthread_cond_init(c, NULL)
#define __debug_cond_wait(c, m, F, L) pthread_cond_wait(c,m)
#define __debug_cond_timedwait(c, m, t, F, L) __cond_timedwait_tv(c,m,t)
#define __debug_cond_signal(c, F, L) pthread_cond_signal(c)
#define __debug_cond_broadcast(c, F, L) pthread_cond_broadcast(c)

#endif

typedef mutex_t mutex_lock_t;
typedef rwlock_t rwlock_w_lock_t;
typedef rwlock_t rwlock_r_lock_t;

INLINE void mutex_ptr_unlock(mutex_lock_t *m) {
	mutex_unlock(m);
}
INLINE mutex_lock_t *mutex_auto_lock(mutex_t *m) {
	mutex_lock(m);
	return m;
}
INLINE void rwlock_ptr_unlock_r(rwlock_r_lock_t *m) {
	rwlock_unlock_r(m);
}
INLINE rwlock_r_lock_t *rwlock_auto_lock_r(rwlock_t *m) {
	rwlock_lock_r(m);
	return m;
}
INLINE void rwlock_ptr_unlock_w(rwlock_w_lock_t *m) {
	rwlock_unlock_w(m);
}
INLINE rwlock_w_lock_t *rwlock_auto_lock_w(rwlock_t *m) {
	rwlock_lock_w(m);
	return m;
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(mutex_lock_t, mutex_ptr_unlock)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(rwlock_r_lock_t, rwlock_ptr_unlock_w)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(rwlock_w_lock_t, rwlock_ptr_unlock_r)

#define CONCAT2(a, b) a ## b
#define CONCAT(a, b) CONCAT2(a, b)
#define LOCK(m) g_autoptr(mutex_lock_t) CONCAT(__auto_lock_, __COUNTER__) \
		__attribute__((unused)) = mutex_auto_lock(m)
#define RWLOCK_R(m) g_autoptr(rwlock_r_lock_t) CONCAT(__auto_lock_, __COUNTER__) \
		__attribute__((unused)) = rwlock_auto_lock_r(m)
#define RWLOCK_W(m) g_autoptr(rwlock_w_lock_t) CONCAT(__auto_lock_, __COUNTER__) \
		__attribute__((unused)) = rwlock_auto_lock_w(m)




/*** TIMEVAL FUNCTIONS ***/

INLINE long long timeval_us(const struct timeval *t) {
	return (long long) ((long long) t->tv_sec * 1000000LL) + t->tv_usec;
}
INLINE void timeval_from_us(struct timeval *t, long long ms) {
	t->tv_sec = ms/1000000LL;
	t->tv_usec = ms%1000000LL;
}
INLINE long long timeval_diff(const struct timeval *a, const struct timeval *b) {
	return timeval_us(a) - timeval_us(b);
}
INLINE void timeval_subtract(struct timeval *result, const struct timeval *a, const struct timeval *b) {
	timeval_from_us(result, timeval_diff(a, b));
}
INLINE void timeval_multiply(struct timeval *result, const struct timeval *a, const long multiplier) {
	timeval_from_us(result, timeval_us(a) * multiplier);
}
INLINE void timeval_divide(struct timeval *result, const struct timeval *a, const long divisor) {
	if (divisor == 0) {
		result->tv_sec = 0;
		result->tv_usec = 0;
		return ;
	}
	timeval_from_us(result, timeval_us(a) / divisor);
}
INLINE void timeval_add(struct timeval *result, const struct timeval *a, const struct timeval *b) {
	timeval_from_us(result, timeval_us(a) + timeval_us(b));
}
INLINE void timeval_add_usec(struct timeval *tv, long usec) {
	timeval_from_us(tv, timeval_us(tv) + usec);
}
INLINE int long_cmp(long long a, long long b) {
	if (a == b)
		return 0;
	if (a < b)
		return -1;
	return 1;
}
INLINE int timeval_cmp(const struct timeval *a, const struct timeval *b) {
	int r = long_cmp(a->tv_sec, b->tv_sec);
	if (r != 0)
		return r;
	return long_cmp(a->tv_usec, b->tv_usec);
}
// as a GCompareFunc
int timeval_cmp_zero(const void *a, const void *b);
int timeval_cmp_ptr(const void *a, const void *b);

INLINE void timeval_lowest(struct timeval *l, const struct timeval *n) {
	if (!n->tv_sec)
		return;
	if (!l->tv_sec || timeval_cmp(l, n) == 1)
		*l = *n;
}
INLINE double ntp_ts_to_double(uint32_t whole, uint32_t frac) {
	return (double) whole + (double) frac / 4294967296.0;
}


/*** GLIB HELPERS ***/

INLINE int g_tree_clear_cb(void *k, void *v, void *p) {
	GQueue *q = p;
	g_queue_push_tail(q, k);
	return 0;
}
INLINE void g_tree_clear(GTree *t) {
	GQueue q = G_QUEUE_INIT;
	g_tree_foreach(t, g_tree_clear_cb, &q);
	while (q.length) {
		void *k = g_queue_pop_head(&q);
		g_tree_remove(t, k);
	}
}


int rtpe_tree_find_first_cmp(void *, void *, void *);
int rtpe_tree_find_all_cmp(void *, void *, void *);

struct rtpe_g_tree_find_helper {
	GEqualFunc func;
	void *data;
	union {
		GQueue *out_q;
		void *out_p;
	};
};

INLINE void *g_tree_find_first(GTree *t, GEqualFunc f, void *data) {
	struct rtpe_g_tree_find_helper h = {
		.func = f,
		.data = data,
	};
	g_tree_foreach(t, rtpe_tree_find_first_cmp, &h);
	return h.out_p;
}
INLINE void g_tree_find_all(GQueue *out, GTree *t, GEqualFunc f, void *data) {
	struct rtpe_g_tree_find_helper h = {
		.func = f,
		.data = data,
		.out_q = out,
	};
	g_tree_foreach(t, rtpe_tree_find_all_cmp, &h);
}
INLINE void g_tree_get_values(GQueue *out, GTree *t) {
	g_tree_find_all(out, t, NULL, NULL);
}
INLINE void g_tree_find_remove_all(GQueue *out, GTree *t) {
	GList *l;
	g_queue_init(out);
	g_tree_find_all(out, t, NULL, NULL);
	for (l = out->head; l; l = l->next)
		g_tree_remove(t, l->data);
}
INLINE void g_tree_insert_coll(GTree *t, gpointer key, gpointer val, void (*cb)(gpointer, gpointer)) {
	gpointer old = g_tree_lookup(t, key);
	if (old)
		cb(old, val);
	g_tree_insert(t, key, val);
}
INLINE void g_tree_add_all(GTree *t, GQueue *q, void (*cb)(gpointer, gpointer)) {
	GList *l;
	for (l = q->head; l; l = l->next)
		g_tree_insert_coll(t, l->data, l->data, cb);
	g_queue_clear(q);
}


#if !GLIB_CHECK_VERSION(2,68,0)
# define __g_memdup(a,b) g_memdup(a,b)
#else
# define __g_memdup(a,b) g_memdup2(a,b)
#endif

#if !GLIB_CHECK_VERSION(2,58,0)
INLINE gboolean g_hash_table_steal_extended(GHashTable *ht, gconstpointer lookup, gpointer *ret_key,
		gpointer *ret_val)
{
	gboolean found = g_hash_table_lookup_extended(ht, lookup, ret_key, ret_val);
	if (!found)
		return false;
	g_hash_table_steal(ht, lookup);
	return true;
}
#endif



/*** MISC ***/

INLINE long unsigned int ssl_random(void) {
	long unsigned int ret;
	random_string((void *) &ret, sizeof(ret));
	return ret;
}


INLINE int rlim(int res, rlim_t val) {
	struct rlimit rlim;

	ZERO(rlim);
	rlim.rlim_cur = rlim.rlim_max = val;
	return setrlimit(res, &rlim);
}

#if defined(__GLIBC__) && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 30))
INLINE pid_t gettid(void) {
	return syscall(SYS_gettid);
}
#endif

INLINE unsigned int int64_hash(const uint64_t *s) {
	return g_int64_hash(s);
}
INLINE gboolean int64_eq(const uint64_t *a, const uint64_t *b) {
	return *a == *b;
}



/*** TAINT FUNCTIONS ***/

#if HAS_ATTR(__error__)
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
taint_func(srandom, "use rtpe_ssl_init() instead");


/*** ATOMIC64 ***/

typedef struct {
	uint64_t a;
} atomic64;

INLINE uint64_t atomic64_get(const atomic64 *u) {
	return __atomic_load_n(&u->a, __ATOMIC_SEQ_CST);
}
INLINE uint64_t atomic64_get_na(const atomic64 *u) {
	return __atomic_load_n(&u->a, __ATOMIC_RELAXED);
}
INLINE void atomic64_set(atomic64 *u, uint64_t a) {
	__atomic_store_n(&u->a, a, __ATOMIC_SEQ_CST);
}
INLINE gboolean atomic64_set_if(atomic64 *u, uint64_t a, uint64_t i) {
	return __atomic_compare_exchange_n(&u->a, &i, a, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
INLINE void atomic64_set_na(atomic64 *u, uint64_t a) {
	__atomic_store_n(&u->a, a, __ATOMIC_RELAXED);
}
INLINE uint64_t atomic64_add(atomic64 *u, uint64_t a) {
	return __atomic_fetch_add(&u->a, a, __ATOMIC_SEQ_CST);
}
INLINE uint64_t atomic64_add_na(atomic64 *u, uint64_t a) {
	return __atomic_fetch_add(&u->a, a, __ATOMIC_RELAXED);
}
INLINE uint64_t atomic64_get_set(atomic64 *u, uint64_t a) {
	uint64_t old;
	do {
		old = atomic64_get(u);
		if (__atomic_compare_exchange_n(&u->a, &old, a, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
			return old;
	} while (1);
}
INLINE uint64_t atomic64_or(atomic64 *u, uint64_t a) {
	return __atomic_fetch_or(&u->a, a, __ATOMIC_SEQ_CST);
}
INLINE uint64_t atomic64_and(atomic64 *u, uint64_t a) {
	return __atomic_fetch_and(&u->a, a, __ATOMIC_SEQ_CST);
}

INLINE uint64_t atomic64_inc(atomic64 *u) {
	return atomic64_add(u, 1);
}
INLINE uint64_t atomic64_inc_na(atomic64 *u) {
	return atomic64_add_na(u, 1);
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
		uint64_t old = atomic64_get_na(min);
		if (old && old <= val)
			break;
		if (atomic64_set_if(min, val, old))
			break;
	} while (1);
}
INLINE void atomic64_max(atomic64 *max, uint64_t val) {
	do {
		uint64_t old = atomic64_get_na(max);
		if (old && old >= val)
			break;
		if (atomic64_set_if(max, val, old))
			break;
	} while (1);
}

INLINE void atomic64_calc_rate_from_diff(long long run_diff_us, uint64_t diff, atomic64 *rate_var) {
	atomic64_set_na(rate_var, run_diff_us ? diff * 1000000LL / run_diff_us : 0);
}
INLINE void atomic64_calc_rate(const atomic64 *ax_var, long long run_diff_us,
		atomic64 *intv_var, atomic64 *rate_var)
{
	uint64_t ax = atomic64_get_na(ax_var);
	uint64_t old_intv = atomic64_get_na(intv_var);
	atomic64_set_na(intv_var, ax);
	atomic64_calc_rate_from_diff(run_diff_us, ax - old_intv, rate_var);
}
INLINE void atomic64_calc_diff(const atomic64 *ax_var, atomic64 *intv_var, atomic64 *diff_var) {
	uint64_t ax = atomic64_get_na(ax_var);
	uint64_t old_intv = atomic64_get_na(intv_var);
	atomic64_set_na(intv_var, ax);
	atomic64_set_na(diff_var, ax - old_intv);
}
INLINE void atomic64_mina(atomic64 *min, atomic64 *inp) {
	atomic64_min(min, atomic64_get_na(inp));
}
INLINE void atomic64_maxa(atomic64 *max, atomic64 *inp) {
	atomic64_max(max, atomic64_get_na(inp));
}
INLINE double atomic64_div(const atomic64 *n, const atomic64 *d) {
	int64_t dd = atomic64_get_na(d);
	if (!dd)
		return 0.;
	return (double) atomic64_get_na(n) / (double) dd;
}

#define atomic_get_na(x) __atomic_load_n(x, __ATOMIC_RELAXED)
#define atomic_set_na(x,y) __atomic_store_n(x, y, __ATOMIC_RELAXED)
#define atomic_inc_na(x) __atomic_fetch_add(x, 1, __ATOMIC_RELAXED);


/*** ATOMIC BITFIELD OPERATIONS ***/

/* checks if at least one of the flags is set */
INLINE bool bf_isset(const atomic64 *u, const uint64_t f) {
	if ((atomic64_get(u) & f))
		return true;
	return false;
}
/* checks if all of the flags are set */
INLINE bool bf_areset(const atomic64 *u, const uint64_t f) {
	if ((atomic64_get(u) & f) == f)
		return true;
	return false;
}
/* returns true if at least one of the flags was set already */
INLINE bool bf_set(atomic64 *u, const uint64_t f) {
	return (atomic64_or(u, f) & f) ? true : false;
}
/* returns true if at least one of the flags was set */
INLINE bool bf_clear(atomic64 *u, const uint64_t f) {
	return (atomic64_and(u, ~f) & f) ? true : false;
}
INLINE void bf_set_clear(atomic64 *u, const uint64_t f, bool cond) {
	if (cond)
		bf_set(u, f);
	else
		bf_clear(u, f);
}
/* works only for single flags */
INLINE void bf_copy(atomic64 *u, const uint64_t f,
		const atomic64 *s, const uint64_t g)
{
	bf_set_clear(u, f, bf_isset(s, g));
}
/* works for multiple flags */
INLINE void bf_copy_same(atomic64 *u, const atomic64 *s, const uint64_t g) {
	unsigned int old, set, clear;
	old = atomic64_get(s);
	set = old & g;
	clear = ~old & g;
	bf_set(u, set);
	bf_clear(u, clear);
}


#endif
