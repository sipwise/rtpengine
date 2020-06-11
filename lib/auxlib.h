#ifndef _AUXLIB_H_
#define _AUXLIB_H_

#include <glib.h>
#include <assert.h>
#include "compat.h"
#include <openssl/rand.h>
#include <pthread.h>


#define THREAD_BUF_SIZE		64
#define NUM_THREAD_BUFS		8


struct rtpengine_common_config {
	char *config_file;
	char *config_section;
	char *log_facility;
	volatile int log_level;
	int log_stderr;
	int no_log_timestamps;
	char *log_mark_prefix;
	char *log_mark_suffix;
	char *pidfile;
	int foreground;
};

extern struct rtpengine_common_config *rtpe_common_config_ptr;



/*** GLOBALS ***/

extern __thread struct timeval rtpe_now;
extern volatile int rtpe_shutdown;




/*** PROTOTYPES ***/

void daemonize(void);
void wpidfile(void);
void service_notify(const char *message);
void config_load_free(struct rtpengine_common_config *);
void config_load(int *argc, char ***argv, GOptionEntry *entries, const char *description,
		char *default_config, char *default_section,
		struct rtpengine_common_config *);

char *get_thread_buf(void);

unsigned int in6_addr_hash(const void *p);
int in6_addr_eq(const void *a, const void *b);
unsigned int uint32_hash(const void *p);
int uint32_eq(const void *a, const void *b);


/*** HELPER MACROS ***/

#define ZERO(x)			memset(&(x), 0, sizeof(x))

#define UINT64F			"%" G_GUINT64_FORMAT

void free_gbuf(char **);
void free_gvbuf(char ***);

#define AUTO_CLEANUP(decl, func)		decl __attribute__ ((__cleanup__(func)))
#define AUTO_CLEANUP_INIT(decl, func, val)	AUTO_CLEANUP(decl, func) = val
#define AUTO_CLEANUP_NULL(decl, func)		AUTO_CLEANUP_INIT(decl, func, 0)
#define AUTO_CLEANUP_GBUF(var)			AUTO_CLEANUP_NULL(char *var, free_gbuf)
#define AUTO_CLEANUP_GVBUF(var)			AUTO_CLEANUP_NULL(char **var, free_gvbuf)


/*** STRING HELPERS ***/

INLINE void random_string(unsigned char *buf, int len) {
	int ret = RAND_bytes(buf, len);
	assert(ret == 1);
	(void) ret;
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
#define rwlock_unlock_w(l) __debug_rwlock_unlock_w(l, __FILE__, __LINE__)

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
int timeval_cmp_ptr(const void *a, const void *b);

INLINE void timeval_lowest(struct timeval *l, const struct timeval *n) {
	if (!n->tv_sec)
		return;
	if (!l->tv_sec || timeval_cmp(l, n) == 1)
		*l = *n;
}
INLINE double ntp_ts_to_double(u_int32_t whole, u_int32_t frac) {
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


#endif
