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



#if 0 && defined(__DEBUG)
#define __THREAD_DEBUG 1
#endif




#define OFFSET_OF(t,e)		((unsigned int) (unsigned long) &(((t *) 0)->e))
#define ZERO(x)			memset(&(x), 0, sizeof(x))

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

#define BIT_ARRAY_DECLARE(name, size)	unsigned long name[((size) + sizeof(long) * 8 - 1) / (sizeof(long) * 8)]

#define UINT64F			"%" G_GUINT64_FORMAT




typedef int (*parse_func)(char **, void **, void *);

GList *g_list_link(GList *, GList *);
int pcre_multi_match(pcre *, pcre_extra *, const char *, unsigned int, parse_func, void *, GQueue *);
INLINE void strmove(char **, char **);
INLINE void strdupfree(char **, const char *);


#if !GLIB_CHECK_VERSION(2,14,0)
#define G_QUEUE_INIT { NULL, NULL, 0 }
void g_string_vprintf(GString *string, const gchar *format, va_list args);
void g_queue_clear(GQueue *);
#endif

#if !GLIB_CHECK_VERSION(2,32,0)
INLINE int g_hash_table_contains(GHashTable *h, const void *k) {
	return g_hash_table_lookup(h, k) ? 1 : 0;
}
#endif

INLINE void g_queue_move(GQueue *dst, GQueue *src) {
	GList *l;
	while ((l = g_queue_pop_head_link(src)))
		g_queue_push_tail_link(dst, l);
}
INLINE void g_queue_truncate(GQueue *q, unsigned int len) {
	while (q->length > len)
		g_queue_pop_tail(q);
}


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


INLINE void nonblock(int fd) {
	fcntl(fd, F_SETFL, O_NONBLOCK);
}
INLINE void reuseaddr(int fd) {
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
}
INLINE void ipv6only(int fd, int yn) {
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yn, sizeof(yn));
}

INLINE unsigned long bit_array_isset(unsigned long *name, unsigned int bit) {
	return name[(bit) / (sizeof(long) * 8)] & (1UL << ((bit) % (sizeof(long) * 8)));
}

INLINE void bit_array_set(unsigned long *name, unsigned int bit) {
	name[(bit) / (sizeof(long) * 8)] |= 1UL << ((bit) % (sizeof(long) * 8));
}

INLINE void bit_array_clear(unsigned long *name, unsigned int bit) {
	name[(bit) / (sizeof(long) * 8)] &= ~(1UL << ((bit) % (sizeof(long) * 8)));
}

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

INLINE void in4_to_6(struct in6_addr *o, u_int32_t ip) {
	o->s6_addr32[0] = 0;
	o->s6_addr32[1] = 0;
	o->s6_addr32[2] = htonl(0xffff);
	o->s6_addr32[3] = ip;
}

INLINE void smart_ntop(char *o, struct in6_addr *a, size_t len) {
	const char *r;

	if (IN6_IS_ADDR_V4MAPPED(a))
		r = inet_ntop(AF_INET, &(a->s6_addr32[3]), o, len);
	else
		r = inet_ntop(AF_INET6, a, o, len);

	if (!r)
		*o = '\0';
}

INLINE char *smart_ntop_p(char *o, struct in6_addr *a, size_t len) {
	int l;

	if (IN6_IS_ADDR_V4MAPPED(a)) {
		if (inet_ntop(AF_INET, &(a->s6_addr32[3]), o, len))
			return o + strlen(o);
		*o = '\0';
		return NULL;
	}
	else {
		*o = '[';
		if (!inet_ntop(AF_INET6, a, o+1, len-2)) {
			*o = '\0';
			return NULL;
		}
		l = strlen(o);
		o[l] = ']';
		o[l+1] = '\0';
		return o + (l + 1);
	}
}

INLINE void smart_ntop_port(char *o, struct sockaddr_in6 *a, size_t len) {
	char *e;

	e = smart_ntop_p(o, &a->sin6_addr, len);
	if (!e)
		return;
	if (len - (e - o) < 7)
		return;
	sprintf(e, ":%hu", ntohs(a->sin6_port));
}

INLINE int smart_pton(int af, char *src, void *dst) {
	char *p;
	int ret;

	if (af == AF_INET6) {
		if (src[0] == '[' && (p = strchr(src, ']'))) {
			*p = '\0';
			ret = inet_pton(af, src+1, dst);
			*p = ']';
			return ret;
		}
	}
	return inet_pton(af, src, dst);
}

INLINE int strmemcmp(const void *mem, int len, const char *str) {
	int l = strlen(str);
	if (l < len)
		return -1;
	if (l > len)
		return 1;
	return memcmp(mem, str, len);
}

/* XXX replace with better source of randomness */
INLINE void random_string(unsigned char *buf, int len) {
	while (len--)
		*buf++ = random() % 0x100;
}



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
#define cond_signal(c) __debug_cond_signal(c, __FILE__, __LINE__)
#define cond_broadcast(c) __debug_cond_broadcast(c, __FILE__, __LINE__)
#define COND_STATIC_INIT PTHREAD_COND_INITIALIZER

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
#define __debug_cond_signal(c, F, L) pthread_cond_signal(c)
#define __debug_cond_broadcast(c, F, L) pthread_cond_broadcast(c)

#else


#include "log.h"



INLINE int __debug_mutex_init(mutex_t *m, const char *file, unsigned int line) {
	mylog(LOG_DEBUG, "mutex_init(%p) at %s:%u", m, file, line);
	return pthread_mutex_init(m, NULL);
}
INLINE int __debug_mutex_destroy(mutex_t *m, const char *file, unsigned int line) {
	mylog(LOG_DEBUG, "mutex_destroy(%p) at %s:%u", m, file, line);
	return pthread_mutex_destroy(m);
}
INLINE int __debug_mutex_lock(mutex_t *m, const char *file, unsigned int line) {
	int ret;
	mylog(LOG_DEBUG, "mutex_lock(%p) at %s:%u ...", m, file, line);
	ret = pthread_mutex_lock(m);
	mylog(LOG_DEBUG, "mutex_lock(%p) at %s:%u returning %i", m, file, line, ret);
	return ret;
}
INLINE int __debug_mutex_trylock(mutex_t *m, const char *file, unsigned int line) {
	int ret;
	mylog(LOG_DEBUG, "mutex_trylock(%p) at %s:%u ...", m, file, line);
	ret = pthread_mutex_trylock(m);
	mylog(LOG_DEBUG, "mutex_trylock(%p) at %s:%u returning %i", m, file, line, ret);
	return ret;
}
INLINE int __debug_mutex_unlock(mutex_t *m, const char *file, unsigned int line) {
	mylog(LOG_DEBUG, "mutex_unlock(%p) at %s:%u", m, file, line);
	return pthread_mutex_unlock(m);
}

INLINE int __debug_rwlock_init(rwlock_t *m, const char *file, unsigned int line) {
	mylog(LOG_DEBUG, "rwlock_init(%p) at %s:%u", m, file, line);
	return pthread_rwlock_init(m, NULL);
}
INLINE int __debug_rwlock_destroy(rwlock_t *m, const char *file, unsigned int line) {
	mylog(LOG_DEBUG, "rwlock_destroy(%p) at %s:%u", m, file, line);
	return pthread_rwlock_destroy(m);
}
INLINE int __debug_rwlock_lock_r(rwlock_t *m, const char *file, unsigned int line) {
	int ret;
	mylog(LOG_DEBUG, "rwlock_lock_r(%p) at %s:%u ...", m, file, line);
	ret = pthread_rwlock_rdlock(m);
	mylog(LOG_DEBUG, "rwlock_lock_r(%p) at %s:%u returning %i", m, file, line, ret);
	return ret;
}
INLINE int __debug_rwlock_lock_w(rwlock_t *m, const char *file, unsigned int line) {
	int ret;
	mylog(LOG_DEBUG, "rwlock_lock_w(%p) at %s:%u ...", m, file, line);
	ret = pthread_rwlock_wrlock(m);
	mylog(LOG_DEBUG, "rwlock_lock_w(%p) at %s:%u returning %i", m, file, line, ret);
	return ret;
}
INLINE int __debug_rwlock_unlock_r(rwlock_t *m, const char *file, unsigned int line) {
	mylog(LOG_DEBUG, "rwlock_unlock_r(%p) at %s:%u", m, file, line);
	return pthread_rwlock_unlock(m);
}
INLINE int __debug_rwlock_unlock_w(rwlock_t *m, const char *file, unsigned int line) {
	mylog(LOG_DEBUG, "rwlock_unlock_w(%p) at %s:%u", m, file, line);
	return pthread_rwlock_unlock(m);
}

#define __debug_cond_init(c, F, L) pthread_cond_init(c, NULL)
#define __debug_cond_wait(c, m, F, L) pthread_cond_wait(c,m)
#define __debug_cond_signal(c, F, L) pthread_cond_signal(c)
#define __debug_cond_broadcast(c, F, L) pthread_cond_broadcast(c)

#endif



void threads_join_all(int);
void thread_create_detach(void (*)(void *), void *);



INLINE int rlim(int res, rlim_t val) {
	struct rlimit rlim;

	ZERO(rlim);
	rlim.rlim_cur = rlim.rlim_max = val;
	return setrlimit(res, &rlim);
}

INLINE int is_addr_unspecified(const struct in6_addr *a) {
	if (a->s6_addr32[0])
		return 0;
	if (a->s6_addr32[1])
		return 0;
	if (a->s6_addr32[3])
		return 0;
	if (a->s6_addr32[2] == 0 || a->s6_addr32[2] == htonl(0xffff))
		return 1;
	return 0;
}

/* checks if at least one of the flags is set */
INLINE int bf_isset(const unsigned int *u, unsigned int f) {
	if ((*u & f))
		return -1;
	return 0;
}
INLINE void bf_set(unsigned int *u, unsigned int f) {
	*u |= f;
}
INLINE void bf_clear(unsigned int *u, unsigned int f) {
	*u &= ~f;
}
INLINE void bf_xset(unsigned int *u, unsigned int f, int cond) {
	bf_clear(u, f);
	bf_set(u, cond ? f : 0);
}
/* works only for single flags */
INLINE void bf_copy(unsigned int *u, unsigned int f, const unsigned int *s, unsigned int g) {
	/* a good compiler will optimize out the calls to log2() */
	*u &= ~f;
	if (f >= g)
		*u |= (*s & g) << (int) (log2(f) - log2(g));
	else
		*u |= (*s & g) >> (int) (log2(g) - log2(f));
}
/* works for multiple flags */
INLINE void bf_copy_same(unsigned int *u, const unsigned int *s, unsigned int g) {
	bf_copy(u, g, s, g);
}

#endif
