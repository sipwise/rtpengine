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
#include <uuid/uuid.h>
#include <arpa/inet.h>




#define OFFSET_OF(t,e)		((unsigned int) (unsigned long) &(((t *) 0)->e))
#define ZERO(x)			memset(&(x), 0, sizeof(x))

#define IPF			"%u.%u.%u.%u"
#define IPP(x)			((unsigned char *) (&(x)))[0], ((unsigned char *) (&(x)))[1], ((unsigned char *) (&(x)))[2], ((unsigned char *) (&(x)))[3]
#define DF			IPF ":%u"
#define DP(x)			IPP((x).sin_addr.s_addr), ntohs((x).sin_port)

#define BIT_ARRAY_DECLARE(name, size)	int name[((size) + sizeof(int) * 8 - 1) / (sizeof(int) * 8)]




typedef int (*parse_func)(char **, void **, void *);

int mybsearch(void *, unsigned int, unsigned int, void *, unsigned int, unsigned int, int);
GList *g_list_link(GList *, GList *);
GQueue *pcre_multi_match(pcre **, pcre_extra **, const char *, const char *, unsigned int, parse_func, void *);
void strmove(char **, char **);
void strdupfree(char **, const char *);


#if !GLIB_CHECK_VERSION(2,14,0)
#define G_QUEUE_INIT { NULL, NULL, 0 }
void g_string_vprintf(GString *string, const gchar *format, va_list args);
void g_queue_clear(GQueue *);
#endif


static inline void nonblock(int fd) {
	fcntl(fd, F_SETFL, O_NONBLOCK);
}

static inline void reuseaddr(int fd) {
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
}

static inline int bit_array_isset(int *name, unsigned int bit) {
	return name[(bit) / (sizeof(int) * 8)] & (1 << ((bit) % (sizeof(int) * 8)));
}

static inline void bit_array_set(int *name, unsigned int bit) {
	name[(bit) / (sizeof(int) * 8)] |= 1 << ((bit) % (sizeof(int) * 8));
}

static inline void bit_array_clear(int *name, unsigned int bit) {
	name[(bit) / (sizeof(int) * 8)] &= ~(1 << ((bit) % (sizeof(int) * 8)));
}

static inline char chrtoupper(char x) {
	return x & 0xdf;
}

static inline void uuid_str_generate(char *s) {
	uuid_t uuid;
	uuid_generate(uuid);
	uuid_unparse(uuid, s);
}

static inline void swap_ptrs(void *a, void *b) {
	void *t, **aa, **bb;
	aa = a;
	bb = b;
	t = *aa;
	*aa = *bb;
	*bb = t;
}

static inline void in4_to_6(struct in6_addr *o, u_int32_t ip) {
	o->s6_addr32[0] = 0;
	o->s6_addr32[1] = 0;
	o->s6_addr32[2] = htonl(0xffff);
	o->s6_addr32[3] = ip;
}

static inline void smart_ntop(char *o, struct in6_addr *a, size_t len) {
	if (IN6_IS_ADDR_V4MAPPED(a))
		inet_ntop(AF_INET, &(a->s6_addr32[3]), o, len);
	else
		inet_ntop(AF_INET6, a, o, len);
}



#endif
