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




#define OFFSET_OF(t,e)		((unsigned int) (unsigned long) &(((t *) 0)->e))
#define ZERO(x)			memset(&(x), 0, sizeof(x))

#define IPF			"%u.%u.%u.%u"
#define IPP(x)			((unsigned char *) (&(x)))[0], ((unsigned char *) (&(x)))[1], ((unsigned char *) (&(x)))[2], ((unsigned char *) (&(x)))[3]
#define DF			IPF ":%u"
#define DP(x)			IPP((x).sin_addr.s_addr), ntohs((x).sin_port)
#define IP6F			"%x:%x:%x:%x:%x:%x:%x:%x"
#define IP6P(x)			ntohs(((u_int16_t *) (x))[0]), \
				ntohs(((u_int16_t *) (x))[1]), \
				ntohs(((u_int16_t *) (x))[2]), \
				ntohs(((u_int16_t *) (x))[3]), \
				ntohs(((u_int16_t *) (x))[4]), \
				ntohs(((u_int16_t *) (x))[5]), \
				ntohs(((u_int16_t *) (x))[6]), \
				ntohs(((u_int16_t *) (x))[7])
#define D6F			IP6F ":%u"
#define D6P(x)			IP6P((x).sin6_addr.s6_addr), ntohs((x).sin6_port)

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



#endif
