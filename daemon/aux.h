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

#define NONBLOCK(x)		fcntl(x, F_SETFL, O_NONBLOCK)
#define REUSEADDR(x)		do { int ONE = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(ONE)); } while (0)

#define BIT_ARRAY_DECLARE(name, size)	int name[((size) + sizeof(int) * 8 - 1) / (sizeof(int) * 8)]
#define BIT_ARRAY_SET(name, bit)	name[(bit) / (sizeof(int) * 8)] |= 1 << ((bit) % (sizeof(int) * 8))
#define BIT_ARRAY_CLEAR(name, bit)	name[(bit) / (sizeof(int) * 8)] &= ~(1 << ((bit) % (sizeof(int) * 8)))
#define BIT_ARRAY_ISSET(name, bit)	(name[(bit) / (sizeof(int) * 8)] & (1 << ((bit) % (sizeof(int) * 8))))




typedef int (*parse_func)(char **, void **, void *);

int mybsearch(void *, unsigned int, unsigned int, void *, unsigned int, unsigned int, int);
GList *g_list_link(GList *, GList *);
GQueue *pcre_multi_match(pcre **, pcre_extra **, const char *, const char *, unsigned int, parse_func, void *);
void strmove(char **, char **);
void strdupfree(char **, const char *);


#if !GLIB_CHECK_VERSION(2,14,0)
void g_string_vprintf(GString *string, const gchar *format, va_list args);
#endif


static inline void uuid_str_generate(char *s) {
	uuid_t uuid;
	uuid_generate(uuid);
	uuid_unparse(uuid, s);
}



#endif
