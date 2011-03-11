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




#define OFFSET_OF(t,e)		((unsigned int) (unsigned long) &(((t *) 0)->e))
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof(*(x)))
#define ZERO(x)			memset(&(x), 0, sizeof(x))

#define IPF			"%u.%u.%u.%u"
#define IPP(x)			((unsigned char *) (&(x)))[0], ((unsigned char *) (&(x)))[1], ((unsigned char *) (&(x)))[2], ((unsigned char *) (&(x)))[3]
#define DF			IPF ":%u"
#define DP(x)			IPP((x).sin_addr.s_addr), ntohs((x).sin_port)

#define NONBLOCK(x)		fcntl(x, F_SETFL, O_NONBLOCK)
#define REUSEADDR(x)		do { int ONE = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(ONE)); } while (0)




typedef int (*parse_func)(char **, void **, void *);

int mybsearch(void *, unsigned int, unsigned int, void *, unsigned int, unsigned int, int);
GList *g_list_link(GList *, GList *);
GQueue *pcre_multi_match(pcre **, pcre_extra **, const char *, const char *, unsigned int, parse_func, void *);
void strmove(char **, char **);
void strdupfree(char **, const char *);


#if !GLIB_CHECK_VERSION(2,14,0)
void g_string_vprintf(GString *string, const gchar *format, va_list args);
#endif



#endif
