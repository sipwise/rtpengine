#ifndef __BUFFER_H__
#define __BUFFER_H__



#include <sys/types.h>
#include <time.h>
#include <glib.h>
#include <stdarg.h>

#include "compat.h"
#include "str.h"



struct poller;



struct streambuf {
	GString		*buf;
	int		fd;
	struct poller	*poller;
	time_t		active;
};



struct streambuf *streambuf_new(struct poller *, int);
void streambuf_destroy(struct streambuf *);
int streambuf_writeable(struct streambuf *);
int streambuf_readable(struct streambuf *);
char *streambuf_getline(struct streambuf *);
unsigned int streambuf_bufsize(struct streambuf *);
void streambuf_printf(struct streambuf *, const char *, ...) __attribute__ ((format (printf, 2, 3)));
void streambuf_vprintf(struct streambuf *, const char *, va_list);
void streambuf_write(struct streambuf *, const char *, unsigned int);
INLINE void streambuf_write_str(struct streambuf *b, str *s) {
	streambuf_write(b, s->s, s->len);
}


#endif
