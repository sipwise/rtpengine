#ifndef __BUFFER_H__
#define __BUFFER_H__



#include <sys/types.h>
#include <time.h>
#include <glib.h>
#include <stdarg.h>

#include "compat.h"
#include "str.h"
#include "auxlib.h"



struct poller;



struct streambuf_funcs {
	ssize_t (*write)(void *, const void *, size_t);
	ssize_t (*read)(void *, void *, size_t);
};
struct streambuf {
	mutex_t		lock;
	GString		*buf;
	void		*fd_ptr;
	struct poller	*poller;
	time_t		active;
	int		eof;
	const struct streambuf_funcs
			*funcs;
};



struct streambuf *streambuf_new(struct poller *, int);
struct streambuf *streambuf_new_ptr(struct poller *, void *, const struct streambuf_funcs *);
void streambuf_destroy(struct streambuf *);
int streambuf_writeable(struct streambuf *);
int streambuf_readable(struct streambuf *);
char *streambuf_getline(struct streambuf *);
size_t streambuf_bufsize(struct streambuf *);
size_t streambuf_printf(struct streambuf *, const char *, ...) __attribute__ ((format (printf, 2, 3)));
size_t streambuf_vprintf(struct streambuf *, const char *, va_list);
void streambuf_write(struct streambuf *, const char *, unsigned int);
INLINE void streambuf_write_str(struct streambuf *b, str *s) {
	streambuf_write(b, s->s, s->len);
}


#endif
