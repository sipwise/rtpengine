#ifndef __BUFFER_H__
#define __BUFFER_H__



#include <sys/types.h>
#include <time.h>
#include <glib.h>



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
void streambuf_printf(struct streambuf *, char *, ...) __attribute__ ((format (printf, 2, 3)));
void streambuf_write(struct streambuf *, char *, unsigned int);


#endif
