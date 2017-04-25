TARGET=		rtpengine-recording

CFLAGS=		-g -Wall -pthread -I. -I../lib/
CFLAGS+=	-std=c99
CFLAGS+=	-D_GNU_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE
CFLAGS+=	`pkg-config --cflags glib-2.0`
CFLAGS+=	`pkg-config --cflags gthread-2.0`
CFLAGS+=	`pkg-config --cflags libavcodec`
CFLAGS+=	`pkg-config --cflags libavformat`
CFLAGS+=	`pkg-config --cflags libavutil`
CFLAGS+=	`pkg-config --cflags libavresample`
CFLAGS+=	`pkg-config --cflags libavfilter`
CFLAGS+=	`mysql_config --cflags`

LDFLAGS=	-lm
LDFLAGS+=	`pkg-config --libs glib-2.0`
LDFLAGS+=	`pkg-config --libs gthread-2.0`
LDFLAGS+=	`pkg-config --libs libavcodec`
LDFLAGS+=	`pkg-config --libs libavformat`
LDFLAGS+=	`pkg-config --libs libavutil`
LDFLAGS+=	`pkg-config --libs libavresample`
LDFLAGS+=	`pkg-config --libs libavfilter`
LDFLAGS+=	`mysql_config --libs`

include ../lib/lib.Makefile

SRCS=		epoll.c garbage.c inotify.c main.c metafile.c stream.c recaux.c packet.c \
		decoder.c output.c mix.c resample.c db.c log.c
LIBSRCS=	loglib.c auxlib.c rtplib.c
OBJS=		$(SRCS:.c=.o) $(LIBSRCS:.c=.o)


.PHONY:		all dep clean debug install

all:
	$(MAKE) $(TARGET)

debug:
	$(MAKE) DBG=yes all

dep:		.depend

clean:
	rm -f $(OBJS) $(TARGET) $(LIBSRCS) .depend core core.*

.depend:	$(SRCS) $(LIBSRCS) Makefile
	$(CC) $(CFLAGS) -M $(SRCS) $(LIBSRCS) | sed -e 's/:/ .depend:/' > .depend

$(TARGET):	$(OBJS) .depend Makefile
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(OBJS):	Makefile

$(LIBSRCS):
		ln -fs ../lib/$@

install:

include		.depend
