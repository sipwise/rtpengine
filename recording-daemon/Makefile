TARGET=		rtpengine-recording

CC?=gcc
CFLAGS=		-g -Wall -pthread -I. -I../lib/
CFLAGS+=	-std=c99
CFLAGS+=	-D_GNU_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE
CFLAGS+=	`pkg-config --cflags glib-2.0`
CFLAGS+=	`pkg-config --cflags gthread-2.0`
CFLAGS+=	`pcre-config --cflags`
CFLAGS+=	`pkg-config --cflags libavcodec`
CFLAGS+=	`pkg-config --cflags libavformat`
CFLAGS+=	`pkg-config --cflags libavutil`

ifeq ($(DBG),yes)
CFLAGS+=	-D__DEBUG=1
else
CFLAGS+=	-O3
endif

LDFLAGS=	-lm
LDFLAGS+=	`pkg-config --libs glib-2.0`
LDFLAGS+=	`pkg-config --libs gthread-2.0`
LDFLAGS+=	`pcre-config --libs`
LDFLAGS+=	`pkg-config --libs libavcodec`
LDFLAGS+=	`pkg-config --libs libavformat`
LDFLAGS+=	`pkg-config --libs libavutil`

ifneq ($(DBG),yes)
  DPKG_BLDFLGS=	$(shell which dpkg-buildflags 2>/dev/null)
  ifneq ($(DPKG_BLDFLGS),)
    # support http://wiki.debian.org/Hardening for >=wheezy
    CFLAGS+=	`dpkg-buildflags --get CFLAGS`
    CPPFLAGS+=	`dpkg-buildflags --get CPPFLAGS`
    LDFLAGS+=	`dpkg-buildflags --get LDFLAGS`
  endif
endif

SRCS=		epoll.c garbage.c inotify.c main.c metafile.c stream.c recaux.c rtplib.c packet.c \
		decoder.c
OBJS=		$(SRCS:.c=.o)


.PHONY:		all dep clean tests debug

all:
	$(MAKE) $(TARGET)

debug:
	$(MAKE) DBG=yes all

dep:		.depend

clean:
	rm -f $(OBJS) $(TARGET) .depend core core.*

.depend:	$(SRCS) Makefile
	$(CC) $(CFLAGS) -M $(SRCS) | sed -e 's/:/ .depend:/' > .depend

$(TARGET):	$(OBJS) .depend Makefile
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(OBJS):	Makefile


include		.depend
