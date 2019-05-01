TARGET=		rtpengine-recording

CFLAGS=		-g -Wall -Wstrict-prototypes -pthread -I. -I../lib/ -I../kernel-module/
CFLAGS+=	-std=c99 -fno-strict-aliasing
CFLAGS+=	-D_GNU_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE
CFLAGS+=	$(shell pkg-config --cflags glib-2.0)
CFLAGS+=	$(shell pkg-config --cflags gthread-2.0)
CFLAGS+=	$(shell pkg-config --cflags libavcodec)
CFLAGS+=	$(shell pkg-config --cflags libavformat)
CFLAGS+=	$(shell pkg-config --cflags libavutil)
CFLAGS+=	$(shell pkg-config --cflags libswresample)
CFLAGS+=	$(shell pkg-config --cflags libavfilter)
CFLAGS+=	$(shell mysql_config --cflags)
CFLAGS+=	$(shell pkg-config --cflags openssl)

LDLIBS=		-lm
LDLIBS+=	$(shell pkg-config --libs glib-2.0)
LDLIBS+=	$(shell pkg-config --libs gthread-2.0)
LDLIBS+=	$(shell pkg-config --libs libavcodec)
LDLIBS+=	$(shell pkg-config --libs libavformat)
LDLIBS+=	$(shell pkg-config --libs libavutil)
LDLIBS+=	$(shell pkg-config --libs libswresample)
LDLIBS+=	$(shell pkg-config --libs libavfilter)
LDLIBS+=	$(shell mysql_config --libs)
LDLIBS+=	$(shell pkg-config --libs openssl)

SRCS=		epoll.c garbage.c inotify.c main.c metafile.c stream.c recaux.c packet.c \
		decoder.c output.c mix.c db.c log.c forward.c tag.c poller.c
LIBSRCS=	loglib.c auxlib.c rtplib.c codeclib.c resample.c str.c socket.c streambuf.c ssllib.c \
		dtmflib.c
OBJS=		$(SRCS:.c=.o) $(LIBSRCS:.c=.o)

include ../lib/common.Makefile

include		.depend
