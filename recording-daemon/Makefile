TARGET=		rtpengine-recording

CFLAGS=		-g -Wall -pthread -I. -I../lib/
CFLAGS+=	-std=c99
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

LDFLAGS=	-lm
LDFLAGS+=	$(shell pkg-config --libs glib-2.0)
LDFLAGS+=	$(shell pkg-config --libs gthread-2.0)
LDFLAGS+=	$(shell pkg-config --libs libavcodec)
LDFLAGS+=	$(shell pkg-config --libs libavformat)
LDFLAGS+=	$(shell pkg-config --libs libavutil)
LDFLAGS+=	$(shell pkg-config --libs libswresample)
LDFLAGS+=	$(shell pkg-config --libs libavfilter)
LDFLAGS+=	$(shell mysql_config --libs)
LDFLAGS+=	$(shell pkg-config --libs openssl)

SRCS=		epoll.c garbage.c inotify.c main.c metafile.c stream.c recaux.c packet.c \
		decoder.c output.c mix.c db.c log.c forward.c
LIBSRCS=	loglib.c auxlib.c rtplib.c codeclib.c resample.c str.c
OBJS=		$(SRCS:.c=.o) $(LIBSRCS:.c=.o)

include ../lib/common.Makefile

include		.depend
