TARGET=		rtpengine-recording

CFLAGS?=	-g -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wstrict-prototypes
CFLAGS+=	-pthread -I. -I../lib/ -I../kernel-module/
CFLAGS+=	-std=c99 -fno-strict-aliasing
CFLAGS+=	-D_GNU_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE
CFLAGS+=	$(shell pkg-config --cflags glib-2.0)
CFLAGS+=	$(shell pkg-config --cflags gthread-2.0)
CFLAGS+=	$(shell pkg-config --cflags libavcodec)
CFLAGS+=	$(shell pkg-config --cflags libavformat)
CFLAGS+=	$(shell pkg-config --cflags libavutil)
CFLAGS+=	$(shell pkg-config --cflags libswresample)
CFLAGS+=	$(shell pkg-config --cflags libavfilter)
CFLAGS+=	$(shell pkg-config --cflags opus)
CFLAGS+=	$(shell mysql_config --cflags)
CFLAGS+=	$(shell pkg-config --cflags openssl)
CFLAGS+=	$(shell pkg-config --cflags libcurl)

LDLIBS=		-lm -ldl
LDLIBS+=	$(shell pkg-config --libs glib-2.0)
LDLIBS+=	$(shell pkg-config --libs gthread-2.0)
LDLIBS+=	$(shell pkg-config --libs libavcodec)
LDLIBS+=	$(shell pkg-config --libs libavformat)
LDLIBS+=	$(shell pkg-config --libs libavutil)
LDLIBS+=	$(shell pkg-config --libs libswresample)
LDLIBS+=	$(shell pkg-config --libs libavfilter)
LDLIBS+=	$(shell pkg-config --libs opus)
LDLIBS+=	$(shell mysql_config --libs)
LDLIBS+=	$(shell pkg-config --libs openssl)
LDLIBS+=	$(shell pkg-config --libs libcurl)

include ../lib/g729.Makefile

SRCS=		epoll.c garbage.c inotify.c main.c metafile.c stream.c recaux.c packet.c \
		decoder.c output.c mix.c db.c log.c forward.c tag.c poller.c notify.c
LIBSRCS=	loglib.c auxlib.c rtplib.c codeclib.strhash.c resample.c str.c socket.c streambuf.c ssllib.c \
		dtmflib.c
OBJS=		$(SRCS:.c=.o) $(LIBSRCS:.c=.o)

PODS=		rtpengine-recording.pod
MANS=		$(PODS:.pod=.8)

include ../lib/common.Makefile

install: $(TARGET) $(MANS)
	install -m 0755 -D $(TARGET) $(DESTDIR)/usr/bin/$(TARGET)
	install -m 0644 -D $(TARGET).8 $(DESTDIR)/usr/share/man/man8/$(TARGET).8
