TARGET=		rtpengine-recording

export top_srcdir = ..

include ../lib/deps.Makefile

ifeq ($(origin CFLAGS),undefined)
CFLAGS?=	-g -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wstrict-prototypes -Werror=return-type \
		-Wshadow
else
CFLAGS:=	$(CFLAGS)
endif
CFLAGS+=	-pthread
CFLAGS+=	-std=c11
CFLAGS+=	-I. -I../lib/ -I../kernel-module/
CFLAGS+=	-D_GNU_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE
CFLAGS+=	$(CFLAGS_LIBPCRE)
CFLAGS+=	$(CFLAGS_GLIB)
CFLAGS+=	$(CFLAGS_JSON_GLIB)
CFLAGS+=	$(CFLAGS_GTHREAD)
CFLAGS+=	$(CFLAGS_LIBAVCODEC)
CFLAGS+=	$(CFLAGS_LIBAVFORMAT)
CFLAGS+=	$(CFLAGS_LIBAVUTIL)
CFLAGS+=	$(CFLAGS_LIBSWRESAMPLE)
CFLAGS+=	$(CFLAGS_LIBAVFILTER)
CFLAGS+=	$(CFLAGS_OPUS)
CFLAGS+=	$(CFLAGS_MYSQL)
CFLAGS+=	$(CFLAGS_OPENSSL)
CFLAGS+=	$(CFLAGS_LIBCURL)

LDLIBS:=	-lm -ldl
LDLIBS+=	$(LDLIBS_GLIB)
LDLIBS+=	$(LDLIBS_JSON_GLIB)
LDLIBS+=	$(LDLIBS_GTHREAD)
LDLIBS+=	$(LDLIBS_LIBAVCODEC)
LDLIBS+=	$(LDLIBS_LIBAVFORMAT)
LDLIBS+=	$(LDLIBS_LIBAVUTIL)
LDLIBS+=	$(LDLIBS_LIBSWRESAMPLE)
LDLIBS+=	$(LDLIBS_LIBAVFILTER)
LDLIBS+=	$(LDLIBS_OPUS)
LDLIBS+=	$(LDLIBS_MYSQL)
LDLIBS+=	$(LDLIBS_OPENSSL)
LDLIBS+=	$(LDLIBS_LIBCURL)

CFLAGS+=	$(CFLAGS_BCG729)
LDLIBS+=	$(LDLIBS_BCG729)

CFLAGS+=	-DCUSTOM_POLLER

SRCS=		epoll.c garbage.c inotify.c main.c metafile.c stream.c recaux.c packet.c \
		decoder.c output.c mix.c db.c log.c forward.c tag.c custom_poller.c notify.c tls_send.c
LIBSRCS=	loglib.c auxlib.c rtplib.c codeclib.strhash.c resample.c str.c socket.c streambuf.c ssllib.c \
		dtmflib.c bufferpool.c bencode.c
LIBASM=		mvr2s_x64_avx2.S mvr2s_x64_avx512.S mix_in_x64_avx2.S mix_in_x64_avx512bw.S mix_in_x64_sse2.S

MDS=		rtpengine-recording.ronn
MANS=		$(MDS:.ronn=.8)

include ../lib/common.Makefile

install: $(TARGET) $(MANS)
	install -m 0755 -D $(TARGET) $(DESTDIR)/usr/bin/$(TARGET)
	install -m 0644 -D $(TARGET).8 $(DESTDIR)/usr/share/man/man8/$(TARGET).8
