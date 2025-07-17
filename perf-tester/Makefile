TARGET = rtpengine-perftest

export top_srcdir = ..

include ../lib/deps.Makefile

FIXTURES_PATH ?= ../fixtures

ifeq ($(origin CFLAGS),undefined)
CFLAGS ?= -g -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wstrict-prototypes -Werror=return-type \
		-Wshadow
else
CFLAGS := $(CFLAGS)
endif

CFLAGS += -pthread
CFLAGS += -std=c11
CFLAGS += -I. -I../kernel-module/ -I../lib/
CFLAGS += -D_GNU_SOURCE
CFLAGS += -DFIXTURES_PATH="\"$(FIXTURES_PATH)\""
CFLAGS += -DWITH_TRANSCODING
CFLAGS += $(CFLAGS_LIBPCRE)
CFLAGS += $(CFLAGS_GLIB)
CFLAGS += $(CFLAGS_JSON_GLIB)
CFLAGS += $(CFLAGS_GTHREAD)
CFLAGS += $(CFLAGS_LIBAVCODEC)
CFLAGS += $(CFLAGS_LIBAVFORMAT)
CFLAGS += $(CFLAGS_LIBAVUTIL)
CFLAGS += $(CFLAGS_LIBSWRESAMPLE)
CFLAGS += $(CFLAGS_LIBAVFILTER)
CFLAGS += $(CFLAGS_SPANDSP)
CFLAGS += $(CFLAGS_OPUS)
CFLAGS += $(CFLAGS_NCURSESW)
CFLAGS += $(CFLAGS_OPENSSL)

LDLIBS := -lm -ldl
LDLIBS += $(LDLIBS_GLIB)
LDLIBS += $(LDLIBS_JSON_GLIB)
LDLIBS += $(LDLIBS_GTHREAD)
LDLIBS += $(LDLIBS_LIBAVCODEC)
LDLIBS += $(LDLIBS_LIBAVFORMAT)
LDLIBS += $(LDLIBS_LIBAVUTIL)
LDLIBS += $(LDLIBS_LIBSWRESAMPLE)
LDLIBS += $(LDLIBS_LIBAVFILTER)
LDLIBS += $(LDLIBS_SPANDSP)
LDLIBS += $(LDLIBS_OPUS)
LDLIBS += $(LDLIBS_NCURSESW)
LDLIBS += $(LDLIBS_OPENSSL)

CFLAGS += $(CFLAGS_BCG729)
LDLIBS += $(LDLIBS_BCG729)

CFLAGS += $(CFLAGS_CODEC_CHAIN)
LDLIBS += $(LDLIBS_CODEC_CHAIN)

SRCS = main.c log.c
LIBSRCS = codeclib.strhash.c loglib.c auxlib.c resample.c str.c dtmflib.c rtplib.c poller.c ssllib.c bufferpool.c \
	  bencode.c uring.c
LIBASM = mvr2s_x64_avx2.S mvr2s_x64_avx512.S

include ../lib/common.Makefile

main.o: ../lib/fix_frame_channel_layout.h

install: $(TARGET)
	install -m 0755 -D $(TARGET) $(DESTDIR)/usr/bin/$(TARGET)
