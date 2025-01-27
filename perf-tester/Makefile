TARGET = rtpengine-perftest

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
CFLAGS += -DPCRE2_CODE_UNIT_WIDTH=8
CFLAGS += -DFIXTURES_PATH="\"$(FIXTURES_PATH)\""
CFLAGS += $(shell pkg-config --cflags glib-2.0)
CFLAGS += $(shell pkg-config --cflags json-glib-1.0)
CFLAGS += $(shell pkg-config --cflags gthread-2.0)
CFLAGS += -D_GNU_SOURCE
CFLAGS += $(shell pkg-config --cflags libavcodec)
CFLAGS += $(shell pkg-config --cflags libavformat)
CFLAGS += $(shell pkg-config --cflags libavutil)
CFLAGS += $(shell pkg-config --cflags libswresample)
CFLAGS += $(shell pkg-config --cflags libavfilter)
CFLAGS += $(shell pkg-config --cflags spandsp)
CFLAGS += $(shell pkg-config --cflags opus)
CFLAGS += $(shell pkg-config --cflags ncursesw)
CFLAGS += -DWITH_TRANSCODING
CFLAGS += $(shell pkg-config --cflags openssl)

LDLIBS := -lm -ldl
LDLIBS += $(shell pkg-config --libs glib-2.0)
LDLIBS += $(shell pkg-config --libs json-glib-1.0)
LDLIBS += $(shell pkg-config --libs gthread-2.0)
LDLIBS += $(shell pkg-config --libs libavcodec)
LDLIBS += $(shell pkg-config --libs libavformat)
LDLIBS += $(shell pkg-config --libs libavutil)
LDLIBS += $(shell pkg-config --libs libswresample)
LDLIBS += $(shell pkg-config --libs libavfilter)
LDLIBS += $(shell pkg-config --libs spandsp)
LDLIBS += $(shell pkg-config --libs opus)
LDLIBS += $(shell pkg-config --libs ncursesw)
LDLIBS += $(shell pkg-config --libs openssl)

include ../lib/g729.Makefile
include ../lib/codec-chain.Makefile

SRCS = main.c log.c
LIBSRCS = codeclib.strhash.c loglib.c auxlib.c resample.c str.c dtmflib.c rtplib.c poller.c ssllib.c bufferpool.c \
	  bencode.c
LIBASM = mvr2s_x64_avx2.S mvr2s_x64_avx512.S

OBJS = $(SRCS:.c=.o) $(LIBSRCS:.c=.o) $(LIBASM:.S=.o)

include ../lib/common.Makefile

main.o: fix_frame_channel_layout.h

install: $(TARGET)
	install -m 0755 -D $(TARGET) $(DESTDIR)/usr/bin/$(TARGET)
