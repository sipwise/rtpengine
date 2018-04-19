TARGET=		unit-tests

with_transcoding ?= yes

CFLAGS=		-g -Wall -pthread -fno-strict-aliasing
CFLAGS+=	-std=c99
CFLAGS+=	$(shell pkg-config --cflags glib-2.0)
CFLAGS+=	$(shell pkg-config --cflags gthread-2.0)
CFLAGS+=	$(shell pkg-config --cflags openssl)
CFLAGS+=	-I. -I../lib/
CFLAGS+=	-D_GNU_SOURCE
ifeq ($(with_transcoding),yes)
CFLAGS+=	$(shell pkg-config --cflags libavcodec)
CFLAGS+=	$(shell pkg-config --cflags libavformat)
CFLAGS+=	$(shell pkg-config --cflags libavutil)
CFLAGS+=	$(shell pkg-config --cflags libswresample)
CFLAGS+=	$(shell pkg-config --cflags libavfilter)
CFLAGS+=	-DWITH_TRANSCODING
else
CFLAGS+=	-DWITHOUT_CODECLIB
endif

LDFLAGS+=	$(shell pkg-config --libs glib-2.0)
LDFLAGS+=	$(shell pkg-config --libs gthread-2.0)
LDFLAGS+=       $(shell pkg-config --libs libcrypto)
LDFLAGS+=	$(shell pkg-config --libs openssl)
ifeq ($(with_transcoding),yes)
LDFLAGS+=	$(shell pkg-config --libs libavcodec)
LDFLAGS+=	$(shell pkg-config --libs libavformat)
LDFLAGS+=	$(shell pkg-config --libs libavutil)
LDFLAGS+=	$(shell pkg-config --libs libswresample)
LDFLAGS+=	$(shell pkg-config --libs libavfilter)
endif

SRCS=		bitstr-test.c amr-decode-test.c amr-encode-test.c
LIBSRCS=	loglib.c auxlib.c str.c rtplib.c
ifeq ($(with_transcoding),yes)
LIBSRCS+=	codeclib.c resample.c
endif
OBJS=		$(SRCS:.c=.o) $(LIBSRCS:.c=.o)

include ../lib/common.Makefile

include		.depend

.PHONY:		unit-tests

TESTS=		bitstr-test
ifeq ($(with_transcoding),yes)
TESTS+=		amr-decode-test amr-encode-test
endif

ADD_CLEAN=	$(TESTS)

unit-tests:	$(TESTS)
	for x in $(TESTS); do echo testing: $$x; ./$$x || exit 1; done

bitstr-test:	bitstr-test.o

amr-decode-test: amr-decode-test.o codeclib.o str.o auxlib.o resample.o rtplib.o loglib.o

amr-encode-test: amr-encode-test.o codeclib.o str.o auxlib.o resample.o rtplib.o loglib.o
