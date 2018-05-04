TARGET=		unit-tests

with_transcoding ?= yes

CFLAGS=		-g -Wall -pthread -fno-strict-aliasing
CFLAGS+=	-std=c99
CFLAGS+=	$(shell pkg-config --cflags glib-2.0)
CFLAGS+=	$(shell pkg-config --cflags gthread-2.0)
CFLAGS+=	$(shell pkg-config --cflags openssl)
CFLAGS+=	-I. -I../lib/ -I../kernel-module/ -I../include/
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

LDLIBS+=	$(shell pkg-config --libs glib-2.0)
LDLIBS+=	$(shell pkg-config --libs gthread-2.0)
LDLIBS+=	$(shell pkg-config --libs libcrypto)
LDLIBS+=	$(shell pkg-config --libs openssl)
ifeq ($(with_transcoding),yes)
LDLIBS+=	$(shell pkg-config --libs libavcodec)
LDLIBS+=	$(shell pkg-config --libs libavformat)
LDLIBS+=	$(shell pkg-config --libs libavutil)
LDLIBS+=	$(shell pkg-config --libs libswresample)
LDLIBS+=	$(shell pkg-config --libs libavfilter)
endif

SRCS=		bitstr-test.c aes-crypt.c
ifeq ($(with_transcoding),yes)
SRCS+=		amr-decode-test.c amr-encode-test.c
endif
LIBSRCS=	loglib.c auxlib.c str.c rtplib.c
ifeq ($(with_transcoding),yes)
LIBSRCS+=	codeclib.c resample.c
endif
DAEMONSRCS=	crypto.c
OBJS=		$(SRCS:.c=.o) $(LIBSRCS:.c=.o) $(DAEMONSRCS:.c=.o)

COMMONOBJS=	str.o auxlib.o rtplib.o loglib.o

include ../lib/common.Makefile

include		.depend

.PHONY:		unit-tests

TESTS=		bitstr-test aes-crypt
ifeq ($(with_transcoding),yes)
TESTS+=		amr-decode-test amr-encode-test
endif

ADD_CLEAN=	$(TESTS)

unit-tests:	$(TESTS)
	for x in $(TESTS); do echo testing: $$x; ./$$x || exit 1; done

bitstr-test:	bitstr-test.o

amr-decode-test: amr-decode-test.o $(COMMONOBJS) codeclib.o resample.o

amr-encode-test: amr-encode-test.o $(COMMONOBJS) codeclib.o resample.o

aes-crypt:	aes-crypt.o $(COMMONOBJS) crypto.o
