TARGET=		unit-tests

CFLAGS=		-g -Wall -pthread -fno-strict-aliasing
CFLAGS+=	-std=c99
CFLAGS+=	$(shell pkg-config --cflags glib-2.0)
CFLAGS+=	$(shell pkg-config --cflags gthread-2.0)
CFLAGS+=	$(shell pkg-config --cflags openssl)
CFLAGS+=	-I. -I../lib/
CFLAGS+=	-D_GNU_SOURCE

LDFLAGS+=	$(shell pkg-config --libs glib-2.0)
LDFLAGS+=	$(shell pkg-config --libs gthread-2.0)
LDFLAGS+=       $(shell pkg-config --libs libcrypto)
LDFLAGS+=	$(shell pkg-config --libs openssl)

SRCS=		bitstr-test.c
LIBSRCS=	loglib.c auxlib.c str.c
OBJS=		$(SRCS:.c=.o) $(LIBSRCS:.c=.o)

include ../lib/common.Makefile

include		.depend

.PHONY:		unit-tests

TESTS=		bitstr-test

ADD_CLEAN=	$(TESTS)

unit-tests:	$(TESTS)
	for x in $(TESTS); do echo testing: $$x; ./$$x || exit 1; done

bitstr-test:	bitstr-test.o
