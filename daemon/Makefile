REDIS=yes

CC=		gcc
CFLAGS=		-g -Wall `pkg-config --cflags glib-2.0` `pcre-config --cflags` -fno-strict-aliasing
CFLAGS+=	-I/lib/modules/`uname -r`/build/include/ -I../kernel-module/
CFLAGS+=	-D_GNU_SOURCE
CFLAGS+=	-DMEDIAPROXY_VERSION="\"$(shell dpkg-parsechangelog -l../debian/changelog | awk '/^Version: / {print $$2}')\""

ifneq ($(REDIS),yes)
CFLAGS+=	-DNO_REDIS=1
endif

ifeq ($(DBG),yes)
CFLAGS+=	-D__DEBUG=1
else
CFLAGS+=	-O2
endif

LDFLAGS=	`pkg-config --libs glib-2.0` `pcre-config --libs`

ifeq ($(REDIS),yes)
LDFLAGS+=	-lhiredis -luuid
endif

SRCS=		main.c kernel.c poller.c aux.c control.c streambuf.c call.c control_udp.c
ifeq ($(REDIS),yes)
SRCS+=		redis.c
endif

OBJS=		$(SRCS:.c=.o)


.PHONY:		all dep clean tests no-redis debug

all:
	$(MAKE) mediaproxy-ng

no-redis:
	$(MAKE) REDIS=no all

debug:
	$(MAKE) DBG=yes all

tests:
	$(MAKE) aux-test poller-test

dep:		.depend

clean:
	rm -f $(OBJS) mediaproxy-ng aux-test poller-test aux-test.o poller-test.o .depend core

.depend:	$(SRCS) Makefile
	$(CC) $(CFLAGS) -M $(SRCS) | sed -e 's/:/ .depend:/' > .depend

mediaproxy-ng:	$(OBJS) .depend
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

aux-test:	aux.o aux-test.o .depend
	$(CC) $(CFLAGS) -o $@ aux-test.o aux.o $(LDFLAGS)

poller-test:	poller.o poller-test.o aux.o .depend
	$(CC) $(CFLAGS) -o $@ poller-test.o poller.o aux.o $(LDFLAGS)


include		.depend
