CC=		gcc
CFLAGS=		-g -Wall -pthread -fno-strict-aliasing
CFLAGS+=	`pkg-config --cflags glib-2.0`
CFLAGS+=	`pkg-config --cflags gthread-2.0`
CFLAGS+=	`pcre-config --cflags`
CFLAGS+=	-I/lib/modules/`uname -r`/build/include/ -I../kernel-module/
CFLAGS+=	-D_GNU_SOURCE
CFLAGS+=	-DMEDIAPROXY_VERSION="\"$(shell dpkg-parsechangelog -l../debian/changelog | awk '/^Version: / {print $$2}')\""
CFLAGS+=	-DMP_PLUGIN_DIR="\"/usr/lib/mediaproxy-ng\""

ifeq ($(DBG),yes)
CFLAGS+=	-D__DEBUG=1
else
CFLAGS+=	-O2
endif

LDFLAGS=	-ldl -rdynamic
LDFLAGS+=	`pkg-config --libs glib-2.0`
LDFLAGS+=	`pkg-config --libs gthread-2.0`
LDFLAGS+=	`pcre-config --libs`
LDFLAGS+=	`xmlrpc-c-config client --libs`

SRCS=		main.c kernel.c poller.c aux.c control.c streambuf.c call.c control_udp.c redis.c
OBJS=		$(SRCS:.c=.o)


.PHONY:		all dep clean tests debug

all:
	$(MAKE) mediaproxy-ng

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


include		.depend
