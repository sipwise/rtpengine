LIBREDISDIR=	libhiredis-v0.10.0-3-gdf203bc

CC=		gcc
CFLAGS=		-g -Wall `pkg-config --cflags glib-2.0` `pcre-config --cflags`
CFLAGS+=	-I/lib/modules/`uname -r`/build/include/ -I../kernel-module/
CFLAGS+=	-D_GNU_SOURCE
#CFLAGS+=	-O2
CFLAGS+=	-I$(LIBREDISDIR)
LDFLAGS=	`pkg-config --libs glib-2.0` `pcre-config --libs`
LDFLAGS+=	-L$(LIBREDISDIR) -lhiredis

SRCS=		main.c kernel.c poller.c aux.c control.c streambuf.c call.c control_udp.c

OBJS=		$(SRCS:.c=.o)


.PHONY:		all dep clean tests

all:
	make -C $(LIBREDISDIR)
	make mediaproxy-ng

tests:
	make aux-test poller-test

dep:		.depend

clean:
	rm -f $(OBJS) mediaproxy-ng aux-test poller-test aux-test.o poller-test.o .depend build_time.h core
	make -C $(LIBREDISDIR) clean

.depend:	$(SRCS) Makefile build_time.h
	$(CC) $(CFLAGS) -M $(SRCS) | sed -e 's/:/ .depend:/' > .depend

build_time.h:	$(SRCS) Makefile
	date +"#define BUILD_TIME \"%Y-%m-%d %H:%M:%S\"" > build_time.h

mediaproxy-ng:	$(OBJS) .depend build_time.h
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

aux-test:	aux.o aux-test.o .depend build_time.h
	$(CC) $(CFLAGS) -o $@ aux-test.o aux.o $(LDFLAGS)

poller-test:	poller.o poller-test.o aux.o .depend build_time.h
	$(CC) $(CFLAGS) -o $@ poller-test.o poller.o aux.o $(LDFLAGS)


include		.depend
