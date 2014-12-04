CC=		gcc
CFLAGS=		-g -Wall -pthread -fno-strict-aliasing
CFLAGS+=	-std=c99
CFLAGS+=	`pkg-config --cflags glib-2.0`
CFLAGS+=	`pkg-config --cflags gthread-2.0`
CFLAGS+=	`pkg-config --cflags zlib`
CFLAGS+=	`pkg-config --cflags openssl`
CFLAGS+=	`pcre-config --cflags`
CFLAGS+=	-I../kernel-module/
CFLAGS+=	-D_GNU_SOURCE

ifeq ($(RTPENGINE_VERSION),)
  DPKG_PRSCHNGLG= $(shell which dpkg-parsechangelog 2>/dev/null)
  ifneq ($(DPKG_PRSCHNGLG),)
    DPKG_PRSCHNGLG=$(shell dpkg-parsechangelog -l../debian/changelog | awk '/^Version: / {print $$2}')
  endif
  GIT_BR_COMMIT=$(shell git branch --no-color --no-column -v 2> /dev/null | awk '/^\*/ {OFS="-"; print "git", $$2, $$3}')

  ifneq ($(DPKG_PRSCHNGLG),)
    RTPENGINE_VERSION+=$(DPKG_PRSCHNGLG)
  endif
  ifneq ($(GIT_BR_COMMIT),)
    RTPENGINE_VERSION+=$(GIT_BR_COMMIT)
  endif

  ifeq ($(RTPENGINE_VERSION),)
    RTPENGINE_VERSION+=undefined
  endif
endif
CFLAGS+=	-DRTPENGINE_VERSION="\"$(RTPENGINE_VERSION)\""

CFLAGS+=	-DMP_PLUGIN_DIR="\"/usr/lib/rtpengine\""

#CFLAGS+=	-DSRTCP_KEY_DERIVATION_RFC_COMPLIANCE

ifeq ($(DBG),yes)
CFLAGS+=	-D__DEBUG=1
else
CFLAGS+=	-O3
endif

LDFLAGS=	-ldl -rdynamic -lm
LDFLAGS+=	`pkg-config --libs glib-2.0`
LDFLAGS+=	`pkg-config --libs gthread-2.0`
LDFLAGS+=	`pkg-config --libs zlib`
LDFLAGS+=       `pkg-config --libs libpcre`
LDFLAGS+=       `pkg-config --libs libcrypto`
LDFLAGS+=	`pkg-config --libs openssl`
LDFLAGS+=	`pcre-config --libs`
LDFLAGS+=	`xmlrpc-c-config client --libs`

ifneq ($(DBG),yes)
  DPKG_BLDFLGS=	$(shell which dpkg-buildflags 2>/dev/null)
  ifneq ($(DPKG_BLDFLGS),)
    # support http://wiki.debian.org/Hardening for >=wheezy
    CFLAGS+=	`dpkg-buildflags --get CFLAGS`
    CPPFLAGS+=	`dpkg-buildflags --get CPPFLAGS`
    LDFLAGS+=	`dpkg-buildflags --get LDFLAGS`
  endif
endif

SRCS=		main.c kernel.c poller.c aux.c control_tcp.c streambuf.c call.c control_udp.c redis.c \
		bencode.c cookie_cache.c udp_listener.c control_ng.c sdp.c str.c stun.c rtcp.c \
		crypto.c rtp.c call_interfaces.c dtls.c log.c cli.c
OBJS=		$(SRCS:.c=.o)


.PHONY:		all dep clean tests debug

all:
	$(MAKE) rtpengine

debug:
	$(MAKE) DBG=yes all

dep:		.depend

clean:
	rm -f $(OBJS) rtpengine .depend core core.*

.depend:	$(SRCS) Makefile
	$(CC) $(CFLAGS) -M $(SRCS) | sed -e 's/:/ .depend:/' > .depend

rtpengine:	$(OBJS) .depend
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)


include		.depend
