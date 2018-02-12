TARGET=		rtpengine

with_iptables_option ?= yes
with_transcoding ?= yes

# look for bcg729
# /usr/src
ifneq (,$(wildcard /usr/src/bcg729/include/bcg729/decoder.h))
have_bcg729 := yes
bcg729_inc := /usr/src/bcg729/include/
bcg729_lib := /usr/src/bcg729/src/
else
# rfuchs dev
ifneq (,$(wildcard $(HOME)/src/bcg729/include/bcg729/decoder.h))
have_bcg729 := yes
bcg729_inc := $(HOME)/src/bcg729/include/
bcg729_lib := $(HOME)/src/bcg729/src/
else
# home directory
ifneq (,$(wildcard $(HOME)/bcg729/include/bcg729/decoder.h))
have_bcg729 := yes
bcg729_inc := $(HOME)/bcg729/include/
bcg729_lib := $(HOME)/bcg729/src/
else
# included toplevel
ifneq (,$(wildcard ../bcg729/include/bcg729/decoder.h))
have_bcg729 := yes
bcg729_inc := ../bcg729/include/
bcg729_lib := ../bcg729/src/
endif
endif
endif
endif

CFLAGS=		-g -Wall -pthread -fno-strict-aliasing
CFLAGS+=	-std=c99
CFLAGS+=	`pkg-config --cflags glib-2.0`
CFLAGS+=	`pkg-config --cflags gthread-2.0`
CFLAGS+=	`pkg-config --cflags zlib`
CFLAGS+=	`pkg-config --cflags openssl`
CFLAGS+=	`pkg-config --cflags libevent_pthreads`
CFLAGS+=	`pcre-config --cflags`
CFLAGS+=	`pkg-config xmlrpc_client --cflags 2> /dev/null || xmlrpc-c-config client --cflags`
CFLAGS+=	`pkg-config xmlrpc --cflags 2> /dev/null`
CFLAGS+=	`pkg-config xmlrpc_util --cflags 2> /dev/null`
CFLAGS+=	`pkg-config --cflags json-glib-1.0`
ifeq ($(with_iptables_option),yes)
CFLAGS+=	`pkg-config --cflags libiptc`
CFLAGS+=	-DWITH_IPTABLES_OPTION
endif
CFLAGS+=	-I. -I../kernel-module/ -I../lib/
CFLAGS+=	-D_GNU_SOURCE
ifeq ($(with_transcoding),yes)
CFLAGS+=	`pkg-config --cflags libavcodec`
CFLAGS+=	`pkg-config --cflags libavformat`
CFLAGS+=	`pkg-config --cflags libavutil`
CFLAGS+=	`pkg-config --cflags libavresample`
CFLAGS+=	`pkg-config --cflags libavfilter`
CFLAGS+=	-DWITH_TRANSCODING
else
CFLAGS+=	-DWITHOUT_CODECLIB
endif
ifeq ($(have_bcg729),yes)
CFLAGS+=	-DHAVE_BCG729 -I$(bcg729_inc)
endif

CFLAGS+=	-DRE_PLUGIN_DIR="\"/usr/lib/rtpengine\""

### compile time options:
#CFLAGS+=	-DSRTCP_KEY_DERIVATION_RFC_COMPLIANCE
#CFLAGS+=	-DTERMINATE_SDP_AT_BLANK_LINE
#CFLAGS+=	-DSTRICT_SDES_KEY_LIFETIME

LDFLAGS=	-lm
LDFLAGS+=	`pkg-config --libs glib-2.0`
LDFLAGS+=	`pkg-config --libs gthread-2.0`
LDFLAGS+=	`pkg-config --libs zlib`
LDFLAGS+=       `pkg-config --libs libpcre`
LDFLAGS+=       `pkg-config --libs libcrypto`
LDFLAGS+=	`pkg-config --libs openssl`
LDFLAGS+=	`pkg-config --libs libevent_pthreads`
LDFLAGS+=	-lpcap
LDFLAGS+=	`pcre-config --libs`
LDFLAGS+=	`pkg-config xmlrpc_client --libs 2> /dev/null || xmlrpc-c-config client --libs`
LDFLAGS+=	`pkg-config xmlrpc --libs 2> /dev/null`
LDFLAGS+=	`pkg-config xmlrpc_util --libs 2> /dev/null`
LDFLAGS+=	-lhiredis
LDFLAGS+=	`pkg-config --libs json-glib-1.0`
ifeq ($(with_iptables_option),yes)
LDFLAGS+=	`pkg-config --libs libiptc`
endif
ifeq ($(with_transcoding),yes)
LDFLAGS+=	`pkg-config --libs libavcodec`
LDFLAGS+=	`pkg-config --libs libavformat`
LDFLAGS+=	`pkg-config --libs libavutil`
LDFLAGS+=	`pkg-config --libs libavresample`
LDFLAGS+=	`pkg-config --libs libavfilter`
endif
ifeq ($(have_bcg729),yes)
LDFLAGS+=	-L$(bcg729_lib) -lbcg729
endif

include ../lib/lib.Makefile

SRCS=		main.c kernel.c poller.c aux.c control_tcp.c streambuf.c call.c control_udp.c redis.c \
		bencode.c cookie_cache.c udp_listener.c control_ng.c sdp.c stun.c rtcp.c \
		crypto.c rtp.c call_interfaces.c dtls.c log.c cli.c graphite.c ice.c socket.c \
		media_socket.c homer.c recording.c statistics.c cdr.c ssrc.c iptables.c tcp_listener.c \
		codec.c
LIBSRCS=	loglib.c auxlib.c rtplib.c str.c
ifeq ($(with_transcoding),yes)
LIBSRCS+=	codeclib.c resample.c
endif
OBJS=		$(SRCS:.c=.o) $(LIBSRCS:.c=.o)


.PHONY:		all dep clean debug install

all:
	$(MAKE) $(TARGET)

debug:
	$(MAKE) DBG=yes all

dep:		.depend

clean:
	rm -f $(OBJS) $(TARGET) $(LIBSRCS) .depend core core.*

.depend:	$(SRCS) $(LIBSRCS) Makefile
	$(CC) $(CFLAGS) -M $(SRCS) $(LIBSRCS) | sed -e 's/:/ .depend:/' > .depend

$(TARGET):	$(OBJS) .depend Makefile
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(OBJS):	Makefile

$(LIBSRCS):
		ln -fs ../lib/$@

install:

include		.depend
