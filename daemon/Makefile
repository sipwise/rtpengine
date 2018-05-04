TARGET=		rtpengine

with_iptables_option ?= yes
with_transcoding ?= yes

# look for bcg729
# system pkg-config
ifeq ($(shell pkg-config --exists libbcg729 && echo yes),yes)
have_bcg729 := yes
bcg729_inc := $(shell pkg-config --cflags libbcg729)
bcg729_lib := $(shell pkg-config --libs libbcg729)
else
# system generic
ifneq (,$(wildcard /usr/include/bcg729/decoder.h))
have_bcg729 := yes
else
# /usr/src
ifneq (,$(wildcard /usr/src/bcg729/include/bcg729/decoder.h))
have_bcg729 := yes
bcg729_inc := -I/usr/src/bcg729/include/
bcg729_lib := -L/usr/src/bcg729/src/ -lbcg729
else
# rfuchs dev
ifneq (,$(wildcard $(HOME)/src/bcg729/include/bcg729/decoder.h))
have_bcg729 := yes
bcg729_inc := -I$(HOME)/src/bcg729/include/
bcg729_lib := -L$(HOME)/src/bcg729/src/ -lbcg729
else
# home directory
ifneq (,$(wildcard $(HOME)/bcg729/include/bcg729/decoder.h))
have_bcg729 := yes
bcg729_inc := -I$(HOME)/bcg729/include/
bcg729_lib := -L$(HOME)/bcg729/src/ -lbcg729
else
# included toplevel
ifneq (,$(wildcard ../bcg729/include/bcg729/decoder.h))
have_bcg729 := yes
bcg729_inc := -I../bcg729/include/
bcg729_lib := -L../bcg729/src/ -lbcg729
endif
endif
endif
endif
endif
endif

CFLAGS=		-g -Wall -pthread -fno-strict-aliasing
CFLAGS+=	-std=c99
CFLAGS+=	$(shell pkg-config --cflags glib-2.0)
CFLAGS+=	$(shell pkg-config --cflags gthread-2.0)
CFLAGS+=	$(shell pkg-config --cflags zlib)
CFLAGS+=	$(shell pkg-config --cflags openssl)
CFLAGS+=	$(shell pkg-config --cflags libevent_pthreads)
CFLAGS+=	$(shell pcre-config --cflags)
CFLAGS+=	$(shell pkg-config xmlrpc_client --cflags 2> /dev/null || xmlrpc-c-config client --cflags)
CFLAGS+=	$(shell pkg-config xmlrpc --cflags 2> /dev/null)
CFLAGS+=	$(shell pkg-config xmlrpc_util --cflags 2> /dev/null)
CFLAGS+=	$(shell pkg-config --cflags json-glib-1.0)
ifeq ($(with_iptables_option),yes)
CFLAGS+=	$(shell pkg-config --cflags libiptc)
CFLAGS+=	-DWITH_IPTABLES_OPTION
endif
CFLAGS+=	-I. -I../kernel-module/ -I../lib/ -I../include/
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
ifeq ($(have_bcg729),yes)
CFLAGS+=	-DHAVE_BCG729
CFLAGS+=	$(bcg729_inc)
endif

CFLAGS+=	-DRE_PLUGIN_DIR="\"/usr/lib/rtpengine\""

### compile time options:
#CFLAGS+=	-DSRTCP_KEY_DERIVATION_RFC_COMPLIANCE
#CFLAGS+=	-DTERMINATE_SDP_AT_BLANK_LINE
#CFLAGS+=	-DSTRICT_SDES_KEY_LIFETIME

LDLIBS=		-lm
LDLIBS+=	$(shell pkg-config --libs glib-2.0)
LDLIBS+=	$(shell pkg-config --libs gthread-2.0)
LDLIBS+=	$(shell pkg-config --libs zlib)
LDLIBS+=       $(shell pkg-config --libs libpcre)
LDLIBS+=       $(shell pkg-config --libs libcrypto)
LDLIBS+=	$(shell pkg-config --libs openssl)
LDLIBS+=	$(shell pkg-config --libs libevent_pthreads)
LDLIBS+=	-lpcap
LDLIBS+=	$(shell pcre-config --libs)
LDLIBS+=	$(shell pkg-config xmlrpc_client --libs 2> /dev/null || xmlrpc-c-config client --libs)
LDLIBS+=	$(shell pkg-config xmlrpc --libs 2> /dev/null)
LDLIBS+=	$(shell pkg-config xmlrpc_util --libs 2> /dev/null)
LDLIBS+=	-lhiredis
LDLIBS+=	$(shell pkg-config --libs json-glib-1.0)
ifeq ($(with_iptables_option),yes)
LDLIBS+=	$(shell pkg-config --libs libiptc)
endif
ifeq ($(with_transcoding),yes)
LDLIBS+=	$(shell pkg-config --libs libavcodec)
LDLIBS+=	$(shell pkg-config --libs libavformat)
LDLIBS+=	$(shell pkg-config --libs libavutil)
LDLIBS+=	$(shell pkg-config --libs libswresample)
LDLIBS+=	$(shell pkg-config --libs libavfilter)
endif
ifeq ($(have_bcg729),yes)
LDLIBS+=	$(bcg729_lib)
endif

SRCS=		main.c kernel.c poller.c aux.c control_tcp.c streambuf.c call.c control_udp.c redis.c \
		bencode.c cookie_cache.c udp_listener.c control_ng.c sdp.c stun.c rtcp.c \
		crypto.c rtp.c call_interfaces.c dtls.c log.c cli.c graphite.c ice.c socket.c \
		media_socket.c homer.c recording.c statistics.c cdr.c ssrc.c iptables.c tcp_listener.c \
		codec.c load.c
LIBSRCS=	loglib.c auxlib.c rtplib.c str.c
ifeq ($(with_transcoding),yes)
LIBSRCS+=	codeclib.c resample.c
endif
OBJS=		$(SRCS:.c=.o) $(LIBSRCS:.c=.o)

include ../lib/common.Makefile

include		.depend
