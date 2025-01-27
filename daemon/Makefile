TARGET=		rtpengine

with_iptables_option ?= yes
with_transcoding ?= yes

ifeq ($(origin CFLAGS),undefined)
CFLAGS:=	-g -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wstrict-prototypes -Werror=return-type \
		-Wshadow
else
CFLAGS:=	$(CFLAGS)
endif
CFLAGS+=	-pthread
CFLAGS+=	-std=c11
CFLAGS+=	$(shell pkg-config --cflags glib-2.0)
CFLAGS+=	$(shell pkg-config --cflags gthread-2.0)
CFLAGS+=	$(shell pkg-config --cflags zlib)
CFLAGS+=	$(shell pkg-config --cflags openssl)
CFLAGS+=	$(shell pkg-config --cflags libevent_pthreads)
CFLAGS+=	-DPCRE2_CODE_UNIT_WIDTH=8
CFLAGS+=	$(shell pkg-config --cflags libpcre2-8)
CFLAGS+=	$(shell pkg-config xmlrpc_client --cflags 2> /dev/null || xmlrpc-c-config client --cflags)
CFLAGS+=	$(shell pkg-config xmlrpc --cflags 2> /dev/null)
CFLAGS+=	$(shell pkg-config xmlrpc_util --cflags 2> /dev/null)
CFLAGS+=	$(shell pkg-config --cflags json-glib-1.0)
CFLAGS+=	$(shell pkg-config --cflags libwebsockets)
CFLAGS+=	$(shell pkg-config --cflags libnftnl)
CFLAGS+=	$(shell pkg-config --cflags libmnl)
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
CFLAGS+=	$(shell pkg-config --cflags spandsp)
CFLAGS+=	$(shell pkg-config --cflags opus)
CFLAGS+=	-DWITH_TRANSCODING
CFLAGS+=        $(shell mysql_config --cflags)
else
CFLAGS+=	-DWITHOUT_CODECLIB
endif
ifeq ($(without_nftables),yes)
CFLAGS+=	-DWITHOUT_NFTABLES
endif

### compile time options:
#CFLAGS+=	-DSRTCP_KEY_DERIVATION_RFC_COMPLIANCE
#CFLAGS+=	-DSTRICT_SDES_KEY_LIFETIME

LDLIBS:=	-lm -ldl
LDLIBS+=	$(shell pkg-config --libs glib-2.0)
LDLIBS+=	$(shell pkg-config --libs gthread-2.0)
LDLIBS+=	$(shell pkg-config --libs zlib)
LDLIBS+=	$(shell pkg-config --libs libpcre2-8)
LDLIBS+=	$(shell pkg-config --libs libcrypto)
LDLIBS+=	$(shell pkg-config --libs openssl)
LDLIBS+=	$(shell pkg-config --libs libevent_pthreads)
LDLIBS+=	-lpcap
LDLIBS+=	$(shell pkg-config xmlrpc_client --libs 2> /dev/null || xmlrpc-c-config client --libs)
LDLIBS+=	$(shell pkg-config xmlrpc --libs 2> /dev/null)
LDLIBS+=	$(shell pkg-config xmlrpc_util --libs 2> /dev/null)
LDLIBS+=	-lhiredis
LDLIBS+=	$(shell pkg-config --libs json-glib-1.0)
LDLIBS+=	$(shell pkg-config --libs libwebsockets)
LDLIBS+=	$(shell pkg-config --libs libnftnl)
LDLIBS+=	$(shell pkg-config --libs libmnl)
ifeq ($(with_iptables_option),yes)
LDLIBS+=	$(shell pkg-config --libs libiptc)
endif
ifeq ($(with_transcoding),yes)
LDLIBS+=	$(shell pkg-config --libs libavcodec)
LDLIBS+=	$(shell pkg-config --libs libavformat)
LDLIBS+=	$(shell pkg-config --libs libavutil)
LDLIBS+=	$(shell pkg-config --libs libswresample)
LDLIBS+=	$(shell pkg-config --libs libavfilter)
LDLIBS+=	$(shell pkg-config --libs spandsp)
LDLIBS+=	$(shell pkg-config --libs opus)
LDLIBS+=        $(shell mysql_config --libs)
endif

ifeq ($(with_transcoding),yes)
include ../lib/g729.Makefile
include ../lib/codec-chain.Makefile
endif

include ../lib/mqtt.Makefile

SRCS=		main.c kernel.c helpers.c control_tcp.c call.c control_udp.c redis.c \
		cookie_cache.c udp_listener.c control_ng_flags_parser.c control_ng.strhash.c sdp.strhash.c stun.c rtcp.c \
		crypto.c rtp.c call_interfaces.strhash.c dtls.c log.c cli.strhash.c graphite.c ice.c \
		media_socket.c homer.c recording.c statistics.c cdr.c ssrc.c iptables.c tcp_listener.c \
		codec.c load.c dtmf.c timerthread.c media_player.c jitter_buffer.c t38.c websocket.c \
		mqtt.c janus.strhash.c audio_player.c arena.c
ifneq ($(without_nftables),yes)
SRCS+=		nftables.c
endif
LIBSRCS=	loglib.c auxlib.c rtplib.c str.c socket.c streambuf.c ssllib.c dtmflib.c mix_buffer.c poller.c \
		bufferpool.c bencode.c
ifeq ($(with_transcoding),yes)
LIBSRCS+=	codeclib.strhash.c resample.c
LIBASM=		mvr2s_x64_avx2.S mvr2s_x64_avx512.S mix_in_x64_avx2.S mix_in_x64_avx512bw.S mix_in_x64_sse2.S
endif
ifneq ($(have_liburing),yes)
LIBSRCS+=	uring.c
endif
OBJS=		$(SRCS:.c=.o) $(LIBSRCS:.c=.o) $(LIBASM:.S=.o)

MDS=		rtpengine.ronn
MANS=		$(MDS:.ronn=.8)

include ../lib/common.Makefile

install: $(TARGET) $(MANS)
	install -m 0755 -D $(TARGET) $(DESTDIR)/usr/bin/$(TARGET)
	install -m 0644 -D $(TARGET).8 $(DESTDIR)/usr/share/man/man8/$(TARGET).8
