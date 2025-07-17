TARGET=		rtpengine

export top_srcdir = ..

include ../lib/deps.Makefile

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
CFLAGS+=	-I. -I../kernel-module/ -I../lib/ -I../include/
CFLAGS+=	-Iprivate
CFLAGS+=	-D_GNU_SOURCE
CFLAGS+=	$(CFLAGS_GLIB)
CFLAGS+=	$(CFLAGS_GTHREAD)
CFLAGS+=	$(CFLAGS_LIBZ)
CFLAGS+=	$(CFLAGS_OPENSSL)
CFLAGS+=	$(CFLAGS_LIBEVENT)
CFLAGS+=	$(CFLAGS_LIBPCRE)
CFLAGS+=	$(CFLAGS_LIBCURL)
CFLAGS+=	$(CFLAGS_JSON_GLIB)
CFLAGS+=	$(CFLAGS_LIBWEBSOCKETS)
CFLAGS+=	$(CFLAGS_LIBNFTNL)
CFLAGS+=	$(CFLAGS_LIBMNL)
ifeq ($(with_iptables_option),yes)
CFLAGS+=	$(CFLAGS_LIBIPTC)
CFLAGS+=	-DWITH_IPTABLES_OPTION
endif
ifeq ($(with_transcoding),yes)
CFLAGS+=	$(CFLAGS_LIBAVCODEC)
CFLAGS+=	$(CFLAGS_LIBAVFORMAT)
CFLAGS+=	$(CFLAGS_LIBAVUTIL)
CFLAGS+=	$(CFLAGS_LIBSWRESAMPLE)
CFLAGS+=	$(CFLAGS_LIBAVFILTER)
CFLAGS+=	$(CFLAGS_SPANDSP)
CFLAGS+=	$(CFLAGS_OPUS)
CFLAGS+=	-DWITH_TRANSCODING
CFLAGS+=	$(CFLAGS_MYSQL)
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
LDLIBS+=	$(LDLIBS_GLIB)
LDLIBS+=	$(LDLIBS_GTHREAD)
LDLIBS+=	$(LDLIBS_LIBZ)
LDLIBS+=	$(LDLIBS_LIBPCRE)
LDLIBS+=	$(LDLIBS_LIBCURL)
LDLIBS+=	$(LDLIBS_LIBCRYPTO)
LDLIBS+=	$(LDLIBS_OPENSSL)
LDLIBS+=	$(LDLIBS_LIBEVENT)
LDLIBS+=	$(LDLIBS_LIBPCAP)
LDLIBS+=	$(LDLIBS_LIBHIREDIS)
LDLIBS+=	$(LDLIBS_JSON_GLIB)
LDLIBS+=	$(LDLIBS_LIBWEBSOCKETS)
LDLIBS+=	$(LDLIBS_LIBNFTNL)
LDLIBS+=	$(LDLIBS_LIBMNL)
ifeq ($(with_iptables_option),yes)
LDLIBS+=	$(LDLIBS_LIBIPTC)
endif
ifeq ($(with_transcoding),yes)
LDLIBS+=	$(LDLIBS_LIBAVCODEC)
LDLIBS+=	$(LDLIBS_LIBAVFORMAT)
LDLIBS+=	$(LDLIBS_LIBAVUTIL)
LDLIBS+=	$(LDLIBS_LIBSWRESAMPLE)
LDLIBS+=	$(LDLIBS_LIBAVFILTER)
LDLIBS+=	$(LDLIBS_SPANDSP)
LDLIBS+=	$(LDLIBS_OPUS)
LDLIBS+=	$(LDLIBS_MYSQL)
endif

ifeq ($(with_transcoding),yes)
CFLAGS+=	$(CFLAGS_BCG729)
LDLIBS+=	$(LDLIBS_BCG729)

CFLAGS+=	$(CFLAGS_CODEC_CHAIN)
LDLIBS+=	$(LDLIBS_CODEC_CHAIN)
endif

CFLAGS+=	$(CFLAGS_MQTT)
LDLIBS+=	$(LDLIBS_MQTT)

SRCS=		main.c kernel.c helpers.c control_tcp.c call.c control_udp.c redis.c \
		cookie_cache.c udp_listener.c control_ng_flags_parser.c control_ng.strhash.c sdp.strhash.c stun.c rtcp.c \
		crypto.c rtp.c call_interfaces.strhash.c dtls.c log.c cli.strhash.c graphite.c ice.c \
		media_socket.c homer.c recording.c statistics.c cdr.c ssrc.c iptables.c tcp_listener.c \
		codec.c load.c dtmf.c timerthread.c media_player.c jitter_buffer.c t38.c websocket.c \
		mqtt.c janus.strhash.c audio_player.c arena.c ng_client.c
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

MDS=		rtpengine.ronn
MANS=		$(MDS:.ronn=.8)

include ../lib/common.Makefile

install: $(TARGET) $(MANS)
	install -m 0755 -D $(TARGET) $(DESTDIR)/usr/bin/$(TARGET)
	install -m 0644 -D $(TARGET).8 $(DESTDIR)/usr/share/man/man8/$(TARGET).8
