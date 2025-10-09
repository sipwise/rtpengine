TARGET=		all-tests

export top_srcdir = ..

include ../lib/deps.Makefile

with_transcoding ?= yes

ifeq ($(origin CFLAGS),undefined)
CFLAGS?=	-g -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wstrict-prototypes -Werror=return-type \
		-Wshadow
else
CFLAGS:=	$(CFLAGS)
endif
PRELOAD_CFLAGS := $(CFLAGS)
CFLAGS+=	-pthread
CFLAGS+=	-std=c11
CFLAGS+=	-I. -I../lib/ -I../kernel-module/ -I../include/
CFLAGS+=	-D_GNU_SOURCE
CFLAGS+=	$(CFLAGS_GLIB)
CFLAGS+=	$(CFLAGS_GTHREAD)
CFLAGS+=	$(CFLAGS_OPENSSL)
CFLAGS+=	$(CFLAGS_LIBPCRE)
CFLAGS+=	$(CFLAGS_LIBCURL)
CFLAGS+=	$(CFLAGS_JSON_GLIB)
ifeq ($(with_transcoding),yes)
CFLAGS+=	$(CFLAGS_LIBAVCODEC)
CFLAGS+=	$(CFLAGS_LIBAVFORMAT)
CFLAGS+=	$(CFLAGS_LIBAVUTIL)
CFLAGS+=	$(CFLAGS_LIBSWRESAMPLE)
CFLAGS+=	$(CFLAGS_LIBAVFILTER)
CFLAGS+=	$(CFLAGS_SPANDSP)
CFLAGS+=	$(CFLAGS_OPUS)
CFLAGS+=	$(CFLAGS_LIBZ)
CFLAGS+=	$(CFLAGS_LIBWEBSOCKETS)
CFLAGS+=	$(CFLAGS_LIBEVENT)
CFLAGS+=	-DWITH_TRANSCODING
ifeq ($(RTPENGINE_EXTENDED_TESTS),1)
CFLAGS+=	-DWITH_AMR_TESTS
endif
CFLAGS+=	$(CFLAGS_MYSQL)
else
CFLAGS+=	-DWITHOUT_CODECLIB
endif

LDLIBS:=	-lm -ldl
LDLIBS+=	$(LDLIBS_GLIB)
LDLIBS+=	$(LDLIBS_GTHREAD)
LDLIBS+=	$(LDLIBS_LIBCRYPTO)
LDLIBS+=	$(LDLIBS_OPENSSL)
LDLIBS+=	$(LDLIBS_LIBPCRE)
LDLIBS+=	$(LDLIBS_LIBCURL)
LDLIBS+=	$(LDLIBS_JSON_GLIB)
ifeq ($(with_transcoding),yes)
LDLIBS+=	$(LDLIBS_LIBAVCODEC)
LDLIBS+=	$(LDLIBS_LIBAVFORMAT)
LDLIBS+=	$(LDLIBS_LIBAVUTIL)
LDLIBS+=	$(LDLIBS_LIBSWRESAMPLE)
LDLIBS+=	$(LDLIBS_LIBAVFILTER)
LDLIBS+=	$(LDLIBS_SPANDSP)
LDLIBS+=	$(LDLIBS_OPUS)
LDLIBS+=	$(LDLIBS_LIBZ)
LDLIBS+=	$(LDLIBS_LIBWEBSOCKETS)
LDLIBS+=	$(LDLIBS_LIBPCAP)
LDLIBS+=	$(LDLIBS_LIBEVENT)
LDLIBS+=	$(LDLIBS_LIBHIREDIS)
LDLIBS+=	$(LDLIBS_MYSQL)
endif

CFLAGS+=	$(CFLAGS_CODEC_CHAIN)
LDLIBS+=	$(LDLIBS_CODEC_CHAIN)

SRCS=		test-bitstr.c aes-crypt.c aead-aes-crypt.c test-const_str_hash.strhash.c aead-decrypt.c
LIBSRCS=	loglib.c auxlib.c str.c rtplib.c ssllib.c mix_buffer.c bufferpool.c bencode.c
DAEMONSRCS=	crypto.c ssrc.c helpers.c rtp.c cli.strhash.c

ifeq ($(with_transcoding),yes)
SRCS+=		test-transcode.c test-dtmf-detect.c test-payload-tracker.c test-resample.c test-stats.c
SRCS+=		spandsp_recv_fax_pcm.c spandsp_recv_fax_t38.c spandsp_send_fax_pcm.c \
		spandsp_send_fax_t38.c test-mix-buffer.c
ifeq ($(RTPENGINE_EXTENDED_TESTS),1)
SRCS+=		test-amr-decode.c test-amr-encode.c
endif
LIBSRCS+=	codeclib.strhash.c resample.c socket.c streambuf.c dtmflib.c poller.c
DAEMONSRCS+=	control_ng_flags_parser.c codec.c call.c ice.c kernel.c media_socket.c stun.c \
		dtls.c recording.c statistics.c rtcp.c redis.c iptables.c graphite.c \
		cookie_cache.c udp_listener.c homer.c load.c cdr.c dtmf.c timerthread.c \
		media_player.c jitter_buffer.c t38.c tcp_listener.c mqtt.c websocket.c \
		audio_player.c arena.c ng_client.c call_interfaces.strhash.c sdp.strhash.c \
		janus.strhash.c control_ng.strhash.c
LIBASM=		mvr2s_x64_avx2.S mvr2s_x64_avx512.S mix_in_x64_avx2.S mix_in_x64_avx512bw.S mix_in_x64_sse2.S
endif
ifneq ($(have_liburing),yes)
LIBSRCS+=	uring.c
endif

SRCS+=		s3-auth.c
LIBSRCS+=	s3utils.c

SRCS+=		kernel-extmap-filter.c

COMMONOBJS=	str.o auxlib.o rtplib.o loglib.o ssllib.o

include ../lib/common.Makefile

.PHONY:		all-tests unit-tests daemon-tests daemon-tests \
	daemon-tests-main daemon-tests-jb daemon-tests-dtx daemon-tests-dtx-cn daemon-tests-pubsub \
	daemon-tests-intfs daemon-tests-stats daemon-tests-delay-buffer daemon-tests-delay-timing \
	daemon-tests-evs daemon-tests-player-cache daemon-tests-redis daemon-tests-redis-json \
	daemon-tests-measure-rtp daemon-tests-mos-legacy daemon-tests-mos-fullband daemon-tests-config-file \
	daemon-tests-templ-def daemon-tests-templ-def-offer daemon-tests-t38 daemon-tests-evs-dtx \
	daemon-tests-transform daemon-tests-http daemon-tests-heuristic daemon-tests-asymmetric \
	daemon-tests-dtx-no-shift daemon-tests-rtcp daemon-tests-redis-subscribe daemon-tests-rtp-ext \
	daemon-tests-bundle daemon-tests-dtls

TESTS=		test-bitstr aes-crypt aead-aes-crypt test-const_str_hash.strhash
ifeq ($(with_transcoding),yes)
TESTS+=		test-transcode test-dtmf-detect test-payload-tracker test-resample test-stats test-mix-buffer
ifeq ($(RTPENGINE_EXTENDED_TESTS),1)
TESTS+=		test-amr-decode test-amr-encode
endif
endif
TESTS+=		s3-auth

ADD_CLEAN=	tests-preload.so time-fudge-preload.so $(TESTS) aead-decrypt
ADD_CLEAN+=	s3-auth

ifeq ($(with_transcoding),yes)
all-tests:	unit-tests daemon-tests
else
all-tests:	unit-tests
endif
	true # override linking recipe from common.Makefile

unit-tests:	$(TESTS) aead-decrypt kernel-extmap-filter
	failed="" ; \
	for x in $(TESTS); do \
	  echo `date +"%Y-%m-%d %H:%M:%S"` testing: $$x ; \
	  G_DEBUG=fatal-warnings ./$$x ; \
	  if [ $$? -eq 0 ] ; \
	    then echo `date +"%Y-%m-%d %H:%M:%S"` test $$x: succeeded ; \
	    else echo `date +"%Y-%m-%d %H:%M:%S"` test $$x: failed ; failed="$$failed $$x" ; \
	  fi ; \
	done ; \
	if [ -n "$$failed" ] ; then \
	  echo "Tests failed: $$failed" ; \
	  exit 1 ; \
	fi

daemon-tests: daemon-tests-main daemon-tests-jb daemon-tests-pubsub daemon-tests-websocket \
	daemon-tests-evs daemon-tests-async-tc \
	daemon-tests-audio-player daemon-tests-audio-player-play-media \
	daemon-tests-intfs daemon-tests-stats daemon-tests-player-cache daemon-tests-redis \
	daemon-tests-rtpp-flags daemon-tests-redis-json daemon-tests-measure-rtp daemon-tests-mos-legacy \
	daemon-tests-mos-fullband daemon-tests-config-file \
	daemon-tests-templ-def daemon-tests-templ-def-offer \
	daemon-tests-sdp-manipulations daemon-tests-sdes-manipulations \
	daemon-tests-sdp-orig-replacements daemon-tests-moh daemon-tests-evs-dtx daemon-tests-transform \
	daemon-tests-transcode-config daemon-tests-codec-prefs daemon-tests-http daemon-tests-heuristic \
	daemon-tests-asymmetric daemon-tests-rtcp daemon-tests-redis-subscribe daemon-tests-rtp-ext \
	daemon-tests-bundle daemon-tests-dtls

daemon-test-deps:	tests-preload.so
	$(MAKE) -C ../daemon

daemon-tests-main:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests.pl

daemon-tests-jb:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-jb.pl

daemon-tests-heuristic:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-heuristic.pl

daemon-tests-asymmetric:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-asymmetric.pl

daemon-tests-dtx:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-dtx.pl

daemon-tests-dtx-no-shift:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-dtx-no-shift.pl

daemon-tests-dtx-cn:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-dtx-cn.pl

daemon-tests-pubsub:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-pubsub.pl

daemon-tests-transform:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-transform.pl

daemon-tests-transcode-config:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-transcode-config.pl

daemon-tests-stats:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-stats.pl

daemon-tests-websocket:	daemon-test-deps
	./auto-test-helper "$@" python3 auto-daemon-tests-websocket.py

daemon-tests-intfs:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-intfs.pl

daemon-tests-delay-buffer:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-delay-buffer.pl

daemon-tests-delay-timing:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-delay-timing.pl

daemon-tests-evs:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-evs.pl

daemon-tests-player-cache:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-player-cache.pl

daemon-tests-redis:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-redis.pl

daemon-tests-redis-subscribe:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-redis-subscribe.pl

daemon-tests-redis-json:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-redis-json.pl

daemon-tests-audio-player:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-audio-player.pl

daemon-tests-audio-player-play-media:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-audio-player-play-media.pl

daemon-tests-rtpp-flags:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-rtpp-flags.pl

daemon-tests-unknown-fmtp:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-unknown-fmtp.pl

daemon-tests-sdp-manipulations:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-sdp-manipulations.pl

daemon-tests-sdes-manipulations:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-sdes-manipulations.pl

daemon-tests-sdp-orig-replacements:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-sdp-orig-replacements.pl

daemon-tests-moh:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-moh.pl

daemon-tests-async-tc:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-async-tc.pl

daemon-tests-measure-rtp:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-measure-rtp.pl

daemon-tests-mos-legacy:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-mos-legacy.pl

daemon-tests-mos-fullband:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-mos-fullband.pl

daemon-tests-config-file:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-config-file.pl

daemon-tests-templ-def-offer:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-templ-def-offer.pl

daemon-tests-templ-def:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-templ-def.pl

daemon-tests-t38:	daemon-test-deps spandsp_recv_fax_pcm spandsp_recv_fax_t38 \
			spandsp_send_fax_pcm spandsp_send_fax_t38
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-t38.pl

daemon-tests-evs-dtx:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-evs-dtx.pl

daemon-tests-codec-prefs:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-codec-prefs.pl

daemon-tests-http:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-http.pl

daemon-tests-rtcp:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-rtcp.pl

daemon-tests-rtp-ext:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-rtp-ext.pl

daemon-tests-bundle:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-bundle.pl

daemon-tests-dtls:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-dtls.pl

test-bitstr:	test-bitstr.o

test-mix-buffer:	test-mix-buffer.o $(COMMONOBJS) mix_buffer.o ssrc.o rtp.o crypto.o helpers.o \
	mix_in_x64_avx2.o mix_in_x64_sse2.o mix_in_x64_avx512bw.o codeclib.strhash.o dtmflib.o \
	mvr2s_x64_avx2.o mvr2s_x64_avx512.o resample.o bufferpool.o uring.o poller.o bencode.o

spandsp_send_fax_pcm:	spandsp_send_fax_pcm.o

spandsp_recv_fax_pcm:	spandsp_recv_fax_pcm.o

spandsp_send_fax_t38:	spandsp_send_fax_t38.o

spandsp_recv_fax_t38:	spandsp_recv_fax_t38.o

spandsp_raw_fax_tests: spandsp_send_fax_pcm spandsp_recv_fax_pcm spandsp_send_fax_t38 spandsp_recv_fax_t38

test-amr-decode: test-amr-decode.o $(COMMONOBJS) codeclib.strhash.o resample.o dtmflib.o resample.o \
	mvr2s_x64_avx2.o mvr2s_x64_avx512.o bencode.o

test-amr-encode: test-amr-encode.o $(COMMONOBJS) codeclib.strhash.o resample.o dtmflib.o \
	mvr2s_x64_avx2.o mvr2s_x64_avx512.o bencode.o

test-dtmf-detect: test-dtmf-detect.o

aes-crypt:	aes-crypt.o $(COMMONOBJS) crypto.o bencode.o

aead-decrypt:	aead-decrypt.o $(COMMONOBJS) crypto.o rtp.o bencode.o

aead-aes-crypt:	aead-aes-crypt.o $(COMMONOBJS) crypto.o bencode.o

test-stats:	test-stats.o $(COMMONOBJS) codeclib.strhash.o resample.o codec.o ssrc.o call.o ice.o helpers.o \
	kernel.o media_socket.o stun.o bencode.o socket.o poller.o dtls.o recording.o statistics.o \
	rtcp.o redis.o iptables.o graphite.o call_interfaces.strhash.o sdp.strhash.o rtp.o crypto.o \
	control_ng_flags_parser.o control_ng.strhash.o graphite.o \
	streambuf.o cookie_cache.o udp_listener.o homer.o load.o cdr.o dtmf.o timerthread.o \
	media_player.o jitter_buffer.o dtmflib.o t38.o tcp_listener.o mqtt.o janus.strhash.o \
	websocket.o cli.strhash.o mvr2s_x64_avx2.o mvr2s_x64_avx512.o audio_player.o mix_buffer.o \
	mix_in_x64_avx2.o mix_in_x64_sse2.o mix_in_x64_avx512bw.o bufferpool.o uring.o arena.o ng_client.o

test-transcode:	test-transcode.o $(COMMONOBJS) codeclib.strhash.o resample.o codec.o ssrc.o call.o ice.o helpers.o \
	kernel.o media_socket.o stun.o bencode.o socket.o poller.o dtls.o recording.o statistics.o \
	rtcp.o redis.o iptables.o graphite.o call_interfaces.strhash.o sdp.strhash.o rtp.o crypto.o \
	control_ng_flags_parser.o control_ng.strhash.o \
	streambuf.o cookie_cache.o udp_listener.o homer.o load.o cdr.o dtmf.o timerthread.o \
	media_player.o jitter_buffer.o dtmflib.o t38.o tcp_listener.o mqtt.o janus.strhash.o websocket.o \
	cli.strhash.o mvr2s_x64_avx2.o mvr2s_x64_avx512.o audio_player.o mix_buffer.o \
	mix_in_x64_avx2.o mix_in_x64_sse2.o mix_in_x64_avx512bw.o bufferpool.o uring.o arena.o ng_client.o

test-resample:	test-resample.o $(COMMONOBJS) codeclib.strhash.o resample.o dtmflib.o mvr2s_x64_avx2.o \
	mvr2s_x64_avx512.o bencode.o

test-payload-tracker: test-payload-tracker.o $(COMMONOBJS) ssrc.o helpers.o auxlib.o rtp.o crypto.o codeclib.strhash.o \
	resample.o dtmflib.o mvr2s_x64_avx2.o mvr2s_x64_avx512.o bufferpool.o uring.o poller.o bencode.o

test-kernel-module: test-kernel-module.o $(COMMONOBJS) kernel.o

test-const_str_hash.strhash: test-const_str_hash.strhash.o $(COMMONOBJS) bencode.o

s3-auth:	s3-auth.o s3utils.o

kernel-extmap-filter:	kernel-extmap-filter.o

PRELOAD_CFLAGS += -D_GNU_SOURCE -std=c11
PRELOAD_LIBS += -ldl

tests-preload.so:	tests-preload.c
	$(CC) $(PRELOAD_CFLAGS) -o $@ -shared -fPIC $< $(PRELOAD_LIBS)

time-fudge-preload.so:	time-fudge-preload.c
	$(CC) $(PRELOAD_CFLAGS) -o $@ -shared -fPIC $< $(PRELOAD_LIBS)

spandsp_send_fax_pcm.c:	../lib/spandsp_logging.h
spandsp_send_fax_t38.c:	../lib/spandsp_logging.h
spandsp_recv_fax_t38.c:	../lib/spandsp_logging.h
spandsp_recv_fax_pcm.c:	../lib/spandsp_logging.h
