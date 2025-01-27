TARGET=		all-tests

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
CFLAGS+=	$(shell pkg-config --cflags glib-2.0)
CFLAGS+=	$(shell pkg-config --cflags gthread-2.0)
CFLAGS+=	$(shell pkg-config --cflags openssl)
CFLAGS+=	-I. -I../lib/ -I../kernel-module/ -I../include/
CFLAGS+=	-D_GNU_SOURCE
CFLAGS+=	-DPCRE2_CODE_UNIT_WIDTH=8
CFLAGS+=	$(shell pkg-config --cflags libpcre2-8)
CFLAGS+=	$(shell pkg-config --cflags json-glib-1.0)
ifeq ($(with_transcoding),yes)
CFLAGS+=	$(shell pkg-config --cflags libavcodec)
CFLAGS+=	$(shell pkg-config --cflags libavformat)
CFLAGS+=	$(shell pkg-config --cflags libavutil)
CFLAGS+=	$(shell pkg-config --cflags libswresample)
CFLAGS+=	$(shell pkg-config --cflags libavfilter)
CFLAGS+=	$(shell pkg-config --cflags spandsp)
CFLAGS+=	$(shell pkg-config --cflags opus)
CFLAGS+=	-DWITH_TRANSCODING
CFLAGS+=	$(shell pkg-config --cflags zlib)
CFLAGS+=	$(shell pkg-config --cflags libwebsockets)
CFLAGS+=	$(shell pkg-config --cflags libevent_pthreads)
CFLAGS+=	$(shell pkg-config xmlrpc_client --cflags 2> /dev/null || xmlrpc-c-config client --cflags)
CFLAGS+=	$(shell pkg-config xmlrpc --cflags 2> /dev/null)
CFLAGS+=	$(shell pkg-config xmlrpc_util --cflags 2> /dev/null)
ifeq ($(RTPENGINE_EXTENDED_TESTS),1)
CFLAGS+=	-DWITH_AMR_TESTS
endif
CFLAGS+=	$(shell mysql_config --cflags)
else
CFLAGS+=	-DWITHOUT_CODECLIB
endif

LDLIBS:=	-lm -ldl
LDLIBS+=	$(shell pkg-config --libs glib-2.0)
LDLIBS+=	$(shell pkg-config --libs gthread-2.0)
LDLIBS+=	$(shell pkg-config --libs libcrypto)
LDLIBS+=	$(shell pkg-config --libs openssl)
LDLIBS+=	$(shell pkg-config --libs libpcre2-8)
LDLIBS+=	$(shell pkg-config --libs json-glib-1.0)
ifeq ($(with_transcoding),yes)
LDLIBS+=	$(shell pkg-config --libs libavcodec)
LDLIBS+=	$(shell pkg-config --libs libavformat)
LDLIBS+=	$(shell pkg-config --libs libavutil)
LDLIBS+=	$(shell pkg-config --libs libswresample)
LDLIBS+=	$(shell pkg-config --libs libavfilter)
LDLIBS+=	$(shell pkg-config --libs spandsp)
LDLIBS+=	$(shell pkg-config --libs opus)
LDLIBS+=	$(shell pkg-config --libs zlib)
LDLIBS+=	$(shell pkg-config --libs libwebsockets)
LDLIBS+=	-lpcap
LDLIBS+=	$(shell pkg-config --libs libevent_pthreads)
LDLIBS+=	$(shell pkg-config xmlrpc_client --libs 2> /dev/null || xmlrpc-c-config client --libs)
LDLIBS+=	$(shell pkg-config xmlrpc --libs 2> /dev/null)
LDLIBS+=	$(shell pkg-config xmlrpc_util --libs 2> /dev/null)
LDLIBS+=	-lhiredis
LDLIBS+=	$(shell mysql_config --libs)
endif

include ../lib/codec-chain.Makefile

SRCS=		test-bitstr.c aes-crypt.c aead-aes-crypt.c test-const_str_hash.strhash.c aead-decrypt.c
LIBSRCS=	loglib.c auxlib.c str.c rtplib.c ssllib.c mix_buffer.c bufferpool.c bencode.c
DAEMONSRCS=	crypto.c ssrc.c helpers.c rtp.c
HASHSRCS=	cli.c

ifeq ($(with_transcoding),yes)
SRCS+=		test-transcode.c test-dtmf-detect.c test-payload-tracker.c test-resample.c test-stats.c
SRCS+=		spandsp_recv_fax_pcm.c spandsp_recv_fax_t38.c spandsp_send_fax_pcm.c \
		spandsp_send_fax_t38.c test-mix-buffer.c
ifeq ($(RTPENGINE_EXTENDED_TESTS),1)
SRCS+=		test-amr-decode.c test-amr-encode.c
endif
LIBSRCS+=	codeclib.strhash.c resample.c socket.c streambuf.c dtmflib.c poller.c
DAEMONSRCS+=	control_ng_flags_parser.c codec.c call.c ice.c kernel.c media_socket.c stun.c bencode.c \
		dtls.c recording.c statistics.c rtcp.c redis.c iptables.c graphite.c \
		cookie_cache.c udp_listener.c homer.c load.c cdr.c dtmf.c timerthread.c \
		media_player.c jitter_buffer.c t38.c tcp_listener.c mqtt.c websocket.c \
		audio_player.c arena.c
HASHSRCS+=	call_interfaces.c control_ng.c sdp.c janus.c
LIBASM=		mvr2s_x64_avx2.S mvr2s_x64_avx512.S mix_in_x64_avx2.S mix_in_x64_avx512bw.S mix_in_x64_sse2.S
endif
ifneq ($(have_liburing),yes)
LIBSRCS+=	uring.c
endif

OBJS=		$(SRCS:.c=.o) $(LIBSRCS:.c=.o) $(DAEMONSRCS:.c=.o) $(HASHSRCS:.c=.strhash.o) $(LIBASM:.S=.o)

COMMONOBJS=	str.o auxlib.o rtplib.o loglib.o ssllib.o

include ../lib/common.Makefile

.PHONY:		all-tests unit-tests daemon-tests daemon-tests \
	daemon-tests-main daemon-tests-jb daemon-tests-dtx daemon-tests-dtx-cn daemon-tests-pubsub \
	daemon-tests-intfs daemon-tests-stats daemon-tests-delay-buffer daemon-tests-delay-timing \
	daemon-tests-evs daemon-tests-player-cache daemon-tests-redis daemon-tests-redis-json \
	daemon-tests-measure-rtp daemon-tests-mos-legacy daemon-tests-mos-fullband daemon-tests-config-file \
	daemon-tests-templ-def daemon-tests-templ-def-offer

TESTS=		test-bitstr aes-crypt aead-aes-crypt test-const_str_hash.strhash
ifeq ($(with_transcoding),yes)
TESTS+=		test-transcode test-dtmf-detect test-payload-tracker test-resample test-stats test-mix-buffer
ifeq ($(RTPENGINE_EXTENDED_TESTS),1)
TESTS+=		test-amr-decode test-amr-encode
endif
endif

ADD_CLEAN=	tests-preload.so time-fudge-preload.so $(TESTS)

ifeq ($(with_transcoding),yes)
all-tests:	unit-tests daemon-tests
else
all-tests:	unit-tests
endif
	true # override linking recipe from common.Makefile

unit-tests:	$(TESTS) aead-decrypt
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
	daemon-tests-sdp-orig-replacements daemon-tests-moh

daemon-test-deps:	tests-preload.so
	$(MAKE) -C ../daemon

daemon-tests-main:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests.pl

daemon-tests-jb:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-jb.pl

daemon-tests-dtx:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-dtx.pl

daemon-tests-dtx-cn:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-dtx-cn.pl

daemon-tests-pubsub:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-pubsub.pl

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

daemon-tests-redis-json:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-redis-json.pl

daemon-tests-audio-player:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-audio-player.pl

daemon-tests-audio-player-play-media:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-audio-player-play-media.pl

daemon-tests-rtpp-flags:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-rtpp-flags.pl

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
	mix_in_x64_avx2.o mix_in_x64_sse2.o mix_in_x64_avx512bw.o bufferpool.o uring.o arena.o

test-transcode:	test-transcode.o $(COMMONOBJS) codeclib.strhash.o resample.o codec.o ssrc.o call.o ice.o helpers.o \
	kernel.o media_socket.o stun.o bencode.o socket.o poller.o dtls.o recording.o statistics.o \
	rtcp.o redis.o iptables.o graphite.o call_interfaces.strhash.o sdp.strhash.o rtp.o crypto.o \
	control_ng_flags_parser.o control_ng.strhash.o \
	streambuf.o cookie_cache.o udp_listener.o homer.o load.o cdr.o dtmf.o timerthread.o \
	media_player.o jitter_buffer.o dtmflib.o t38.o tcp_listener.o mqtt.o janus.strhash.o websocket.o \
	cli.strhash.o mvr2s_x64_avx2.o mvr2s_x64_avx512.o audio_player.o mix_buffer.o \
	mix_in_x64_avx2.o mix_in_x64_sse2.o mix_in_x64_avx512bw.o bufferpool.o uring.o arena.o

test-resample:	test-resample.o $(COMMONOBJS) codeclib.strhash.o resample.o dtmflib.o mvr2s_x64_avx2.o \
	mvr2s_x64_avx512.o bencode.o

test-payload-tracker: test-payload-tracker.o $(COMMONOBJS) ssrc.o helpers.o auxlib.o rtp.o crypto.o codeclib.strhash.o \
	resample.o dtmflib.o mvr2s_x64_avx2.o mvr2s_x64_avx512.o bufferpool.o uring.o poller.o bencode.o

test-kernel-module: test-kernel-module.o $(COMMONOBJS) kernel.o

test-const_str_hash.strhash: test-const_str_hash.strhash.o $(COMMONOBJS) bencode.o

PRELOAD_CFLAGS += -D_GNU_SOURCE -std=c11
PRELOAD_LIBS += -ldl

tests-preload.so:	tests-preload.c
	$(CC) $(PRELOAD_CFLAGS) -o $@ -shared -fPIC $< $(PRELOAD_LIBS)

time-fudge-preload.so:	time-fudge-preload.c
	$(CC) $(PRELOAD_CFLAGS) -o $@ -shared -fPIC $< $(PRELOAD_LIBS)

spandsp_send_fax_pcm.c:	spandsp_logging.h
spandsp_send_fax_t38.c:	spandsp_logging.h
spandsp_recv_fax_t38.c:	spandsp_logging.h
spandsp_recv_fax_pcm.c:	spandsp_logging.h
