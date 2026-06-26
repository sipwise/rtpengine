TARGET=		all-tests

export top_srcdir = ..

include ../lib/deps.Makefile

with_transcoding ?= yes

include ../lib/flags.Makefile

PRELOAD_CFLAGS := $(CFLAGS)

CFLAGS += -I$(top_srcdir)/include/
CFLAGS += $(CFLAGS_GLIB)
CFLAGS += $(CFLAGS_GTHREAD)
CFLAGS += $(CFLAGS_OPENSSL)
CFLAGS += $(CFLAGS_LIBPCRE)
CFLAGS += $(CFLAGS_LIBCURL)
CFLAGS += $(CFLAGS_JSON_GLIB)
CFLAGS += $(CFLAGS_LIBIPTC)
ifeq ($(with_transcoding),yes)
CFLAGS += $(CFLAGS_LIBAVCODEC)
CFLAGS += $(CFLAGS_LIBAVFORMAT)
CFLAGS += $(CFLAGS_LIBAVUTIL)
CFLAGS += $(CFLAGS_LIBSWRESAMPLE)
CFLAGS += $(CFLAGS_LIBAVFILTER)
CFLAGS += $(CFLAGS_SPANDSP)
CFLAGS += $(CFLAGS_OPUS)
CFLAGS += $(CFLAGS_LIBZ)
CFLAGS += $(CFLAGS_LIBWEBSOCKETS)
CFLAGS += $(CFLAGS_LIBEVENT)
CFLAGS += -DWITH_TRANSCODING
ifeq ($(RTPENGINE_EXTENDED_TESTS),1)
CFLAGS += -DWITH_AMR_TESTS
endif
CFLAGS += $(CFLAGS_MYSQL)
else
CFLAGS += -DWITHOUT_CODECLIB
endif

LDLIBS += $(LDLIBS_GLIB)
LDLIBS += $(LDLIBS_GTHREAD)
LDLIBS += $(LDLIBS_LIBCRYPTO)
LDLIBS += $(LDLIBS_OPENSSL)
LDLIBS += $(LDLIBS_LIBPCRE)
LDLIBS += $(LDLIBS_LIBCURL)
LDLIBS += $(LDLIBS_JSON_GLIB)
LDLIBS += $(LDLIBS_LIBIPTC)
ifeq ($(with_transcoding),yes)
LDLIBS += $(LDLIBS_LIBAVCODEC)
LDLIBS += $(LDLIBS_LIBAVFORMAT)
LDLIBS += $(LDLIBS_LIBAVUTIL)
LDLIBS += $(LDLIBS_LIBSWRESAMPLE)
LDLIBS += $(LDLIBS_LIBAVFILTER)
LDLIBS += $(LDLIBS_SPANDSP)
LDLIBS += $(LDLIBS_OPUS)
LDLIBS += $(LDLIBS_LIBZ)
LDLIBS += $(LDLIBS_LIBWEBSOCKETS)
LDLIBS += $(LDLIBS_LIBPCAP)
LDLIBS += $(LDLIBS_LIBEVENT)
LDLIBS += $(LDLIBS_LIBHIREDIS)
LDLIBS += $(LDLIBS_MYSQL)
LDLIBS += $(LDLIBS_BCG729)
endif

CFLAGS += $(CFLAGS_CODEC_CHAIN)
LDLIBS += $(LDLIBS_CODEC_CHAIN)

CFLAGS += $(CFLAGS_MQTT)
LDLIBS += $(LDLIBS_MQTT)

COMMONOBJS := ../lib/str.o ../lib/auxlib.o ../lib/rtplib.o ../lib/loglib.o ../lib/ssllib.o

include ../lib/common.Makefile

.PHONY:		all-tests unit-tests daemon-tests daemon-tests \
	daemon-tests-main daemon-tests-jb daemon-tests-dtx daemon-tests-dtx-cn daemon-tests-pubsub \
	daemon-tests-intfs daemon-tests-stats daemon-tests-delay-buffer daemon-tests-delay-timing \
	daemon-tests-evs daemon-tests-player-cache daemon-tests-redis daemon-tests-redis-json \
	daemon-tests-measure-rtp daemon-tests-mos-legacy daemon-tests-mos-fullband daemon-tests-config-file \
	daemon-tests-templ-def daemon-tests-templ-def-offer daemon-tests-t38 daemon-tests-evs-dtx \
	daemon-tests-transform daemon-tests-http daemon-tests-heuristic daemon-tests-asymmetric \
	daemon-tests-dtx-no-shift daemon-tests-rtcp daemon-tests-redis-subscribe daemon-tests-rtp-ext \
	daemon-tests-bundle daemon-tests-dtls \
	daemon-tests-recording daemon-tests-create

TESTS := test-bitstr aes-crypt aead-aes-crypt test-const_str_hash.strhash
ifeq ($(with_transcoding),yes)
TESTS += test-transcode test-dtmf-detect test-payload-tracker test-resample test-stats test-mix-buffer
ifeq ($(RTPENGINE_EXTENDED_TESTS),1)
TESTS += test-amr-decode test-amr-encode
endif
endif
TESTS += s3-auth

ADD_CLEAN := tests-preload.so time-fudge-preload.so $(TESTS) aead-decrypt
ADD_CLEAN += s3-auth

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
	daemon-tests-record-egress-play-media \
	daemon-tests-intfs daemon-tests-stats daemon-tests-player-cache daemon-tests-redis \
	daemon-tests-rtpp-flags daemon-tests-redis-json daemon-tests-measure-rtp daemon-tests-mos-legacy \
	daemon-tests-mos-fullband daemon-tests-config-file \
	daemon-tests-templ-def daemon-tests-templ-def-offer \
	daemon-tests-sdp-manipulations daemon-tests-sdes-manipulations \
	daemon-tests-sdp-orig-replacements daemon-tests-moh daemon-tests-evs-dtx daemon-tests-transform \
	daemon-tests-transcode-config daemon-tests-codec-prefs daemon-tests-http daemon-tests-heuristic \
	daemon-tests-asymmetric daemon-tests-rtcp daemon-tests-redis-subscribe daemon-tests-rtp-ext \
	daemon-tests-bundle daemon-tests-dtls \
	daemon-tests-recording daemon-tests-create \
	daemon-tests-dtx daemon-tests-dtx-cn daemon-tests-dtx-no-shift

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

daemon-tests-create:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-create.pl

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

daemon-tests-record-egress-play-media:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-record-egress-play-media.pl

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

daemon-tests-recording:	daemon-test-deps
	./auto-test-helper "$@" perl -I../perl auto-daemon-tests-recording.pl

test-bitstr:	test-bitstr.o

test-mix-buffer:	test-mix-buffer.o \
	$(COMMONOBJS) \
	../daemon/crypto.o \
	../daemon/helpers.o \
	../daemon/rtp.o \
	../daemon/ssrc.o \
	../lib/bencode.o \
	../lib/bufferpool.o \
	../lib/codeclib.strhash.o \
	../lib/dtmflib.o \
	../lib/mix_buffer.o \
	../lib/mix_in_x64_avx2.o \
	../lib/mix_in_x64_avx512bw.o \
	../lib/mix_in_x64_sse2.o \
	../lib/mvr2s_x64_avx2.o \
	../lib/mvr2s_x64_avx512.o \
	../lib/poller.o \
	../lib/resample.o \
	../lib/uring.o \
	log.o

spandsp_send_fax_pcm:	spandsp_send_fax_pcm.o

spandsp_recv_fax_pcm:	spandsp_recv_fax_pcm.o

spandsp_send_fax_t38:	spandsp_send_fax_t38.o

spandsp_recv_fax_t38:	spandsp_recv_fax_t38.o

spandsp_raw_fax_tests: spandsp_send_fax_pcm spandsp_recv_fax_pcm spandsp_send_fax_t38 spandsp_recv_fax_t38

test-amr-decode: test-amr-decode.o \
	$(COMMONOBJS) \
	../lib/bencode.o \
	../lib/codeclib.strhash.o \
	../lib/dtmflib.o \
	../lib/mvr2s_x64_avx2.o \
	../lib/mvr2s_x64_avx512.o \
	../lib/resample.o \
	log.o

test-amr-encode: test-amr-encode.o \
	$(COMMONOBJS) \
	../lib/bencode.o \
	../lib/codeclib.strhash.o \
	../lib/dtmflib.o \
	../lib/mvr2s_x64_avx2.o \
	../lib/mvr2s_x64_avx512.o \
	../lib/resample.o \
	log.o

test-dtmf-detect: test-dtmf-detect.o

aes-crypt:	aes-crypt.o $(COMMONOBJS) ../daemon/crypto.o ../lib/bencode.o log.o

aead-decrypt:	aead-decrypt.o $(COMMONOBJS) ../daemon/crypto.o ../daemon/rtp.o ../lib/bencode.o log.o

aead-aes-crypt:	aead-aes-crypt.o $(COMMONOBJS) ../daemon/crypto.o ../lib/bencode.o log.o

test-stats:	test-stats.o \
	$(COMMONOBJS) \
	../daemon/arena.o \
	../daemon/audio_player.o \
	../daemon/call_flags.strhash.o \
	../daemon/call_interfaces.o \
	../daemon/call.o \
	../daemon/cdr.o \
	../daemon/cli.strhash.o \
	../daemon/codec.o \
	../daemon/control_ng_flags_parser.o \
	../daemon/control_ng.o \
	../daemon/cookie_cache.o \
	../daemon/crypto.o \
	../daemon/dtls.o  \
	../daemon/dtmf.o \
	../daemon/graphite.o \
	../daemon/graphite.o \
	../daemon/helpers.o \
	../daemon/homer.o \
	../daemon/ice.o \
	../daemon/iptables.o \
	../daemon/janus.strhash.o \
	../daemon/jitter_buffer.o \
	../daemon/kernel.o \
	../daemon/load.o \
	../daemon/media_player.o \
	../daemon/media_socket.o \
	../daemon/mqtt.o \
	../daemon/ng_client.o \
	../daemon/recording.o \
	../daemon/redis.o \
	../daemon/rtcp.o \
	../daemon/rtp.o \
	../daemon/sdp.strhash.o \
	../daemon/ssrc.o \
	../daemon/statistics.o \
	../daemon/stun.o \
	../daemon/t38.o \
	../daemon/tcp_listener.o \
	../daemon/timerthread.o \
	../daemon/udp_listener.o \
	../daemon/websocket.o \
	../lib/bencode.o \
	../lib/bufferpool.o \
	../lib/codeclib.strhash.o \
	../lib/dtmflib.o \
	../lib/mix_buffer.o \
	../lib/mix_in_x64_avx2.o \
	../lib/mix_in_x64_avx512bw.o \
	../lib/mix_in_x64_sse2.o \
	../lib/mvr2s_x64_avx2.o \
	../lib/mvr2s_x64_avx512.o \
	../lib/poller.o \
	../lib/resample.o \
	../lib/socket.o \
	../lib/streambuf.o \
	../lib/uring.o \
	log.o

test-transcode:	test-transcode.o \
	$(COMMONOBJS) \
	../daemon/arena.o \
	../daemon/audio_player.o \
	../daemon/call_flags.strhash.o \
	../daemon/call_interfaces.o \
	../daemon/call.o \
	../daemon/cdr.o \
	../daemon/cli.strhash.o \
	../daemon/codec.o \
	../daemon/control_ng_flags_parser.o \
	../daemon/control_ng.o \
	../daemon/cookie_cache.o \
	../daemon/crypto.o \
	../daemon/dtls.o \
	../daemon/dtmf.o \
	../daemon/graphite.o \
	../daemon/helpers.o \
	../daemon/homer.o \
	../daemon/ice.o \
	../daemon/iptables.o \
	../daemon/janus.strhash.o \
	../daemon/jitter_buffer.o \
	../daemon/kernel.o \
	../daemon/load.o \
	../daemon/media_player.o \
	../daemon/media_socket.o \
	../daemon/mqtt.o \
	../daemon/ng_client.o \
	../daemon/recording.o \
	../daemon/redis.o \
	../daemon/rtcp.o \
	../daemon/rtp.o \
	../daemon/sdp.strhash.o \
	../daemon/ssrc.o \
	../daemon/statistics.o \
	../daemon/stun.o \
	../daemon/t38.o \
	../daemon/tcp_listener.o \
	../daemon/timerthread.o \
	../daemon/udp_listener.o \
	../daemon/websocket.o \
	../lib/bencode.o \
	../lib/bufferpool.o \
	../lib/codeclib.strhash.o \
	../lib/dtmflib.o \
	../lib/mix_buffer.o \
	../lib/mix_in_x64_avx2.o \
	../lib/mix_in_x64_avx512bw.o \
	../lib/mix_in_x64_sse2.o \
	../lib/mvr2s_x64_avx2.o \
	../lib/mvr2s_x64_avx512.o \
	../lib/poller.o \
	../lib/resample.o \
	../lib/socket.o \
	../lib/streambuf.o \
	../lib/uring.o \
	log.o

test-resample:	test-resample.o \
	$(COMMONOBJS) \
	../lib/bencode.o \
	../lib/codeclib.strhash.o \
	../lib/dtmflib.o \
	../lib/mvr2s_x64_avx2.o \
	../lib/mvr2s_x64_avx512.o \
	../lib/resample.o \
	log.o

test-payload-tracker: test-payload-tracker.o \
	$(COMMONOBJS) \
	../daemon/crypto.o \
	../daemon/helpers.o \
	../daemon/rtp.o \
	../daemon/ssrc.o \
	../lib/bencode.o \
	../lib/bufferpool.o \
	../lib/codeclib.strhash.o \
	../lib/dtmflib.o \
	../lib/mvr2s_x64_avx2.o \
	../lib/mvr2s_x64_avx512.o \
	../lib/poller.o \
	../lib/resample.o \
	../lib/uring.o \
	log.o

test-kernel-module: test-kernel-module.o $(COMMONOBJS) ../daemon/kernel.o

test-const_str_hash.strhash: test-const_str_hash.strhash.o $(COMMONOBJS) ../lib/bencode.o log.o

s3-auth:	s3-auth.o ../lib/s3utils.o

kernel-extmap-filter:	kernel-extmap-filter.o

PRELOAD_CFLAGS += -D_GNU_SOURCE -std=c11
PRELOAD_LIBS += -ldl

tests-preload.so:	tests-preload.c
	$(CC) $(PRELOAD_CFLAGS) -o $@ -shared -fPIC $< $(PRELOAD_LIBS)

time-fudge-preload.so:	time-fudge-preload.c
	$(CC) $(PRELOAD_CFLAGS) -o $@ -shared -fPIC $< $(PRELOAD_LIBS)

spandsp_send_fax_pcm.c:	../lib/spandsp_logging.compat
spandsp_send_fax_t38.c:	../lib/spandsp_logging.compat
spandsp_recv_fax_t38.c:	../lib/spandsp_logging.compat
spandsp_recv_fax_pcm.c:	../lib/spandsp_logging.compat
