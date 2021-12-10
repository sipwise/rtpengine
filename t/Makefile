TARGET=		all-tests

with_transcoding ?= yes

CFLAGS?=	-g -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wstrict-prototypes
PRELOAD_CFLAGS := $(CFLAGS)
CFLAGS+=	-pthread -fno-strict-aliasing
CFLAGS+=	-std=c99
CFLAGS+=	$(shell pkg-config --cflags glib-2.0)
CFLAGS+=	$(shell pkg-config --cflags gthread-2.0)
CFLAGS+=	$(shell pkg-config --cflags openssl)
CFLAGS+=	-I. -I../lib/ -I../kernel-module/ -I../include/
CFLAGS+=	-D_GNU_SOURCE
CFLAGS+=	$(shell pkg-config --cflags libpcre)
CFLAGS+=	$(shell pkg-config --cflags json-glib-1.0)
ifeq ($(with_transcoding),yes)
CFLAGS+=	$(shell pkg-config --cflags libavcodec)
CFLAGS+=	$(shell pkg-config --cflags libavformat)
CFLAGS+=	$(shell pkg-config --cflags libavutil)
CFLAGS+=	$(shell pkg-config --cflags libswresample)
CFLAGS+=	$(shell pkg-config --cflags libavfilter)
CFLAGS+=	$(shell pkg-config --cflags spandsp)
CFLAGS+=	-DWITH_TRANSCODING
CFLAGS+=	$(shell pkg-config --cflags zlib)
CFLAGS+=	$(shell pkg-config --cflags libwebsockets)
CFLAGS+=	$(shell pkg-config --cflags libevent_pthreads)
CFLAGS+=	$(shell pkg-config xmlrpc_client --cflags 2> /dev/null || xmlrpc-c-config client --cflags)
CFLAGS+=	$(shell pkg-config xmlrpc --cflags 2> /dev/null)
CFLAGS+=	$(shell pkg-config xmlrpc_util --cflags 2> /dev/null)
ifeq ($(with_amr_tests),yes)
CFLAGS+=	-DWITH_AMR_TESTS
endif
CFLAGS+=	$(shell mysql_config --cflags)
else
CFLAGS+=	-DWITHOUT_CODECLIB
endif

LDLIBS=		-lm
LDLIBS+=	$(shell pkg-config --libs glib-2.0)
LDLIBS+=	$(shell pkg-config --libs gthread-2.0)
LDLIBS+=	$(shell pkg-config --libs libcrypto)
LDLIBS+=	$(shell pkg-config --libs openssl)
LDLIBS+=	$(shell pkg-config --libs libpcre)
LDLIBS+=	$(shell pkg-config --libs json-glib-1.0)
ifeq ($(with_transcoding),yes)
LDLIBS+=	$(shell pkg-config --libs libavcodec)
LDLIBS+=	$(shell pkg-config --libs libavformat)
LDLIBS+=	$(shell pkg-config --libs libavutil)
LDLIBS+=	$(shell pkg-config --libs libswresample)
LDLIBS+=	$(shell pkg-config --libs libavfilter)
LDLIBS+=	$(shell pkg-config --libs spandsp)
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

SRCS=		test-bitstr.c aes-crypt.c aead-aes-crypt.c test-const_str_hash.strhash.c
LIBSRCS=	loglib.c auxlib.c str.c rtplib.c ssllib.c
DAEMONSRCS=	crypto.c ssrc.c aux.c rtp.c
HASHSRCS=

ifeq ($(with_transcoding),yes)
SRCS+=		test-transcode.c test-dtmf-detect.c test-payload-tracker.c test-resample.c test-stats.c
SRCS+=		spandsp_recv_fax_pcm.c spandsp_recv_fax_t38.c spandsp_send_fax_pcm.c \
		spandsp_send_fax_t38.c
ifeq ($(with_amr_tests),yes)
SRCS+=		test-amr-decode.c test-amr-encode.c
endif
LIBSRCS+=	codeclib.c resample.c socket.c streambuf.c dtmflib.c
DAEMONSRCS+=	codec.c call.c ice.c kernel.c media_socket.c stun.c bencode.c poller.c \
		dtls.c recording.c statistics.c rtcp.c redis.c iptables.c graphite.c \
		cookie_cache.c udp_listener.c homer.c load.c cdr.c dtmf.c timerthread.c \
		media_player.c jitter_buffer.c t38.c tcp_listener.c mqtt.c websocket.c cli.c
HASHSRCS+=	call_interfaces.c control_ng.c sdp.c janus.c
endif

OBJS=		$(SRCS:.c=.o) $(LIBSRCS:.c=.o) $(DAEMONSRCS:.c=.o) $(HASHSRCS:.c=.strhash.o)

COMMONOBJS=	str.o auxlib.o rtplib.o loglib.o ssllib.o

include ../lib/common.Makefile

.PHONY:		all-tests unit-tests daemon-tests daemon-tests \
	daemon-tests-main daemon-tests-jb daemon-tests-dtx daemon-tests-dtx-cn daemon-tests-pubsub \
	daemon-tests-intfs daemon-tests-stats

TESTS=		test-bitstr aes-crypt aead-aes-crypt test-const_str_hash.strhash
ifeq ($(with_transcoding),yes)
TESTS+=		test-transcode test-dtmf-detect test-payload-tracker test-resample test-stats
ifeq ($(with_amr_tests),yes)
TESTS+=		test-amr-decode test-amr-encode
endif
endif

ADD_CLEAN=	tests-preload.so $(TESTS)

ifeq ($(with_transcoding),yes)
all-tests:	unit-tests daemon-tests
else
all-tests:	unit-tests
endif
	true # override linking recipe from common.Makefile

unit-tests:	$(TESTS)
	for x in $(TESTS); do echo testing: $$x; G_DEBUG=fatal-warnings ./$$x || exit 1; done

daemon-tests: daemon-tests-main daemon-tests-jb daemon-tests-pubsub daemon-tests-websocket \
	daemon-tests-intfs daemon-tests-stats

daemon-test-deps:	tests-preload.so
	$(MAKE) -C ../daemon

daemon-tests-main:	daemon-test-deps
	rm -rf fake-$@-sockets
	mkdir fake-$@-sockets
	LD_PRELOAD=../t/tests-preload.so RTPE_BIN=../daemon/rtpengine TEST_SOCKET_PATH=./fake-$@-sockets \
		   perl -I../perl auto-daemon-tests.pl
	test "$$(ls fake-$@-sockets)" = ""
	rmdir fake-$@-sockets

daemon-tests-jb:	daemon-test-deps
	rm -rf fake-$@-sockets
	mkdir fake-$@-sockets
	LD_PRELOAD=../t/tests-preload.so RTPE_BIN=../daemon/rtpengine TEST_SOCKET_PATH=./fake-$@-sockets \
		   perl -I../perl auto-daemon-tests-jb.pl
	test "$$(ls fake-$@-sockets)" = ""
	rmdir fake-$@-sockets

daemon-tests-dtx:	daemon-test-deps
	rm -rf fake-$@-sockets
	mkdir fake-$@-sockets
	LD_PRELOAD=../t/tests-preload.so RTPE_BIN=../daemon/rtpengine TEST_SOCKET_PATH=./fake-$@-sockets \
		   perl -I../perl auto-daemon-tests-dtx.pl
	test "$$(ls fake-$@-sockets)" = ""
	rmdir fake-$@-sockets

daemon-tests-dtx-cn:	daemon-test-deps
	rm -rf fake-$@-sockets
	mkdir fake-$@-sockets
	LD_PRELOAD=../t/tests-preload.so RTPE_BIN=../daemon/rtpengine TEST_SOCKET_PATH=./fake-$@-sockets \
		   perl -I../perl auto-daemon-tests-dtx-cn.pl
	test "$$(ls fake-$@-sockets)" = ""
	rmdir fake-$@-sockets

daemon-tests-pubsub:	daemon-test-deps
	rm -rf fake-$@-sockets
	mkdir fake-$@-sockets
	LD_PRELOAD=../t/tests-preload.so RTPE_BIN=../daemon/rtpengine TEST_SOCKET_PATH=./fake-$@-sockets \
		   perl -I../perl auto-daemon-tests-pubsub.pl
	test "$$(ls fake-$@-sockets)" = ""
	rmdir fake-$@-sockets

daemon-tests-stats:	daemon-test-deps
	rm -rf fake-$@-sockets
	mkdir fake-$@-sockets
	LD_PRELOAD=../t/tests-preload.so RTPE_BIN=../daemon/rtpengine TEST_SOCKET_PATH=./fake-$@-sockets \
		   perl -I../perl auto-daemon-tests-stats.pl
	test "$$(ls fake-$@-sockets)" = ""
	rmdir fake-$@-sockets

daemon-tests-websocket:	daemon-test-deps
	rm -rf fake-$@-sockets
	mkdir fake-$@-sockets
	LD_PRELOAD=../t/tests-preload.so RTPE_BIN=../daemon/rtpengine TEST_SOCKET_PATH=./fake-$@-sockets \
		   python3 auto-daemon-tests-websocket.py
	test "$$(ls fake-$@-sockets)" = ""
	rmdir fake-$@-sockets

daemon-tests-intfs:	daemon-test-deps
	rm -rf fake-$@-sockets
	mkdir fake-$@-sockets
	LD_PRELOAD=../t/tests-preload.so RTPE_BIN=../daemon/rtpengine TEST_SOCKET_PATH=./fake-$@-sockets \
		   perl -I../perl auto-daemon-tests-intfs.pl
	test "$$(ls fake-$@-sockets)" = ""
	rmdir fake-$@-sockets

test-bitstr:	test-bitstr.o

spandsp_send_fax_pcm:	spandsp_send_fax_pcm.o

spandsp_recv_fax_pcm:	spandsp_recv_fax_pcm.o

spandsp_send_fax_t38:	spandsp_send_fax_t38.o

spandsp_recv_fax_t38:	spandsp_recv_fax_t38.o

spandsp_raw_fax_tests: spandsp_send_fax_pcm spandsp_recv_fax_pcm spandsp_send_fax_t38 spandsp_recv_fax_t38

test-amr-decode: test-amr-decode-test.o $(COMMONOBJS) codeclib.o resample.o dtmflib.o

test-amr-encode: test-amr-encode-test.o $(COMMONOBJS) codeclib.o resample.o dtmflib.o

test-dtmf-detect: test-dtmf-detect.o

aes-crypt:	aes-crypt.o $(COMMONOBJS) crypto.o

aead-aes-crypt:	aead-aes-crypt.o $(COMMONOBJS) crypto.o

test-stats:	test-stats.o $(COMMONOBJS) codeclib.o resample.o codec.o ssrc.o call.o ice.o aux.o \
	kernel.o media_socket.o stun.o bencode.o socket.o poller.o dtls.o recording.o statistics.o \
	rtcp.o redis.o iptables.o graphite.o call_interfaces.strhash.o sdp.strhash.o rtp.o crypto.o \
	control_ng.strhash.o graphite.o \
	streambuf.o cookie_cache.o udp_listener.o homer.o load.o cdr.o dtmf.o timerthread.o \
	media_player.o jitter_buffer.o dtmflib.o t38.o tcp_listener.o mqtt.o janus.strhash.o \
	websocket.o cli.o

test-transcode:	test-transcode.o $(COMMONOBJS) codeclib.o resample.o codec.o ssrc.o call.o ice.o aux.o \
	kernel.o media_socket.o stun.o bencode.o socket.o poller.o dtls.o recording.o statistics.o \
	rtcp.o redis.o iptables.o graphite.o call_interfaces.strhash.o sdp.strhash.o rtp.o crypto.o \
	control_ng.strhash.o \
	streambuf.o cookie_cache.o udp_listener.o homer.o load.o cdr.o dtmf.o timerthread.o \
	media_player.o jitter_buffer.o dtmflib.o t38.o tcp_listener.o mqtt.o janus.strhash.o websocket.o \
	cli.o

test-resample:	test-resample.o $(COMMONOBJS) codeclib.o resample.o dtmflib.o

test-payload-tracker: test-payload-tracker.o $(COMMONOBJS) ssrc.o aux.o auxlib.o rtp.o crypto.o codeclib.o \
	resample.o dtmflib.o

test-kernel-module: test-kernel-module.o $(COMMONOBJS) kernel.o

test-const_str_hash.strhash: test-const_str_hash.strhash.o $(COMMONOBJS)

PRELOAD_CFLAGS += -D_GNU_SOURCE -std=c99
PRELOAD_LIBS += -ldl

tests-preload.so:	tests-preload.c
	$(CC) $(PRELOAD_CFLAGS) -o $@ -shared -fPIC $< $(LDFLAGS) $(PRELOAD_LIBS)

spandsp_send_fax_pcm.c:	spandsp_logging.h
spandsp_send_fax_t38.c:	spandsp_logging.h
spandsp_recv_fax_t38.c:	spandsp_logging.h
spandsp_recv_fax_pcm.c:	spandsp_logging.h
