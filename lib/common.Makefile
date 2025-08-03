.DEFAULT_GOAL := all

include ../lib/lib.Makefile

CFLAGS += -fPIE
LDFLAGS += -pie
LDLIBS += -latomic

all:	$(TARGET) $(MANS)


OBJS = $(SRCS:.c=.o)

LIBOBJS = $(LIBSRCS:.c=.o)

DAEMONOBJS = $(DAEMONSRCS:.c=.o)

LIBASMOBJS = $(LIBASM:.S=.o)

ALLOBJS = $(OBJS) $(LIBOBJS) $(LIBASMOBJS) $(DAEMONOBJS)


$(OBJS): %.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

$(LIBOBJS): %.o: ../lib/%.c
	$(CC) -c $(CFLAGS) $< -o $@

$(DAEMONOBJS): %.o: ../daemon/%.c
	$(CC) -c $(CFLAGS) $< -o $@

$(LIBASMOBJS): %.o: ../lib/%.S
	$(CC) -c $(ASFLAGS) $< -o $@


$(TARGET):	$(ALLOBJS) Makefile
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(ALLOBJS) $(LDLIBS)


debug:
	$(MAKE) DBG=yes all


BUILD_TEST_ALTS = ../lib/fix_frame_channel_layout.h ../lib/dtmf_rx_fillin.h ../lib/spandsp_logging.h

clean:
	rm -f $(ALLOBJS) $(TARGET) $(LIBSRCS) $(LIBASM) $(DAEMONSRCS) $(MANS) $(ADD_CLEAN) core core.*
	rm -f $(BUILD_TEST_ALTS) $(BUILD_TEST_ALTS:.h=-test) *.strhash.c

install:

$(ALLOBJS):	Makefile ../include/* ../lib/*.h ../kernel-module/*.h

%.8: ../docs/%.md
	cat "$<" | sed '/^# /d; s/^##/#/' | \
		pandoc -s -t man \
			-M "footer:$(RTPENGINE_VERSION)" \
			-M "date:$(BUILD_DATE)" \
			-o "$@"

resample.c ../lib/codeclib.strhash.c mix.c packet.c:	../lib/fix_frame_channel_layout.h

ifeq ($(with_transcoding),yes)
../daemon/codec.c codec.c:	../lib/dtmf_rx_fillin.h
media_player.c ../daemon/media_player.c ../daemon/codec.c codec.c test-resample.c:	../lib/fix_frame_channel_layout.h
endif

t38.c ../daemon/t38.c:		../lib/spandsp_logging.h

%.strhash.c:	%.c ../utils/const_str_hash
	../utils/const_str_hash "$<" $(CFLAGS) < "$<" > "$@"

$(BUILD_TEST_ALTS):	$(wildcard $(subst .h,-*,$(BUILD_TEST_ALTS)))
	../utils/build_test_wrapper "$@" 2> /dev/null

.PHONY: all debug clean install
