.DEFAULT_GOAL := all

include ../lib/lib.Makefile

all:	$(TARGET) $(MANS)


SRCS := $(SRCS) $(patsubst %,$(top_srcdir)/lib/%,$(LIBSRCS))

OBJS := $(SRCS:.c=.o)

ASM := $(ASM) $(patsubst %,$(top_srcdir)/lib/%,$(LIBASM))

OBJS := $(OBJS) $(ASM:.S=.o)


$(TARGET):	$(OBJS) Makefile
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)


debug:
	$(MAKE) DBG=yes all


BUILD_TEST_ALTS := ../lib/fix_frame_channel_layout.compat \
		   ../lib/dtmf_rx_fillin.compat \
		   ../lib/spandsp_logging.compat

clean:
	rm -f $(OBJS) $(TARGET) $(MANS) $(ADD_CLEAN) core core.*
	rm -f $(BUILD_TEST_ALTS) $(BUILD_TEST_ALTS:.compat=-test) *.strhash.c

install:

$(OBJS):	Makefile ../include/* ../lib/*.h ../kernel-module/*.h

%.8: ../docs/%.md
	cat "$<" | sed '/^# /d; s/^##/#/' | \
		pandoc -s -t man \
			-M "footer:$(RTPENGINE_VERSION)" \
			-M "date:$(BUILD_DATE)" \
			-o "$@"

resample.c codeclib.strhash.c mix.c packet.c:	../lib/fix_frame_channel_layout.compat

ifeq ($(with_transcoding),yes)
../daemon/codec.c codec.c:	../lib/dtmf_rx_fillin.compat
media_player.c ../daemon/media_player.c ../daemon/codec.c codec.c test-resample.c:	../lib/fix_frame_channel_layout.compat
endif

t38.c ../daemon/t38.c:		../lib/spandsp_logging.compat

%.strhash.c:	%.c ../utils/const_str_hash
	../utils/const_str_hash "$<" $(CFLAGS) < "$<" > "$@"

$(BUILD_TEST_ALTS):	$(wildcard $(subst .compat,-*,$(BUILD_TEST_ALTS)))
	../utils/build_test_wrapper "$@"

.PHONY: all debug clean install
