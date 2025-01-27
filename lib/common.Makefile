include ../lib/lib.Makefile

CFLAGS += -fPIE
LDFLAGS += -pie
LDLIBS += -latomic

all:	$(TARGET) $(MANS)

$(TARGET):	$(OBJS) Makefile
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

debug:
	$(MAKE) DBG=yes all

BUILD_TEST_ALTS = fix_frame_channel_layout.h dtmf_rx_fillin.h spandsp_logging.h

clean:
	rm -f $(OBJS) $(TARGET) $(LIBSRCS) $(LIBASM) $(DAEMONSRCS) $(MANS) $(ADD_CLEAN) core core.*
	rm -f $(BUILD_TEST_ALTS) $(BUILD_TEST_ALTS:.h=-test.c) $(BUILD_TEST_ALTS:.h=-test) *.strhash.c $(HASHSRCS)

install:

$(OBJS):	Makefile ../include/* ../lib/*.h ../kernel-module/*.h

$(LIBSRCS):	$(patsubst %,../lib/%,$(LIBSRCS))
		( echo '/******** GENERATED FILE ********/' && \
		echo '#line 1' && \
		cat ../lib/"$@" ) > "$@"

$(LIBASM):	$(patsubst %,../lib/%,$(LIBASM))
		( echo '/******** GENERATED FILE ********/' && \
		echo '#line 1' && \
		cat ../lib/"$@" ) > "$@"

$(DAEMONSRCS) $(HASHSRCS):	$(patsubst %,../daemon/%,$(DAEMONSRCS)) $(patsubst %,../daemon/%,$(HASHSRCS))
		( echo '/******** GENERATED FILE ********/' && \
		echo '#line 1' && \
		cat ../daemon/"$@" ) > "$@"

%.8: ../docs/%.md
	cat "$<" | sed '/^# /d; s/^##/#/' | \
		pandoc -s -t man \
			-M "footer:$(RTPENGINE_VERSION)" \
			-M "date:$(BUILD_DATE)" \
			-o "$@"

resample.c codeclib.strhash.c mix.c packet.c:	fix_frame_channel_layout.h

ifeq ($(with_transcoding),yes)
codec.c:	dtmf_rx_fillin.h
media_player.c codec.c test-resample.c:	fix_frame_channel_layout.h
endif

t38.c:		spandsp_logging.h

%.strhash.c:	%.c ../utils/const_str_hash
	../utils/const_str_hash "$<" < "$<" > "$@"

$(BUILD_TEST_ALTS):	$(wildcard ../lib/$(subst .h,-*,$(BUILD_TEST_ALTS)))
	../utils/build_test_wrapper "$@" 2> /dev/null

.PHONY: all debug clean install
