include ../lib/lib.Makefile

all:
	$(MAKE) $(TARGET) $(MANS)

$(TARGET):	$(OBJS) .depend Makefile
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

debug:
	$(MAKE) DBG=yes all

dep:		.depend

BUILD_TEST_ALTS = fix_frame_channel_layout.h dtmf_rx_fillin.h

clean:
	rm -f $(OBJS) $(TARGET) $(LIBSRCS) $(DAEMONSRCS) $(MANS) $(ADD_CLEAN) .depend core core.*
	rm -f $(BUILD_TEST_ALTS) $(BUILD_TEST_ALTS:.h=-test.c) $(BUILD_TEST_ALTS:.h=-test) *.strhash.c $(HASHSRCS)

.depend:	$(SRCS) $(LIBSRCS) $(DAEMONSRCS) Makefile
	$(CC) $(CFLAGS) -M $(SRCS) $(LIBSRCS) $(DAEMONSRCS) | sed -e 's/:/ .depend:/' > .depend

install:

$(OBJS):	Makefile

$(LIBSRCS):	$(patsubst %,../lib/%,$(LIBSRCS))
		rm -f "$@"
		echo '/******** GENERATED FILE ********/' > "$@"
		cat ../lib/"$@" >> "$@"

$(DAEMONSRCS) $(HASHSRCS):	$(patsubst %,../daemon/%,$(DAEMONSRCS)) $(patsubst %,../daemon/%,$(HASHSRCS))
		rm -f "$@"
		echo '/******** GENERATED FILE ********/' > "$@"
		cat ../daemon/"$@" >> "$@"

%.8: %.pod
	pod2man \
		--center="NGCP rtpengine" \
		--date="$(RELEASE_DATE)" \
		--release="$(RTPENGINE_VERSION)" \
		$< $@

resample.c:	fix_frame_channel_layout.h

%.strhash.c:	%.c ../utils/const_str_hash
	../utils/const_str_hash < $< > $@

$(BUILD_TEST_ALTS):	../lib/$(@:.h=-*)
	echo "Looking for usable alternative for $@"; \
	rm -f $(@:.h=-test{.c,}); \
	ln -s ../lib/$(@:.h=-test.c); \
	for x in ../lib/$(@:.h=-*.h); do \
		echo "Trying build with $$x"; \
		rm -f "$@"; \
		echo '/******** GENERATED FILE ********/' > "$@"; \
		cat "$$x" >> "$@"; \
		$(MAKE) $(@:.h=-test) && break; \
		echo "Failed build with $$x"; \
		rm -f "$@"; \
	done; \
	rm -f $(@:.h=-test{.c,}); \
	test -f "$@"

.PHONY: all debug dep clean install
