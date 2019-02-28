include ../lib/lib.Makefile

all:
	$(MAKE) $(TARGET)

$(TARGET):	$(OBJS) .depend Makefile
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

debug:
	$(MAKE) DBG=yes all

dep:		.depend

clean:
	rm -f $(OBJS) $(TARGET) $(LIBSRCS) $(DAEMONSRCS) $(ADD_CLEAN) .depend core core.*
	rm -f fix_frame_channel_layout.h fix_frame_channel_layout-test.[co] *.strhash.c $(HASHSRCS)

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

resample.c:	fix_frame_channel_layout.h

ifeq (, $(shell which gperf))
$(error "No gperf binary found, make sure to have gperf installed")
endif

%.strhash.c:	%.c ../utils/const_str_hash
	../utils/const_str_hash < $< > $@

fix_frame_channel_layout.h:	../lib/fix_frame_channel_layout-*
	echo "Looking for usable alternative for $@"; \
	rm -f fix_frame_channel_layout-test.[co]; \
	ln -s ../lib/fix_frame_channel_layout-test.c; \
	for x in ../lib/fix_frame_channel_layout-*.h; do \
		echo "Trying build with $$x"; \
		rm -f "$@"; \
		echo '/******** GENERATED FILE ********/' > "$@"; \
		cat "$$x" >> "$@"; \
		$(MAKE) fix_frame_channel_layout-test.o && break; \
		echo "Failed build with $$x"; \
		rm -f "$@"; \
	done; \
	rm -f fix_frame_channel_layout-test.[co]; \
	test -f "$@"

.PHONY: all debug dep clean install
