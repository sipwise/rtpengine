include ../lib/lib.Makefile

all:
	$(MAKE) $(TARGET)

$(TARGET):	$(OBJS) .depend Makefile
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

debug:
	$(MAKE) DBG=yes all

dep:		.depend

clean:
	rm -f $(OBJS) $(TARGET) $(LIBSRCS) .depend core core.*
	rm -f fix_frame_channel_layout.h fix_frame_channel_layout-test.[co]

.depend:	$(SRCS) $(LIBSRCS) Makefile
	$(CC) $(CFLAGS) -M $(SRCS) $(LIBSRCS) | sed -e 's/:/ .depend:/' > .depend

install:

$(OBJS):	Makefile

$(LIBSRCS):
		rm -f "$@"
		echo '/******** GENERATED FILE ********/' > "$@"
		cat ../lib/"$@" >> "$@"

resample.c:	fix_frame_channel_layout.h

fix_frame_channel_layout.h:	../lib/fix_frame_channel_layout-*
	rm -f fix_frame_channel_layout-test.[co]; \
	ln -s ../lib/fix_frame_channel_layout-test.c; \
	for x in ../lib/fix_frame_channel_layout-*.h; do \
		echo '/******** GENERATED FILE ********/' > "$@"; \
		cat "$$x" >> "$@"; \
		$(MAKE) fix_frame_channel_layout-test.o && break; \
		rm -f fix_frame_channel_layout.h; \
	done; \
	rm -f fix_frame_channel_layout-test.[co]

.PHONY: all debug dep clean install install
