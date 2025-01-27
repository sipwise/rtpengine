RTPENGINE_ROOT_DIR=.
with_transcoding ?= yes

ifeq ($(DO_ASAN_FLAGS),1)
ASAN_FLAGS = -ggdb -O0 -fsanitize=address -fsanitize=leak -fsanitize=undefined
ifeq ($(origin CFLAGS),undefined)
CFLAGS := -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wstrict-prototypes
else
CFLAGS := $(CFLAGS)
endif
CFLAGS += $(ASAN_FLAGS)
CFLAGS += -DASAN_BUILD
LDFLAGS += $(ASAN_FLAGS)
export CFLAGS
export LDFLAGS
export ASAN_OPTIONS=verify_asan_link_order=0
export UBSAN_OPTIONS=print_stacktrace=1
export G_SLICE=always-malloc
endif

include lib/lib.Makefile

.PHONY:	all distclean clean coverity

all:
	$(MAKE) -C daemon
ifeq ($(with_transcoding),yes)
	$(MAKE) -C recording-daemon
	$(MAKE) -C perf-tester
endif

install:
	$(MAKE) -C daemon install
ifeq ($(with_transcoding),yes)
	$(MAKE) -C recording-daemon install
	$(MAKE) -C perf-tester install
endif
	mkdir -p $(DESTDIR)/usr/libexec/rtpengine/ $(DESTDIR)/usr/bin $(DESTDIR)/usr/share/man/man1
	install -m 0755 utils/rtpengine-get-table $(DESTDIR)/usr/libexec/rtpengine/
	install -m 0755 utils/rtpengine-ctl utils/rtpengine-ng-client $(DESTDIR)/usr/bin/
	install -m 0644 utils/rtpengine-ctl.1 utils/rtpengine-ng-client.1 $(DESTDIR)/usr/share/man/man1

coverity:
	$(MAKE) -C daemon
ifeq ($(with_transcoding),yes)
	$(MAKE) -C recording-daemon
	$(MAKE) -C perf-tester
endif

.PHONY: with-kernel

with-kernel: all
	$(MAKE) -C kernel-module

install-with-kernel: all install
	$(MAKE) -C kernel-module install

distclean clean:
	$(MAKE) -C daemon clean
	$(MAKE) -C recording-daemon clean
	$(MAKE) -C perf-tester clean
	$(MAKE) -C kernel-module clean
	$(MAKE) -C t clean

.DEFAULT:
	$(MAKE) -C daemon $@
	$(MAKE) -C recording-daemon $@
	$(MAKE) -C perf-tester
	$(MAKE) -C kernel-module $@

.PHONY: check asan-check

check: all
	$(MAKE) -C t

asan-check:
	DO_ASAN_FLAGS=1 $(MAKE) check
