.DEFAULT_GOAL := all

with_transcoding ?= yes

export top_srcdir = $(CURDIR)

# Initialize all flags, so that we only compute them once.
include lib/deps.Makefile

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
	$(MAKE) -C lib clean
	rm -f config.mk

.DEFAULT:
	$(MAKE) -C daemon $@
	$(MAKE) -C recording-daemon $@
	$(MAKE) -C perf-tester
	$(MAKE) -C kernel-module $@

.PHONY: check asan-check asan

check: all
	$(MAKE) -C t

asan-check:
	DO_ASAN_FLAGS=1 $(MAKE) check

asan:
	DO_ASAN_FLAGS=1 $(MAKE)
