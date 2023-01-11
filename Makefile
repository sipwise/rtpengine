RTPENGINE_ROOT_DIR=.
with_transcoding ?= yes

ifeq ($(DO_ASAN_FLAGS),1)
ASAN_FLAGS = -ggdb -O0 -fsanitize=address -fsanitize=leak -fsanitize=undefined
CFLAGS ?= -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wstrict-prototypes
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
endif
	$(MAKE) -C iptables-extension

install:
	$(MAKE) -C daemon install
ifeq ($(with_transcoding),yes)
	$(MAKE) -C recording-daemon install
endif
	$(MAKE) -C iptables-extension install

coverity:
	$(MAKE) -C daemon
ifeq ($(with_transcoding),yes)
	$(MAKE) -C recording-daemon
endif

.PHONY: with-kernel

with-kernel: all
	$(MAKE) -C kernel-module

install-with-kernel: all install
	$(MAKE) -C kernel-module install

distclean clean:
	$(MAKE) -C daemon clean
	$(MAKE) -C recording-daemon clean
	$(MAKE) -C iptables-extension clean
	$(MAKE) -C kernel-module clean
	$(MAKE) -C t clean

.DEFAULT:
	$(MAKE) -C daemon $@
	$(MAKE) -C recording-daemon $@
	$(MAKE) -C iptables-extension $@
	$(MAKE) -C kernel-module $@

.PHONY: check asan-check

check: all
	$(MAKE) -C t

asan-check:
	DO_ASAN_FLAGS=1 $(MAKE) check
