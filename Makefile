RTPENGINE_ROOT_DIR=.
with_transcoding ?= yes

include lib/lib.Makefile

.PHONY:	all distclean clean coverity

all:
	$(MAKE) -C daemon
ifeq ($(with_transcoding),yes)
	$(MAKE) -C recording-daemon
endif
	$(MAKE) -C iptables-extension

coverity:
	$(MAKE) -C daemon
ifeq ($(with_transcoding),yes)
	$(MAKE) -C recording-daemon
endif

.PHONY: with-kernel

with-kernel: all
	$(MAKE) -C kernel-module

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

.PHONY: check

check: all
	$(MAKE) -C t
