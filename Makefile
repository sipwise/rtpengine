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

.PHONY: with-kernel

with-kernel: all
	$(MAKE) -C kernel-module

distclean clean:
	$(MAKE) -C daemon clean
	$(MAKE) -C recording-daemon clean
	$(MAKE) -C iptables-extension clean
	$(MAKE) -C kernel-module clean
	$(MAKE) -C t clean
	rm -rf project.tgz cov-int

.DEFAULT:
	$(MAKE) -C daemon $@
	$(MAKE) -C recording-daemon $@
	$(MAKE) -C iptables-extension $@
	$(MAKE) -C kernel-module $@

.PHONY: check

check: all
	$(MAKE) -C t

coverity:
	cov-build --dir cov-int $(MAKE) check
	tar -czf project.tgz cov-int
	curl --form token=$(COVERITY_RTPENGINE_TOKEN) \
	  --form email=$(DEBEMAIL) \
	  --form file=@project.tgz \
	  --form version="$(RTPENGINE_VERSION)" \
	  --form description="automatic upload" \
	  https://scan.coverity.com/builds?project=$(COVERITY_RTPENGINE_PROJECT)
