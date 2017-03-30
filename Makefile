RTPENGINE_ROOT_DIR=.

include lib/lib.Makefile

.PHONY:	all clean coverity

all:
	$(MAKE) -C daemon
	$(MAKE) -C recording-daemon
	$(MAKE) -C iptables-extension

with-kernel:
	$(MAKE)
	$(MAKE) -C kernel-module

clean:
	$(MAKE) -C daemon clean
	$(MAKE) -C recording-daemon clean
	$(MAKE) -C iptables-extension clean
	$(MAKE) -C kernel-module clean
	rm -rf project.tgz cov-int

.DEFAULT:
	$(MAKE) -C daemon $@
	$(MAKE) -C recording-daemon $@
	$(MAKE) -C iptables-extension $@
	$(MAKE) -C kernel-module $@

coverity:
	cov-build --dir cov-int $(MAKE)
	tar -czf project.tgz cov-int
	curl --form token=$(COVERITY_RTPENGINE_TOKEN) \
	  --form email=$(DEBEMAIL) \
	  --form file=@project.tgz \
	  --form version="$(RTPENGINE_VERSION)" \
	  --form description="automatic upload" \
	  https://scan.coverity.com/builds?project=$(COVERITY_RTPENGINE_PROJECT)
