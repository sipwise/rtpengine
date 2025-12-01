KSRC   ?= /lib/modules/$(shell uname -r)/build
KBUILD := $(KSRC)
M      ?= $(CURDIR)

export M

include $(M)/rtpengine-kmod.mk

ccflags-y    += -DRTPENGINE_VERSION="\"$(RTPENGINE_VERSION)\""

obj-m        += nft_rtpengine.o

.PHONY:		modules clean install

modules:
		$(MAKE) -C $(KBUILD) M=$(CURDIR) O=$(KBUILD) modules

clean:
		$(MAKE) -C $(KBUILD) M=$(CURDIR) clean || true
		rm -f rtpengine-kmod.mk

install:
	install -D nft_rtpengine.ko $(DESTDIR)/lib/modules/$(shell uname -r)/updates/nft_rtpengine.ko
	depmod -a

$(M)/rtpengine-kmod.mk:
	$(M)/gen-rtpengine-kmod-flags >$@
