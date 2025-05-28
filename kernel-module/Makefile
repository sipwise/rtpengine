KSRC   ?= /lib/modules/$(shell uname -r)/build
KBUILD := $(KSRC)
M      ?= $(CURDIR)

export M

include $(M)/rtpengine-kmod.mk

EXTRA_CFLAGS+=	-DRTPENGINE_VERSION="\"$(RTPENGINE_VERSION)\""

obj-m        += xt_RTPENGINE.o

.PHONY:		modules clean install

modules:
		$(MAKE) -C $(KBUILD) M=$(CURDIR) O=$(KBUILD) modules

clean:
		$(MAKE) -C $(KBUILD) M=$(CURDIR) clean || true
		rm -f rtpengine-kmod.mk

install:
	install -D xt_RTPENGINE.ko $(DESTDIR)/lib/modules/$(shell uname -r)/updates/xt_RTPENGINE.ko
	depmod -a

$(M)/rtpengine-kmod.mk:
	$(M)/gen-rtpengine-kmod-flags >$@
