KSRC   ?= /lib/modules/$(shell uname -r)/build
KBUILD := $(KSRC)
M      ?= $(CURDIR)

export M

include rtpengine-kmod.mk

EXTRA_CFLAGS+=	-DRTPENGINE_VERSION="\"$(RTPENGINE_VERSION)\""

obj-m        += xt_RTPENGINE.o

.PHONY:		modules clean patch install

modules:
		$(MAKE) -C $(KBUILD) M=$(CURDIR) O=$(KBUILD) modules

clean:
		$(MAKE) -C $(KBUILD) M=$(CURDIR) clean || true
		rm -f rtpengine-kmod.mk

patch:
		../utils/patch-kernel magic "$(CURDIR)" "$(KERNEL)" "$(RTPENGINE_VERSION)"

install:
	install -D xt_RTPENGINE.ko $(DESTDIR)/lib/modules/$(shell uname -r)/updates/xt_RTPENGINE.ko
	depmod -a

rtpengine-kmod.mk:
	./gen-rtpengine-kmod-flags >$@
