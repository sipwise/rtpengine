PWD    := $(shell pwd)
KSRC   ?= /lib/modules/$(shell uname -r)/build
KBUILD := $(KSRC)
ifeq ($(origin MEDIAPROXY_VERSION), undefined)
MEDIAPROXY_VERSION := $(shell dpkg-parsechangelog -l../debian/changelog | awk '/^Version: / {print $$2}')
export MEDIAPROXY_VERSION
endif
EXTRA_CFLAGS += -DMEDIAPROXY_VERSION="\"$(MEDIAPROXY_VERSION)\"" -D__MP_EXTERNAL

obj-m        += xt_MEDIAPROXY.o

.PHONY:		modules clean patch

modules:
		make -C $(KBUILD) M=$(PWD) O=$(KBUILD) modules

clean:
		make -C $(KBUILD) M=$(PWD) clean

patch:
		../utils/patch-kernel magic "$(PWD)" "$(KERNEL)" "$(MEDIAPROXY_VERSION)"
