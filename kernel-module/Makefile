PWD    := $(shell pwd)
KSRC   ?= /lib/modules/$(shell uname -r)/build
KBUILD := $(KSRC)

ifneq ($(MEDIAPROXY_VERSION),)
  EXTRA_CFLAGS += -DMEDIAPROXY_VERSION="\"$(MEDIAPROXY_VERSION)\""
else
  DPKG_PRSCHNGLG= $(shell which dpkg-parsechangelog 2>/dev/null)
  ifneq ($(DPKG_PRSCHNGLG),)
    EXTRA_CFLAGS += -DMEDIAPROXY_VERSION="\"$(shell dpkg-parsechangelog -l$(M)/../debian/changelog | awk '/^Version: / {print $$2}')\""
  else
    EXTRA_CFLAGS += -DMEDIAPROXY_VERSION="\"undefined\""
  endif
endif
EXTRA_CFLAGS += -D__MP_EXTERNAL

obj-m        += xt_MEDIAPROXY.o

.PHONY:		modules clean patch

modules:
		make -C $(KBUILD) M=$(PWD) O=$(KBUILD) modules

clean:
		make -C $(KBUILD) M=$(PWD) clean

patch:
		../utils/patch-kernel magic "$(PWD)" "$(KERNEL)" "$(MEDIAPROXY_VERSION)"
