PWD    := $(shell pwd)
KSRC   ?= /lib/modules/$(shell uname -r)/build
KBUILD := $(KSRC)
MEDIAPROXY_VERSION = $(shell dpkg-parsechangelog -l$(M)/../debian/changelog | awk '/^Version: / {print $$2}')
EXTRA_CFLAGS += -DMEDIAPROXY_VERSION="\"$(MEDIAPROXY_VERSION)\""

obj-m        += xt_MEDIAPROXY.o

modules:
		make -C $(KBUILD) M=$(PWD) O=$(KBUILD) modules

clean:
		make -C $(KBUILD) M=$(PWD) clean
