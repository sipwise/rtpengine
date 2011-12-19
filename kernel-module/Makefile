PWD    := $(shell pwd)
KSRC   ?= /lib/modules/$(shell uname -r)/build
KBUILD := $(KSRC)
EXTRA_CFLAGS += -DMEDIAPROXY_VERSION="\"$(shell dpkg-parsechangelog -l$(M)/../debian/changelog | awk '/^Version: / {print $$2}')\""

obj-m        += xt_MEDIAPROXY.o

modules:
		make -C $(KBUILD) M=$(PWD) O=$(KBUILD) modules

clean:
		make -C $(KBUILD) M=$(PWD) clean
