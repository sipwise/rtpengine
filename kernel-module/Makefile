PWD    := $(shell pwd)
KSRC   ?= /lib/modules/$(shell uname -r)/build
KBUILD := $(KSRC)

ifeq ($(RTPENGINE_VERSION),)
  DPKG_PRSCHNGLG= $(shell which dpkg-parsechangelog 2>/dev/null)
  DEB_CHANGELOG=$(shell test -f $(M)/../debian/changelog && echo $(M)/../debian/changelog || echo $(M)/debian/changelog)
  ifneq ($(DPKG_PRSCHNGLG),)
    DPKG_PRSCHNGLG=$(shell dpkg-parsechangelog -l$(DEB_CHANGELOG) | awk '/^Version: / {print $$2}')
  endif
  GIT_BR_COMMIT=$(shell git branch --no-color --no-column -v 2> /dev/null | awk '/^\*/ {OFS="-"; print "git", $$2, $$3}')

  ifneq ($(DPKG_PRSCHNGLG),)
    RTPENGINE_VERSION+=$(DPKG_PRSCHNGLG)
  endif
  ifneq ($(GIT_BR_COMMIT),)
    RTPENGINE_VERSION+=$(GIT_BR_COMMIT)
  endif

  ifeq ($(RTPENGINE_VERSION),)
    RTPENGINE_VERSION+=undefined
  endif
endif
EXTRA_CFLAGS+=	-DRTPENGINE_VERSION="\"$(RTPENGINE_VERSION)\""

EXTRA_CFLAGS += -D__RE_EXTERNAL

obj-m        += xt_RTPENGINE.o

.PHONY:		modules clean patch

modules:
		make -C $(KBUILD) M=$(PWD) O=$(KBUILD) modules

clean:
		make -C $(KBUILD) M=$(PWD) clean

patch:
		../utils/patch-kernel magic "$(PWD)" "$(KERNEL)" "$(RTPENGINE_VERSION)"
