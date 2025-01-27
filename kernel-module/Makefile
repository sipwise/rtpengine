PWD    := $(shell pwd)
KSRC   ?= /lib/modules/$(shell uname -r)/build
KBUILD := $(KSRC)
M      ?= $(PWD)

ifeq ($(RTPENGINE_VERSION),)
  DPKG_PRSCHNGLG := $(shell which dpkg-parsechangelog 2>/dev/null)
  DEB_CHANGELOG := $(shell test -f $(M)/../debian/changelog && echo $(M)/../debian/changelog || echo $(M)/debian/changelog)
  ifneq ($(DPKG_PRSCHNGLG),)
    DPKG_PRSCHNGLG := $(shell dpkg-parsechangelog -l$(DEB_CHANGELOG) | awk '/^Version: / {print $$2}')
  endif
  GIT_BR_COMMIT := git-$(shell cd $(M) && git rev-parse --abbrev-ref --symbolic-full-name HEAD 2> /dev/null)-$(shell cd $(M) && git rev-parse --short HEAD 2> /dev/null)

  ifneq ($(DPKG_PRSCHNGLG),)
    RTPENGINE_VERSION+=$(DPKG_PRSCHNGLG)
  endif
  ifneq ($(GIT_BR_COMMIT),git--)
    RTPENGINE_VERSION+=$(GIT_BR_COMMIT)
  endif

  ifeq ($(RTPENGINE_VERSION),)
    RTPENGINE_VERSION+=undefined
  endif
endif
EXTRA_CFLAGS+=	-DRTPENGINE_VERSION="\"$(RTPENGINE_VERSION)\""

obj-m        += xt_RTPENGINE.o

.PHONY:		modules clean patch install

modules:
		$(MAKE) -C $(KBUILD) M=$(PWD) O=$(KBUILD) modules

clean:
		$(MAKE) -C $(KBUILD) M=$(PWD) clean || true

patch:
		../utils/patch-kernel magic "$(PWD)" "$(KERNEL)" "$(RTPENGINE_VERSION)"

install:
	install -D xt_RTPENGINE.ko $(DESTDIR)/lib/modules/$(shell uname -r)/updates/xt_RTPENGINE.ko
	depmod -a
