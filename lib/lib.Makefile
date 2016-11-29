CC ?= gcc


ifeq ($(RTPENGINE_VERSION),)
  DPKG_PRSCHNGLG= $(shell which dpkg-parsechangelog 2>/dev/null)
  ifneq ($(DPKG_PRSCHNGLG),)
    DPKG_PRSCHNGLG=$(shell dpkg-parsechangelog -l../debian/changelog | awk '/^Version: / {print $$2}')
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
CFLAGS+=	-DRTPENGINE_VERSION="\"$(RTPENGINE_VERSION)\""


ifeq ($(DBG),yes)
CFLAGS+=	-D__DEBUG=1
else
CFLAGS+=	-O3
endif


ifneq ($(DBG),yes)
  DPKG_BLDFLGS=	$(shell which dpkg-buildflags 2>/dev/null)
  ifneq ($(DPKG_BLDFLGS),)
    # support http://wiki.debian.org/Hardening for >=wheezy
    CFLAGS+=	`dpkg-buildflags --get CFLAGS`
    CPPFLAGS+=	`dpkg-buildflags --get CPPFLAGS`
    LDFLAGS+=	`dpkg-buildflags --get LDFLAGS`
  endif
endif
