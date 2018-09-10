CC ?= gcc


ifeq ($(RTPENGINE_ROOT_DIR),)
	RTPENGINE_ROOT_DIR=..
endif

ifeq ($(RTPENGINE_VERSION),)
  DPKG_PRSCHNGLG= $(shell which dpkg-parsechangelog 2>/dev/null)
  ifneq ($(DPKG_PRSCHNGLG),)
    DPKG_PRSCHNGLG=$(shell dpkg-parsechangelog -l$(RTPENGINE_ROOT_DIR)/debian/changelog | awk '/^Version: / {print $$2}')
  endif
  GIT_BR_COMMIT=git-$(shell git rev-parse --abbrev-ref --symbolic-full-name HEAD)-$(shell git rev-parse --short HEAD)

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

# look for libsystemd
ifeq ($(shell pkg-config --exists libsystemd && echo yes),yes)
have_libsystemd := yes
endif
ifeq ($(have_libsystemd),yes)
CFLAGS+=	$(shell pkg-config --cflags libsystemd)
CFLAGS+=	-DHAVE_LIBSYSTEMD
LDLIBS+=	$(shell pkg-config --libs libsystemd)
endif

ifeq ($(DBG),yes)
CFLAGS+=	-D__DEBUG=1
else
CFLAGS+=	-O3
endif


ifneq ($(DBG),yes)
  DPKG_BLDFLGS=	$(shell which dpkg-buildflags 2>/dev/null)
  ifneq ($(DPKG_BLDFLGS),)
    # support http://wiki.debian.org/Hardening for >=wheezy
    CFLAGS+=	$(shell dpkg-buildflags --get CFLAGS)
    CPPFLAGS+=	$(shell dpkg-buildflags --get CPPFLAGS)
    LDFLAGS+=	$(shell dpkg-buildflags --get LDFLAGS)
    LDLIBS+=	$(shell dpkg-buildflags --get LDLIBS)
  endif
endif
