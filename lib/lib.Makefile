CC ?= gcc


ifeq ($(RTPENGINE_ROOT_DIR),)
	RTPENGINE_ROOT_DIR=..
endif

HAVE_DPKG_PARSECHANGELOG := $(shell which dpkg-parsechangelog 2>/dev/null)

ifeq ($(RELEASE_DATE),)
  ifneq ($(HAVE_DPKG_PARSECHANGELOG),)
    RELEASE_DATE := $(shell date -u -d "@$$(dpkg-parsechangelog -l$(RTPENGINE_ROOT_DIR)/debian/changelog -STimestamp)" '+%F')
  endif
  ifeq ($(RELEASE_DATE),)
    RELEASE_DATE := undefined
  endif
endif

ifeq ($(RTPENGINE_VERSION),)
  ifneq ($(HAVE_DPKG_PARSECHANGELOG),)
    DPKG_PRSCHNGLG := $(shell dpkg-parsechangelog -l$(RTPENGINE_ROOT_DIR)/debian/changelog | awk '/^Version: / {print $$2}')
  endif
  GIT_BR_COMMIT := git-$(shell git rev-parse --abbrev-ref --symbolic-full-name HEAD 2> /dev/null)-$(shell git rev-parse --short HEAD 2> /dev/null)

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
CFLAGS+=	-DRTPENGINE_VERSION="\"$(RTPENGINE_VERSION)\""

# look for libsystemd
have_libsystemd := $(shell pkg-config --exists libsystemd && echo yes)
ifeq ($(have_libsystemd),yes)
CFLAGS+=	$(shell pkg-config --cflags libsystemd)
CFLAGS+=	-DHAVE_LIBSYSTEMD
LDLIBS+=	$(shell pkg-config --libs libsystemd)
endif

# look for liburing
ifeq (,$(filter pkg.ngcp-rtpengine.nouring,${DEB_BUILD_PROFILES}))
have_liburing := $(shell pkg-config --atleast-version=2.3 liburing && echo yes)
ifeq ($(have_liburing),yes)
CFLAGS+=	$(shell pkg-config --cflags liburing)
CFLAGS+=	-DHAVE_LIBURING
LDLIBS+=	$(shell pkg-config --libs liburing)
endif
endif

ifeq ($(DBG),yes)
CFLAGS+=	-D__DEBUG=1
endif

# keep debugging symbols for backtrace_symbols()
LDFLAGS += -rdynamic

ifneq ($(DBG),yes)
  ifeq (,$(filter $(CFLAGS),-O0))
    DPKG_BLDFLGS := $(shell which dpkg-buildflags 2>/dev/null)
    ifneq ($(DPKG_BLDFLGS),)
      # support http://wiki.debian.org/Hardening for >=wheezy
      CFLAGS+=	$(shell dpkg-buildflags --get CFLAGS)
      CPPFLAGS+=	$(shell dpkg-buildflags --get CPPFLAGS)
      LDFLAGS+=	$(shell dpkg-buildflags --get LDFLAGS)
      LDLIBS+=	$(shell dpkg-buildflags --get LDLIBS)
    endif
    CFLAGS+=-O3 -flto=auto -ffat-lto-objects
    LDFLAGS+=-flto=auto
  endif
endif


DATE_FMT = +%Y-%m-%d
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
