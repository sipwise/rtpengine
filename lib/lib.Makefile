CC ?= gcc

CFLAGS+=	-DRTPENGINE_VERSION="\"$(RTPENGINE_VERSION)\""

CFLAGS+=	$(CFLAGS_LIBSYSTEMD)
LDLIBS+=	$(LDLIBS_LIBSYSTEMD)

# look for liburing
ifeq (,$(filter pkg.ngcp-rtpengine.nouring,${DEB_BUILD_PROFILES}))
CFLAGS+=	$(CFLAGS_LIBURING)
LDLIBS+=	$(LDLIBS_LIBURING)
endif

ifeq ($(DBG),yes)
CFLAGS+=	-D__DEBUG=1
endif

# keep debugging symbols for backtrace_symbols()
LDFLAGS += -rdynamic

ifneq ($(DBG),yes)
  ifeq (,$(filter $(CFLAGS),-O0))
    CFLAGS+=	$(CFLAGS_DEFAULT)
    CPPFLAGS+=	$(CPPFLAGS_DEFAULT)
    LDFLAGS+=	$(LDFLAGS_DEFAULT)
  endif
endif


DATE_FMT = +%Y-%m-%d
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
