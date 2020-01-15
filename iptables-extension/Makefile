CC?=gcc
CFLAGS		= -O2 -Wall -Wstrict-prototypes -shared -fPIC
ifneq ($(RTPENGINE_VERSION),)
  CFLAGS	+= -DRTPENGINE_VERSION="\"$(RTPENGINE_VERSION)\""
else
  DPKG_PRSCHNGLG= $(shell which dpkg-parsechangelog 2>/dev/null)
  ifneq ($(DPKG_PRSCHNGLG),)
    CFLAGS	+= -DRTPENGINE_VERSION="\"$(shell dpkg-parsechangelog -l../debian/changelog | awk '/^Version: / {print $$2}')\""
  else
    CFLAGS	+= -DRTPENGINE_VERSION="\"undefined\""
  endif
endif

XTABLES_INSTALLED=$(shell \
  if pkg-config --exists xtables; then \
    echo 'xtables found'; \
  fi)
ifneq ($(XTABLES_INSTALLED),)
XTABLES = 1
CFLAGS  += $(shell pkg-config --cflags --libs xtables)
else
XTABLES = $(shell test -e /usr/include/xtables.h && echo 1)
endif

IPTABLES	= $(shell test -e /usr/include/iptables.h && echo 1)
IP6TABLES	= $(shell test -e /usr/include/ip6tables.h && echo 1)

WORK=0

.PHONY: all module clean install

all: module

ifeq ($(XTABLES),1)

WORK=1
module: libxt_RTPENGINE.so

libxt_RTPENGINE.so: libxt_RTPENGINE.c
	$(CC) $(CFLAGS) -o libxt_RTPENGINE.so libxt_RTPENGINE.c

else

ifeq ($(IPTABLES),1)
WORK=1
module: libipt_RTPENGINE.so
endif
ifeq ($(IP6TABLES),1)
WORK=1
module: libip6t_RTPENGINE.so
endif

libipt_RTPENGINE.so: libxt_RTPENGINE.c
	$(CC) $(CFLAGS) -D__ipt -o libipt_RTPENGINE.so libxt_RTPENGINE.c

libip6t_RTPENGINE.so: libxt_RTPENGINE.c
	$(CC) $(CFLAGS) -D__ip6t -o libip6t_RTPENGINE.so libxt_RTPENGINE.c

endif

ifeq ($(WORK),0)
module:
	@echo No iptables dev packages installed!
endif

clean:
	rm -f libxt_RTPENGINE.so libipt_RTPENGINE.so libip6t_RTPENGINE.so

install:
