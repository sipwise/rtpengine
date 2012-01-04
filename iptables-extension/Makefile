CFLAGS		= -O2 -Wall -shared -fPIC
CFLAGS		+= -DMEDIAPROXY_VERSION="\"$(shell dpkg-parsechangelog -l../debian/changelog | awk '/^Version: / {print $$2}')\""

XTABLES		= $(shell test -e /usr/include/xtables.h && echo 1)
IPTABLES	= $(shell test -e /usr/include/iptables.h && echo 1)
IP6TABLES	= $(shell test -e /usr/include/ip6tables.h && echo 1)

.PHONY: all module clean

all: module

ifeq ($(XTABLES),1)

module: libxt_MEDIAPROXY.so

libxt_MEDIAPROXY.so: libxt_MEDIAPROXY.c
	gcc $(CFLAGS) -o libxt_MEDIAPROXY.so libxt_MEDIAPROXY.c

else

ifeq ($(IPTABLES),1)
module: libipt_MEDIAPROXY.so
endif
ifeq ($(IP6TABLES),1)
module: libip6t_MEDIAPROXY.so
endif

libipt_MEDIAPROXY.so: libxt_MEDIAPROXY.c
	gcc $(CFLAGS) -D__ipt -o libipt_MEDIAPROXY.so libxt_MEDIAPROXY.c

libip6t_MEDIAPROXY.so: libxt_MEDIAPROXY.c
	gcc $(CFLAGS) -D__ip6t -o libip6t_MEDIAPROXY.so libxt_MEDIAPROXY.c

endif

clean:
	rm -f libxt_MEDIAPROXY.so libipt_MEDIAPROXY.so libip6t_MEDIAPROXY.so
