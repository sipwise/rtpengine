CFLAGS		= -O2 -Wall -shared -fPIC
CFLAGS		+= -DMEDIAPROXY_VERSION="\"$(shell dpkg-parsechangelog -l../debian/changelog | awk '/^Version: / {print $$2}')\""

.PHONY: all clean

all: libxt_MEDIAPROXY.so

libxt_MEDIAPROXY.so: libxt_MEDIAPROXY.c
	gcc $(CFLAGS) -o libxt_MEDIAPROXY.so libxt_MEDIAPROXY.c

clean:
	rm -f libxt_MEDIAPROXY.so
