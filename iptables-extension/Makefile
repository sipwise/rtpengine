.PHONY: all clean

all: libxt_MEDIAPROXY.so

libxt_MEDIAPROXY.so: libxt_MEDIAPROXY.c
	gcc -O2 -Wall -shared -fPIC -o libxt_MEDIAPROXY.so libxt_MEDIAPROXY.c

clean:
	rm -f libxt_MEDIAPROXY.so
