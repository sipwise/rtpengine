all: pysip_lite/belle-wrap.so

pysip_lite/belle-wrap.so: src/belle-wrap.o
	$(LD) -g -shared src/belle-wrap.o -o pysip_lite/belle-wrap.so $(shell pkg-config --libs belle-sip glib-2.0) -lc

src/belle-wrap.o: src/belle-wrap.c
	gcc -fPIC -O3 -g -Wall $(shell pkg-config --cflags belle-sip glib-2.0) src/belle-wrap.c -c -o src/belle-wrap.o

.PHONY: clean
clean:
	rm -f src/belle-wrap.o pysip_lite/belle-wrap.so
