PWD    := $(shell pwd)
KSRC   ?= /lib/modules/$(shell uname -r)/build
KBUILD := $(KSRC)

obj-m        += ipt_MEDIAPROXY.o

modules:
		make -C $(KBUILD) M=$(PWD) O=$(KBUILD) modules

clean:
		make -C $(KBUILD) M=$(PWD) clean
