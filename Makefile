all:
	make -C daemon
	make -C recording-daemon
	make -C iptables-extension
	make -C kernel-module

.DEFAULT:
	make -C daemon $@
	make -C recording-daemon $@
	make -C iptables-extension $@
	make -C kernel-module $@
