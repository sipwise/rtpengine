mediaproxy-ng for Enterprise Linux
==================================

Installing from RPMs
--------------------

TBD


RPM Compliation
---------------

TBD


Manual Compilation
------------------

There are three parts to mediaproxy-ng, each of which can be found in the
respective subdirectories.

* `daemon`

	The userspace daemon and workhorse, minimum requirement for anything
	to work. Running `MEDIAPROXY_VERSION="\"<version number>\"" make` will
	compile the binary, which will be called `mediaproxy-ng`. The
	following software packages are required to compile the daemon:

	- *gcc*
	- *make*
	- *pkgconfig*
	- *glib2-devel*
	- *libcurl-devel*
	- *openssl-devel*
	- *pcre-devel*
	- *xmlrpc-c-devel*
	- *zlib-devel*

* `iptables-extension`

	Required for in-kernel packet forwarding. Running
	`MEDIAPROXY_VERSION="\"<version number>\"" make` will compile the plugin
	for `iptables` and `ip6tables`. The file will be called
	`libxt_MEDIAPROXY.so` and should be copied into the directory
	`/lib/xtables/` in 32-bit environments and `/lib64/xtables/` in 64-bit
	environments. The following software packages are required to compile
	the plugin:

	- *gcc*
	- *make*
	- *iptables-devel*

* `kernel-module`

	Required for in-kernel packet forwarding. Compilation of the kernel
	module requires the kernel development packages for the kernel version
	you are using (see output of `uname -r`) to be installed. Running
	`MEDIAPROXY_VERSION="\"<version number>\"" make` will compile the kernel
	module.

	Successful compilation of the module will produce the file
	`xt_MEDIAPROXY.ko`. The module can be inserted into the running kernel
	manually through `insmod xt_MEDIAPROXY.ko` (which will result in an
	error if depending modules aren't loaded, for example the `x_tables`
	module), but it's recommended to copy the module into
	`/lib/modules/<version number>/updates/`, followed by running
	`depmod -a`. After this, the module can be loaded by issuing
	`modprobe xt_MEDIAPROXY`.

	The following software packages are required to compile the plugin:

	- *gcc*
	- *make*
	- *kernel-devel*
	- *kernel-headers*

	Note: the *kernel-devel* and *kernel-headers* packages are meta-packages
	that install the headers and source for the latest kernel version. This
	will be what you want unless you are running a custom or older kernel.

