mediaproxy-ng for Enterprise Linux
==================================

Installing from RPMs
--------------------

There are three RPMs:

- *ngcp-mediaproxy-ng*: the userspace daemon
- *ngcp-mediaproxy-ng-kernel*: the iptables plugin
- *ngcp-mediaproxy-ng-dkms*: the kernel module source

All of the RPMs have correctly set dependencies and if you just want the
userspace daemon you can install it with yum (assuming you have access to a
CentOS repository).

The *ngcp-mediaproxy-ng-kernel* package is dependent on the
*ngcp-mediaproxy-ng*, and *ngcp-mediaproxy-ng-dkms* packages. The
*ngcp-mediaproxy-ng-dkms* package has a dependency (DKMS) that cannot be met
by the CentOS base repository. If you want to use in-kernel forwarding you
need to add the [*EPEL*](http://fedoraproject.org/wiki/EPEL) repository and
install the *dkms* package before attempting to install
*ngcp-mediaproxy-ng-dkms* or *ngcp-mediaproxy-ng-kernel*.

Note: installing *ngcp-mediaproxy-ng-dkms* builds a kernel module which requires
the sources for the running kernel. The *kernel-devel* and *kernel-headers*
packages are meta-packages that install the headers and source for the latest
kernel version. This will be what what you want unless you are running a custom
or older kernel. *ngcp-mediaproxy-ng-dkms* does not have *kernel-devel* and
*kernel-headers* as dependencies as this could cause problems if you are using
a custom or older kernel, so you need to install these manually.


RPM Compliation
---------------

To build the RPMs you need all of the packages listed in the Manual Compilation
section (except for *kernel-devel* and *kernel-headers*) plus:

- *redhat-rpm-config*
- *rpm-build*

To build the RPMs:
- Checkout (clone) the Git repository
- Create the `~/rpmbuild/SOURCES` directory
- Create a tar archive.  For example, from within the cloned directory you can
  use
  `git archive --output ~/rpmbuild/SOURCES/ngcp-mediaproxy-ng-<version number>.tar.gz --prefix=ngcp-mediaproxy-ng-<version number>/ master`
  where `<version number>` is the version number of the master branch
- Build the RPMs. For example,
   `rpmbuild -ta ~/rpmbuild/SOURCES/ngcp-mediaproxy-ng-<version number>.tar.gz`

Once the build has completed the binary RPMs will be in `~/rpmbuild/RPMS`.


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

