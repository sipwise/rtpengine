rtpengine for Enterprise Linux
==================================

Installing from RPMs
--------------------

There are three RPMs:

- *ngcp-rtpengine*: the userspace daemon
- *ngcp-rtpengine-kernel*: the iptables plugin
- *ngcp-rtpengine-dkms*: the kernel module source

All of the RPMs have correctly set dependencies and if you just want the
userspace daemon you can install it with yum (assuming you have access to a
CentOS repository).

The *ngcp-rtpengine-kernel* package is dependent on the
*ngcp-rtpengine*, and *ngcp-rtpengine-dkms* packages. The
*ngcp-rtpengine-dkms* package has a dependency (DKMS) that cannot be met
by the CentOS base repository. If you want to use in-kernel forwarding you
need to add the [*EPEL*](http://fedoraproject.org/wiki/EPEL) repository and
install the *dkms* package before attempting to install
*ngcp-rtpengine-dkms* or *ngcp-rtpengine-kernel*.

Note: installing *ngcp-rtpengine-dkms* builds a kernel module which requires
the sources for the running kernel. The *kernel-devel* and *kernel-headers*
packages are meta-packages that install the headers and source for the latest
kernel version. This will be what what you want unless you are running a custom
or older kernel. *ngcp-rtpengine-dkms* does not have *kernel-devel* and
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
  `git archive --output ~/rpmbuild/SOURCES/ngcp-rtpengine-<version number>.tar.gz --prefix=ngcp-rtpengine-<version number>/ master`
  where `<version number>` is the version number of the master branch
- Build the RPMs. For example,
   `rpmbuild -ta ~/rpmbuild/SOURCES/ngcp-rtpengine-<version number>.tar.gz`

Once the build has completed the binary RPMs will be in `~/rpmbuild/RPMS`.


Manual Compilation
------------------

There are three parts to rtpengine, each of which can be found in the
respective subdirectories.

* `daemon`

	The userspace daemon and workhorse, minimum requirement for anything
	to work. Running `RTPENGINE_VERSION="\"<version number>\"" make` will
	compile the binary, which will be called `rtpengine`. The
	following software packages are required to compile the daemon:

	- *gcc*
	- *make*
	- *pkgconfig*
	- *glib2-devel*
	- *hiredis-devel*
	- *libcurl-devel*
	- *openssl-devel*
	- *pcre-devel*
	- *xmlrpc-c-devel*
	- *zlib-devel*

* `iptables-extension`

	Required for in-kernel packet forwarding. Running
	`RTPENGINE_VERSION="\"<version number>\"" make` will compile the plugin
	for `iptables` and `ip6tables`. The file will be called
	`libxt_RTPENGINE.so` and should be copied into the directory
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
	`RTPENGINE_VERSION="\"<version number>\"" make` will compile the kernel
	module.

	Successful compilation of the module will produce the file
	`xt_RTPENGINE.ko`. The module can be inserted into the running kernel
	manually through `insmod xt_RTPENGINE.ko` (which will result in an
	error if depending modules aren't loaded, for example the `x_tables`
	module), but it's recommended to copy the module into
	`/lib/modules/<version number>/updates/`, followed by running
	`depmod -a`. After this, the module can be loaded by issuing
	`modprobe xt_RTPENGINE`.

	The following software packages are required to compile the plugin:

	- *gcc*
	- *make*
	- *kernel-devel*
	- *kernel-headers*

	Note: the *kernel-devel* and *kernel-headers* packages are meta-packages
	that install the headers and source for the latest kernel version. This
	will be what you want unless you are running a custom or older kernel.

