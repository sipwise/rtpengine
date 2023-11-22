# Compiling and Installing

## Package Repositories

Prebuilt packages for some newer releases of Debian are available on [this repository](https://dfx.at/rtpengine)

## Compiling on a Debian System

On a Debian system, everything can be built and packaged into Debian packages
by executing `dpkg-buildpackage` (which can be found in the `dpkg-dev` package) in the main directory.
This script will issue an error and stop if any of the dependency packages are
not installed. The script `dpkg-checkbuilddeps` can be used to check missing dependencies.
(See the note about G.729 at the end of this section.)

This will produce a number of `.deb` files, which can then be installed using the
`dpkg -i` command.

The generated files are (with version 6.2.0.0 being built on an amd64 system):

* `ngcp-rtpengine_6.2.0.0+0~mr6.2.0.0_all.deb`

	This is a meta-package, which doesn't contain or install anything on its own, but rather
	only depends on the other packages to be installed. Not strictly necessary to be installed.

* `ngcp-rtpengine-daemon_6.2.0.0+0~mr6.2.0.0_amd64.deb`

	This installed the userspace daemon, which is the main workhorse of rtpengine. This is
	the minimum requirement for anything to work.

* `ngcp-rtpengine-kernel-dkms_6.2.0.0+0~mr6.2.0.0_all.deb`

	Kernel module, DKMS version of the package. Recommended for in-kernel operation. The kernel
	module will be compiled against the currently running kernel using DKMS.

* `ngcp-rtpengine-kernel-source_6.2.0.0+0~mr6.2.0.0_all.deb`

	If DKMS is unavailable or not desired, then this package will install the sources for the kernel
	module for manual compilation. Required for in-kernel operation, but only if the DKMS package
	can't be used.

* `ngcp-rtpengine-recording-daemon_6.2.0.0+0~mr6.2.0.0_amd64.deb`

	Optional separate userspace daemon used for call recording features.

* `-dbg...` or `-dbgsym...` packages

	Debugging symbols for the various components. Optional.

For transcoding purposes, Debian provides an additional package `libavcodec-extra` to replace
the regular `libavcodec` package. It is recommended to install this extra package to offer support
for additional codecs.

To support the G.729 codec for transcoding purposes, the external library *bcg729* is required. Please
see the section on *G.729 support* below for details.

## Manual Compilation

There are 3 main parts to *rtpengine* plus one optional component, which can be
found in the respective subdirectories. Running `make` on the top source
directory will build all parts. Running `make check` additionally will run the
test suite.

* `daemon`

	The userspace daemon and workhorse, minimum requirement for anything to work. Running `make`
	will compile the binary, which will be called `rtpengine`. The following software packages
	including their development headers are required to compile the daemon:

	- *pkg-config*
	- *GLib* including *GThread* and *GLib-JSON* version 2.x
	- *zlib*
	- *OpenSSL*
	- *PCRE* library
	- *XMLRPC-C* version 1.16.08 or higher
	- *hiredis* library
	- *gperf*
	- *libcurl* version 3.x or 4.x
	- *libevent* version 2.x
	- *libpcap*
	- *libsystemd*
	- *spandsp*
	- *MySQL* or *MariaDB* client library (optional for media playback and call recording daemon)
	- *libiptc* library for iptables management (optional)
	- *ffmpeg* codec libraries for transcoding (optional) such as *libavcodec*, *libavfilter*, *libswresample*
	- *bcg729* for full G.729 transcoding support (optional)
	- *libmosquitto*
	- *libwebsockets*
	- *libopus*

	The `Makefile` contains a few Debian-specific flags, which may have to removed for compilation to
	be successful. This will not affect operation in any way.

	If you do not wish to (or cannot) compile the optional iptables management feature, the
	`Makefile` also contains a switch to disable it. See the `--iptables-chain` option for
	a description. The name of the `make` switch and its default value is `with_iptables_option=yes`.

	Similarly, the transcoding feature can be excluded via a switch in the `Makefile`, making it
	unnecessary to have the *ffmpeg* libraries installed. The name of the `make` switch and
	its default value is `with_transcoding=yes`.

	Both `Makefile` switches can be provided to the `make` system via environment variables, for
	example by building with the shell command `with_transcoding=no make`.

* `kernel-module`

	Required for in-kernel packet forwarding. Supported for kernels versions 4.4 and newer.

	Compilation of the kernel module requires the kernel development headers to be installed in
	`/lib/modules/$VERSION/build/`, where *$VERSION* is the output of the command `uname -r`. For
	example, if the command `uname -r` produces the output `4.19-1-amd64`, then the kernel headers
	must be present in `/lib/modules/4.19-1-amd64/build/`. The last component of this path (`build`)
	is usually a symlink somewhere into `/usr/src/`, which is fine.

	Successful compilation of the module will produce the file `xt_RTPENGINE.ko`. The module can be inserted
	into the running kernel manually through `insmod xt_RTPENGINE.ko` (which will result in an error if
	depending modules aren't loaded, for example the `x_tables` module), but it's recommended to copy the
	module into `/lib/modules/$VERSION/updates/`, followed by running `depmod -a`.  This copying is performed
	on `make install`. After this, the module can be loaded by issuing `modprobe xt_RTPENGINE`.

* `recording-daemon`

	Optional component for the call recording feature. Prerequisites are
	usage of the kernel module and availability of transcoding (via
	*ffmpeg*)
