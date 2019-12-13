What is rtpengine?
=======================

The [Sipwise](http://www.sipwise.com/) NGCP rtpengine is a proxy for RTP traffic and other UDP based
media traffic. It's meant to be used with the [Kamailio SIP proxy](http://www.kamailio.org/)
and forms a drop-in replacement for any of the other available RTP and media
proxies.

Currently the only supported platform is GNU/Linux.

Features
=========

* Media traffic running over either IPv4 or IPv6
* Bridging between IPv4 and IPv6 user agents
* Bridging between different IP networks or interfaces
* TOS/QoS field setting
* Customizable port range
* Multi-threaded
* Advertising different addresses for operation behind NAT
* In-kernel packet forwarding for low-latency and low-CPU performance
* Automatic fallback to normal userspace operation if kernel module is unavailable
* Support for *Kamailio*'s *rtpproxy* module
* Legacy support for old *OpenSER* *mediaproxy* module

When used through the *rtpengine* module (or its older counterpart called *rtpproxy-ng*),
the following additional features are available:

- Full SDP parsing and rewriting
- Supports non-standard RTCP ports (RFC 3605)
- ICE (RFC 5245) support:
  + Bridging between ICE-enabled and ICE-unaware user agents
  + Optionally acting only as additional ICE relay/candidate
  + Optionally forcing relay of media streams by removing other ICE candidates
- SRTP (RFC 3711) support:
  + Support for SDES (RFC 4568) and DTLS-SRTP (RFC 5764)
  + AES-CM and AES-F8 ciphers, both in userspace and in kernel
  + HMAC-SHA1 packet authentication
  + Bridging between RTP and SRTP user agents
- Support for RTCP profile with feedback extensions (RTP/AVPF, RFC 4585 and 5124)
- Arbitrary bridging between any of the supported RTP profiles (RTP/AVP, RTP/AVPF,
  RTP/SAVP, RTP/SAVPF)
- RTP/RTCP multiplexing (RFC 5761) and demultiplexing
- Breaking of BUNDLE'd media streams (draft-ietf-mmusic-sdp-bundle-negotiation)
- Recording of media streams, decrypted if possible
- Transcoding and repacketization
- Transcoding between RFC 2833/4733 DTMF event packets and in-band DTMF tones (and vice versa)
- Injection of DTMF events or PCM DTMF tones into running audio streams
- Playback of pre-recorded streams/announcements

*Rtpengine* does not (yet) support:

* ZRTP, although ZRTP passes through *rtpengine* just fine

Compiling and Installing
=========================

On a Debian System
------------------

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

* `ngcp-rtpengine-iptables_6.2.0.0+0~mr6.2.0.0_amd64.deb`

	Installs the plugin for `iptables` and `ip6tables`. Necessary for in-kernel operation.

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

Manual Compilation
------------------

There's 3 parts to *rtpengine*, which can be found in the respective
subdirectories. Running `make check` on the top source directory will
build all parts and run the test suite.

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

* `iptables-extension`

	Required for in-kernel packet forwarding.

	With the `iptables` development headers installed, issuing `make` will compile the plugin for
	`iptables` and `ip6tables`. The file will be called `libxt_RTPENGINE.so` and needs to be copied
	into the `xtables` module directory. The location of this directory can be determined through
	`pkg-config xtables --variable=xtlibdir` on newer systems, and/or is usually either
	`/lib/xtables/` or `/usr/lib/x86_64-linux-gnu/xtables/`.

* `kernel-module`

	Required for in-kernel packet forwarding.

	Compilation of the kernel module requires the kernel development headers to be installed in
	`/lib/modules/$VERSION/build/`, where *$VERSION* is the output of the command `uname -r`. For
	example, if the command `uname -r` produces the output `3.9-1-amd64`, then the kernel headers
	must be present in `/lib/modules/3.9-1-amd64/build/`. The last component of this path (`build`)
	is usually a symlink somewhere into `/usr/src/`, which is fine.

	Successful compilation of the module will produce the file `xt_RTPENGINE.ko`. The module can be inserted
	into the running kernel manually through `insmod xt_RTPENGINE.ko` (which will result in an error if
	depending modules aren't loaded, for example the `x_tables` module), but it's recommended to copy the
	module into `/lib/modules/$VERSION/updates/`, followed by running `depmod -a`. After this, the module can
	be loaded by issuing `modprobe xt_RTPENGINE`.

Usage
=====

Userspace Daemon
----------------

The options are described in detail in the rtpengine(1) man page.

In-kernel Packet Forwarding
---------------------------

In normal userspace-only operation, the overhead involved in processing each individual RTP or media packet
is quite significant. This comes from the fact that each time a packet is received on a network interface,
the packet must first traverse the stack of the kernel's network protocols, down to locating a process's
file descriptor. At this point the linked user process (the daemon) has to be signalled that a new packet
is available to be read, the process has to be scheduled to run, once running the process must read the packet,
which means it must be copied from kernel space to user space, involving an expensive context switch. Once the
packet has been processed by the daemon, it must be sent out again, reversing the whole process.

All this wouldn't be a big deal if it wasn't for the fact that RTP traffic generally consists of many small
packets being transferred at high rates. Since the forwarding overhead is incurred on a per-packet basis, the
ratio of useful data processed to overhead drops dramatically.

For these reasons, *rtpengine* provides a kernel module to offload the bulk of the packet forwarding
duties from user space to kernel space. Using this technique, a large percentage of the overhead can be
eliminated, CPU usage greatly reduced and the number of concurrent calls possible to be handled increased.

In-kernel packet forwarding is implemented as an *iptables* module
(or more precisely, an *x\_tables* module). As such, it comes in two parts, both of
which are required for proper operation. One part is the actual kernel module called `xt_RTPENGINE`. The
second part is a plugin to the `iptables` and `ip6tables` command-line utilities to make it possible to
actually add the required rule to the tables.

### Overview ###

In short, the prerequisites for in-kernel packet forwarding are:

1. The `xt_RTPENGINE` kernel module must be loaded.
2. An `iptables` and/or `ip6tables` rule must be present in the `INPUT` chain (or in a custom user-defined
   chain which is then called by the `INPUT` chain) to send packets
   to the `RTPENGINE` target. This rule should be limited to UDP packets, but otherwise there
   are no restrictions.
3. The `rtpengine` daemon must be running.
4. All of the above must be set up with the same forwarding table ID (see below).

The sequence of events for a newly established media stream is then:

1. The SIP proxy (e.g. *Kamailio*) controls *rtpengine* and informs it about a newly established call.
2. The `rtpengine` daemon allocates local UDP ports and sets up preliminary forward rules
   based on the info received
   from the SIP proxy. Only userspace forwarding is set up, nothing is pushed to the kernel module yet.
3. An RTP packet is received on the local port.
4. It traverses the *iptables* chains and gets passed to the *xt\_RTPENGINE* module.
5. The module doesn't recognize it as belonging to an established stream and thus ignores it.
6. The packet continues normal processing and eventually ends up in the daemon's receive queue.
7. The daemon reads it, processes it and forwards it. It also updates some internal data.
8. This userspace-only processing and forwarding continues for a little while, during which time information
   about additional streams and/or endpoints may be obtained from the SIP proxy.
9. After a few seconds, when the daemon is satisfied with what it has learned about the media endpoints,
   it pushes the forwarding rules to the kernel.
10. From this moment on, the kernel module will recognize incoming packets belonging to those streams
    and will forward them on its own. It will stop those packets from traversing the network stacks any
    further, so the daemon will not see them any more on its receive queues.
11. In-kernel forwarding is allowed to cease to work at any given time, either accidentally (e.g. by
    removal of the *iptables* rule) or deliberately (the daemon will do so in case of a re-invite), in which
    case forwarding falls back to userspace-only operation.

### The Kernel Module ###

The kernel module supports multiple forwarding tables (not to be confused with the tables managed
by *iptables*), which are identified through their ID number. By default, up to 64 forwarding tables
can be created and used, giving them the ID numbers 0 through 63.

Each forwarding table can be thought of a separate proxy instance. Each running instance of the
*rtpengine* daemon controls one such table, and each table can only be controlled by one
running instance of the daemon at any given time. In the most common setup, there will be only a single
instance of the daemon running and there will be only a single forwarding table in use, with ID zero.

The kernel module can be loaded with the command `modprobe xt_RTPENGINE`. With the module loaded, a new
directory will appear in `/proc/`, namely `/proc/rtpengine/`. After loading, the directory will contain
only two pseudo-files, `control` and `list`. The `control` file is write-only and is used to create and
delete forwarding tables, while the `list` file is read-only and will produce a list of currently
active forwarding tables. With no tables active, it will produce an empty output.

The `control` pseudo-file supports two commands, `add` and `del`, each followed by the forwarding table
ID number. To manually create a forwarding table with ID 42, the following command can be used:

	echo 'add 42' > /proc/rtpengine/control

After this, the `list` pseudo-file will produce the single line `42` as output. This will also create a
directory called `42` in `/proc/rtpengine/`, which contains additional pseudo-files to control this
particular forwarding table.

To delete this forwarding table, the command `del 42` can be issued like above. This will only work
if no *rtpengine* daemon is currently running and controlling this table.

Each subdirectory `/proc/rtpengine/$ID/` corresponding to each forwarding table contains the pseudo-files
`blist`, `control`, `list` and `status`. The `control` file is write-only while the others are read-only.
The `control` file will be kept open by the *rtpengine* daemon while it's running to issue updates
to the forwarding rules during runtime. The daemon also reads the `blist` file on a regular basis, which
produces a list of currently active forwarding rules together with their stats and other details
within that table in a binary format. The same output,
but in human-readable format, can be obtained by reading the `list` file. Lastly, the `status` file produces
a short stats output for the forwarding table.

Manual creation of forwarding tables is normally not required as the daemon will do so itself, however
deletion of tables may be required after shutdown of the daemon or before a restart to ensure that the
daemon can create the table it wants to use.

The kernel module can be unloaded through `rmmod xt_RTPENGINE`, however this only works if no forwarding
table currently exists and no *iptables* rule currently exists.

### The *iptables* module ###

In order for the kernel module to be able to actually forward packets, an *iptables* rule must be set up
to send packets into the module. Each such rule is associated with one forwarding table. In the simplest case,
for forwarding table 42, this can be done through:

	iptables -I INPUT -p udp -j RTPENGINE --id 42

If IPv6 traffic is expected, the same should be done using `ip6tables`.

It is possible but not strictly
necessary to restrict the rules to the UDP port range used by *rtpengine*, e.g. by supplying a parameter
like `--dport 30000:40000`. If the kernel module receives a packet that it doesn't recognize as belonging
to an active media stream, it will simply ignore it and hand it back to the network stack for normal
processing.

The `RTPENGINE` rule need not necessarily be present directly in the `INPUT` chain. It can also be in a
user-defined chain which is then referenced by the `INPUT` chain, like so:

	iptables -N rtpengine
	iptables -I INPUT -p udp -j rtpengine
	iptables -I rtpengine -j RTPENGINE --id 42

This can be a useful setup if certain firewall scripts are being used.

Summary
-------

A typical start-up sequence including in-kernel forwarding might look like this:

	# this only needs to be one once after system (re-) boot
	modprobe xt_RTPENGINE
	iptables -I INPUT -p udp -j RTPENGINE --id 0
	ip6tables -I INPUT -p udp -j RTPENGINE --id 0

	# ensure that the table we want to use doesn't exist - usually needed after a daemon
	# restart, otherwise will error
	echo 'del 0' > /proc/rtpengine/control

	# start daemon
	/usr/sbin/rtpengine --table=0 --interface=10.64.73.31 --interface=2001:db8::4f3:3d \
	--listen-ng=127.0.0.1:2223 --tos=184 --pidfile=/run/rtpengine.pid --no-fallback

Running Multiple Instances
--------------------------

In some cases it may be desired to run multiple instances of *rtpengine* on the same machine, for example
if the host is multi-homed and has multiple usable network interfaces with different addresses. This is
supported by running multiple instances of the daemon using different command-line options (different
local addresses and different listening ports), together with
multiple different kernel forwarding tables.

For example, if one local network interface has address 10.64.73.31 and another has address 192.168.65.73,
then the start-up sequence might look like this:

	modprobe xt_RTPENGINE
	iptables -I INPUT -p udp -d 10.64.73.31 -j RTPENGINE --id 0
	iptables -I INPUT -p udp -d 192.168.65.73 -j RTPENGINE --id 1

	echo 'del 0' > /proc/rtpengine/control
	echo 'del 1' > /proc/rtpengine/control

	/usr/sbin/rtpengine --table=0 --interface=10.64.73.31 \
	--listen-ng=127.0.0.1:2223 --tos=184 --pidfile=/run/rtpengine-10.pid --no-fallback
	/usr/sbin/rtpengine --table=1 --interface=192.168.65.73 \
	--listen-ng=127.0.0.1:2224 --tos=184 --pidfile=/run/rtpengine-192.pid --no-fallback

With this setup, the SIP proxy can choose which instance of *rtpengine* to talk to and thus which local
interface to use by sending its control messages to either port 2223 or port 2224.

Transcoding
===========

Currently transcoding is supported for audio streams. The feature can be disabled on a compile-time
basis, and is enabled by default.

Even though the transcoding feature is available by default, it is not automatically engaged for
normal calls. Normally *rtpengine* leaves codec negotiation up to the clients involved in the call
and does not interfere. In this case, if the clients fail to agree on a codec, the call will fail.

The transcoding feature can be engaged for a call by instructing *rtpengine* to do so by using
one of the transcoding options in the *ng* control protocol, such as `transcode` or `ptime` (see below).
If a codec is requested via the `transcode` option that was not originally offered, transcoding will
be engaged for that call.

With transcoding active for a call, all unsupported codecs will be removed from the SDP. Transcoding
happens in userspace only, so in-kernel packet forwarding will not be available for transcoded codecs.
However, even if the transcoding feature has been engaged for a call, not all codecs will necessarily
end up being transcoded. Codecs that are supported by both sides will simply be passed through
transparently (unless repacketization is active). In-kernel packet forwarding will still be available
for these codecs.

The following codecs are supported by *rtpengine*:

* G.711 (a-Law and µ-Law)
* G.722
* G.723.1
* G.729
* Speex
* GSM
* iLBC
* Opus
* AMR (narrowband and wideband)

Codec support is dependent on support provided by the `ffmpeg` codec libraries, which may vary from
version to version. Use the `--codecs` command line option to have *rtpengine* print a list of codecs
and their supported status. The list includes some codecs that are not listed above. Some of these
are not actual VoIP codecs (such as MP3), while others lack support for encoding by *ffmpeg* at the
time of writing (such as QCELP or ATRAC). If encoding support for these codecs becomes available
in *ffmpeg*, *rtpengine* will be able to support them.

Audio format conversion including resampling and mono/stereo up/down-mixing happens automatically
as required by the codecs involved. For example, one side could be using stereo Opus at 48 kHz
sampling rate, and the other side could be using mono G.711 at 8 kHz, and *rtpengine* will perform
the necessary conversions.

If repacketization (using the `ptime` option) is requested, the transcoding feature will also be
engaged for the call, even if no additional codecs were requested.

Non-audio pseudo-codecs (such as T.38) are not currently supported, with the exception of RFC
2833/4733 DTMF event packets (`telephone-event`) as described below.

G.729 support
-------------

As *ffmpeg* does not currently provide an encoder for G.729, transcoding support for it is available
via the [bcg729](https://www.linphone.org/technical-corner/bcg729/) library
(mirror on [GitHub](https://github.com/BelledonneCommunications/bcg729)). The build system looks for
the *bcg729* headers in a few locations and uses the library if found. If the library is located
elsewhere, see `daemon/Makefile` to control where the build system is looking for it.

In a Debian build environment, `debian/control` lists a build-time dependency on *bcg729*. Since
Debian proper does not currently include a *bcg729* package, one can be built locally using these
instructions on [GitHub](https://github.com/ossobv/bcg729-deb). *Sipwise* provides a pre-packaged
version of this as part of our
[C5 CE](https://www.sipwise.com/products/class-5-softswitch-carrier-grade-for-voice-over-ip/)
product which is [available here](https://deb.sipwise.com/spce/mr6.2.1/pool/main/b/bcg729/).

Alternatively the build dependency
can be removed from `debian/control` or by switching to a different Debian build profile.
Set the environment variable
`export DEB_BUILD_PROFILES="pkg.ngcp-rtpengine.nobcg729"` (or use the `-P` flag to the *dpkg* tools)
and then build the *rtpengine* packages.

DTMF transcoding
----------------

*Rtpengine* supports transcoding between RFC 2833/4733 DTMF event packets (`telephone-event` payloads)
and in-band DTMF audio tones. When enabled, *rtpengine* translates DTMF event packets to in-band DTMF
audio by generating DTMF tones and injecting them into the audio stream, and translates in-band DTMF
tones by running the audio stream through a DSP, and generating DTMF event packets when a DTMF tone
is detected.

Support for DTMF transcoding can be enabled in one of two ways:

* In the forward direction, DTMF transcoding is enabled by adding the codec `telephone-event` to the
  list of codecs offered for transcoding. Specifically, if the incoming SDP body doesn't yet list
  `telephone-event` as a supported codec, adding the option *codec → transcode → telephone-event* would
  enable DTMF transcoding. The receiving RTP client can then accept this codec and start sending DTMF
  event packets, which *rtpengine* would translate into in-band DTMF audio. If the receiving RTP client
  also offers `telephone-event` in their behalf, *rtpengine* would then detect in-band DTMF audio coming
  from the originating RTP client and translate it to DTMF event packets.

* In the reverse direction, DTMF transcoding is enabled by adding the option `always transcode` to the
  `flags` if the incoming SDP body offers `telephone-event` as a supported codec. If the receiving RTP
  client then rejects the offered `telephone-event` codec, DTMF transcoding is then enabled and is
  performed in the same way as described above.

Enabling DTMF transcoding (in one of the two ways described above) implicitly enables the flag
`always transcode` for the call and forces all of the audio to pass through the transcoding engine.
Therefore, for performance reasons, this should only be done when really necessary.

Call recording
==============

Call recording can be accomplished in one of two ways: 

* The *rtpengine* daemon can write `libpcap`-formatted captures directly (`--recording-method=pcap`);

* The *rtpengine* daemon can write audio frames into a sink in `/proc/rtpengine` (`--recording-method=proc`). These frames must then be consumed within a short period by another process; while this can be any process, the packaged `rtpengine-recording` daemon is a useful ready implementation of a call recording solution. The recording daemon uses `ffmpeg` libraries to implement a variety of on-the-fly format conversion and mixing options, as well as metadata logging. See `rtpengine-recording -h` for details.

**Important note**: The *rtpengine* daemon emits data into a "spool directory" (`--recording-dir` option), by default `/var/spool/rtpengine`. The recording daemon is then configured to consume this using the `--spool-dir` option, and to store the final emitted recordings (in whatever desired target format, etc.) in `--output-dir`. Ensure that the `--spool-dir` and the `--output-dir` are **different** directories, or you will run into problems (as discussed in [#81](https://github.com/sipwise/rtpengine/issues/808)).

The *ng* Control Protocol
=========================

In order to enable several advanced features in *rtpengine*, a new advanced control protocol has been devised
which passes the complete SDP body from the SIP proxy to the *rtpengine* daemon, has the body rewritten in
the daemon, and then passed back to the SIP proxy to embed into the SIP message.

This control protocol is based on the [bencode](http://en.wikipedia.org/wiki/Bencode) standard and runs over
UDP transport. *Bencoding* supports a similar feature set as the more popular JSON encoding (dictionaries/hashes,
lists/arrays, arbitrary byte strings) but offers some benefits over JSON encoding, e.g. simpler and more efficient
encoding, less encoding overhead, deterministic encoding and faster encoding and decoding. A disadvantage over
JSON is that it's not a readily human readable format.

Each message passed between the SIP proxy and the media proxy contains of two parts: a message cookie, and a
bencoded dictionary, separated by a single space. The message cookie serves the same purpose as in the control
protocol used by *Kamailio*'s *rtpproxy* module: matching requests to responses, and retransmission detection.
The message cookie in the response generated to a particular request therefore must be the same as in the
request.

The dictionary of each request must contain at least one key called `command`. The corresponding value must be
a string and determines the type of message. Currently the following commands are defined:

* ping
* offer
* answer
* delete
* query
* start recording
* stop recording
* block DTMF
* unblock DTMF
* block media
* unblock media
* start forwarding
* stop forwarding
* play media
* stop media
* play DTMF

The response dictionary must contain at least one key called `result`. The value can be either `ok` or `error`.
For the `ping` command, the additional value `pong` is allowed. If the result is `error`, then another key
`error-reason` must be given, containing a string with a human-readable error message. No other keys should
be present in the error case. If the result is `ok`, the optional key `warning` may be present, containing a
human-readable warning message. This can be used for non-fatal errors.

For readability, all data objects below are represented in a JSON-like notation and without the message cookie.
For example, a `ping` message and its corresponding `pong` reply would be written as:

	{ "command": "ping" }
	{ "result": "pong" }

While the actual messages as encoded on the wire, including the message cookie, might look like this:

	5323_1 d7:command4:pinge
	5323_1 d6:result4:ponge

All keys and values are case-sensitive unless specified otherwise. The requirement stipulated by the *bencode*
standard that dictionary keys must be present in lexicographical order is not currently honoured.

The *ng* protocol is used by *Kamailio*'s *rtpengine* module, which is based on the older module called *rtpproxy-ng*.

`ping` Message
--------------

The request dictionary contains no other keys and the reply dictionary also contains no other keys. The
only valid value for `result` is `pong`.

`offer` Message
---------------

The request dictionary must contain at least the following keys:

* `sdp`

  Contains the complete SDP body as string.

* `call-id`

  The SIP call ID as string.

* `from-tag`

  The SIP `From` tag as string.

Optionally included keys are:

* `via-branch`

	The SIP `Via` branch as string. Used to additionally refine the matching logic between media streams
	and calls and call branches.

* `label`

	A custom free-form string which *rtpengine* remembers for this participating endpoint and reports
	back in logs and statistics output.

* `flags`

	The value of the `flags` key is a list. The list contains zero or more of the following strings.
	Spaces in each string my be replaced by hyphens.

	- `SIP source address`

		Ignore any IP addresses given in the SDP body and use the source address of the received
		SIP message (given in `received from`) as default endpoint address. This was the default
		behaviour of older versions of *rtpengine* and can still be made the default behaviour
		through the `--sip-source` CLI switch.
		Can be overridden through the `media address` key.

	- `trust address`

		The opposite of `SIP source address`. This is the default behaviour unless the CLI switch
		`--sip-source` is active. Corresponds to the *rtpproxy* `r` flag.
		Can be overridden through the `media address` key.

	- `symmetric`

		Corresponds to the *rtpproxy* `w` flag. Not used by *rtpengine* as this is the default,
		unless `asymmetric` is specified.

	- `asymmetric`

		Corresponds to the *rtpproxy* `a` flag. Advertises an RTP endpoint which uses asymmetric
		RTP, which disables learning of endpoint addresses (see below).

	- `unidirectional`

		When this flag is present, kernelize also one-way rtp media.

	- `strict source`

		Normally, *rtpengine* attempts to learn the correct endpoint address for every stream during
		the first few seconds after signalling by observing the source address and port of incoming
		packets (unless `asymmetric` is specified). Afterwards, source address and port of incoming
		packets are normally ignored and packets are forwarded regardless of where they're coming from.
		With the `strict source` option set, *rtpengine* will continue to inspect the source address
		and port of incoming packets after the learning phase and compare them with the endpoint
		address that has been learned before. If there's a mismatch, the packet will be dropped and
		not forwarded.

	- `media handover`

		Similar to the `strict source` option, but instead of dropping packets when the source address
		or port don't match, the endpoint address will be re-learned and moved to the new address. This
		allows endpoint addresses to change on the fly without going through signalling again. Note that
		this opens a security hole and potentially allows RTP streams to be hijacked, either partly or
		in whole.

	- `reset`

		This causes *rtpengine* to un-learn certain aspects of the RTP endpoints involved, such as
		support for ICE or support for SRTP. For example, if `ICE=force` is given, then *rtpengine*
		will initially offer ICE to the remote endpoint. However, if a subsequent answer from that
		same endpoint indicates that it doesn't support ICE, then no more ICE offers will be made
		towards that endpoint, even if `ICE=force` is still specified. With the `reset` flag given,
		this aspect will be un-learned and *rtpengine* will again offer ICE to this endpoint.
		This flag is valid only in an `offer` message and is useful when the call has been
		transferred to a new endpoint without change of `From` or `To` tags.

	- `port latching`

		Forces *rtpengine* to retain its local ports during a signalling exchange even when the
		remote endpoint changes its port.

	- `record call`

		Identical to setting `record call` to `on` (see below).

	- `no rtcp attribute`

		Omit the `a=rtcp` line from the outgoing SDP.

	- `full rtcp attribute`

		Include the full version of the `a=rtcp` line (complete with network address) instead of
		the short version with just the port number.

	- `loop protect`

		Inserts a custom attribute (`a=rtpengine:...`) into the outgoing SDP to prevent *rtpengine*
		processing and rewriting the same SDP multiple times. This is useful if your setup
		involves signalling loops and need to make sure that *rtpengine* doesn't start looping
		media packets back to itself. When this flag is present and *rtpengine* sees a matching
		attribute already present in the SDP, it will leave the SDP untouched and not process
		the message.

	- `always transcode`

		When transcoding is in use, *rtpengine* will normally match up the codecs offered with
		one side with the codecs offered by the other side, and engage the transcoding engine
		only for codec pairs that are not supported by both sides. With this flag present,
		*rtpengine* will skip the codec match-up routine and always trancode any received media
		to the first (highest priority) codec offered by the other side that is supported for
		transcoding. Using this flag engages the transcoding engine even if no other
		`transcoding` flags are present. Unlike other transcoding options, this one is directional,
		which means that it's applied only to the one side doing the signalling that is being
		handled (i.e. the side doing the `offer` or the `answer`).

	- `asymmetric codecs`

		This flag is relevant to transcoding scenarios. By default, if an RTP client rejects a
		codec that was offered to it (by not including it in the answer SDP), *rtpengine* will
		assume that this client will also not send this codec (in addition to not wishing to
		receive it). With this flag given, *rtpengine* will not make this assumption, meaning
		that *rtpengine* will expect to potentially receive a codec from an RTP client even if
		that RTP client rejected this codec in its answer SDP.

		The effective difference is that when *rtpengine* is instructed to offer a new codec for
		transcoding to an RTP client, and then this RTP client rejects this codec, by default
		*rtpengine* is then able to shut down its transcoding engine and revert to non-transcoding
		operation for this call. With this flag given however, *rtpengine* would not be able
		to shut down its transcoding engine in this case, resulting in potentially different media
		flow, and potentially transcoding media when it otherwise would not have to.

		This flag should be given as part of the `answer` message.

	- `all`

		Only relevant to the `unblock media` message. Instructs *rtpengine* to remove not only a
		full-call media block, but also remove directional media blocks that were imposed on
		individual participants.

	- `pad crypto`

		RFC 4568 (section 6.1) is somewhat ambiguous regarding the base64 encoding format of
		`a=crypto` parameters added to an SDP body. The default interpretation is that trailing
		`=` characters used for padding should be omitted. With this flag set, these padding
		characters will be left in place.

	- `generate mid`

		Add `a=mid` attributes to the outgoing SDP if they were not already present.

	- `original sendrecv`

		With this flag present, *rtpengine* will leave the media direction attributes
		(`sendrecv`, `recvonly`, `sendonly`, and `inactive`) from the received SDP body
		unchanged. Normally *rtpengine* would consume these attributes and insert its
		own version of them based on other media parameters (e.g. a media section with
		a zero IP address would come out as `sendonly` or `inactive`).

	- `inject DTMF`

		Signals to *rtpengine* that the audio streams involved in this `offer` or `answer`
		(the flag should be present in both of them) are to be made available for DTMF
		injection via the `play DTMF` control message. See `play DTMF` below for additional
		information.

* `replace`

	Similar to the `flags` list. Controls which parts of the SDP body should be rewritten.
	Contains zero or more of:

	- `origin`

		Replace the address found in the *origin* (o=) line of the SDP body. Corresponds
		to *rtpproxy* `o` flag.

	- `session connection` or `session-connection`

		Replace the address found in the *session-level connection* (c=) line of the SDP body.
		Corresponds to *rtpproxy* `c` flag.

* `direction`

	Contains a list of two strings and corresponds to the *rtpproxy* `e` and `i` flags. Each element must
	correspond to one of the named logical interfaces configured on the
	command line (through `--interface`). For example, if there is one logical interface named `pub` and
	another one named `priv`, then if side A (originator of the message) is considered to be
	on the private network and side B (destination of the message) on the public network, then that would
	be rendered within the dictionary as:

		{ ..., "direction": [ "priv", "pub" ], ... }

	This only needs to be done for an initial `offer`; for the `answer` and any subsequent offers (between
	the same endpoints) *rtpengine* will remember the selected network interface.

	As a special case to support legacy usage of this option, if the given interface names are
	`internal` or `external` and if no such interfaces have been configured, then they're understood as
	selectors between IPv4 and IPv6 addresses.
	However, this mechanism for selecting the address family is now obsolete
	and the `address family` dictionary key should be used instead.

	For legacy support, the special direction keyword `round-robin-calls` can be used to invoke the
	round-robin interface selection algorithm described in the section *Interfaces configuration*.
	If this special keyword is used, the round-robin selection will run over all configured
	interfaces, whether or not they are configured using the `BASE:SUFFIX` interface name notation.
	This special keyword is provided only for legacy support and should be considered obsolete.
	It will be removed in future versions.

* `received from`

	Contains a list of exactly two elements. The first element denotes the address family and the second
	element is the SIP message's source address itself. The address family can be one of `IP4` or `IP6`.
	Used if SDP addresses are neither trusted (through `SIP source address` or `--sip-source`) nor the
	`media address` key is present.

* `ICE`

	Contains a string, valid values are `remove`, `force` or `force-relay`.
	With `remove`, any ICE attributes are
	stripped from the SDP body. With `force`, ICE attributes are first stripped, then new attributes are
	generated and inserted, which leaves the media proxy as the only ICE candidate. The default behavior
	(no `ICE` key present at all) is: if no ICE attributes are present, a new set is generated and the
	media proxy lists itself as ICE candidate; otherwise, the media proxy inserts itself as a
	low-priority candidate.

	With `force-relay`, existing ICE candidates are left in place except `relay`
	type candidates, and *rtpengine* inserts itself as a `relay` candidate. It will also leave SDP
	c= and m= lines unchanged.

	This flag operates independently of the `replace` flags.

* `transport protocol`

	The transport protocol specified in the SDP body is to be rewritten to the string value given here.
	The media
	proxy will expect to receive this protocol on the allocated ports, and will talk this protocol when
	sending packets out. Translation between different transport protocols will happen as necessary.

	Valid values are: `RTP/AVP`, `RTP/AVPF`, `RTP/SAVP`, `RTP/SAVPF`.

* `media address`

	This can be used to override both the addresses present in the SDP body
	and the `received from` address. Contains either an IPv4 or an IPv6 address, expressed as a simple
	string. The format must be dotted-quad notation for IPv4 or RFC 5952 notation for IPv6.
	It's up to the RTP proxy to determine the address family type.

* `address family`

	A string value of either `IP4` or `IP6` to select the primary address family in the substituted SDP
	body. The default is to auto-detect the address family if possible (if the receiving end is known
	already) or otherwise to leave it unchanged.

* `rtcp-mux`

	A list of strings controlling the behaviour regarding rtcp-mux (multiplexing RTP and RTCP on a single
	port, RFC 5761). The default behaviour is to go along with the client's preference. The list can contain
	zero of more of the following strings. Note that some of them are mutually exclusive.

	- `offer`

		Instructs *rtpengine* to always offer rtcp-mux, even if the client itself doesn't offer it.

	- `require`

		Similar to `offer` but pretends that the receiving client has already accepted rtcp-mux.
		The effect is that no separate RTCP ports will be advertised, even in an initial offer
		(which is against RFC 5761). This option is provided to talk to WebRTC clients.

	- `demux`

		If the client is offering rtcp-mux, don't offer it to the other side, but accept it back to
		the offering client.

	- `accept`

		Instructs *rtpengine* to accept rtcp-mux and also offer it to the other side if it has been
		offered.

	- `reject`

		Reject rtcp-mux if it has been offered. Can be used together with `offer` to achieve the opposite
		effect of `demux`.

* `TOS`

	Contains an integer. If present, changes the TOS value for the entire call, i.e. the TOS value used
	in outgoing RTP packets of all RTP streams in all directions. If a negative value is used, the previously
	used TOS value is left unchanged. If this key is not present or its value is too large (256 or more), then
	the TOS value is reverted to the default (as per `--tos` command line).

* `DTLS`

	Contains a string and influences the behaviour of DTLS-SRTP. Possible values are:

	- `off` or `no` or `disable`

		Prevents *rtpengine* from offering or acceping DTLS-SRTP when otherwise it would. The default
		is to offer DTLS-SRTP when encryption is desired and to favour it over SDES when accepting
		an offer.

	- `passive`

		Instructs *rtpengine* to prefer the passive (i.e. server) role for the DTLS
		handshake. The default is to take the active (client) role if possible. This is useful in cases
		where the SRTP endpoint isn't able to receive or process the DTLS handshake packets, for example
		when it's behind NAT or needs to finish ICE processing first.

* `SDES`

	A list of strings controlling the behaviour regarding SDES. The default is to offer SDES without any
	session parameters when encryption is desired, and to accept it when DTLS-SRTP is unavailable. If two
	SDES endpoints are connected to each other, then the default is to offer SDES with the same options
	as were received from the other endpoint. Additionally, all other supported SDES crypto suites are
	added to the outgoing offer by default.

	These options can also be put into the `flags` list using a prefix of `SDES-`. All options controlling
	SDES session parameters can be used either in all lower case or in all upper case.

	- `off` or `no` or `disable`

		Prevents *rtpengine* from offering SDES, leaving DTLS-SRTP as the other option.

	- `unencrypted_srtp`, `unencrypted_srtcp` and `unauthenticated_srtp`

		Enables the respective SDES session parameter (see section 6.3 or RFC 4568). The default is to
		copy these options from the offering client, or not to have them enabled if SDES wasn't offered.

	- `encrypted_srtp`, `encrypted_srtcp` and `authenticated_srtp`

		Negates the respective option. This is useful if one of the session parameters was offered by
		an SDES endpoint, but it should not be offered on the far side if this endpoint also speaks SDES.

	- `no-`*SUITE*

		Exclude individual crypto suites from being included in the offer. For example,
		`no-NULL_HMAC_SHA1_32` would exclude the crypto suite `NULL_HMAC_SHA1_32` from
		the offer. This has two effects: if a given crypto suite was present in a received
		offer, it will be removed and will be missing in the outgoing offer; and if a given crypto
		suite was not present in the received offer, it will not be added to it.

* `record call`

	Contains one of the strings `yes`, `no`, `on` or `off`. This tells the rtpengine
	whether or not to record the call to PCAP files. If the call is recorded, it
	will generate PCAP files for each stream and a metadata file for each call.
	Note that rtpengine *will not* force itself into the media path, and other
	flags like `ICE=force` may be necessary to ensure the call is recorded.

	See the `--recording-dir` option above.

	Enabling call recording via this option has the same effect as doing it separately
	via the `start recording` message, except that this option guarantees that the
	entirety of the call gets recorded, including all details such as SDP bodies
	passing through *rtpengine*.

* `metadata`

	This is a generic metadata string. The metadata will be written to the bottom of
	metadata files within `/path/to/recording_dir/metadata/` or to
	`recording_metakeys` table.  In the latter case, `metadata` string must
	contain a list of `key:val` pairs separated by `|` character.  `metadata` can be used to
	record additional information about recorded calls. `metadata` values passed in
	through subsequent messages will overwrite previous metadata values.

	See the `--recording-dir` option above.

* `codec`

	Contains a dictionary controlling various aspects of codecs (or RTP payload types).
	These options are only processed in `offer` messages and ignored otherwise.

	These options can also be put into the `flags` list using a prefix of `codec-`. For example,
	to set the codec options for two variants of Opus when they're implicitly accepted, (see
	the example under `set`), one would put the following into the `flags` list:
	`codec-set-opus/48000/1/16000` `codec-set-opus/48000/2/32000`

	The following keys are understood:

	* `strip`

		Contains a list of strings. Each string is the name of a codec or RTP payload
		type that should be removed from the SDP. Codec names are case sensitive, and
		can be either from the list of codecs explicitly defined by the SDP through
		an `a=rtpmap` attribute, or can be from the list of RFC-defined codecs. Examples
		are `PCMU`, `opus`, or `telephone-event`. Codecs stripped using this option
		are treated as if they had never been in the SDP.

		It is possible to specify codec format parameters alongside with the codec name
		in the same format as they're written in SDP for codecs that support them,
		for example `opus/48000` to
		specify Opus with 48 kHz sampling rate and one channel (mono), or
		`opus/48000/2` for stereo Opus. If any format parameters are specified,
		the codec will only be stripped if all of the format parameters match, and other
		instances of the same codec with different format parameters will be left
		untouched.

		As a special keyword, `all` can be used to remove all codecs, except the ones
		that should explicitly offered (see below). Note that it is an error to strip
		all codecs and leave none that could be offered. In this case, the original
		list of codecs will be left unchanged.

	* `offer`

		Contains a list of strings. Each string is the name of a codec that should be
		included in the list of codecs offered. This is primarily useful to block all
		codecs (`strip -> all`) except the ones given in the `offer` whitelist.
		Codecs that were not present in the original list of codecs
		offered by the client will be ignored.

		This list also supports codec format parameters as per above.

	* `transcode`

		Similar to `offer` but allows codecs to be added to the list of offered codecs
		even if they were not present in the original list of codecs. In this case,
		the transcoding engine will be engaged. Only codecs that are supported for both
		decoding and encoding can be added in this manner. This also has the side effect
		of automatically stripping all unsupported codecs from the list of offered codecs,
		as *rtpengine* must expect to receive or even send in any codec that is present
		in the list.

		Note that using this option does not necessarily always engage the transcoding
		engine. If all codecs given in the `transcode` list were present in the original
		list of offered codecs, then no transcoding will be done. Also note that if
		transcoding takes place, in-kernel forwarding is disabled for this media stream
		and all processing happens in userspace.

		If no codec format parameters are specified in this list (e.g. just `opus`
		instead of `opus/48000/2`), default values will be chosen for them.

		For codecs that support different bitrates, it can be specified by appending
		another slash followed by the bitrate in bits per second,
		e.g. `opus/48000/2/32000`. In this case, all format parameters (clock rate,
		channels) must also be specified.

		Additional options that can be appended to the codec string with additional slashes
		are ptime and the `fmtp` string, for example `iLBC/8000/1///mode=30`.

		As a special case, if the `strip=all` option has been used and the `transcode`
		option is used on a codec that was originally present in the offer, then
		*rtpengine* will treat this codec the same as if it had been used with the `offer`
		option, i.e. it will simply restore it from the list of stripped codecs and won't
		actually engage transcoding for this codec. On the other hand, if a codec has
		been stripped explicitly by name using the `strip` option and then used again
		with the `transcode` option, then the codec will not simply be restored from the
		list of stripped codecs, but instead a new transcoded instance of the codec will
		be inserted into the offer.

	* `mask`

		Similar to `strip` except that codecs listed here will still be accepted and
		used for transcoding on the offering side. Useful only in combination with
		`transcode`. For example, if an offer advertises Opus and the options
		`mask=opus, transcode=G723` are given, then the rewritten outgoing offer
		will contain only G.723 as offered codec, and transcoding will happen
		between Opus and G.723. In contrast, if only `transcode=G723` were given, then
		the rewritten outgoing offer would contain both Opus and G.723. On the other
		hand, if `strip=opus, transcode=G723` were given, then Opus would be unavailable
		for transcoding.

		As with the `strip` option, the special keyword `all` can be used to mask all
		codecs that have been offered.

	* `set`

		Contains a list of strings. This list makes it possible to set codec options
		(bitrate in particular) for codecs that are implicitly accepted for transcoding.
		For example, if `AMR` was offered, `transcode=PCMU` was given, and the remote
		ended up accepting `PCMU`, then this option can be used to set the bitrate used
		for the AMR transcoding process.

		Each string must be a full codec specification as per above, including clock rate
		and number of channels. Using the example above, `set=AMR/8000/1/7400` can be used
		to transcode to AMR with 7.4 kbit/s.

		Codec options (bitrate) are only applied to codecs that match the given parameters
		(clock rate, channels), and multiple options can be given for the same coded with
		different parameters. For example, to specify different bitrates for Opus for both
		mono and stereo output, one could use `set=[opus/48000/1/16000,opus/48000/2/32000]`.

* `ptime`

	Contains an integer. If set, changes the `a=ptime` attribute's value in the outgoing
	SDP to the provided value. It also engages the transcoding engine for supported codecs
	to provide repacketization functionality, even if no additional codec has actually
	been requested for transcoding. Note that not all codecs support all packetization
	intervals.

	The selected ptime (which represents the duration of a single media packet in milliseconds)
	will be used towards the endpoint receiving this offer, even if the matching answer
	prefers a different ptime.

	This option is ignored in `answer` messages. See below for the reverse.

* `ptime-reverse`

	This is the reciprocal to `ptime`. It sets the ptime to be used towards the endpoint
	who has sent the offer. It will be inserted in the `answer` SDP. This option is also
	ignored in `answer` messages.

* `supports`

	Contains a list of strings. Each string indicates support for an additional feature
	that the controlling SIP proxy supports. Currently defined values are:

	* `load limit`

		Indicates support for an extension to the *ng* protocol to facilitate certain load
		balancing mechanisms. If *rtpengine* is configured with certain session or load
		limit options enabled (such as the `max-sessions` option), then normally *rtpengine*
		would reply with an error to an `offer` if one of the limits is exceeded. If support
		for the `load limit` extension is indicated, then instead of replying with an error,
		*rtpengine* responds with the string `load limit` in the `result` key of the response
		dictionary. The response dictionary may also contain the optional key `message` with
		an explanatory string. No other key is required in the response dictionary.

* `xmlrpc-callback`

	Contains a string that encodes an IP address (either IPv4 or IPv6) in printable format.
	If specified, then this address will be used as destination address for the XMLRPC timeout
	callback (see `b2b-url` option).

An example of a complete `offer` request dictionary could be (SDP body abbreviated):

	{ "command": "offer", "call-id": "cfBXzDSZqhYNcXM", "from-tag": "mS9rSAn0Cr",
	"sdp": "v=0\r\no=...", "via-branch": "5KiTRPZHH1nL6",
	"flags": [ "trust address" ], "replace": [ "origin", "session connection" ],
	"address family": "IP6", "received-from": [ "IP4", "10.65.31.43" ],
	"ICE": "force", "transport protocol": "RTP/SAVPF", "media address": "2001:d8::6f24:65b",
	"DTLS": "passive" }

The response message only contains the key `sdp` in addition to `result`, which contains the re-written
SDP body that the SIP proxy should insert into the SIP message.

Example response:

	{ "result": "ok", "sdp": "v=0\r\no=..." }

`answer` Message
----------------

The `answer` message is identical to the `offer` message, with the additional requirement that the
dictionary must contain the key `to-tag` containing the SIP `To` tag. It doesn't make sense to include
the `direction` key in the `answer` message.

The reply message is identical as in the `offer` reply.

`delete` Message
----------------

The `delete` message must contain at least the keys `call-id` and `from-tag` and may optionally include
`to-tag` and `via-branch`, as defined above. It may also optionally include a key `flags` containing a list
of zero or more strings. The following flags are defined:

* `fatal`

	Specifies that any non-syntactical error encountered when deleting the stream
	(such as unknown call-ID) shall
	result in an error reply (i.e. `"result": "error"`). The default is to reply with a warning only
	(i.e. `"result": "ok", "warning": ...`).

Other optional keys are:

* `delete delay`

	Contains an integer and overrides the global command-line option `delete-delay`. Call/branch will be
	deleted immediately if a zero is given. Value must be positive (in seconds) otherwise.

The reply message may contain additional keys with statistics about the deleted call. Those additional keys
are the same as used in the `query` reply.

`list` Message
--------------

The `list` command retrieves the list of currently active call-ids. This list is limited to 32 elements by
default.

* `limit`

	Optional integer value that specifies the maximum number of results (default: 32). Must be > 0. Be
	careful when setting big values, as the response may not fit in a UDP packet, and therefore be invalid.

`query` Message
---------------

The minimum requirement is the presence of the `call-id` key. Keys `from-tag` and/or `to-tag` may optionally
be specified.

The response dictionary contains the following keys:

* `created`

	Contains an integer corresponding to the creation time of this call within the media proxy,
	expressed as seconds since the UNIX epoch.

* `last signal`

	The last time a signalling event (offer, answer, etc) occurred. Also expressed as an integer
	UNIX timestamp.

* `tags`

	Contains a dictionary. The keys of the dictionary are all the SIP tags (From-tag, To-Tag) known
	by *rtpengine* related to this call. One of the keys may be an empty string, which corresponds to
	one side of a dialogue which hasn't signalled its SIP tag yet. Each value of the dictionary is
	another dictionary with the following keys:

	- `created`

		UNIX timestamp of when this SIP tag was first seen by *rtpengine*.

	- `tag`

		Identical to the corresponding key of the `tags` dictionary. Provided to allow for easy
		traversing of the dictionary values without paying attention to the keys.

	- `label`

		The label assigned to this endpoint in the `offer` or `answer` message.

	- `in dialogue with`

		Contains the SIP tag of the other side of this dialogue. May be missing in case of a
		half-established dialogue, in which case the other side is represented by the null-string
		entry of the `tags` dictionary.

	- `medias`

		Contains a list of dictionaries, one for each SDP media stream known to *rtpengine*. The
		dictionaries contain the following keys:

		+ `index`

			Integer, sequentially numbered index of the media, starting with one.

		+ `type`

			Media type as string, usually `audio` or `video`.

		+ `protocol`

			If the protocol is recognized by *rtpengine*, this string contains it.
			Usually `RTP/AVP` or `RTP/SAVPF`.

		+ `flags`

			A list of strings containing various status flags. Contains zero of more
			of: `initialized`, `rtcp-mux`, `DTLS-SRTP`, `SDES`, `passthrough`, `ICE`.

		+ `streams`

			Contains a list of dictionary representing the packet streams associated
			with this SDP media. Usually contains two entries, one for RTP and one for RTCP.
			The keys found in these dictionaries are listed below:

		+ `local port`

			Integer representing the local UDP port. May be missing in case of an inactive stream.

		+ `endpoint`

			Contains a dictionary with the keys `family`, `address` and `port`. Represents the
			endpoint address used for packet forwarding. The `family` may be one of `IPv4` or
			`IPv6`.

		+ `advertised endpoint`

			As above, but representing the endpoint address advertised in the SDP body.

		+ `crypto suite`

			Contains a string such as `AES_CM_128_HMAC_SHA1_80` representing the encryption
			in effect. Missing if no encryption is active.

		+ `last packet`

			UNIX timestamp of when the last UDP packet was received on this port.

		+ `flags`

			A list of strings with various internal flags. Contains zero or more of:
			`RTP`, `RTCP`, `fallback RTCP`, `filled`, `confirmed`, `kernelized,`
			`no kernel support`.

		+ `stats`

			Contains a dictionary with the keys `bytes`, `packets` and `errors`.
			Statistics counters for this packet stream.

* `totals`

	Contains a dictionary with two keys, `RTP` and `RTCP`, each one containing another dictionary
	identical to the `stats` dictionary described above.

A complete response message might look like this (formatted for readability):

          {
            "totals": {
              "RTCP": {
                    "bytes": 2244,
                    "errors": 0,
                    "packets": 22
                  },
              "RTP": {
                   "bytes": 100287,
                   "errors": 0,
                   "packets": 705
                 }
                  },
            "last_signal": 1402064116,
            "tags": {
                  "cs6kn1rloc": {
                  "created": 1402064111,
                  "medias": [
                          {
                      "flags": [
                             "initialized"
                           ],
                      "streams": [
                               {
                           "endpoint": {
                               "port": 57370,
                               "address": "10.xx.xx.xx",
                               "family": "IPv4"
                                   },
                           "flags": [
                                  "RTP",
                                  "filled",
                                  "confirmed",
                                  "kernelized"
                                ],
                           "local port": 30018,
                           "last packet": 1402064124,
                           "stats": {
                                  "packets": 343,
                                  "errors": 0,
                                  "bytes": 56950
                                },
                           "advertised endpoint": {
                                    "family": "IPv4",
                                    "port": 57370,
                                    "address": "10.xx.xx.xx"
                                  }
                               },
                               {
                           "stats": {
                                  "bytes": 164,
                                  "errors": 0,
                                  "packets": 2
                                },
                           "advertised endpoint": {
                                    "family": "IPv4",
                                    "port": 57371,
                                    "address": "10.xx.xx.xx"
                                  },
                           "endpoint": {
                               "address": "10.xx.xx.xx",
                               "port": 57371,
                               "family": "IPv4"
                                   },
                           "last packet": 1402064123,
                           "local port": 30019,
                           "flags": [
                                  "RTCP",
                                  "filled",
                                  "confirmed",
                                  "kernelized",
                                  "no kernel support"
                                ]
                               }
                             ],
                      "protocol": "RTP/AVP",
                      "index": 1,
                      "type": "audio"
                          }
                        ],
                  "in dialogue with": "0f0d2e18",
                  "tag": "cs6kn1rloc"
                      },
                  "0f0d2e18": {
                      "in dialogue with": "cs6kn1rloc",
                      "tag": "0f0d2e18",
                      "medias": [
                        {
                          "protocol": "RTP/SAVPF",
                          "index": 1,
                          "type": "audio",
                          "streams": [
                             {
                               "endpoint": {
                                   "family": "IPv4",
                                   "address": "10.xx.xx.xx",
                                   "port": 58493
                                 },
                               "crypto suite": "AES_CM_128_HMAC_SHA1_80",
                               "local port": 30016,
                               "last packet": 1402064124,
                               "flags": [
                                "RTP",
                                "filled",
                                "confirmed",
                                "kernelized"
                              ],
                               "stats": {
                                "bytes": 43337,
                                "errors": 0,
                                "packets": 362
                              },
                               "advertised endpoint": {
                                  "address": "10.xx.xx.xx",
                                  "port": 58493,
                                  "family": "IPv4"
                                }
                             },
                             {
                               "local port": 30017,
                               "last packet": 1402064124,
                               "flags": [
                                "RTCP",
                                "filled",
                                "confirmed",
                                "kernelized",
                                "no kernel support"
                              ],
                               "endpoint": {
                                   "family": "IPv4",
                                   "port": 60193,
                                   "address": "10.xx.xx.xx"
                                 },
                               "crypto suite": "AES_CM_128_HMAC_SHA1_80",
                               "advertised endpoint": {
                                  "family": "IPv4",
                                  "port": 60193,
                                  "address": "10.xx.xx.xx"
                                },
                               "stats": {
                                "packets": 20,
                                "bytes": 2080,
                                "errors": 0
                              }
                             }
                           ],
                          "flags": [
                           "initialized",
                           "DTLS-SRTP",
                           "ICE"
                         ]
                        }
                      ],
                      "created": 1402064111
                    }
                },
            "created": 1402064111,
            "result": "ok"
          }

`start recording` Message
-------------------------

The `start recording` message must contain at least the key `call-id` and may optionally include `from-tag`,
`to-tag` and `via-branch`, as defined above. The reply dictionary contains no additional keys.

Enables call recording for the call, either for the entire call or for only the specified call leg. Currently
*rtpengine* always enables recording for the entire call and does not support recording only individual
call legs, therefore all keys other than `call-id` are currently ignored.

If the chosen recording method doesn't support in-kernel packet forwarding, enabling call recording
via this messages will force packet forwarding to happen in userspace only.

`stop recording` Message
-------------------------

The `stop recording` message must contain the key `call-id` as defined above. The reply dictionary contains
no additional keys.

Disables call recording for the call. This can be sent during a call to immediately stop recording it.

`block DTMF` and `unblock DTMF` Messages
----------------------------------------

These message types must include the key `call-id` in the message. They enable and disable blocking of DTMF
events (RFC 4733 type packets), respectively.

Packets can be blocked for an entire call if only the `call-id` key is present in the message, or can be blocked
directionally for individual participants. Participants can be selected by their SIP tag if the `from-tag` key
is included in the message, they can be selected by their SDP media address if the `address` key is included
in the message, or they can be selected by the user-provided `label` if the `label` key is included in the
message. For an address, it can be an IPv4 or IPv6 address, and any participant that is
found to have a matching address advertised as their SDP media address will have their originating RTP
packets blocked (or unblocked).

Unblocking packets for the entire call (i.e. only `call-id` is given) does not automatically unblock packets for
participants which had their packets blocked directionally, unless the string `all` is included in the `flags`
section of the message.

When DTMF blocking is enabled, DTMF event packets will not be forwarded to the receiving peer.
If DTMF logging is enabled, DTMF events will still be logged to syslog while blocking is enabled. Blocking
of DTMF events can be enabled and disabled at any time during call runtime.

`block media` and `unblock media` Messages
------------------------------------------

Analogous to `block DTMF` and `unblock DTMF` but blocks media packets instead of DTMF packets. DTMF packets
can still pass through when media blocking is enabled. Media packets can be blocked for an entire call, or
directionally for individual participants. See `block DTMF` above for details.

`start forwarding` and `stop forwarding` Messages
-------------------------------------------------

These messages control the recording daemon's mechanism to forward PCM via TCP/TLS. Unlike the call recording
mechanism, forwarding can be enabled for individual participants (directionally) only, therefore these
messages can be used with the same options as the `block` and `unblock` messages above. The PCM forwarding
mechanism is independent of the call recording mechanism, and so forwarding and recording can be started
and stopped independently of each other.

`play media` Message
--------------------

Only available if compiled with transcoding support. The message must contain the key `call-id` and one
of the participant selection keys described under the `block DTMF` message (such as `from-tag`,
`address`, or `label`).

Starts playback of a provided media file to the selected call participant. The format of the media file
can be anything that is supported by *ffmpeg*, for example a `.wav` or `.mp3` file. It will automatically
be resampled and transcoded to the appropriate sampling rate and codec. The selected participant's first
listed (preferred) codec that is supported will be chosen for this purpose.

Media files can be provided through one of these keys:

* `file`

	Contains a string that points to a file on the local file system. File names can be relative
	to the daemon's working direction.

* `blob`

	Contains a binary blob (string) of the contents of a media file. Due to the limitations of the
	*ng* transport protocol, only very short files can be provided this way, and so this is primarily
	useful for testing and debugging.

* `db-id`

	Contains an integer. This requires the daemon to be configured for accessing a *MySQL* (or *MariaDB*)
	database via (at the minimum) the `mysql-host` and `mysql-query` config keys. The daemon will then
	retrieve the media file as a binary blob (not a file name!) from the database via the provided query.

In addition to the `result` key, the response dictionary may contain the key `duration` if the length of
the media file could be determined. The duration is given as in integer representing milliseconds.

`stop media` Message
--------------------

Stops the playback previously started by a `play media` message. Media playback stops automatically when
the end of the media file is reached, so this message is only useful for prematurely stopping playback.
The same participant selection keys as for the `play media` message can and must be used.

`play DTMF` Message
-------------------

Instructs *rtpengine* to inject a DTMF tone or event into a running audio stream. A call participant must
be selected in the same way as described under the `block DTMF` message above. The selected call participant
is the one generating the DTMF event, not the one receiving it.

The dictionary key `code` must be present in the message, indicating the DTMF event to be generated. It can
be either an integer with values 0-15, or a string containing a single character
(`0` - `9`, `*`, `#`, `A` - `D`). Additional optional dictionary keys are: `duration` indicating the duration
of the event in milliseconds (defaults to 250 ms, with a minimum of 100 and a maximum of 5000);
`volume` indicating the volume in absolute decibels (defaults to -8 dB, with 0 being the maximum volume and
positive integers being interpreted as negative); and `pause` indicating the pause in between consecutive
DTMF events in milliseconds (defaults to 100 ms, with a minimum of 100 and a maximum of 5000).

This message can be used to implement `application/dtmf-relay` or `application/dtmf` payloads carried
in SIP INFO messages. Multiple DTMF events can be queued up by issuing multiple consecutive
`play DTMF` messages.

If the destination participant supports the `telephone-event` RTP payload type, then it will be used to
send the DTMF event. Otherwise a PCM DTMF tone will be inserted into the audio stream. Audio samples
received during a generated DTMF event will be suppressed.

The call must be marked for DTMF injection using the `inject DTMF` flag used in both `offer` and `answer`
messages. Enabling this flag forces all audio to go through the transcoding engine, even if input and output
codecs are the same (similar to DTMF transcoding, see above).
