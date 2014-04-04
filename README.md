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
  + Supports ice-lite only
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

Mediaproxy-ng does not (yet) support:

* Repacketization or transcoding
* Playback of pre-recorded streams/announcements
* Recording of media streams
* ZRTP

Compiling and Installing
=========================

On a Debian System
------------------

On a Debian system, everything can be built and packaged into Debian packages
by executing `dpkg-buildpackage` (which can be found in the `dpkg-dev` package) in the main directory. 
This script will issue an error and stop if any of the dependency packages are
not installed.

This will produce a number of `.deb` files, which can then be installed using the
`dpkg -i` command.

The generated files are (with version 2.3.0 being built on an amd64 system):

* `ngcp-rtpengine_2.3.0_all.deb`

	This is a meta-package, which doesn't contain or install anything on its own, but rather
	only depends on the other packages to be installed. Not strictly necessary to be installed.

* `ngcp-rtpengine-daemon_2.3.0_amd64.deb`

	This installed the userspace daemon, which is the main workhorse of rtpengine. This is
	the minimum requirement for anything to work.

* `ngcp-rtpengine-dbg_2.3.0_amd64.deb`

	Debugging symbols for the daemon. Optional.

* `ngcp-rtpengine-dev_2.3.0_all.deb`

	Development headers from the daemon. Only necessary if additional modules need to be compiled.

* `ngcp-rtpengine-iptables_2.3.0_amd64.deb`

	Installs the plugin for `iptables` and `ip6tables`. Necessary for in-kernel operation.

* `ngcp-rtpengine-kernel-dkms_2.3.0_all.deb`

	Kernel module, DKMS version of the package. Recommended for in-kernel operation. The kernel
	module will be compiled against the currently running kernel using DKMS.

* `ngcp-rtpengine-kernel-source_2.3.0_all.deb`

	If DKMS is unavailable or not desired, then this package will install the sources for the kernel
	module for manual compilation. Required for in-kernel operation, but only if the DKMS package
	can't be used.

Manual Compilation
------------------

There's 3 parts to rtpengine, which can be found in the respective subdirectories.

* `daemon`

	The userspace daemon and workhorse, minimum requirement for anything to work. Running `make`
	will compile the binary, which will be called `rtpengine`. The following software packages
	including their development headers are required to compile the daemon:

	- *pkg-config*
	- *GLib* including *GThread* version 2.x
	- *zlib*
	- *OpenSSL*
	- *PCRE* library
	- *libcurl*
	- *XMLRPC-C* version 1.16.08 or higher

	The `Makefile` contains a few Debian-specific flags, which may have to removed for compilation to
	be successful. This will not affect operation in any way.

* `iptables-extension`

	Required for in-kernel packet forwarding.

	With the `iptables` development headers installed, issuing `make` will compile the plugin for
	`iptables` and `ip6tables`. The file will be called `libxt_MEDIAPROXY.so` and should be copied
	into the directory `/lib/xtables/`.

* `kernel-module`

	Required for in-kernel packet forwarding.

	Compilation of the kernel module requires the kernel development headers to be installed in
	`/lib/modules/$VERSION/build/`, where *$VERSION* is the output of the command `uname -r`. For
	example, if the command `uname -r` produces the output `3.9-1-amd64`, then the kernel headers
	must be present in `/lib/modules/3.9-1-amd64/build/`. The last component of this path (`build`)
	is usually a symlink somewhere into `/usr/src/`, which is fine.

	Successful compilation of the module will produce the file `xt_MEDIAPROXY.ko`. The module can be inserted
	into the running kernel manually through `insmod xt_MEDIAPROXY.ko` (which will result in an error if
	depending modules aren't loaded, for example the `x_tables` module), but it's recommended to copy the
	module into `/lib/modules/$VERSION/updates/`, followed by running `depmod -a`. After this, the module can
	be loaded by issuing `modprobe xt_MEDIAPROXY`.

Usage
=====

Userspace Daemon
----------------

The daemon supports a number of command-line options, which it will print if started with the `--help`
option and which are reproduced below:

	  -v, --version                    Print build time and exit
	  -t, --table=INT                  Kernel table to use
	  -F, --no-fallback                Only start when kernel module is available
	  -i, --ip=IP                      Local IPv4 address for RTP
	  -a, --advertised-ip=IP           IPv4 address to advertise
	  -I, --ip6=IP6                    Local IPv6 address for RTP
	  -A, --advertised-ip6=IP6         IPv6 address to advertise
	  -l, --listen-tcp=[IP:]PORT       TCP port to listen on
	  -u, --listen-udp=[IP46:]PORT     UDP port to listen on
	  -n, --listen-ng=[IP46:]PORT      UDP port to listen on, NG protocol
	  -T, --tos=INT                    TOS value to set on streams
	  -o, --timeout=SECS               RTP timeout
	  -s, --silent-timeout=SECS        RTP timeout for muted
	  -p, --pidfile=FILE               Write PID to file
	  -f, --foreground                 Don't fork to background
	  -m, --port-min=INT               Lowest port to use for RTP
	  -M, --port-max=INT               Highest port to use for RTP
	  -r, --redis=IP:PORT              Connect to Redis database
	  -R, --redis-db=INT               Which Redis DB to use
	  -b, --b2b-url=STRING             XMLRPC URL of B2B UA

Most of these options are indeed optional, with two exceptions. It's mandatory to specify a local
IPv4 address through `--ip`, and at least one of the `--listen-...` options must be given.

The options are described in more detail below.

* -v, --version

	If called with this option, the *rtpengine* daemon will simply print its version number
	and exit.

* -t, --table

	Takes an integer argument and specifies which kernel table to use for in-kernel packet forwarding. See
	the section on in-kernel operation for more detail. Optional and defaults to zero. If in-kernel
	operation is not desired, a negative number can be specified.

* -F, --no-fallback

	Will prevent fallback to userspace-only operation if the kernel module is unavailable. In this case,
	startup of the daemon will fail with an error if this option is given.

* -i, --ip, -I, --ip6

	Takes an IPv4 address and an IPv6 address as argument, respectively. Specifies the local interfaces to
	use for packet forwarding and to allocate UDP ports from. IPv4 address is mandatory, IPv6 is optional and
	will result in IPv6 not being available if not specified.

* -a, --advertised-ip, -A, --advertised-ip6

	Takes an IPv4 address and an IPv6 address as argument, respectively. Optional. If specified,
	*rtpengine* will advertise addresses different from those given in the `--ip` and `--ip6` options
	as its local address. This is useful for operation behind NAT.

* -l, --listen-tcp, -u, --listen-udp, -n, --listen-ng

	These options each enable one of the 3 available control protocols if given and each take either
	just a port number as argument, or an *address:port* pair, separated by colon. At least one of these
	3 options must be given.

	The *tcp* protocol is obsolete. It was used by old versions of *OpenSER* and its *mediaproxy* module.
	It's provided for backwards compatibility.

	The *udp* protocol is used by Kamailio's *rtpproxy* module. In this mode, *rtpengine* can
	be used as a drop-in replacement for any other compatible RTP proxy.

	The *ng* protocol is an advanced control protocol and can be used with *Kamailio*'s *rtpengine*
	module. With this protocol, the complete SDP body is passed to *rtpengine*, rewritten and
	passed back to *Kamailio*. Several additional features are available with this protocol, such as
	ICE handling, SRTP bridging, etc.

	It is recommended to specify not only a local port number, but also 127.0.0.1 as interface to bind to.

* -t, --tos

	Takes an integer as argument and if given, specifies the TOS value that should be set in outgoing
	packets. The default is to leave the TOS field untouched. A typical value is 184 (Expedited Forwarding).

* -o, --timeout

	Takes the number of seconds as argument after which a media stream should be considered dead if no media
	traffic has been received. If all media streams belonging to a particular call go dead, then the call
	is removed from *rtpengine*'s internal state table. Defaults to 60 seconds.

* -s, --silent-timeout

	Ditto as the `--timeout` option, but applies to muted or inactive media streams. Defaults to 3600
	(one hour).

* -p, --pidfile

	Specifies a path and file name to write the daemon's PID number to.

* -f, --foreground

	If given, prevents the daemon from daemonizing, meaning it will stay in the foreground.
	Useful for debugging.

* -m, --port-min, -M, --port-max

	Both take an integer as argument and together define the local port range from which *rtpengine*
	will allocate UDP ports for media traffic relay. Default to 30000 and 40000 respectively.

*  -r, --redis, -R, --redis-db, -b, --b2b-url

	NGCP-specific options

A typical command line (enabling both UDP and NG protocols) thus may look like:

	/usr/sbin/rtpengine --table=0 --ip=10.64.73.31 --ip6=2001:db8::4f3:3d \
	--listen-udp=127.0.0.1:22222 --listen-ng=127.0.0.1:2223 --tos=184 \
	--pidfile=/var/run/rtpengine.pid

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
packets being tranferred at high rates. Since the forwarding overhead is incurred on a per-packet basis, the
ratio of useful data processed to overhead drops dramatically.

For these reasons, *rtpengine* provides a kernel module to offload the bulk of the packet forwarding
duties from user space to kernel space. Using this technique, a large percentage of the overhead can be
eliminated, CPU usage greatly reduced and the number of concurrent calls possible to be handled increased.

In-kernel packet forwarding is implemented as an *iptables* module
(or more precisely, an *x\_tables* module). As such, it comes in two parts, both of
which are required for proper operation. One part is the actual kernel module called `xt_MEDIAPROXY`. The
second part is a plugin to the `iptables` and `ip6tables` command-line utilities to make it possible to
actually add the required rule to the tables.

### Overview ###

In short, the prerequisites for in-kernel packet forwarding are:

1. The `xt_MEDIAPROXY` kernel module must be loaded.
2. An `iptables` and/or `ip6tables` rule must be present in the `INPUT` chain to send packets
   to the `MEDIAPROXY` target. This rule should be limited to UDP packets, but otherwise there
   are no restrictions.
3. The `rtpengine` daemon must be running.
4. All of the above must be set up with the same forwarding table ID (see below).

The sequence of events for a newly established media stream is then:

1. The SIP proxy (e.g. *Kamailio*) controls *rtpengine* and informs it about a newly established call.
2. The `rtpengine` daemon allocates local UDP ports and sets up preliminary forward rules
   based on the info received
   from the SIP proxy. Only userspace forwarding is set up, nothing is pushed to the kernel module yet.
3. An RTP packet is received on the local port.
4. It traverses the *iptables* chains and gets passed to the *xt\_MEDIAPROXY* module.
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
    removal of the *iptables* rule) or deliberatly (the daemon will do so in case of a re-invite), in which
    case forwarding falls back to userspace-only operation.

### The Kernel Module ###

The kernel module supports multiple forwarding tables (not to be confused with the tables managed
by *iptables*), which are identified through their ID number. By default, up to 64 forwarding tables
can be created and used, giving them the ID numbers 0 through 63.

Each forwarding table can be thought of a separate proxy instance. Each running instance of the
*rtpengine* daemon controls one such table, and each table can only be controlled by one
running instance of the daemon at any given time. In the most common setup, there will be only a single
instance of the daemon running and there will be only a single forwarding table in use, with ID zero.

The kernel module can be loaded with the command `modprobe xt_MEDIAPROXY`. With the module loaded, a new
directory will appear in `/proc/`, namely `/proc/mediaproxy/`. After loading, the directory will contain
only two pseudo-files, `control` and `list`. The `control` file is write-only and is used to create and
delete forwarding tables, while the `list` file is read-only and will produce a list of currently
active forwarding tables. With no tables active, it will produce an empty output.

The `control` pseudo-file supports two commands, `add` and `del`, each followed by the forwarding table
ID number. To manually create a forwarding table with ID 42, the following command can be used:

	echo 'add 42' > /proc/mediaproxy/control

After this, the `list` pseudo-file will produce the single line `42` as output. This will also create a
directory called `42` in `/proc/mediaproxy/`, which contains additional pseudo-files to control this
particular forwarding table.

To delete this forwarding table, the command `del 42` can be issued like above. This will only work
if no *rtpengine* daemon is currently running and controlling this table.

Each subdirectory `/proc/mediaproxy/$ID/` corresponding to each fowarding table contains the pseudo-files
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

The kernel module can be unloaded through `rmmod xt_MEDIAPROXY`, however this only works if no forwarding
table currently exists and no *iptables* rule currently exists.

### The *iptables* module ###

In order for the kernel module to be able to actually forward packets, an *iptables* rule must be set up
to send packets into the module. Each such rule is associated with one forwarding table. In the simplest case,
for forwarding table 42, this can be done through:

	iptables -I INPUT -p udp -j MEDIAPROXY --id 42

If IPv6 traffic is expected, the same should be done using `ip6tables`.

It is possible but not strictly
necessary to restrict the rules to the UDP port range used by *rtpengine*, e.g. by supplying a parameter
like `--dport 30000:40000`. If the kernel module receives a packet that it doesn't recognize as belonging
to an active media stream, it will simply ignore it and hand it back to the network stack for normal
processing.

Summary
-------

A typical start-up sequence including in-kernel forwarding might look like this:

	# this only needs to be one once after system (re-) boot
	modprobe xt_MEDIAPROXY
	iptables -I INPUT -p udp -j MEDIAPROXY --id 0
	ip6tables -I INPUT -p udp -j MEDIAPROXY --id 0

	# ensure that the table we want to use doesn't exist - usually needed after a daemon
	# restart, otherwise will error
	echo 'del 0' > /proc/mediaproxy/control

	# start daemon
	/usr/sbin/rtpengine --table=0 --ip=10.64.73.31 --ip6=2001:db8::4f3:3d \
	--listen-ng=127.0.0.1:2223 --tos=184 --pidfile=/var/run/rtpengine.pid --no-fallback

Running Multiple Instances
--------------------------

In some cases it may be desired to run multiple instances of *rtpengine* on the same machine, for example
if the host is multi-homed and has multiple usable network interfaces with different addresses. This is
supported by running multiple instances of the daemon using different command-line options (different
local addresses and different listening ports), together with
multiple different kernel forwarding tables.

For example, if one local network interface has address 10.64.73.31 and another has address 192.168.65.73,
then the start-up sequence might look like this:

	modprobe xt_MEDIAPROXY
	iptables -I INPUT -p udp -d 10.64.73.31 -j MEDIAPROXY --id 0
	iptables -I INPUT -p udp -d 192.168.65.73 -j MEDIAPROXY --id 1

	echo 'del 0' > /proc/mediaproxy/control
	echo 'del 1' > /proc/mediaproxy/control

	/usr/sbin/rtpengine --table=0 --ip=10.64.73.31 \
	--listen-ng=127.0.0.1:2223 --tos=184 --pidfile=/var/run/rtpengine-10.pid --no-fallback
	/usr/sbin/rtpengine --table=1 --ip=192.168.65.73 \
	--listen-ng=127.0.0.1:2224 --tos=184 --pidfile=/var/run/rtpengine-192.pid --no-fallback

With this setup, the SIP proxy can choose which instance of *rtpengine* to talk to and thus which local
interface to use by sending its control messages to either port 2223 or port 2224.

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

The response dictionary must contain at least one key called `result`. The value can be either `ok` or `error`.
For the `ping` command, the additional value `pong` is allowed. If the result is `error`, then another key
`error-reason` must be given, containing a string with a human-readable error message. No other keys should
be present in the error case. If the result is `ok`, the optional key `warning` may be present, containing a
human-readable warning message. This can be used for non-fatal errors.

For readabilty, all data objects below are represented in a JSON-like notation and without the message cookie.
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

* `flags`

	The value of the `flags` key is a list. The list contains zero or more of the following strings:

	- `trust address`

		If given, the media addresses from the SDP body are trusted as correct endpoints. Otherwise, the
		address is taken from the `received from` key. Corresponds to the *rtpproxy* `r` flag.
		Can be overridden through the `media address` key.

	- `symmetric`

		Corresponds to the *rtpproxy* `w` flag. Not used by *rtpengine*.

	- `asymmetric`

		Corresponds to the *rtpproxy* `a` flag. Not used by *rtpengine*.

* `replace`

	Similar to the `flags` list. Controls which parts of the SDP body should be rewritten.
	Contains zero or more of:

	- `origin`

		Replace the address found in the *origin* (o=) line of the SDP body. Corresponds
		to *rtpproxy* `o` flag.

	- `session connection`

		Replace the address found in the *session-level connection* (c=) line of the SDP body.
		Corresponds to *rtpproxy* `c` flag.

* `direction`

	Contains a list of zero, one or two elements, and corresponds to the *rtpproxy* `e` and `i` flags. Each
	element may be either the string `internal` or `external`. For example, if side A is considered to be
	on the external network and side B on the internal network (which in the *rtpproxy* module would be
	specified as flags `ei`), then that would be rendered within the dictionary as:

  		{ ..., "direction": [ "external", "internal" ], ... }

	*Mediaproxy-ng* uses the direction to implement bridging between IPv4 and IPv6: internal is seen as
	IPv4 and external as IPv6.

* `received from`

	Contains a list of exactly two elements. The first element denotes the address family and the second
	element is the SIP message's source address itself. The address family can be one of `IP4` or `IP6`.
	Used if neither the `trust address` flag nor the `media address` key is present.

* `ICE`

	Contains a string, valid values are either `remove` or `force`. With `remove`, any ICE attributes are
	stripped from the SDP body. With `force`, ICE attributes are first stripped, then new attributes are
	generated and inserted, which leaves the media proxy as the only ICE candidate. The default behavior
	(no `ICE` key present at all) is: if no ICE attributes are present, a new set is generated and the
	media proxy lists itself as ICE candidate; otherwise, the media proxy inserts itself as a
	low-priority candidate.

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

An example of a complete `offer` request dictionary could be (SDP body abbreviated):

	{ "command": "offer", "call-id": "cfBXzDSZqhYNcXM", "from-tag": "mS9rSAn0Cr",
	"sdp": "v=0\r\no=...", "via-branch": "5KiTRPZHH1nL6",
	"flags": [ "trust address" ], "replace": [ "origin", "session connection" ],
	"direction": [ "external", "external" ], "received-from": [ "IP4", "10.65.31.43" ],
	"ICE": "force", "transport protocol": "RTP/SAVPF", "media address": "2001:d8::6f24:65b" }

The response message only contains the key `sdp` in addition to `result`, which contains the re-written
SDP body that the SIP proxy should insert into the SIP message.

Example response:

	{ "result": "ok", "sdp": "v=0\r\no=..." }

`answer` Message
---------------

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

The reply message may contain additional keys with statistics about the deleted call. Those additional keys
are the same as used in the `query` reply.

`query` Message
---------------

The minimum requirement is the presence of the `call-id` key. Keys `from-tag` and/or `to-tag` may optionally
be specified.

The response dictionary contains the following keys:

* `created`

	Contains an integer corresponding to the creation time of this call within the media proxy,
	expressed as seconds since the UNIX epoch.

* `streams`

	**SUBJECT TO CHANGE**

	Contains a list of media streams associated with this call. Each list element corresponds to one
	bi-directional media stream and is itself a list with two elements. The first element of each
	sub-list corresponds to side A of the media stream, the second element corresponds to side B.
	Each element of the sub-list is a dictionary with the following keys:

	- `tag`

		The SIP tag (either `From` or `To` tag depending on side A or B)

	- `codec`

		The codec is the media stream, if known.

	- `status`

		A human readable description of the stream's status, such as `in kernel` or `unknown peer address`.

	- `stats`

		A dictionary with two elements, `rtp` and `rtcp`. Each in turn contains the following keys:

		+ `counters`

			Contains another dictionary with counters (each encoded as integers) for `packets`,
			`bytes` and `errors`.

		+ `peer address`

			Contains a dictionary describing the peer's `family` (address family) as either
			`IPv4` or `IPv6`, the `address` in human-readable string encoding, and `port`
			encoded as integer.

		+ `advertised peer address`

			Identical to `peer address`, but contains whatever endpoint was advertised in the
			SDP body.

		+ `local port`

			The local port allocated by the media proxy expressed as an integer.

* `totals`

	Contains a dictionary with two keys, `input` and `output`. Each value contains a dictionary with two
	keys, `rtp` and `rtcp`. Each value in turn is identical to the `counters` key described above.

A complete response message might look like this (formatted for readability):

	{
	  "created": 1373052990,
	  "result": "ok",
	  "streams": [
	    [
	      {
	        "codec": "G711u",
	        "stats": {
	          "rtcp": {
	            "advertised peer address": {
	              "address": "10.76.83.64",
	              "family": "IPv4",
	              "port": 43007
	            },
	            "counters": {
	              "bytes": 792,
	              "errors": 0,
	              "packets": 12
	            },
	            "local port": 40059,
	            "peer address": {
	              "address": "10.76.83.64",
	              "family": "IPv4",
	              "port": 43007
	            }
	          },
	          "rtp": {
	            "advertised peer address": {
	              "address": "10.76.83.64",
	              "family": "IPv4",
	              "port": 43006
	            },
	            "counters": {
	              "bytes": 265408,
	              "errors": 0,
	              "packets": 1508
	            },
	            "local port": 40058,
	            "peer address": {
	              "address": "10.76.83.64",
	              "family": "IPv4",
	              "port": 43006
	            }
	          }
	        },
	        "status": "confirmed peer address",
	        "tag": "Ao5Tg1fidmnZRhn"
	      },
	      {
	        "codec": "G711u",
	        "stats": {
	          "rtcp": {
	            "advertised peer address": {
	              "address": "2001:db8::6f24:65b",
	              "family": "IPv6",
	              "port": 7183
	            },
	            "counters": {
	              "bytes": 624,
	              "errors": 0,
	              "packets": 12
	            },
	            "local port": 40061,
	            "peer address": {
	              "address": "2001:db8::6f24:65b",
	              "family": "IPv6",
	              "port": 7183
	            }
	          },
	          "rtp": {
	            "advertised peer address": {
	              "address": "2001:db8::6f24:65b",
	              "family": "IPv6",
	              "port": 7182
	            },
	            "counters": {
	              "bytes": 259376,
	              "errors": 0,
	              "packets": 1508
	            },
	            "local port": 40060,
	            "peer address": {
	              "address": "2001:db8::6f24:65b",
	              "family": "IPv6",
	              "port": 7182
	            }
	          }
	        },
	        "status": "confirmed peer address",
	        "tag": "DiQOJkgsesbFYpC"
	      }
	    ]
	  ],
	  "totals": {
	    "input": {
	      "rtcp": {
	        "bytes": 792,
	        "errors": 0,
	        "packets": 12
	      },
	      "rtp": {
	        "bytes": 265408,
	        "errors": 0,
	        "packets": 1508
	      },
	      "output": {
	        "rtcp": {
	          "bytes": 624,
	          "errors": 0,
	          "packets": 12
	        },
	        "rtp": {
	          "bytes": 259376,
	          "errors": 0,
	          "packets": 1508
	        }
	      }
	    }
	  }
	}

`start recording` Message
-------------------------

The `start recording` message must contain at least the key `call-id` and may optionally include `from-tag`,
`to-tag` and `via-branch`, as defined above. The reply dictionary contains no additional keys.

This is not implemented by *rtpengine*.
