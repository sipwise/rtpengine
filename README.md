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

*Rtpengine* does not (yet) support:

* Repacketization or transcoding
* Playback of pre-recorded streams/announcements
* ZRTP, although ZRTP passes through *rtpengine* just fine

Compiling and Installing
=========================

On a Debian System
------------------

On a Debian system, everything can be built and packaged into Debian packages
by executing `dpkg-buildpackage` (which can be found in the `dpkg-dev` package) in the main directory.
This script will issue an error and stop if any of the dependency packages are
not installed.

Before that, run `./debian/flavors/no_ngcp` in order to remove any NGCP dependencies.

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

There's 3 parts to *rtpengine*, which can be found in the respective subdirectories.

* `daemon`

	The userspace daemon and workhorse, minimum requirement for anything to work. Running `make`
	will compile the binary, which will be called `rtpengine`. The following software packages
	including their development headers are required to compile the daemon:

	- *pkg-config*
	- *GLib* including *GThread* version 2.x
	- *zlib*
	- *OpenSSL*
	- *PCRE* library
	- *XMLRPC-C* version 1.16.08 or higher
	- *hiredis* library

	The `Makefile` contains a few Debian-specific flags, which may have to removed for compilation to
	be successful. This will not affect operation in any way.

* `iptables-extension`

	Required for in-kernel packet forwarding.

	With the `iptables` development headers installed, issuing `make` will compile the plugin for
	`iptables` and `ip6tables`. The file will be called `libxt_RTPENGINE.so` and should be copied
	into the directory `/lib/xtables/`.

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

The daemon supports a number of command-line options, which it will print if started with the `--help`
option and which are reproduced below:

	  -v, --version                    Print build time and exit
	  -t, --table=INT                  Kernel table to use
	  -F, --no-fallback                Only start when kernel module is available
	  -i, --interface=[NAME/]IP[!IP]   Local interface for RTP
	  -l, --listen-tcp=[IP:]PORT       TCP port to listen on
	  -u, --listen-udp=[IP46:]PORT     UDP port to listen on
	  -n, --listen-ng=[IP46:]PORT      UDP port to listen on, NG protocol
	  -c, --listen-cli=[IP46:]PORT     TCP port to listen on, CLI (command line interface)
	  -g, --graphite=IP46:PORT         TCP address of graphite statistics server
	  -G, --graphite-interval=INT      Graphite data statistics send interval
	  --graphite-prefix=STRING         Graphite prefix for every line
	  -T, --tos=INT                    TOS value to set on streams
	  -o, --timeout=SECS               RTP timeout
	  -s, --silent-timeout=SECS        RTP timeout for muted
	  -a, --final-timeout=SECS         Call timeout
	  -p, --pidfile=FILE               Write PID to file
	  -f, --foreground                 Don't fork to background
	  -m, --port-min=INT               Lowest port to use for RTP
	  -M, --port-max=INT               Highest port to use for RTP
	  -r, --redis=[PW@]IP:PORT/INT     Connect to Redis database
	  -w, --redis-write=[PW@]IP:PORT/INT Connect to Redis write database
	  -k, --subscribe-keyspace         Subscription keyspace list
	  --redis-num-threads=INT          Number of Redis restore threads
	  --redis-expires=INT              Expire time in seconds for redis keys
	  --redis-multikey                 Use multiple redis keys for storing the call (old behaviour) DEPRECATED
	  -q, --no-redis-required          Start even if can't connect to redis databases
	  -b, --b2b-url=STRING             XMLRPC URL of B2B UA
	  -L, --log-level=INT              Mask log priorities above this level
	  --log-facility=daemon|local0|... Syslog facility to use for logging
	  --log-facility-cdr=local0|...    Syslog facility to use for logging CDRs
	  --log-facility-rtcp=local0|...   Syslog facility to use for logging RTCP data (take care of traffic amount)
	  -E, --log-stderr                 Log on stderr instead of syslog
	  -x, --xmlrpc-format=INT          XMLRPC timeout request format to use. 0: SEMS DI, 1: call-id only
	  --num-threads=INT                Number of worker threads to create
	  -d, --delete-delay               Delay for deleting a session from memory.
	  --sip-source                     Use SIP source address by default
	  --dtls-passive                   Always prefer DTLS passive role
	  --max-sessions=INT               Limit the number of maximum concurrent sessions
	  --homer=IP46:PORT                Address of Homer server for RTCP stats
	  --homer-protocol=udp|tcp         Transport protocol for Homer (default udp)
	  --homer-id=INT                   'Capture ID' to use within the HEP protocol
	  --recording-dir=FILE             Spool directory where PCAP call recording data goes
	  --recording-method=pcap|proc     Strategy for call recording
	  --recording-format=raw|eth       PCAP file format for recorded calls.

Most of these options are indeed optional, with two exceptions. It's mandatory to specify at least one local
IP address through `--interface`, and at least one of the `--listen-...` options must be given.

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

* -i, --interface

	Specifies a local network interface for RTP. At least one must be given, but multiple can be specified.
	The format of the value is `[NAME/]IP[!IP]` with `IP` being either an IPv4 address or an IPv6 address.

	The second IP address after the exclamation point is optional and can be used if the address to advertise
	in outgoing SDP bodies should be different from the actual local address. This can be useful in certain
	cases, such as your SIP proxy being behind NAT. For example, `--interface=10.65.76.2!192.0.2.4` means
	that 10.65.76.2 is the actual local address on the server, but outgoing SDP bodies should advertise
	192.0.2.4 as the address that endpoints should talk to. Note that you may have to escape the exlamation
	point from your shell, e.g. using `\!`.

	Giving an interface a name (separated from the address by a slash) is optional; if omitted, the name
	`default` is used. Names are useful to create logical interfaces which consist of one or more local
	addresses. It is then possible to instruct *rtpengine* to use particular interfaces when processing
	an SDP message, to use different local addresses when talking to different endpoints. The most common use
	case for this is to bridge between one or more private IP networks and the public internet.

	For example, if clients coming from a private IP network must communicate their RTP with the local
	address 10.35.2.75, while clients coming from the public internet must communicate with your other
	local address 192.0.2.67, you could create one logical interface `pub` and a second one `priv` by
	using `--interface=pub/192.0.2.67 --interface=priv/10.35.2.75`. You can then use the `direction`
	option to tell *rtpengine* which local address to use for which endpoints (either `pub` or `priv`).

	If multiple logical interfaces are configured, but the `direction` option isn't given in a
	particular call, then the first interface given on the command line will be used.

	It is possible to specify multiple addresses for the same logical interface (the same name). Most
	commonly this would be one IPv4 addrsess and one IPv6 address, for example:
	`--interface=192.168.63.1 --interface=fe80::800:27ff:fe00:0`. In this example, no interface name
	is given, therefore both addresses will be added to a logical interface named `default`. You would use
	the `address family` option to tell *rtpengine* which address to use in a particular case.

	It is also possible to have multiple addresses of the same family in a logical network interface. In
	this case, the first address (of a particular family) given for an interface will be the primary address
	used by *rtpengine* for most purposes. Any additional addresses will be advertised as additional ICE
	candidates with increasingly lower priority. This is useful on multi-homed systems and allows endpoints
	to choose the best possible path to reach the RTP proxy. If ICE is not being used, then additional
	addresses will go unused.

	If you're not using the NG protocol but rather the legacy UDP protocol used by the *rtpproxy* module,
	the interfaces must be named `internal` and `external` corresponding to the `i` and `e` flags if you
	wish to use network bridging in this mode.

* -l, --listen-tcp, -u, --listen-udp, -n, --listen-ng

	These options each enable one of the 3 available control protocols if given and each take either
	just a port number as argument, or an `address:port` pair, separated by colon. At least one of these
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

* -c, --listen-cli

   TCP ip and port to listen for the CLI (command line interface).

* -g, --graphite

	Address of the graphite statistics server.

* -w, --graphite-interval

	Interval of the time when information is sent to the graphite server.

* --graphite-prefix

	Add a prefix for every graphite line.

* -t, --tos

	Takes an integer as argument and if given, specifies the TOS value that should be set in outgoing
	packets. The default is to leave the TOS field untouched. A typical value is 184 (*Expedited Forwarding*).

* -o, --timeout

	Takes the number of seconds as argument after which a media stream should be considered dead if no media
	traffic has been received. If all media streams belonging to a particular call go dead, then the call
	is removed from *rtpengine*'s internal state table. Defaults to 60 seconds.

* -s, --silent-timeout

	Ditto as the `--timeout` option, but applies to muted or inactive media streams. Defaults to 3600
	(one hour).

* -a, --final-timeout

	The number of seconds since call creation, after call is deleted. Useful for limiting the lifetime of a call.
	This feature can be disabled by setting the parameter to 0. By default this timeout is disabled.

* -p, --pidfile

	Specifies a path and file name to write the daemon's PID number to.

* -f, --foreground

	If given, prevents the daemon from daemonizing, meaning it will stay in the foreground.
	Useful for debugging.

* -m, --port-min, -M, --port-max

	Both take an integer as argument and together define the local port range from which *rtpengine*
	will allocate UDP ports for media traffic relay. Default to 30000 and 40000 respectively.

* -L, --log-level

	Takes an integer as argument and controls the highest log level which will be sent to syslog.
	The log levels correspond to the ones found in the syslog(3) man page. The default value is
	6, equivalent to LOG_INFO. The highest possible value is 7 (LOG_DEBUG) which will log everything.

	During runtime, the log level can be decreased by sending the signal SIGURS1 to the daemon and can
	be increased with the signal SIGUSR2.

* --log-facilty=daemon|local0|...|local7|...

	The syslog facilty to use when sending log messages to the syslog daemon. Defaults to `daemon`.

* --log-facilty-cdr=daemon|local0|...|local7|...

	Same as --log-facility with the difference that only CDRs are written to this log facility.

* --log-facilty-rtcp=daemon|local0|...|local7|...

	Same as --log-facility with the difference that only RTCP data is written to this log facility.
	Be careful with this parameter since there may be a lot of information written to it.

* -E, --log-stderr

	Log to stderr instead of syslog. Only useful in combination with `--foreground`.

* --num-threads

	How many worker threads to create, must be at least one. The default is to create as many threads
	as there are CPU cores available. If the number of CPU cores cannot be determined, the default is
	four.

* --sip-source

	The original *rtpproxy* as well as older version of *rtpengine* by default didn't honour IP
	addresses given in the SDP body, and instead used the source address of the received SIP
	message as default endpoint address. Newer versions of *rtpengine* reverse this behaviour and
	honour the addresses given in the SDP body by default. This option restores the old behaviour.

* --dtls-passive

	Enables the `DTLS=passive` flag for all calls unconditionally.

* -d, --delete-delay

	Delete the call from memory after the specified delay from memory. Can be set to zero for
	immediate call deletion.

*  -r, --redis

	Connect to specified Redis database (with the given database number) and use it for persistence
	storage. The format of this option is `ADDRESS:PORT/DBNUM`, for example `127.0.0.1:6379/12`
	to connect to the Redis DB number 12 running on localhost on the default Redis port.

	If the Redis database is protected with an authentication password, the password can be supplied
	by prefixing the argument value with the password, separated by an `@` symbol, for example
	`foobar@127.0.0.1:6379/12`. Note that this leaves the password visible in the process list,
	posing a security risk if untrusted users access the same system. As an alternative, the password
	can also be supplied in the shell environment through the environment variable
	`RTPENGINE_REDIS_AUTH_PW`.

	On startup, *rtpengine* will read the contents of this database and restore all calls
	stored therein. During runtime operation, *rtpengine* will continually update the database's
	contents to keep it current, so that in case of a service disruption, the last state can be restored
	upon a restart.

	When this option is given, *rtpengine* will delay startup until the Redis database adopts the
	master role (but see below).

*  -w, --redis-write

	Configures a second Redis database for write operations. If this option is given in addition to the
	first one, then the first database will be used for read operations (i.e. to restore calls from) while
	the second one will be used for write operations (to update states in the database).

	For password protected Redis servers, the environment variable for the password is
	`RTPENGINE_REDIS_WRITE_AUTH_PW`.

	When both options are given, *rtpengine* will start and use the Redis database regardless of the
	database's role (master or slave).

*  -k, --subscribe-keyspace

	List of redis keyspaces to subscribe. If this is not present, no keyspaces are subscribed (default behaviour).
	Further subscriptions could be added/removed via 'rtpengine-ctl ksadd/ksrm'.
	This may lead to enabling/disabling of the redis keyspace notification feature.

*  --redis-num-threads

	How many redis restore threads to create. The default is four.

*  --redis-expires

        Expire time in seconds for redis keys. Default is 86400.

*  --redis-multikey

	Use multiple redis keys for storing the call (old behaviour) DEPRECATED

*  -q, --no-redis-required
	When this paramter is present or NO_REDIS_REQUIRED='yes' or '1' in config file, rtpengine starts even
	if there is no initial connection to redis databases(either to -r or to -w or to both redis).

	Be aware that if the -r redis can't be initially connected, sessions are not reloaded upon rtpengine startup,
	even though rtpengine still starts.

*  -b, --b2b-url

	Enables and sets the URI for an XMLRPC callback to be made when a call is torn down due to packet
	timeout. The special code `%%` can be used in place of an IP address, in which case the source address
	of the originating request will be used.

* -x, --xmlrpc-format

	Selects the internal format of the XMLRPC callback message for B2BUA call teardown. 0 is for SEMS,
	1 is for a generic format containing the call-ID only.

* --max-sessions

	Limit the number of maximum concurrent sessions. Set at startup via MAX_SESSIONS in config file. Set at runtime via rtpengine-ctl util.
	Setting the 'rtpengine-ctl set maxsessions 0' can be used in draining rtpengine sessions.
	Enable feature: 'MAX_SESSIONS=1000'
	Enable feature: 'rtpengine-ctl set maxsessions' >=0
	Disable feature: 'rtpengine-ctl set maxsessions -1'
	By default, the feature is disabled (i.e. maxsessions == -1).

* --homer

	Enables sending the decoded contents of RTCP packets to a Homer SIP capture server. The transport
	is HEP version 3 and payload format is JSON. This argument takes an IP address and a port number
	as value.

* --homer-protocol

	Can be either "udp" or "tcp" with "udp" being the default.

* --homer-id

	The HEP protocol used by Homer contains a "capture ID" used to distinguish different sources
	of capture data. This ID can be specified using this argument.

* --recording-dir

	An optional argument to specify a path to a directory where PCAP recording
	files and recording metadata files should be stored. If not specified, support
	for call recording will be disabled.

	*Rtpengine* supports multiple mechanisms for recording calls. See `recording-method`
	below for a list. The default recording method `pcap` is described in
	this section.

	PCAP files will be stored within a "pcap" subdirectory and metadata
	within a "metadata" subdirectory.

	The format for a metadata file is (with a trailing newline):

		/path/to/recording-pcap.pcap

		SDP mode: offer
		SDP before RTP packet: 1

		first SDP

		SDP mode: answer
		SDP before RTP packet: 1

		second SDP

		...

		SDP mode: answer
		SDP before RTP packet: 100

		n-th and final SDP


		start timestamp (YYYY-MM-DDThh:mm:ss)
		end timestamp   (YYYY-MM-DDThh:mm:ss)


		generic metadata

	There are two empty lines between each logic block of metadata.
	We write out all answer SDP, each separated from one another by one empty
	line. The generic metadata at the end can be any length with any number of
	lines. Metadata files will appear in the subdirectory when the call
	completes. PCAP files will be written to the subdirectory as the call is
	being recorded.

	Since call recording via this method happens entirely in userspace, in-kernel
	packet forwarding cannot be used for calls that are currently being recorded and
	packet forwarding will thus be done in userspace only.

* --recording-method

	Multiple methods of call recording are supported and this option can be used to select one.
	Currently supported are the method `pcap` and `proc`.
	The default method is `pcap` and is the one described above.

	The recording method `proc` works by writing metadata files directly into the
	`recording-dir` (i.e. not into a subdirectory) and instead of recording RTP packet data
	into pcap files, the packet data is exposed via a special interface in the `/proc` filesystem.
	Packets must then be retrieved from this interface by a dedicated 3rd party userspace component
	(usually a daemon).

	Packet data is held in kernel memory until retrieved by the userspace component, but only a limited
	number of packets (default 10) per media stream. If packets are not retrieved in time, they will
	be simply discarded. This makes it possible to flag all calls to be recorded and then leave it
	to the userspace component to decided whether to use the packet data for any purpose or not.

	In-kernel packet forwarding is fully supported with this recording method even for calls being
	recorded.

* --recording-format

	 When recording to pcap file in raw (default) format, there is no ethernet header.
	 When set to eth, a fake ethernet header is added, making each package 14 bytes larger.

A typical command line (enabling both UDP and NG protocols) thus may look like:

	/usr/sbin/rtpengine --table=0 --interface=10.64.73.31 --interface=2001:db8::4f3:3d \
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
which are required for proper operation. One part is the actual kernel module called `xt_RTPENGINE`. The
second part is a plugin to the `iptables` and `ip6tables` command-line utilities to make it possible to
actually add the required rule to the tables.

### Overview ###

In short, the prerequisites for in-kernel packet forwarding are:

1. The `xt_RTPENGINE` kernel module must be loaded.
2. An `iptables` and/or `ip6tables` rule must be present in the `INPUT` chain to send packets
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

Each subdirectory `/proc/rtpengine/$ID/` corresponding to each fowarding table contains the pseudo-files
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

	modprobe xt_RTPENGINE
	iptables -I INPUT -p udp -d 10.64.73.31 -j RTPENGINE --id 0
	iptables -I INPUT -p udp -d 192.168.65.73 -j RTPENGINE --id 1

	echo 'del 0' > /proc/rtpengine/control
	echo 'del 1' > /proc/rtpengine/control

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

	A direction keyword is *round-robin-calls*. If this is received, a round robin algorithm runs for
	choosing the logical interface for the current stream(e.g. audio, video).
	The algorithm checks that all local interfaces of the tried logical interface have free ports for
	call streams. If a logical interface fails the check, the next one is tried. If there is no logical
	interface found with this property, it fallbacks to the default behaviour (e.g. return first logical
	interface in --interface list even if no free ports are available). The attribute is ignored for
	answers() because the logical interface was already selected at offers().
	Naming an interface "round-robin-calls" and trying to select it using direction will
	__run the above algorithm__!

	Round robin for both legs of the stream:
		{ ..., "direction": [ "round-robin-calls", "round-robin-calls" ], ... }

	Round robin for first leg and and select "pub" for the second leg of the stream:
		{ ..., "direction": [ "round-robin-calls", "pub" ], ... }

	Round robin for first leg and and default behaviour for the second leg of the stream:
		{ ..., "direction": [ "round-robin-calls" ], ... }

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
	body. The default is to auto-detect the address family if possible (if the recieving end is known
	already) or otherwise to leave it unchanged.

* `rtcp-mux`

	A list of strings controlling the behaviour regarding rtcp-mux (multiplexing RTP and RTCP on a single
	port, RFC 5761). The default behaviour is to go along with the client's preference. The list can contain
	zero of more of the following strings. Note that some of them are mutually exclusive.

	- `offer`

		Instructs *rtpengine* to always offer rtcp-mux, even if the client itself doesn't offer it.

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
	as were received from the other endpoint.

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
	metadata files within `/path/to/recording_dir/metadata/`. This can be used to
	record additional information about recorded calls. `metadata` values passed in
	through subsequent messages will overwrite previous metadata values.

	See the `--recording-dir` option above.


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

Other optional keys are:

* `delete delay`

	Contains an integer and overrides the global command-line option `delete-delay`. Call/branch will be
	deleted immediately if a zero is given. Value must be positive (in seconds) otherwise.

The reply message may contain additional keys with statistics about the deleted call. Those additional keys
are the same as used in the `query` reply.

`list` Message
----------------

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
