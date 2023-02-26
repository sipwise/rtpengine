# Usage

## Userspace Daemon

The options are described in detail in the rtpengine(1) man page. If you're
reading this on Github, you can view the current master's man page
[here](https://github.com/sipwise/rtpengine/blob/master/daemon/rtpengine.pod).

## In-kernel Packet Forwarding

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

## Summary

A typical start-up sequence including in-kernel forwarding might look like this:

	# this only needs to be one once after system (re-) boot
	modprobe xt_RTPENGINE
	iptables -I INPUT -p udp -j RTPENGINE --id 0
	ip6tables -I INPUT -p udp -j RTPENGINE --id 0

	# ensure that the table we want to use doesn't exist - usually needed after a daemon
	# restart, otherwise will error
	echo 'del 0' > /proc/rtpengine/control

	# start daemon
	/usr/bin/rtpengine --table=0 --interface=10.64.73.31 --interface=2001:db8::4f3:3d \
	--listen-ng=127.0.0.1:2223 --tos=184 --pidfile=/run/rtpengine.pid --no-fallback

## Running Multiple Instances

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

	/usr/bin/rtpengine --table=0 --interface=10.64.73.31 \
	--listen-ng=127.0.0.1:2223 --tos=184 --pidfile=/run/rtpengine-10.pid --no-fallback
	/usr/bin/rtpengine --table=1 --interface=192.168.65.73 \
	--listen-ng=127.0.0.1:2224 --tos=184 --pidfile=/run/rtpengine-192.pid --no-fallback

With this setup, the SIP proxy can choose which instance of *rtpengine* to talk to and thus which local
interface to use by sending its control messages to either port 2223 or port 2224.
