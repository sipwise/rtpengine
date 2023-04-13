rtpengine(8) - NGCP proxy for RTP and other UDP based media traffic
==========================================

## SYNOPSIS

**rtpengine** **--interface**=_addr_... **--listen-tcp**\|**--listen-udp**\|**--listen-ng**\|**--listen-tcp-ng**\|**--listen-http**\|**--listen-https**=_addr_... \[_option_...\]

## DESCRIPTION

The Sipwise NGCP rtpengine is a proxy for RTP traffic and other UDP based
media traffic.
It is meant to be used with the Kamailio SIP proxy and forms a drop-in
replacement for any of the other available RTP and media proxies.

## OPTIONS

Most of these options are indeed optional, with two exceptions. It's
mandatory to specify at least one local IP address through **--interface**,
and at least one of the **--listen-**_..._ options must be given.

All options can (and should) be provided in a config file instead of
at the command line. See the **--config-file** option below for details.

- **--help**

    Print the usage information.

- **-v**, **--version**

    If called with this option, the **rtpengine** daemon will simply print its
    version number and exit.

- **--codecs**

    Print a list of supported codecs and exit.

- **--config-file=**_FILE_

    Specifies the location of a config file to be used. The config file is an
    _.ini_ style config file, with all command-line options listed here also
    being valid options in the config file.
    For all command-line options, the long name version instead of the
    single-character version (e.g. **table** instead of just **t**) must be
    used in the config file.
    For boolean options that are either present or not (e.g. **no-fallback**), a
    boolean value (either **true** or **false**) must be used in the config file.
    If an option is given in both the config file and at the command line,
    the command-line value overrides the value from the config file.
    Options that can be specified multiple times on the command line must be
    given only once in the config file, with the multiple values separated by
    semicolons (see section [INTERFACES](https://metacpan.org/pod/INTERFACES) below for an example).

    As a special value, **none** can be passed here to suppress loading of the
    default config file `/etc/rtpengine/rtpengine.conf`.

- **--config-section=**_STRING_

    Specifies the _.ini_ style section to be used in the config file.
    Multiple sections can be present in the config file, but only one can be
    used at a time.
    The default value is **rtpengine**.
    A config file section is started in the config file using square brackets
    (e.g. **\[rtpengine\]**).

- **-t**, **--table=**_INT_

    Takes an integer argument and specifies which kernel table to use for
    in-kernel packet forwarding.
    See the section on in-kernel operation in the `README.md` for more detail.
    Optional and defaults to zero.
    If in-kernel operation is not desired, a negative number can be specified.

- **-F**, **--no-fallback**

    Will prevent fallback to userspace-only operation if the kernel module is
    unavailable.
    In this case, startup of the daemon will fail with an error if this option
    is given.

- **-S**, **--save-interface-ports**

    Will bind ports only on the first available local interface, of desired
    family, of logical interface. If no ports available on any local interface
    of desired family, give an error message.

    In this case, ICE will be broken.

- **-i**, **--interface=**\[_NAME_**/**\]_IP_\[**!**_IP_\]

    Specifies a local network interface for RTP.
    At least one must be given, but multiple can be specified.
    See the section [INTERFACES](https://metacpan.org/pod/INTERFACES) just below for details.

- **-l**, **--listen-tcp=**\[_IP_**:**\]_PORT_
- **-u**, **--listen-udp=**\[_IP46_**:**\]_PORT_
- **-n**, **--listen-ng=**\[_IP46_**:**\]_PORT_
- **-n**, **--listen-tcp-ng=**\[_IP46_**:**\]_PORT_

    These options each enable one of the 4 available control protocols if given
    and each take either just a port number as argument, or an _address:port_
    pair, separated by colon.
    At least one of these 3 options must be given.

    The **tcp** protocol is obsolete.
    It was used by old versions of **OpenSER** and its **mediaproxy** module.
    It is provided for backwards compatibility.

    The **udp** protocol is used by **Kamailio**'s **rtpproxy** module.
    In this mode, **rtpengine** can be used as a drop-in replacement for any
    other compatible RTP proxy.

    The **ng** protocol is an advanced control protocol and can be used with
    **Kamailio**'s **rtpengine** module.
    With this protocol, the complete SDP body is passed to **rtpengine**,
    rewritten and passed back to **Kamailio**.
    Several additional features are available with this protocol, such as
    ICE handling, SRTP bridging, etc.

    The **tcp-ng** protocol is in fact the **ng** protocol but transported over TCP.

    It is recommended to specify not only a local port number, but also
    **127.0.0.1** as interface to bind to.

- **-c**, **--listen-cli=**\[_IP46_:\]_PORT_

    TCP ip and port to listen for the CLI (command line interface).

- **-g**, **--graphite=**_IP46_:_PORT_

    Address of the graphite statistics server.

- **-w**, **--graphite-interval=**_INT_

    Interval of the time when information is sent to the graphite server.

- **--graphite-prefix=**_STRING_

    Add a prefix for every graphite line.

- **--graphite-timeout=**_INT_

    Sets after how much time (seconds) to force fail graphite socket connection,
    when graphite server is filtered out. If set to 0, there are no changes.

- **-t**, **--tos=**_INT_

    Takes an integer as argument and if given, specifies the TOS value that
    should be set in outgoing packets.
    The default is to leave the TOS field untouched.
    A typical value is 184 (**Expedited Forwarding**).

- **--control-tos=**_INT_

    Takes an integer as argument and if given, specifies the TOS value that
    should be set in the control-ng interface packets.
    The default is to leave the TOS field untouched.
    This parameter can also be set or listed via **rtpengine-ctl**.

- **--control-pmtu=****want**\|**dont**

    Forces a specific PMTU discovery behaviour on IPv4 UDP control sockets,
    overriding the system-wide default. If set to **want** then path MTU discovery
    is performed, initially enabling the DF (don't fragment) bit on outgoing IPv4
    packets until the path MTU has been discovered through reception of a
    "fragmentation needed" ICMP packet. If set to **dont** then path MTU discovery
    is disabled, leaving the DF bit unset, and relying on the routers within the
    network path to perform any necessary fragmentation.

    The setting of **dont** is useful in broken IPv4 environments without
    functioning PMTU discovery, for example in networks which unconditionally block
    all ICMP.

- **-o**, **--timeout=**_SECS_

    Takes the number of seconds as argument after which a media stream should
    be considered dead if no media traffic has been received.
    If all media streams belonging to a particular call go dead, then the call
    is removed from **rtpengine**'s internal state table.
    Defaults to 60 seconds.

- **-s**, **--silent-timeout=**_SECS_

    Ditto as the **--timeout** option, but applies to muted or inactive media
    streams.
    Defaults to 3600 (one hour).

- **-a**, **--final-timeout=**_SECS_

    The number of seconds since call creation, after call is deleted.
    Useful for limiting the lifetime of a call.
    This feature can be disabled by setting the parameter to 0.
    By default this timeout is disabled.

- **--offer-timeout=**_SECS_

    This timeout (in seconds) is applied to calls which only had an **offer**
    but no **answer**.
    Defaults to 3600 (one hour).

- **-p**, **--pidfile=**_FILE_

    Specifies a path and file name to write the daemon's PID number to.

- **-f**, **--foreground**

    If given, prevents the daemon from daemonizing, meaning it will stay in
    the foreground.
    Useful for debugging.

- **-m**, **--port-min=**_INT_
- **-M**, **--port-max=**_INT_

    Both take an integer as argument and together define the local port range
    from which **rtpengine** will allocate UDP ports for media traffic relay.
    Default to 30000 and 40000 respectively.

- **-L**, **--log-level=**_INT_

    Takes an integer as argument and controls the highest log level which will be
    sent to syslog. This is merely the default log level used for logging
    subsystems (see below) that don't explicitly have a separate log level
    configured.

    The log levels correspond to the ones found in the [syslog(3)](http://man.he.net/man3/syslog) man page.
    The default value is **6**, equivalent to LOG\_INFO.
    The highest possible value is **7** (LOG\_DEBUG) which will log everything.

    During runtime, the log level can be decreased by sending the signal
    SIGURS1 to the daemon and can be increased with the signal SIGUSR2.

- **--log-level-**_subsystem_**=**_INT_

    Configures a log level for one of the logging subsystems. A logging subsystem
    which doesn't have a log level configured explicitly takes its default value
    from the **log-level** setting described above, with the exception of the
    **internals** subsystem which by default has all logging disabled.

    The full list of logging subsystems can be viewed by pulling up the **--help**
    online help. Some (if not all) subsystems are: **core**, **spandsp** (messages
    generated by SpanDSP itself), **ffmpeg** (messages generated by ffmpeg libraries
    themselves), **transcoding** (messages related to RTP/media transcoding),
    **codec** (messages related to codec negotiation), **rtcp**, **ice**, **crypto**
    (messages related to crypto/SRTP/SDES/DTLS negotiation), **srtp** (messages
    related to RTP/SRTP en/decryption), **internals** (disabled by default), **http**
    (includes WebSocket), **control** (messages related to control protocols,
    including SDP exchanges), **dtx**.

- **--log-facilty=****daemon**\|**local0**\|...\|**local7**\|...

    The syslog facilty to use when sending log messages to the syslog daemon.
    Defaults to **daemon**.

- **--log-facilty-cdr=****daemon**\|**local0**\|...\|**local7**\|...

    Same as **--log-facility** with the difference that only CDRs are written
    to this log facility.

- **--log-facilty-rtcp=****daemon**\|**local0**\|...\|**local7**\|...

    Same as **--log-facility** with the difference that only RTCP data is
    written to this log facility.
    Be careful with this parameter since there may be a lot of information
    written to it.

- **--log-facilty-dtmf=****daemon**\|**local0**\|...\|**local7**\|...

    Same as **--log-facility** with the difference that only DTMF events are
    written to this log facility.
    DTMF events are extracted from RTP packets conforming to RFC 4733, are
    encoded in JSON format, and written as soon as the end of an event is
    detected.

- **--log-format=****default**\|**parsable**

    Selects between multiple log output styles.
    The default is to prefix log lines with a description of the relevant
    entity, such as **\[CALLID\]** or **\[CALLID port 12345\]**.
    The **parsable** output style is similar, but makes the ID easier to
    parse by enclosing it in quotes, such as **\[ID="CALLID"\]**
    or **\[ID="CALLID" port="12345"\]**.

- **--dtmf-log-dest=**_IP46_:_PORT_

    Configures a target address for logging detected DTMF event. Similar
    to the feature enabled by **--log-facilty-dtmf**, but instead of writing
    detected DTMF events to syslog, this sends the JSON payload to the
    given address as UDP packets.

- **--dtmf-log-ng-tcp**

    If **--listen-tcp-ng** is enabled, this will send DTMF events to all
    connected clients encoded in bencode format.

- **--dtmf-no-log-injects**
If **--dtmf-no-log-injects** is enabled, DTMF events resulting from a
call to inject-DTMF won't be sent to **--dtmf-log-dest=** or **--listen-tcp-ng**
- **--dtmf-no-suppress**

    Some RTP clients continue to send audio RTP packets during a DTMF event,
    resulting in both audio packets and DTMF packets appearing simultaneously. By
    default, when transcoding, **rtpengine** suppresses audio packets during a DTMF
    event and will only send DTMF packets until the DTMF event is over. Setting
    this option disables this feature.

- **--log-srtp-keys**

    Write SRTP keys to error log instead of debug log.

- **-E**, **--log-stderr**

    Log to stderr instead of syslog.
    Only useful in combination with **--foreground**.

- **--split-logs**

    Split multi-line log messages into individual log messages so that each
    line receives its own log line prefix.

- **--max-log-line-length=**_INT_

    Split log lines into multiple lines when they exceed the character count given
    here. Can be set to a negative value to allow unlimited length log lines. Set
    to zero for the default value, which is unlimited if logging to stderr, or 500
    if logging to syslog.

- **--no-log-timestamps**

    Don't add timestamps to log lines written to stderr.
    Only useful in combination with **--log-stderr**.

- **--log-name=**_STRING_

    Set the id to be printed in syslog.
    Defaults to **rtpengine**.

- **--log-mark-prefix=**_STRING_

    Prefix to be added to particular data fields in log files that are deemed
    sensitive and/or private information. Defaults to an empty string.

- **--log-mark-suffix=**_STRING_

    Suffix to be added to particular data fields in log files that are deemed
    sensitive and/or private information. Defaults to an empty string.

- **--num-threads=**_INT_

    How many worker threads to create, must be at least one.
    The default is to create as many threads as there are CPU cores available.
    If the number of CPU cores cannot be determined or if it is less than four,
    then the default is four.

- **--media-num-threads=**_INT_

    Number of threads to launch for media playback. Defaults to the same
    number as **num-threads**. This can be set to zero if no media playback
    functionality is desired.

    Media playback is actually handled by two threads: One for reading and
    decoding the media file, and another to schedule and send out RTP packets.
    So for example, if this option is set to 4, in total 8 threads will be
    launched.

- **--thread-stack=**_INT_

    Set the stack size of each thread to the value given in kB. Defaults to 2048
    kB. Can be set to -1 to leave the default provided by the OS unchanged.

- **--evs-lib-path=**_FILE_

    Points to the shared object file (**.so**) containing the reference
    implementation for the EVS codec. See the `README` for more details.

- **--sip-source**

    The original **rtpproxy** as well as older version of **rtpengine** by default
    did not honour IP addresses given in the SDP body, and instead used the
    source address of the received SIP message as default endpoint address.
    Newer versions of **rtpengine** reverse this behaviour and honour the
    addresses given in the SDP body by default. This option restores the
    old behaviour.

- **--dtls-passive**

    Enables the **DTLS=passive** flag for all calls unconditionally.

- **-d**, **--delete-delay=**_INT_

    Delete the call after the specified delay from memory.
    Can be set to zero for immediate call deletion.

- **-r**, **--redis=**\[_PW_**@**\]_IP_**:**_PORT_**/**_INT_

    Connect to specified Redis database (with the given database number) and
    use it for persistence storage.
    The format of this option is _ADDRESS_:_PORT_/_DBNUM_, for example
    _127.0.0.1:6379/12_ to connect to the Redis DB number 12 running on
    localhost on the default Redis port.

    If the Redis database is protected with an authentication password, the
    password can be supplied by prefixing the argument value with the password,
    separated by an **@** symbol, for example _foobar@127.0.0.1:6379/12_.
    Note that this leaves the password visible in the process list, posing a
    security risk if untrusted users access the same system.
    As an alternative, the password can also be supplied in the shell
    environment through the environment variable **RTPENGINE\_REDIS\_AUTH\_PW**.

    On startup, **rtpengine** will read the contents of this database and
    restore all calls stored therein.
    During runtime operation, **rtpengine** will continually update the
    database's contents to keep it current, so that in case of a service
    disruption, the last state can be restored upon a restart.

    When this option is given, **rtpengine** will delay startup until the
    Redis database adopts the master role (but see below).

- **-w**, **--redis-write=**\[_PW_**@**\]_IP_**:**_PORT_**/**_INT_

    Configures a second Redis database for write operations.
    If this option is given in addition to the first one, then the first
    database will be used for read operations (i.e. to restore calls from)
    while the second one will be used for write operations (to update states
    in the database).

    For password protected Redis servers, the environment variable for the
    password is **RTPENGINE\_REDIS\_WRITE\_AUTH\_PW**.

    When both options are given, **rtpengine** will start and use the Redis
    database regardless of the database's role (master or slave).

- **-k**, **--subscribe-keyspace=**_INT_

    List of redis keyspaces to subscribe.
    If this is not present, no keyspaces are subscribed (default behaviour).
    Further subscriptions could be added/removed via **rtpengine-ctl ksadd/ksrm**.
    This may lead to enabling/disabling of the redis keyspace notification feature.

- **--redis-num-threads=**_INT_

    How many redis restore threads to create.
    The default is 4.

- **--redis-expires=**_INT_

    Expire time in seconds for redis keys.
    Default is 86400.

- **--active-switchover**

    With this option enabled, any activity (such as signalling or media) on a call
    that was created through a Redis keyspace notification will make **rtpengine**
    take control of that call. Without this option, an explicit command is required
    for **rtpengine** to take (or relinquish) control of a call.

- **-q**, **--no-redis-required**

    When this parameter is present or **NO\_REDIS\_REQUIRED='yes'** or **'1'** in
    the config file, **rtpengine** starts even if there is no initial connection
    to redis databases (either to **-r** or to **-w** or to both redis).

    Be aware that if the **-r** redis cannot be initially connected, sessions
    are not reloaded upon rtpengine startup, even though rtpengine still starts.

- **--redis-allowed-errors**

    If this parameter is present and has a value >= 0, it will configure how
    many consecutive errors are allowed when communicating with a redis server
    before the redis communication will be temporarily disabled for that server.
    While the communication is disabled there will be no attempts to reconnect
    to redis or send commands to that server.
    Default value is -1, meaning that this feature is disabled.
    This parameter can also be set or listed via **rtpengine-ctl**.

- **--redis-disable-time**

    This parameter configures the number of seconds redis communication is
    disabled because of errors.
    This works together with redis-allowed-errors parameter.
    The default value is 10.
    This parameter can also be set or listed via **rtpengine-ctl**.

- **--redis-cmd-timeout=**_INT_

    If this parameter is set to a non-zero value it will set the timeout,
    in milliseconds, for each command to the redis server.
    If redis does not reply within the specified timeout the command will fail.
    The default value is 0, meaning that the commands will be blocking without
    timeout.
    This parameter can also be set or listed via **rtpengine-ctl**; note that
    setting the parameter to 0 will require a reconnect on all configured
    redis servers.

- **--redis-connect-timeout=**_INT_

    This parameter sets the timeout value, in milliseconds, when connecting
    to a redis server.
    If the connection cannot be made within the specified timeout the
    connection will fail.
    Note that in case of failure, when reconnecting to redis, a **PING** command
    is issued before attempting to connect so the **--redis-cmd-timeout** value
    will also be added to the total waiting time.
    This is useful if using **--redis-allowed-errors**, when attempting to
    estimate the total lost time in case of redis failures.
    The default value for the connection timeout is 1000ms.
    This parameter can also be set or listed via **rtpengine-ctl**.

- **-b**, **--b2b-url=**_STRING_

    Enables and sets the URI for an XMLRPC callback to be made when a call is
    torn down due to packet timeout.
    The special code **%%** can be used in place of an IP address, in which case
    the source address of the originating request (or alternatively the address
    specified using the **xmlrpc-callback** **ng** protocol option) will be used.

- **-x**, **--xmlrpc-format=**_INT_

    Selects the internal format of the XMLRPC callback message for B2BUA call
    teardown.
    0 is for SEMS,
    1 is for a generic format containing the call-ID only,
    2 is for Kamailio.

- **--max-sessions=**_INT_

    Limit the number of maximum concurrent sessions.
    Set at startup via **max-sessions** in config file.
    Set at runtime via **rtpengine-ctl** util.
    Setting the **rtpengine-ctl set maxsessions 0** can be used in draining
    rtpengine sessions.
    Enable feature: **max-sessions=1000**
    Enable feature: **rtpengine-ctl set maxsessions** >= 0
    Disable feature: **rtpengine-ctl set maxsessions -1**
    By default, the feature is disabled (i.e. maxsessions == -1).

- **--max-load=**_FLOAT_

    If the current 1-minute load average exceeds the value given here,
    reject new sessions until the load average drops below the threshold.

- **--max-cpu=**_FLOAT_

    If the current CPU usage (in percent) exceeds the value given here,
    reject new sessions until the CPU usage drops below the threshold.
    CPU usage is sampled in 0.5-second intervals.
    Only supported on systems providing a Linux-style `/proc/stat`.

- **--max-bandwidth=**_INT_

    If the current bandwidth usage (in bytes per second) exceeds the value
    given here, reject new sessions until the bandwidth usage drops below
    the threshold.
    Bandwidth usage is sampled in 1-second intervals and is based on
    received packets, not sent packets.

- **--homer=**_IP46_**:**_PORT_

    Enables sending the decoded contents of RTCP packets to a Homer SIP
    capture server.
    The transport is HEP version 3 and payload format is JSON.
    This argument takes an IP address and a port number as value.

- **--homer-protocol=****udp**\|**tcp**

    Can be either **udp** or **tcp** with **udp** being the default.

- **--homer-id=**_INT_

    The HEP protocol used by Homer contains a "capture ID" used to distinguish
    different sources of capture data.
    This ID can be specified using this argument.

- **--recording-dir=**_FILE_

    An optional argument to specify a path to a directory where PCAP recording
    files and recording metadata files should be stored. If not specified,
    support for call recording will be disabled.

    **rtpengine** supports multiple mechanisms for recording calls.
    See **recording-method** below for a list.
    The default recording method **pcap** is described in this section.

    PCAP files will be stored within a `pcap` subdirectory and metadata
    within a `metadata` subdirectory.

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
    line.
    The generic metadata at the end can be any length with any number of
    lines.
    Metadata files will appear in the subdirectory when the call completes.
    PCAP files will be written to the subdirectory as the call is being
    recorded.

    Since call recording via this method happens entirely in userspace,
    in-kernel packet forwarding cannot be used for calls that are currently
    being recorded and packet forwarding will thus be done in userspace only.

- **--recording-method=****pcap**\|**proc**\|**all**

    Multiple methods of call recording are supported and this option can be
    used to select one.
    Currently supported are the method **pcap**, **proc** and **all**.
    The default method is **pcap** and is the one described above.

    The recording method **proc** works by writing metadata files directly into
    the **recording-dir** (i.e. not into a subdirectory) and instead of recording
    RTP packet data into pcap files, the packet data is exposed via a special
    interface in the `/proc` filesystem.
    Packets must then be retrieved from this interface by a dedicated userspace
    component (usually a daemon such as recording-daemon included in this
    repository).

    Packet data is held in kernel memory until retrieved by the userspace
    component, but only a limited number of packets (default 10) per media
    stream.
    If packets are not retrieved in time, they will be simply discarded.
    This makes it possible to flag all calls to be recorded and then leave it
    to the userspace component to decided whether to use the packet data for
    any purpose or not.

    In-kernel packet forwarding is fully supported with this recording method
    even for calls being recorded.

    The recording method **all** will enable both **pcap** and **proc**
    at the same time.

- **--recording-format=****raw**\|**eth**

    When recording to pcap file in **raw** (default) format, there is no
    ethernet header.
    When set to **eth**, a fake ethernet header is added, making each package
    14 bytes larger.

- **--record-egress**

    Apply media recording to egress media streams (as they are sent by
    **rtpengine**) instead of media streams as they are received. This makes it
    possible to include manipulated and generated media (such as from the **play
    media** command) in the recordings.

- **--iptables-chain=**_STRING_

    This option enables explicit management of an iptables chain.
    When enabled, **rtpengine** takes control of the given iptables chain,
    which must exist already prior to starting the daemon.
    Upon startup, **rtpengine** will flush the chain, and then add one **ACCEPT**
    rule for each media port (RTP/RTCP) opened.
    Each rule will exactly match the individual port and destination IP address,
    and will be created with the call ID as iptables comment.
    The rule will be deleted when the port is closed.

    This option allows creating a firewall with a default **DROP** policy for
    the entire port range used by **rtpengine** and then referencing the given
    iptables chain to only selectively allow the ports actually in use.

    Note that this applies only to media ports, and does not apply to any other
    ports (such as the control ports) used by **rtpengine**.

    Also note that the iptables API is not the most efficient one around and
    does not lend itself to fast dynamic creation and deletion of rules.
    If you have a high call volume, and especially many call attempts per
    second, you might experience significant performance impact.
    This is not a shortcoming of **rtpengine** but rather of iptables and its
    API implementation in the Linux kernel.
    In such a case, it is recommended to add a static iptables rule for the
    entire media port range instead, and not use this option.

- **--scheduling=****default**\|...
- **--priority=**_INT_
- **--idle-scheduling=****default**\|...
- **--idle-priority=**_INT_

    These options control various thread scheduling parameters.
    The **scheduling** and **priority** settings are applied to the main
    worker threads, while the **idle-** versions of these settings are
    applied to various lower priority threads, such as timer runs.

    The **scheduling** settings take the name of one of the supported
    scheduler policies.
    Setting it to **default** or **none** is equivalent to not setting the
    option at all and leaves the system default in place.
    The strings **fifo** and **rr** refer to realtime scheduling policies.
    **other** is the Linux default scheduling policy.
    **batch** is similar to **other** except for a small wake-up scheduling
    penalty.
    **idle** is an extremely low priority scheduling policy.
    The Linux-specific **deadline** policy is not supported by **rtpengine**.
    Not all systems necessarily supports all scheduling policies; refer to
    your system's sched(7) man page for details.

    The **priority** settings correspond to the scheduling priority for
    realtime (**fifo** or **rr**) scheduling policies and must be in the range
    of 1 (low) through 99 (high).
    For all other scheduling policies (including no policy specified), the
    **priority** settings correspond to the **nice** value and should be in
    the range of -20 (high) through 19 (low).
    Not all systems support thread-specific **nice** values; on such a system,
    using these settings might have unexpected results.
    (Linux does support thread-specific **nice** values.)
    Refer to your system's sched(7) man page.

- **--mysql-host=**_HOST_\|_IP_
- **--mysql-port=**_INT_
- **--mysql-user=**_USERNAME_
- **--mysql-pass=**_PASSWORD_

    Configuration for playing back media files that are stored in a
    **MySQL** (or **MariaDB**) database. At least **mysql-host** must be configured
    for this to work. The others are optional and default to their respective
    values from the **MySQL**/**MariaDB** client library.

- **--mysql-query=**_STRING_

    Query to be used for retrieving media files from the database. No default
    exist, therefore this is a mandatory configuration for media playback from
    database. The provided query string must contain the single format placeholder
    **%llu** and must not contain any other format placeholders. The ID value
    passed to **rtpengine** in the **db-id** key of the **play media** message will
    be used in place of the placeholder when querying the database.

    An example configuration might look like this:

        mysql-query = select data from voip.files where id = %llu

- **--endpoint-learning=****delayed**\|**immediate**\|**off**\|**heuristic**

    Chooses one of the available algorithms to learn RTP endpoint addresses. The
    legacy setting is **delayed** which waits 3 seconds before committing to an
    endpoint address, which is then learned from the first incoming RTP packet seen
    after this delay. The setting **immediate** learns the endpoint address from the
    first incoming packet seen without the 3-second delay. Using **off** disables
    endpoint learning altogether, likely breaking clients behind NAT. The setting
    **heuristic** includes the 3-second delay, but source addresses seen from
    incoming RTP packets are ranked according to preference: If a packet with a
    source address and port matching the SDP address is seen, this address is used.
    Otherwise, if a packet with a matching source address (but a different port) is
    seen, that address is used. Otherwise, if a packet with a matching source port
    (but different address) is seen, that address is used. Otherwise, the source
    address of any incoming packet seen is used.

- **--jitter-buffer=**_INT_

    Size of (incoming) jitter buffer in packets. A value of zero (the default)
    disables the jitter buffer. The jitter buffer is currently only implemented for
    userspace operation.

- **--jb-clock-drift**

    Enable clock drift compensation for the jitter buffer.

- **--debug-srtp**

    Enable extra log messages to help debug SRTP issues. Per-packet details such as
    sequence numbers, ROC, payloads (plain text and encrypted), authentication
    tags, etc are recorded to the log. Every RTCP packet is logged in this way,
    while every 512th RTP packet is logged. Only applies to packets
    forwarded/processed in userspace.

- **--reject-invalid-sdp**

    With this option set, refuse to process SDP bodies that could not be cleanly
    parsed, instead of skipping over the parsing error and processing the SDP
    anyway. Currently this only affects the processing of SDP bodies that end in a
    blank line.

- **--listen-http=**\[_IP_\|_HOSTNAME_**:**\]_PORT_
- **--listen-https=**\[_IP_\|_HOSTNAME_**:**\]_PORT_

    Enable listening for HTTP or WebSocket connections, or their TLS-secured
    counterparts HTTPS and WSS. If no interface is specified, then the listening
    socket will be bound to all interfaces.

    The HTTP listener supports both HTTP and WS, while the HTTPS listener supports
    both HTTPS and WSS.

    If HTTPS/WSS is enabled, a certificate must also be provided using the options
    below.

- **--https-cert=**_FILE_
- **--https-key=**_FILE_

    Provide a server certificate and corresponding private key for the HTTPS/WSS
    listener, in PEM format.

- **--http-threads=**_INT_

    Number of worker threads for HTTP/HTTPS/WS/WSS. If not specified, then the same
    number as given under **num-threads** will be used. If no HTTP listeners are
    enabled, then no threads are created.

- **--software-id=**_STRING_

    Sets a free-form string that is used to identify this software towards external
    systems with, for example in outgoing ICE/STUN requests. Defaults to
    **rtpengine-**_VERSION_. The string is sanitised to replace all
    non-alphanumeric characters with a dash to make it universally usable.

- **--dtx-delay=**_INT_

    Processing delay in milliseconds to handle discontinuous transmission (DTX) or
    other transmission gaps. Defaults to zero (disabled) and is applicable to
    transcoded audio streams only. When enabled, delays processing of received
    packets for the specified time (much like a jitter buffer) in order to trigger
    DTX handling when a transmission gap occurs. The decoder is then instructed to
    fill in the missing time during a transmission gap, for example by generating
    comfort noise. The delay should be configured to be higher than the expected
    incoming jitter.

- **--max-dtx=**_INT_

    Maximum duration for DTX handling in seconds. If no further RTP media is
    received within this time frame, then DTX processing will stop. Can be set to
    zero or negative to disable and keep DTX processing on indefinitely. Defaults
    to 30 seconds.

- **--dtx-buffer=**_INT_
- **--dtx-lag=**_INT_

    These two options together control the maximum number of packets and amount of
    audio that is allowed to be held in the DTX buffer. The **dtx-buffer** option
    limits the number of packets held in the DTX buffer, while the **dtx-lag**
    option limits the amount of audio (in milliseconds) to be held in the DTX
    buffer. A DTX buffer overflow is declared when both limits are exceeded, in
    which case DTX processing is sped up by **dtx-shift** milliseconds.

    The defaults are 10 packets and 100 milliseconds.

- **--dtx-shift=**_INT_

    Amount of time in milliseconds that DTX processing is shifted forward (sped up)
    or backwards (delayed) in case of a DTX buffer overflow or underflow. An
    underflow occurs when RTP packets are received slower than expected, while an
    overflow occurs when packets are received faster than expected.

    If this value is set to zero then no adjustments of the DTX timer will be made.
    Instead, in order to keep up with the flow of received RTP packets, packets
    will be dropped or additional DTX audio will be generated as needed.

- **--dtx-cn-params=**_INT_

    Specify one comfort noise parameter. This option follows the same format as
    **cn-payload** described below.

    This option is applicable to audio generated to fill in transmission gaps
    during a DTX event. The default setting is no value, which means silence will
    be generated to fill in DTX gaps.

    If any CN parameters are configured, the parameters will be passed to an RFC
    3389 CN decoder, and the generated comfort noise will be used to fill in DTX
    gaps.

- **--amr-dtx=****native**\|**CN**

    Select the DTX behaviour for AMR codecs. The default is use the codec's
    internal processing: during a DTX event, a "no data" frame is passed to the
    decoder and the output is used as audio data.

    If **CN** is selected here, the same DTX mechanism as other codecs use is used
    for AMR, which is to fill in DTX gaps with either silence or RFC 3389 comfort
    noise (see **dtx-cn-params**). This also affects processing of received SID
    frames: SID frames would not be passed to the codec but instead be replaced by
    generated silence or comfort noise.

- **--silence-detect=**_FLOAT_

    Enable silence detection and specify threshold in percent. This option is
    applicable to transcoded stream only and defaults to zero (disabled).

    When enabled, silence detection will be performed on all transcoded audio
    streams. The threshold specified here is the sensitivity for detecting silence:
    higher thresholds result in more audio to be detected as silence, while lower
    thresholds result in less audio to be detected as silence. The threshold is
    specified as percent between zero and 100. If set to 100, then all audio would
    be detected as silence; if set to 50, then any audio that is quieter than 50%
    of the maximum volume would be detected as silence; and so on. Setting it to
    zero disables silence detection. To only detect silence that is very near or
    equal to absolute silence, set this value to a low number such as 0.01. (For
    certain codecs such as PCMA, a higher minimum threshold is required to detect
    complete silence, as their compressed payloads don't decode to actual silence
    but instead have a residual DC offset. For PCMA the minimum value is 0.013.)

    Audio that is detected as silence will be replaced by comfort noise as
    specified by the **cn-payload** option (see below). Currently this is applicable
    only to RTP peers that have advertised support for the **CN** RTP payload type,
    in which case the silence audio frames will be replaced by **CN** RTP frames.

- **--cn-payload=**_INT_

    Specify one comfort noise parameter. This option can be given multiple times
    and the format follows RFC 3389. When specified at the command line, list the
    **--cn-payload=** option multiple times, each one specifying a single CN
    parameter. When used in the config file, list the option only a single time and
    list multiple CN parameters separated by semicolons (e.g.
    _cn-payload = 20;40;60_).

    The first CN payload value given is the noise level, specified as -dBov as per
    RFC 3389. This means that a noise level of zero corresponds to maximum volume,
    while higher numbers correspond to lower volumes. The highest allowable number
    is 127, corresponding to -127 dBov, which is near silence.

    Subsequent CN payload values carry spectral information (reflection
    coefficients) as per RFC 3389. Allowable values for each coefficient are
    between 0 and 254. Specifying spectral information is optional and the number
    of coefficients listed (model order) is variable.

    This option is applicable only to **CN** packets generated from the silence
    detection mechanism described above. The configured CN parameters are used
    directly as payload of **CN** packets sent by **rtpengine**.

    The default values are 32 (-32 dBov) for the noise level and no spectral
    information.

- **--player-cache**

    Enable caching of encoded media packets for media player. This is applicable
    for media playback initiated through the _play media_ command. When enabled
    **rtpengine** will not simply decode given media files and then encode the media
    to RTP on demand and on the fly, but will rather decode and encode each media
    file in full the first time playback is requested, and then cache the resulting
    RTP packets in memory. This is done once for each media file and for each
    output RTP codec requested.

    Caching is done based on unique file name (with no consideration given to
    different file names that may point to the same file), or integer index for
    media files played from database. No verification of changing content of files
    or database entries is done. Media files provided as binary _blob_ are also
    cached, although in this case a hash over the entire media file must be
    performed, therefore this usage is not recommended.

    It's not possible to choose a different _start-pos_ for playback with this
    option enabled.

    RTP data is cached and retained in memory for the lifetime of the process.

- **audio-buffer-length=**_INT_

    Set the buffer length used by the audio player (see below) in milliseconds. The
    default is 500 milliseconds.

    The buffer must be long enough to accommodate at least two frames of audio from
    all contributing sources, which means at least 40 ms or 60 ms for most cases.
    If media playback (via the **play media**) command is desired, then the buffer
    must be able to accommodate at least one full frame from the source media file,
    whose length can vary depending on the format of the source media file. For 8
    kHz **.wav** files this is 256 ms (2048 samples). Therefore 500 ms is the
    recommended value.

- **audio-buffer-delay=**_INT_

    Initial delay for new sources contributing to an audio buffer (used by the
    audio player, see below) in milliseconds. The default is 5 ms.

    The initial delay is meant to compensate for varying inter-arrival times of
    media packets (jitter). If set too low, intermittent high jitter will result in
    gaps in the output audio. If set too high, output audio will have an
    unnecessary latency added to it.

- **audio-player=****on-demand**\|**play-media**\|**transcoding**\|**always**

    Define when to enable the audio player if not explicitly instructed otherwise.
    The default setting is **on-demand**.

    Enabling the audio player for a party to a call makes **rtpengine** produce its
    own audio RTP stream (instead of just forwarding an audio stream received from
    elsewhere). The audio is generated from a circular audio buffer (see above) and
    all contributing audio sources are mixed into that one audio buffer.
    Contributing audio sources are audio streams received from elsewhere (that
    would otherwise simply be forwarded) and audio produced by the **play media**
    command.

    With this set to **on-demand**, the audio player is enabled only if explicitly
    requested by the user for a particular call via the **audio-player=** option
    used in a signalling message.

    When set to **play-media**, the audio player is enabled only while media
    playback via the **play media** command is active. After media playback is
    finished, the audio player is again disabled and audio goes back to simply
    being forwarded.

    Setting this option to **transcoding** leaves the audio player disabled unless
    any sort of transcoding is required for a call.

    With a setting of **always**, the audio player is enabled for all calls, unless
    explicitly disabled via the **audio-player=** option used in a signalling
    message. This forces all audio through the transcoding engine, even if input
    and output codecs are the same.

    Audio player usage can be changed on a call-by-call basis by including the
    **audio-player=** option in a signalling message. This option supports the
    values **transcoding** and **always**, which result in the behaviour described
    just above, and **off** which forces the audio player to be disabled regardless
    of this setting.

- **--poller-per-thread**

    Enable 'poller per thread' functionality: for every worker thread (see the
    \--num-threads option) a poller will be created. With this option on, it is
    guaranteed that only a single thread will ever read from a particular socket,
    thus maintaining the order of the packets. Might help when having issues with
    DTMF packets (RFC 2833).

- **--dtls-cert-cipher=****prime256v1**\|**RSA**

    Choose the type of key to use for the signature used by the self-signed
    certificate used for DTLS. The previous default was **RSA**. The current default
    and the only other option is **prime256v1** which is a 256-bit elliptic-curve
    key.

- **--dtls-signature=****SHA-256**\|**SHA-1**

    Choose the hash algorithm to use for the signature used by the self-signed
    certificate used for DTLS. The default is **SHA-256**. Not to be confused with
    the hash algorithm used for the certificate fingerprint inserted into the SDP
    (**a=fingerprint:**), which is independent of the certificate's signature and
    can be selected during runtime.

- **--dtls-rsa-key-size=**_INT_

    Size in bits of the RSA key used by the DTLS certificate, if RSA is in use.
    Default is 2048 bits.

- **--dtls-ciphers=**_STRING_

    Ciphers allowed during the DTLS key exchange (not to be confused with the
    cipher used by the DTLS certificate). The format of this string is an OpenSSL
    cipher list. The default is
    **DEFAULT:!NULL:!aNULL:!SHA256:!SHA384:!aECDH:!AESGCM+AES256:!aPSK**

- **--dtls-mtu=**_INT_

    Set DTLS MTU to enable fragmenting of large DTLS packets. Defaults to 1200.
    Minimum value is 576 as the internet protocol requires that hosts must be able to 
    process IP datagrams of at least 576 bytes (for IPv4) or 1280 bytes (for IPv6).
    This does not preclude link layers with an MTU smaller than this minimum MTU from 
    conveying IP data. Internet IPv4 path MTU is 68 bytes.

- **--mqtt-host=**_HOST_\|_IP_

    Host or IP address of the Mosquitto broker to connect to. Must be set to enable
    exporting stats to Mosquitto.

- **--mqtt-port=**_INT_

    Port of the Mosquitto broker. Defaults to 1883.

- **--mqtt-id=**_STRING_

    Client ID to use for Mosquitto. Default is a generated random string.

- **--mqtt-keepalive=**_INT_

    Keepalive interval in seconds. Defaults to 30.

- **--mqtt-user=**_USERNAME_
- **--mqtt-pass=**_PASSWORD_

    Credentials to connect to Mosquitto broker. At least a username must be given
    to enable authentication.

- **--mqtt-cafile=**_FILE_
- **--mqtt-capath=**_PATH_
- **--mqtt-certfile=**_FILE_
- **--mqtt-keyfile=**_FILE_
- **--mqtt-tls-alpn=**_STRING_

    Enable TLS to connect to Mosquitto broker, optionally with client certificate
    authentication. At least **cafile** or **capath** must be given to enable TLS. To
    enable client certificate authentication, both **certfile** and **keyfile** must
    be set. All files must be in PEM format. Password-proteted files are not
    supported. The **tls-alpn** can be set (e.g. mqtt) if a service like AWS IoT
    Core shares the same TLS port for two different network protocols.

- **--mqtt-publish-qos=****0**\|**1**\|**2**

    QoS value to use for publishing to Mosquitto. See Mosquitto docs for details.

- **--mqtt-publish-topic=**_STRING_

    Topic string to use for publishing to Mosquitto. Must be set to a non-empty
    string.

- **--mqtt-publish-interval=**_MILLISECONDS_

    Interval in milliseconds to publish to Mosquitto. Defaults to 5000 (5 seconds).

- **--mqtt-publish-scope=****global**\|**summary**\|**call**\|**media**

    When set to **summary**, one message will be published to Mosquitto every
    _interval_ milliseconds containing all global stats. A setting of **global**
    has the same effect as **summary** but will also contain a list of all running
    calls with stats for each call. When set to **call**, one message per call will
    be published to Mosquitto with stats for that call every _interval_
    milliseconds, plus one message every _interval_ milliseconds with global
    stats. When set to **media**, one message per call media (usually one media per
    call participant, so usually 2 media per call) will be published to Mosquitto
    with stats for that call media every _interval_ milliseconds, plus one message
    every _interval_ milliseconds with global stats.

- **--mos=****CQ**\|**LQ**

    MOS (Mean Opinion Score) calculation formula. Defaults to **CQ** (conversational
    quality) which takes RTT into account and therefore requires peers to correctly
    send RTCP. If set to **LQ** (listening quality) RTT is ignored, allowing a MOS to
    be calculated in the absence of RTCP.

- **--measure-rtp**

    Enable measuring RTP metrics even for plain RTP passthrough scenarios. Without
    that option, RTP metrics are measured only in transcoding scenarios.

- **--socket-cpu-affinity=**_INT_

    Enables setting the socket CPU affinity via the **SO\_INCOMING\_CPU** socket
    option if available. The default value is zero which disables this feature. If
    set to a positive number then the CPU affinity for all sockets belonging to the
    same call will be set to the same value. The number specifies the upper limit
    of the affinity to be set, and values will be used in a round-robin fashion
    (e.g. if set to **8** then the values **0** through **7** will be used to set the
    affinity). If this option is set to a negative number, then the number of
    available CPU cores will be used.

## INTERFACES

The command-line options **-i** or **--interface**, or equivalently the
**interface** config file option, specify local network interfaces for RTP.
At least one must be given, but multiple can be specified.
The format of the value is \[_NAME_**/**\]_IP_\[!_IP_\] with _IP_ being
either an IPv4 address, an IPv6 address, the name of a system network interface
(such as _eth0_), a DNS host name (such as _test.example.com_), or **any**.

The possibility of configuring a network interface by name rather than
by address should not be confused with the logical interface name used
internally by **rtpengine** (as described below).
The _NAME_ token in the syntax above refers to the internal logical
interface name, while the name of a system network interface is used
in place of the first _IP_ token in the syntax above.
For example, to configure a logical network interface called _int_
using all the addresses from the existing system network interface
_eth0_, you would use the syntax _int/eth0_.
(Unless omitted, the second _IP_ token used for the advertised address
must be an actual network address and cannot be an interface name.)

If DNS host names are used instead of addresses or interface names, the lookup
will be done only once during daemon start-up.

The special keyword **any** can be used to listen on any and all available local
interface addresses except from loopback devices. This keyword should only be
given once in place of a more explicit interface configuration.

To configure multiple interfaces using the command-line options,
simply present multiple **-i** or **--interface** options.
When using the config file, only use a single **interface** line,
but specify multiple values separated by semicolons (e.g.
_interface = internal/12.23.34.45;external/23.34.45.54_).

If an interface option is given using a system interface name in place
of a network address, and if multiple network address are found
configured on that network interface, then **rtpengine** behaves as
if multiple **--interface** options had been specified.
For example, if interface _eth0_ exists with both addresses
_192.168.1.120_ and _2001:db8:85a3::7334_ configured on it, and if
the option _--interface=ext/eth0_ is given, then **rtpengine** would
behave as if both options _--interface=ext/192.168.1.120_ and
_--interface=ext/2001:db8:85a3::7334_ had been specified.

The second IP address after the exclamation point is optional and can
be used if the address to advertise in outgoing SDP bodies should be
different from the actual local address.
This can be useful in certain cases, such as your SIP proxy being behind NAT.
For example, _--interface=10.65.76.2!192.0.2.4_ means that _10.65.76.2_
is the actual local address on the server, but outgoing SDP bodies should
advertise _192.0.2.4_ as the address that endpoints should talk to.
Note that you may have to escape the exclamation point from your shell
when using command-line options, e.g. using _\\!_.

Giving an interface a name (separated from the address by a slash) is
optional; if omitted, the name **default** is used.
Names are useful to create logical interfaces which consist of one or
more local addresses.
It is then possible to instruct **rtpengine** to use particular interfaces
when processing an SDP message, to use different local addresses when
talking to different endpoints.
The most common use case for this is to bridge between one or more
private IP networks and the public internet.

For example, if clients coming from a private IP network must communicate
their RTP with the local address _10.35.2.75_, while clients coming from
the public internet must communicate with your other local address
_192.0.2.67_, you could create one logical interface _pub_ and a second
one _priv_ by using _--interface=pub/192.0.2.67 --interface=priv/10.35.2.75_.
You can then use the **direction** option to tell **rtpengine** which local
address to use for which endpoints (either _pub_ or _priv_).

If multiple logical interfaces are configured, but the **direction**
option is not given in a particular call, then the first interface
given on the command line will be used.

It is possible to specify multiple addresses for the same logical
interface (the same name).
Most commonly this would be one IPv4 addrsess and one IPv6 address,
for example: _--interface=192.168.63.1 --interface=fe80::800:27ff:fe00:0_.
In this example, no interface name is given, therefore both addresses
will be added to a logical interface named **default**.
You would use the **address family** option to tell **rtpengine** which
address to use in a particular case.

It is also possible to have multiple addresses of the same family in a
logical network interface.
In this case, the first address (of a particular family) given for an
interface will be the primary address used by **rtpengine** for most
purposes.
Any additional addresses will be advertised as additional ICE candidates
with increasingly lower priority.
This is useful on multi-homed systems and allows endpoints to choose the
best possible path to reach the RTP proxy.
If ICE is not being used, then additional addresses will go unused,
even though ports would still get allocated on those interfaces.

Another option is to give interface names in the format _BASE:SUFFIX_.
This allows interfaces to be used in a round-robin fashion, useful
for load-balancing the port ranges of multiple interfaces.
For example, consider the following configuration:
_--interface=pub:1/192.0.2.67 --interface=pub:2/10.35.2.75_.
These two interfaces can still be referenced directly by name (e.g.
_direction=pub:1_), but it is now also possible to reference only
the base name (i.e. _direction=pub_).
If the base name is used, one of the two interfaces is selected in a
round-robin fashion, and only if the interface actually has enough
open ports available.
This makes it possible to effectively increase the number of available
media ports across multiple IP addresses.
There is no limit on how many interfaces can share the same base name.

It is possible to combine the _BASE:SUFFIX_ notation with specifying
multiple addresses for the same interface name.
An advanced example could be (using config file notation, and omitting
actual network addresses):

    interface = pub:1/IPv4 pub:1/IPv4 pub:1/IPv6 pub:2/IPv4 pub:2/IPv6 pub:3/IPv6 pub:4/IPv4

In this example, when _direction=pub_ is IPv4 is needed as a primary
address, either _pub:1_, _pub:2_, or _pub:4_ might be selected.
When _pub:1_ is selected, one IPv4 and one IPv6 address will be used
as additional ICE alternatives.
For _pub:2_, only one IPv6 is used as ICE alternative, and for _pub:4_
no alternatives would be used.
When IPv6 is needed as a primary address, either _pub:1_, _pub:2_, or
_pub:3_ might be selected.
If at any given time not enough ports are available on any interface,
it will not be selected by the round-robin algorithm.

It is possible to use the round-robin algorithm even if the **direction**
is not given.
If the first given interface has the _BASE:SUFFIX_ format then the
round-robin algorithm is used and will select interfaces with the
same _BASE_ name.

If you are not using the NG protocol but rather the legacy UDP protocol
used by the **rtpproxy** module, the interfaces must be named **internal**
and **external** corresponding to the **i** and **e** flags if you wish to
use network bridging in this mode.

## EXIT STATUS

- **0**

    Successful termination.

- **1**

    An error occurred.

## ENVIRONMENT

- **RTPENGINE\_REDIS\_AUTH\_PW**

    Redis server password for persistent state storage.

- **RTPENGINE\_REDIS\_WRITE\_AUTH\_PW**

    Redis server password for write operations, if **--redis** has been
    specified, in which case the one specified in **--redis** will be used for
    read operations only.

## FILES

- `/etc/rtpengine/rtpengine.conf`

    Configuration file.

## EXAMPLES

A typical command line (enabling both UDP and NG protocols) may look like:

    rtpengine --table=0 --interface=10.64.73.31 --interface=2001:db8::4f3:3d \
      --listen-udp=127.0.0.1:22222 --listen-ng=127.0.0.1:2223 --tos=184 \
      --pidfile=/run/rtpengine.pid

## SEE ALSO

[kamailio(8)](http://man.he.net/man8/kamailio).
