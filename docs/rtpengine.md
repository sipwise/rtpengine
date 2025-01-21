---
title: rtpengine
section: 8
header: NGCP rtpengine
---

# rtpengine(8) manual page

## NAME

rtpengine - NGCP proxy for RTP and other UDP based media traffic

## SYNOPSIS

__rtpengine__ __\-\-interface__=*addr*... __\-\-listen-tcp__\|__\-\-listen-udp__\|__\-\-listen-ng__\|__\-\-listen-tcp-ng__\|__\-\-listen-http__\|__\-\-listen-https__=*addr*... \[*option*...\]

## DESCRIPTION

The Sipwise NGCP rtpengine is a proxy for RTP traffic and other UDP based
media traffic.
It is meant to be used with the Kamailio SIP proxy and forms a drop-in
replacement for any of the other available RTP and media proxies.

## OPTIONS

Most of these options are indeed optional, with two exceptions. It's
mandatory to specify at least one local IP address through __\-\-interface__,
and at least one of the __\-\-listen-__*...* options must be given.

All options can (and should) be provided in a config file instead of
at the command line. See the __\-\-config-file__ option below for details.

- __\-\-help__

    Print the usage information.

- __-v__, __\-\-version__

    If called with this option, the __rtpengine__ daemon will simply print its
    version number and exit.

- __\-\-codecs__

    Print a list of supported codecs and exit.

- __\-\-config-file=__*FILE*

    Specifies the location of a config file to be used. The config file is an
    *.ini* style config file, with all command-line options listed here also
    being valid options in the config file.
    For all command-line options, the long name version instead of the
    single-character version (e.g. __table__ instead of just __t__) must be
    used in the config file.
    For boolean options that are either present or not (e.g. __no-fallback__), a
    boolean value (either __true__ or __false__) must be used in the config file.
    If an option is given in both the config file and at the command line,
    the command-line value overrides the value from the config file.
    Options that can be specified multiple times on the command line must be
    given only once in the config file, with the multiple values separated by
    semicolons (see section [INTERFACES](https://metacpan.org/pod/INTERFACES) below for an example).

    As a special value, __none__ can be passed here to suppress loading of the
    default config file `/etc/rtpengine/rtpengine.conf`.

- __\-\-config-section=__*STRING*

    Specifies the *.ini* style section to be used in the config file.
    Multiple sections can be present in the config file, but only one can be
    used at a time.
    The default value is __rtpengine__.
    A config file section is started in the config file using square brackets
    (e.g. __\[rtpengine\]__).

- __-t__, __\-\-table=__*INT*

    Takes an integer argument and specifies which kernel table to use for
    in-kernel packet forwarding.
    See the section on in-kernel operation in the `README.md` for more detail.
    Optional and defaults to zero.
    If in-kernel operation is not desired, a negative number can be specified.

- __\-\-nftables-chain=__*CHAIN*

    Name of the netfilter chain in which to create the custom forwarding rule
    required for in-kernel packet forwarding. Defaults to __rtpengine__. Only
    used if in-kernel packet forwarding is enabled (__table__ set to zero or
    higher).

    At startup __rtpengine__ creates a new netfilter chain with this name (in
    the __filter__ table) if it doesn't  yet exist, or flushes (empties out)
    the chain if it already exists. It then creates a single forwarding rule in
    this chain to direct media packets into the kernel module for processing.

    The rule and the chain are deleted during shutdown.

    Explicitly setting this option to an empty string disables managing of a
    netfilter chain and prevents creation of the custom forwarding rule.

- __\-\-nftables-base-chain=__*CHAIN*

    Name of the netfilter base chain to use as entry point for in-kernel packet
    forwarding. Defaults to __INPUT__ to match legacy __iptables__ setups. Only
    applicable if the option __nftables-chain__ is active.

    If the chain with this name doesn't exist during startup, __rtpengine__
    will create it as a base chain. It then adds a single immediate-goto (jump)
    rule to the chain given by the __nftables-chain__ option. During shutdown
    this rule is again deleted.

    If this option is explicitly set to an empty string, then __rtpengine__
    will directly create the chain given by __nftables-chain__ as a base chain
    and skip creating the immediate-goto rule.

    If this option is set to the special string __none__, then __rtpengine__
    will create its custom chain and rule as it normally would, but will skip
    adding an immediate-goto rule to the custom chain. Doing so requires the
    operator to manually create this immediate-goto rule somewhere themselves.
    Otherwise in-kernel packet forwarding would be left inoperable.

- __\-\-nftables-append__

    With this option set, the netfilter rule created in the base chain is
    appended to the list of existing rules. The default is to prepend it
    (insert it at the beginning).

- __\-\-nftables-family=ip__|__ip6__|__ip,ip6__

    Configure for which netfilter address family to manage tables, chains, and
    rules. The default is to manage both IPv4 and IPv6 address families.

- __\-\-nftables-start__
- __\-\-nftables-stop__

    Instructs __rtpengine__ to execute the actions described under
    __nftables-chain__ and __nftables-base-chain__ and then immediately exit.
    Useful to manually re-create the rule(s) if they have gotten lost during
    runtime, and/or to manually manage creation and deletion of these rules
    from a script (typically in combination with an empty __nftables-chain=__
    in the main config file).

- __\-\-nftables-status__

    Instructs __rtpengine__ to check for the existence of the managed netfilter
    rules and chains, print the result of check, and exit. The process will
    exit with code 0 if the check was successful, and 1 otherwise.

- __-F__, __\-\-no-fallback__

    Will prevent fallback to userspace-only operation if the kernel module is
    unavailable.
    In this case, startup of the daemon will fail with an error if this option
    is given.

- __\-\-templates=__*STR*

    Name of the config file section to contain signalling templates. Requires a
    configuration file to be in use (i.e. not __\-\-config-file=none__).
    Default value is unset (i.e. no templates supported).

    If set, then each entry within the given config section corresponds to a
    named signalling template, which can then be used by referencing it via the
    __template=...__ key in a signalling message to *rtpengine*.

    See section *SIGNALLING TEMPLATES* below.

- __-S__, __\-\-save-interface-ports__

    Will bind ports only on the first available local interface, of desired
    family, of logical interface. If no ports available on any local interface
    of desired family, give an error message.

    In this case, ICE will be broken.

- __-i__, __\-\-interface=__\[*NAME*/\]*IP*\[!*IP*\]

    Specifies a local network interface for RTP.
    At least one must be given, but multiple can be specified.
    See the section [INTERFACES](https://metacpan.org/pod/INTERFACES) just below for details.

- __-l__, __\-\-listen-tcp=__\[*IP*:\]*PORT*
- __-u__, __\-\-listen-udp=__\[*IP46*:\]*PORT*
- __-n__, __\-\-listen-ng=__\[*IP46*:\]*PORT*
- __-n__, __\-\-listen-tcp-ng=__\[*IP46*:\]*PORT*

    These options each enable one of the 4 available control protocols if given
    and each take either just a port number as argument, or an *address:port*
    pair, separated by colon.
    At least one of these 3 options must be given.

    The __tcp__ protocol is obsolete.
    It was used by old versions of __OpenSER__ and its __mediaproxy__ module.
    It is provided for backwards compatibility.

    The __udp__ protocol is used by __Kamailio__'s __rtpproxy__ module.
    In this mode, __rtpengine__ can be used as a drop-in replacement for any
    other compatible RTP proxy.

    The __ng__ protocol is an advanced control protocol and can be used with
    __Kamailio__'s __rtpengine__ module.
    With this protocol, the complete SDP body is passed to __rtpengine__,
    rewritten and passed back to __Kamailio__.
    Several additional features are available with this protocol, such as
    ICE handling, SRTP bridging, etc.

    The __tcp-ng__ protocol is in fact the __ng__ protocol but transported over TCP.

    It is recommended to specify not only a local port number, but also
    __127.0.0.1__ as interface to bind to.

    Each option can be given multiple times to open multiple control ports of
    the same type. In the config file, the option can be given only once, with
    multiple addresses and ports separated by semicolons.

- __-c__, __\-\-listen-cli=__\[*IP46*:\]*PORT*

    TCP IP and port to listen for the CLI (command line interface).

    This option can be given multiple times to open multiple CLI ports. In the
    config file, the option can be given only once, with multiple addresses and
    ports separated by semicolons.

- __-g__, __\-\-graphite=__*IP46*:*PORT*

    Address of the graphite statistics server.

- __-w__, __\-\-graphite-interval=__*INT*

    Interval of the time when information is sent to the graphite server.

- __\-\-graphite-prefix=__*STRING*

    Add a prefix for every graphite line.

- __\-\-graphite-timeout=__*INT*

    Sets after how much time (seconds) to force fail graphite socket connection,
    when graphite server is filtered out. If set to 0, there are no changes.

- __-t__, __\-\-tos=__*INT*

    Takes an integer as argument and if given, specifies the TOS value that
    should be set in outgoing packets.
    The default is to leave the TOS field untouched.
    A typical value is 184 (__Expedited Forwarding__).

- __\-\-control-tos=__*INT*

    Takes an integer as argument and if given, specifies the TOS value that
    should be set in the control-ng interface packets.
    The default is to leave the TOS field untouched.
    This parameter can also be set or listed via __rtpengine-ctl__.

- __\-\-control-pmtu=want__\|__dont__

    Forces a specific PMTU discovery behaviour on IPv4 UDP control sockets,
    overriding the system-wide default. If set to __want__ then path MTU discovery
    is performed, initially enabling the DF (don't fragment) bit on outgoing IPv4
    packets until the path MTU has been discovered through reception of a
    "fragmentation needed" ICMP packet. If set to __dont__ then path MTU discovery
    is disabled, leaving the DF bit unset, and relying on the routers within the
    network path to perform any necessary fragmentation.

    The setting of __dont__ is useful in broken IPv4 environments without
    functioning PMTU discovery, for example in networks which unconditionally block
    all ICMP.

- __-o__, __\-\-timeout=__*SECS*

    Takes the number of seconds as argument after which a media stream should
    be considered dead if no media traffic has been received.
    If all media streams belonging to a particular call go dead, then the call
    is removed from __rtpengine__'s internal state table.
    Defaults to 60 seconds.

- __-s__, __\-\-silent-timeout=__*SECS*

    Ditto as the __\-\-timeout__ option, but applies to muted or inactive media
    streams.
    Defaults to 3600 (one hour).

- __-a__, __\-\-final-timeout=__*SECS*

    The number of seconds since call creation, after call is deleted.
    Useful for limiting the lifetime of a call.
    This feature can be disabled by setting the parameter to 0.
    By default this timeout is disabled.

- __\-\-offer-timeout=__*SECS*

    This timeout (in seconds) is applied to calls which only had an __offer__
    but no __answer__.
    Defaults to 3600 (one hour).

- __-p__, __\-\-pidfile=__*FILE*

    Specifies a path and file name to write the daemon's PID number to.

- __-f__, __\-\-foreground__

    If given, prevents the daemon from daemonizing, meaning it will stay in
    the foreground.
    Useful for debugging.

- __-m__, __\-\-port-min=__*INT*
- __-M__, __\-\-port-max=__*INT*

    Both take an integer as argument and together define the local port range
    from which __rtpengine__ will allocate UDP ports for media traffic relay.
    Default to 30000 and 40000 respectively.

- __-L__, __\-\-log-level=__*INT*

    Takes an integer as argument and controls the highest log level which will be
    sent to syslog. This is merely the default log level used for logging
    subsystems (see below) that don't explicitly have a separate log level
    configured.

    The log levels correspond to the ones found in the [syslog(3)](http://man.he.net/man3/syslog) man page.
    The default value is __6__, equivalent to LOG\_INFO.
    The highest possible value is __7__ (LOG\_DEBUG) which will log everything.

    During runtime, the log level can be decreased by sending the signal
    SIGURS1 to the daemon and can be increased with the signal SIGUSR2.

- __\-\-log-level-__*subsystem*=*INT*

    Configures a log level for one of the logging subsystems. A logging subsystem
    which doesn't have a log level configured explicitly takes its default value
    from the __log-level__ setting described above, with the exception of the
    __internals__ subsystem which by default has all logging disabled.

    The full list of logging subsystems can be viewed by pulling up the __\-\-help__
    online help. Some (if not all) subsystems are: __core__, __spandsp__ (messages
    generated by SpanDSP itself), __ffmpeg__ (messages generated by ffmpeg libraries
    themselves), __transcoding__ (messages related to RTP/media transcoding),
    __codec__ (messages related to codec negotiation), __rtcp__, __ice__, __crypto__
    (messages related to crypto/SRTP/SDES/DTLS negotiation), __srtp__ (messages
    related to RTP/SRTP en/decryption), __internals__ (disabled by default), __http__
    (includes WebSocket), __control__ (messages related to control protocols,
    including SDP exchanges), __dtx__.

- __\-\-log-facilty=daemon__\|__local0__\|...\|__local7__\|...

    The syslog facilty to use when sending log messages to the syslog daemon.
    Defaults to __daemon__.

- __\-\-log-facilty-cdr=daemon__\|__local0__\|...\|__local7__\|...

    Same as __\-\-log-facility__ with the difference that only CDRs are written
    to this log facility.

- __\-\-log-facilty-rtcp=daemon__\|__local0__\|...\|__local7__\|...

    Same as __\-\-log-facility__ with the difference that only RTCP data is
    written to this log facility.
    Be careful with this parameter since there may be a lot of information
    written to it.

- __\-\-log-facilty-dtmf=daemon__\|__local0__\|...\|__local7__\|...

    Same as __\-\-log-facility__ with the difference that only DTMF events are
    written to this log facility.
    DTMF events are extracted from RTP packets conforming to RFC 4733, are
    encoded in JSON format, and written as soon as the end of an event is
    detected.

- __\-\-log-format=default__\|__parsable__

    Selects between multiple log output styles.
    The default is to prefix log lines with a description of the relevant
    entity, such as __\[CALLID\]__ or __\[CALLID port 12345\]__.
    The __parsable__ output style is similar, but makes the ID easier to
    parse by enclosing it in quotes, such as __\[ID="CALLID"\]__
    or __\[ID="CALLID" port="12345"\]__.

- __\-\-dtmf-log-dest=__*IP46*:*PORT*

    Configures a target address for logging detected DTMF event. Similar
    to the feature enabled by __\-\-log-facilty-dtmf__, but instead of writing
    detected DTMF events to syslog, this sends the JSON payload to the
    given address as UDP packets.

- __\-\-dtmf-log-ng-tcp__

    If __\-\-listen-tcp-ng__ is enabled, this will send DTMF events to all
    connected clients encoded in bencode format.

- __\-\-dtmf-no-log-injects__
If __\-\-dtmf-no-log-injects__ is enabled, DTMF events resulting from a
call to inject-DTMF won't be sent to __\-\-dtmf-log-dest=__ or __\-\-listen-tcp-ng__
- __\-\-dtmf-no-suppress__

    Some RTP clients continue to send audio RTP packets during a DTMF event,
    resulting in both audio packets and DTMF packets appearing simultaneously. By
    default, when transcoding, __rtpengine__ suppresses audio packets during a DTMF
    event and will only send DTMF packets until the DTMF event is over. Setting
    this option disables this feature.

- __\-\-log-srtp-keys__

    Write SRTP keys to error log instead of debug log.

- __-E__, __\-\-log-stderr__

    Log to stderr instead of syslog.
    Only useful in combination with __\-\-foreground__.

- __\-\-split-logs__

    Split multi-line log messages into individual log messages so that each
    line receives its own log line prefix.

- __\-\-max-log-line-length=__*INT*

    Split log lines into multiple lines when they exceed the character count given
    here. Can be set to a negative value to allow unlimited length log lines. Set
    to zero for the default value, which is unlimited if logging to stderr, or 500
    if logging to syslog.

- __\-\-no-log-timestamps__

    Don't add timestamps to log lines written to stderr.
    Only useful in combination with __\-\-log-stderr__.

- __\-\-log-name=__*STRING*

    Set the id to be printed in syslog.
    Defaults to __rtpengine__.

- __\-\-log-mark-prefix=__*STRING*

    Prefix to be added to particular data fields in log files that are deemed
    sensitive and/or private information. Defaults to an empty string.

- __\-\-log-mark-suffix=__*STRING*

    Suffix to be added to particular data fields in log files that are deemed
    sensitive and/or private information. Defaults to an empty string.

- __\-\-num-threads=__*INT*

    How many worker threads to create, must be at least one.
    The default is to create as many threads as there are CPU cores available.
    If the number of CPU cores cannot be determined or if it is less than four,
    then the default is four.

- __\-\-media-num-threads=__*INT*

    Number of threads to launch for media playback. Defaults to the same
    number as __num-threads__. This can be set to zero if no media playback
    functionality is desired.

    Media playback is actually handled by two threads: One for reading and
    decoding the media file, and another to schedule and send out RTP packets.
    So for example, if this option is set to 4, in total 8 threads will be
    launched.

- __\-\-codec-num-threads=__*INT*

    Enables asynchroneous transcoding operation using the specified number of
    worker threads. This is an experimental feature and probably doesn't bring
    any benefits over normal synchroneous transcoding.

- __\-\-poller-size=__*INT*

    Set the maximum number of event items (file descriptors) to retrieve from
    the underlying system poll mechanism per iteration. Defaults to 128. A
    lower number can lead to improved load-balancing among a large number of
    threads.

- __\-\-thread-stack=__*INT*

    Set the stack size of each thread to the value given in kB. Defaults to 2048
    kB. Can be set to -1 to leave the default provided by the OS unchanged.

- __\-\-evs-lib-path=__*FILE*

    Points to the shared object file (__.so__) containing the reference
    implementation for the EVS codec. See the `README` for more details.

- __\-\-sip-source__

    The original __rtpproxy__ as well as older version of __rtpengine__ by default
    did not honour IP addresses given in the SDP body, and instead used the
    source address of the received SIP message as default endpoint address.
    Newer versions of __rtpengine__ reverse this behaviour and honour the
    addresses given in the SDP body by default. This option restores the
    old behaviour.

- __\-\-dtls-passive__

    Enables the __DTLS=passive__ flag for all calls unconditionally.

- __-d__, __\-\-delete-delay=__*INT*

    Delete the call after the specified delay from memory.
    Can be set to zero for immediate call deletion.

- __-r__, __\-\-redis=__\[*PW*@\]*IP*:*PORT*/*INT*

    Connect to specified Redis database (with the given database number) and
    use it for persistence storage.
    The format of this option is *ADDRESS*:*PORT*/*DBNUM*, for example
    *127.0.0.1:6379/12* to connect to the Redis DB number 12 running on
    localhost on the default Redis port.

    If the Redis database is protected with an authentication password, the
    password can be supplied by prefixing the argument value with the password,
    separated by an `@` symbol, for example *foobar@127.0.0.1:6379/12*.
    Note that this leaves the password visible in the process list, posing a
    security risk if untrusted users access the same system.
    As an alternative, the password can also be supplied in the shell
    environment through the environment variable __RTPENGINE\_REDIS\_AUTH\_PW__.

    On startup, __rtpengine__ will read the contents of this database and
    restore all calls stored therein.
    During runtime operation, __rtpengine__ will continually update the
    database's contents to keep it current, so that in case of a service
    disruption, the last state can be restored upon a restart.

    When this option is given, __rtpengine__ will delay startup until the
    Redis database adopts the master role (but see below).

- __-w__, __\-\-redis-write=__\[*PW*@\]*IP*:*PORT*/*INT*

    Configures a second Redis database for write operations.
    If this option is given in addition to the first one, then the first
    database will be used for read operations (i.e. to restore calls from)
    while the second one will be used for write operations (to update states
    in the database).

    For password protected Redis servers, the environment variable for the
    password is __RTPENGINE\_REDIS\_WRITE\_AUTH\_PW__.

    When both options are given, __rtpengine__ will start and use the Redis
    database regardless of the database's role (master or slave).

- __\-\-redis-subscribe=__\[*PW*@\]*IP*:*PORT*\[/*INT*\]

    Configures a Redis database for subscribing and receiving notifications.
    This option takes precedence over __\-\-redis__, if configured.
    When __\-\-subscribe-keyspace__ is also configured, the keyspace part of
    __\-\-redis-subscribe=__ is not used, the former takes precedence.
    The keyspace number can also be omitted altogether.

    For password protected Redis servers, the environment variable for the
    password is __RTPENGINE\_REDIS\_SUBSCRIBE\_AUTH\_PW__.

- __-k__, __\-\-subscribe-keyspace=__*INT*

    List of redis keyspaces to subscribe. When it and __\-\-redis-subscribe=__
    are not present, no keyspaces are subscribed (default behaviour).
    In conjunction with __\-\-redis-subscribe=__, __\-\-subscribe-keyspace=__
    overwrites the keyspaces to subscribe to.

    Further subscriptions could be added/removed via __rtpengine-ctl ksadd/ksrm__.
    This may lead to enabling/disabling of the redis keyspace notification feature.

    The list of keyspace subscriptions can initially be left empty, but if any
    keyspaces are to be added later during runtime, the feature must still be
    configured at *rtpengine* startup. This can be achieved by either setting
    __\-\-redis-subscribe=__ to a valid address, or by listing the single value
    __-1__ under __\-\-subscribe-keyspace=__.

- __\-\-redis-num-threads=__*INT*

    How many redis restore threads to create.
    The default is 4.

- __\-\-redis-expires=__*INT*

    Expire time in seconds for redis keys.
    Default is 86400.

- __\-\-active-switchover__

    With this option enabled, any activity (such as signalling or media) on a call
    that was created through a Redis keyspace notification will make __rtpengine__
    take control of that call. Without this option, an explicit command is required
    for __rtpengine__ to take (or relinquish) control of a call.

- __-q__, __\-\-no-redis-required__

    When this parameter is present or __NO\*REDIS\*REQUIRED='yes'__ or __'1'__ in
    the config file, __rtpengine__ starts even if there is no initial connection
    to redis databases (either to __-r__ or to __-w__ or to both redis).

    Be aware that if the __-r__ redis cannot be initially connected, sessions
    are not reloaded upon rtpengine startup, even though rtpengine still starts.

- __\-\-redis-allowed-errors__

    If this parameter is present and has a value >= 0, it will configure how
    many consecutive errors are allowed when communicating with a redis server
    before the redis communication will be temporarily disabled for that server.
    While the communication is disabled there will be no attempts to reconnect
    to redis or send commands to that server.
    Default value is -1, meaning that this feature is disabled.
    This parameter can also be set or listed via __rtpengine-ctl__.

- __\-\-redis-disable-time__

    This parameter configures the number of seconds redis communication is
    disabled because of errors.
    This works together with redis-allowed-errors parameter.
    The default value is 10.
    This parameter can also be set or listed via __rtpengine-ctl__.

- __\-\-redis-cmd-timeout=__*INT*

    If this parameter is set to a non-zero value it will set the timeout,
    in milliseconds, for each command to the redis server.
    If redis does not reply within the specified timeout the command will fail.
    The default value is 0, meaning that the commands will be blocking without
    timeout.
    This parameter can also be set or listed via __rtpengine-ctl__; note that
    setting the parameter to 0 will require a reconnect on all configured
    redis servers.

- __\-\-redis-connect-timeout=__*INT*

    This parameter sets the timeout value, in milliseconds, when connecting
    to a redis server.
    If the connection cannot be made within the specified timeout the
    connection will fail.
    Note that in case of failure, when reconnecting to redis, a __PING__ command
    is issued before attempting to connect so the __\-\-redis-cmd-timeout__ value
    will also be added to the total waiting time.
    This is useful if using __\-\-redis-allowed-errors__, when attempting to
    estimate the total lost time in case of redis failures.
    The default value for the connection timeout is 1000ms.
    This parameter can also be set or listed via __rtpengine-ctl__.

- __\-\-redis-resolve-on-reconnect__

    Enable 'redis resolve on reconnect' functionality: when re-connecting to the
    remote redis server try to re-resolve if the redis hostname was an FQDN
    and not IP address. It is a boolean value (either __true__ or __false__).

- __\-\-redis-format=bencode__\|__JSON__

    Selects the format for serialised call data written to Redis or KeyDB. The
    old default (and previously only option) was as a JSON object. The new
    default is using *bencode* formatting. Using *bencode* has the benefit of
    yielding better performance and lower CPU usage, while making the data less
    human readable.

    Both formats can be restored from, regardless of this setting.

- __-b__, __\-\-b2b-url=__*STRING*

    Enables and sets the URI for an XMLRPC callback to be made when a call is
    torn down due to packet timeout.
    The special code __%%__ can be used in place of an IP address, in which case
    the source address of the originating request (or alternatively the address
    specified using the __xmlrpc-callback__ __ng__ protocol option) will be used.

- __-x__, __\-\-xmlrpc-format=__*INT*

    Selects the internal format of the XMLRPC callback message for B2BUA call
    teardown.
    0 is for SEMS,
    1 is for a generic format containing the call-ID only,
    2 is for Kamailio.

- __\-\-max-sessions=__*INT*

    Limit the number of maximum concurrent sessions.
    Set at startup via __max-sessions__ in config file.
    Set at runtime via __rtpengine-ctl__ util.
    Setting the __rtpengine-ctl set maxsessions 0__ can be used in draining
    rtpengine sessions.
    Enable feature: __max-sessions=1000__
    Enable feature: __rtpengine-ctl set maxsessions__ >= 0
    Disable feature: __rtpengine-ctl set maxsessions -1__
    By default, the feature is disabled (i.e. maxsessions == -1).

- __\-\-max-load=__*FLOAT*

    If the current 1-minute load average exceeds the value given here,
    reject new sessions until the load average drops below the threshold.

- __\-\-max-cpu=__*FLOAT*

    If the current CPU usage (in percent) exceeds the value given here,
    reject new sessions until the CPU usage drops below the threshold.
    CPU usage is sampled in 0.5-second intervals.
    Only supported on systems providing a Linux-style `/proc/stat`.

- __\-\-max-bandwidth=__*INT*

    If the current bandwidth usage (in bytes per second) exceeds the value
    given here, reject new sessions until the bandwidth usage drops below
    the threshold.
    Bandwidth usage is sampled in 1-second intervals and is based on
    received packets, not sent packets.

- __\-\-max-recv-iters=__*INT*

    This parameter sets maximum continuous reading cycles in UDP poller loop,
    can help to avoid dropped packets errors on bursty streams (default 50).

- __\-\-homer=__*IP46*:*PORT*

    Enables sending the decoded contents of RTCP packets to a Homer SIP
    capture server.
    The transport is HEP version 3 and payload format is JSON.
    This argument takes an IP address and a port number as value.
    Also enables sending the control NG traffic to a capturing agent.
    Payload format does not apply in this case.

- __\-\-homer-protocol=udp__\|__tcp__

    Can be either __udp__ or __tcp__ with __udp__ being the default.

- __\-\-homer-id=__*INT*

    The HEP protocol used by Homer contains a "capture ID" used to distinguish
    different sources of capture data.
    This ID can be specified using this argument.

- __\-\-homer-disable-rtcp-stats__

    Disables the default behaviour that RTCP stats are sent when homer
    parameter is set. Sending of RTCP and NG are as such decoupled.

- __\-\-homer-enable-ng__

    Enables sending control NG packages to a Homer capturing software. The
    capturing agent part is not officialy supported OOTB, but it can be
    achieved with Kamailio by using the config. For this feature to work one
    has to set at least the homer parameter.

- __\-\-homer-ng-capture-proto=__*INT*

    The HEP protocol used by Homer contains a "Capture protocol type" UINT8
    used by the capturing agent and UI to make further processing. Some values
    are registered, but currently 0x3d values onwards are free.
    Default value is 0x3d (61).

- __\-\-recording-dir=__*FILE*

    An optional argument to specify a path to a directory where PCAP recording
    files and recording metadata files should be stored. If not specified,
    support for call recording will be disabled.

    __rtpengine__ supports multiple mechanisms for recording calls.
    See __recording-method__ below for a list.
    The default recording method __pcap__ is described in this section.

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

- __\-\-recording-method=pcap__\|__proc__\|__all__

    Multiple methods of call recording are supported and this option can be
    used to select one.
    Currently supported are the method __pcap__, __proc__ and __all__.
    The default method is __pcap__ and is the one described above.

    The recording method __proc__ works by writing metadata files directly into
    the __recording-dir__ (i.e. not into a subdirectory) and instead of recording
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

    The recording method __all__ will enable both __pcap__ and __proc__
    at the same time.

- __\-\-recording-format=raw__\|__eth__

    When recording to pcap file in __raw__ (default) format, there is no
    ethernet header.
    When set to __eth__, a fake ethernet header is added, making each package
    14 bytes larger.

- __\-\-record-egress__

    Apply media recording to egress media streams (as they are sent by
    __rtpengine__) instead of media streams as they are received. This makes it
    possible to include manipulated and generated media (such as from the __play
    media__ command) in the recordings.

- __\-\-iptables-chain=__*STRING*

    This option enables explicit management of an iptables chain.
    When enabled, __rtpengine__ takes control of the given iptables chain,
    which must exist already prior to starting the daemon.
    Upon startup, __rtpengine__ will flush the chain, and then add one __ACCEPT__
    rule for each media port (RTP/RTCP) opened.
    Each rule will exactly match the individual port and destination IP address,
    and will be created with the call ID as iptables comment.
    The rule will be deleted when the port is closed.

    This option allows creating a firewall with a default __DROP__ policy for
    the entire port range used by __rtpengine__ and then referencing the given
    iptables chain to only selectively allow the ports actually in use.

    Note that this applies only to media ports, and does not apply to any other
    ports (such as the control ports) used by __rtpengine__.

    Also note that the iptables API is not the most efficient one around and
    does not lend itself to fast dynamic creation and deletion of rules.
    If you have a high call volume, and especially many call attempts per
    second, you might experience significant performance impact.
    This is not a shortcoming of __rtpengine__ but rather of iptables and its
    API implementation in the Linux kernel.
    In such a case, it is recommended to add a static iptables rule for the
    entire media port range instead, and not use this option.

- __\-\-scheduling=default__\|...
- __\-\-priority=__*INT*
- __\-\-idle-scheduling=default__\|...
- __\-\-idle-priority=__*INT*

    These options control various thread scheduling parameters.
    The __scheduling__ and __priority__ settings are applied to the main
    worker threads, while the __idle-__ versions of these settings are
    applied to various lower priority threads, such as timer runs.

    The __scheduling__ settings take the name of one of the supported
    scheduler policies.
    Setting it to __default__ or __none__ is equivalent to not setting the
    option at all and leaves the system default in place.
    The strings __fifo__ and __rr__ refer to realtime scheduling policies.
    __other__ is the Linux default scheduling policy.
    __batch__ is similar to __other__ except for a small wake-up scheduling
    penalty.
    __idle__ is an extremely low priority scheduling policy.
    The Linux-specific __deadline__ policy is not supported by __rtpengine__.
    Not all systems necessarily supports all scheduling policies; refer to
    your system's sched(7) man page for details.

    The __priority__ settings correspond to the scheduling priority for
    realtime (__fifo__ or __rr__) scheduling policies and must be in the range
    of 1 (low) through 99 (high).
    For all other scheduling policies (including no policy specified), the
    __priority__ settings correspond to the __nice__ value and should be in
    the range of -20 (high) through 19 (low).
    Not all systems support thread-specific __nice__ values; on such a system,
    using these settings might have unexpected results.
    (Linux does support thread-specific __nice__ values.)
    Refer to your system's sched(7) man page.

- __\-\-mysql-host=__*HOST*\|*IP*
- __\-\-mysql-port=__*INT*
- __\-\-mysql-user=__*USERNAME*
- __\-\-mysql-pass=__*PASSWORD*

    Configuration for playing back media files that are stored in a
    __MySQL__ (or __MariaDB__) database. At least __mysql-host__ must be configured
    for this to work. The others are optional and default to their respective
    values from the __MySQL__/__MariaDB__ client library.

- __\-\-mysql-query=__*STRING*

    Query to be used for retrieving media files from the database. No default
    exist, therefore this is a mandatory configuration for media playback from
    database. The provided query string must contain the single format placeholder
    __%llu__ and must not contain any other format placeholders. The ID value
    passed to __rtpengine__ in the __db-id__ key of the __play media__ message will
    be used in place of the placeholder when querying the database.

    An example configuration might look like this:

        mysql-query = select data from voip.files where id = %llu

- __\-\-endpoint-learning=delayed__\|__immediate__\|__off__\|__heuristic__

    Chooses one of the available algorithms to learn RTP endpoint addresses. The
    legacy setting is __delayed__ which waits 3 seconds before committing to an
    endpoint address, which is then learned from the first incoming RTP packet seen
    after this delay. The setting __immediate__ learns the endpoint address from the
    first incoming packet seen without the 3-second delay. Using __off__ disables
    endpoint learning altogether, likely breaking clients behind NAT. The setting
    __heuristic__ includes the 3-second delay, but source addresses seen from
    incoming RTP packets are ranked according to preference: If a packet with a
    source address and port matching the SDP address is seen, this address is used.
    Otherwise, if a packet with a matching source address (but a different port) is
    seen, that address is used. Otherwise, if a packet with a matching source port
    (but different address) is seen, that address is used. Otherwise, the source
    address of any incoming packet seen is used.

- __\-\-jitter-buffer=__*INT*

    Size of (incoming) jitter buffer in packets. A value of zero (the default)
    disables the jitter buffer. The jitter buffer is currently only implemented for
    userspace operation.

- __\-\-jb-clock-drift__

    Enable clock drift compensation for the jitter buffer.

- __\-\-debug-srtp__

    Enable extra log messages to help debug SRTP issues. Per-packet details such as
    sequence numbers, ROC, payloads (plain text and encrypted), authentication
    tags, etc are recorded to the log. Every RTCP packet is logged in this way,
    while every 512th RTP packet is logged. Only applies to packets
    forwarded/processed in userspace.

- __\-\-reject-invalid-sdp__

    With this option set, refuse to process SDP bodies that could not be cleanly
    parsed, instead of skipping over the parsing error and processing the SDP
    anyway. Currently this only affects the processing of SDP bodies that end in a
    blank line.

- __\-\-listen-http=__\[*IP*\|*HOSTNAME*:\]*PORT*
- __\-\-listen-https=__\[*IP*\|*HOSTNAME*:\]*PORT*

    Enable listening for HTTP or WebSocket connections, or their TLS-secured
    counterparts HTTPS and WSS. If no interface is specified, then the listening
    socket will be bound to all interfaces.

    The HTTP listener supports both HTTP and WS, while the HTTPS listener supports
    both HTTPS and WSS.

    If HTTPS/WSS is enabled, a certificate must also be provided using the options
    below.

- __\-\-https-cert=__*FILE*
- __\-\-https-key=__*FILE*

    Provide a server certificate and corresponding private key for the HTTPS/WSS
    listener, in PEM format.

- __\-\-http-threads=__*INT*

    Number of worker threads for HTTP/HTTPS/WS/WSS. If not specified, then the same
    number as given under __num-threads__ will be used. If no HTTP listeners are
    enabled, then no threads are created.

- __\-\-software-id=__*STRING*

    Sets a free-form string that is used to identify this software towards external
    systems with, for example in outgoing ICE/STUN requests. Defaults to
    __rtpengine-__*VERSION*. The string is sanitised to replace all
    non-alphanumeric characters with a dash to make it universally usable.

- __\-\-dtx-delay=__*INT*

    Processing delay in milliseconds to handle discontinuous transmission (DTX) or
    other transmission gaps. Defaults to zero (disabled) and is applicable to
    transcoded audio streams only. When enabled, delays processing of received
    packets for the specified time (much like a jitter buffer) in order to trigger
    DTX handling when a transmission gap occurs. The decoder is then instructed to
    fill in the missing time during a transmission gap, for example by generating
    comfort noise. The delay should be configured to be higher than the expected
    incoming jitter.

- __\-\-max-dtx=__*INT*

    Maximum duration for DTX handling in seconds. If no further RTP media is
    received within this time frame, then DTX processing will stop. Can be set to
    zero or negative to disable and keep DTX processing on indefinitely. Defaults
    to 30 seconds.

- __\-\-dtx-buffer=__*INT*
- __\-\-dtx-lag=__*INT*

    These two options together control the maximum number of packets and amount of
    audio that is allowed to be held in the DTX buffer. The __dtx-buffer__ option
    limits the number of packets held in the DTX buffer, while the __dtx-lag__
    option limits the amount of audio (in milliseconds) to be held in the DTX
    buffer. A DTX buffer overflow is declared when both limits are exceeded, in
    which case DTX processing is sped up by __dtx-shift__ milliseconds.

    The defaults are 10 packets and 100 milliseconds.

- __\-\-dtx-shift=__*INT*

    Amount of time in milliseconds that DTX processing is shifted forward (sped up)
    or backwards (delayed) in case of a DTX buffer overflow or underflow. An
    underflow occurs when RTP packets are received slower than expected, while an
    overflow occurs when packets are received faster than expected.

    If this value is set to zero then no adjustments of the DTX timer will be made.
    Instead, in order to keep up with the flow of received RTP packets, packets
    will be dropped or additional DTX audio will be generated as needed.

- __\-\-dtx-cn-params=__*INT*

    Specify one comfort noise parameter. This option follows the same format as
    __cn-payload__ described below.

    This option is applicable to audio generated to fill in transmission gaps
    during a DTX event. The default setting is no value, which means silence will
    be generated to fill in DTX gaps.

    If any CN parameters are configured, the parameters will be passed to an RFC
    3389 CN decoder, and the generated comfort noise will be used to fill in DTX
    gaps.

- __\-\-amr-dtx=native__\|__CN__

    Select the DTX behaviour for AMR codecs. The default is use the codec's
    internal processing: during a DTX event, a "no data" frame is passed to the
    decoder and the output is used as audio data.

    If __CN__ is selected here, the same DTX mechanism as other codecs use is used
    for AMR, which is to fill in DTX gaps with either silence or RFC 3389 comfort
    noise (see __dtx-cn-params__). This also affects processing of received SID
    frames: SID frames would not be passed to the codec but instead be replaced by
    generated silence or comfort noise.

- __\-\-silence-detect=__*FLOAT*

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
    specified by the __cn-payload__ option (see below). Currently this is applicable
    only to RTP peers that have advertised support for the __CN__ RTP payload type,
    in which case the silence audio frames will be replaced by __CN__ RTP frames.

- __\-\-cn-payload=__*INT*

    Specify one comfort noise parameter. This option can be given multiple times
    and the format follows RFC 3389. When specified at the command line, list the
    __\-\-cn-payload=__ option multiple times, each one specifying a single CN
    parameter. When used in the config file, list the option only a single time and
    list multiple CN parameters separated by semicolons (e.g.
    *cn-payload = 20;40;60*).

    The first CN payload value given is the noise level, specified as -dBov as per
    RFC 3389. This means that a noise level of zero corresponds to maximum volume,
    while higher numbers correspond to lower volumes. The highest allowable number
    is 127, corresponding to -127 dBov, which is near silence.

    Subsequent CN payload values carry spectral information (reflection
    coefficients) as per RFC 3389. Allowable values for each coefficient are
    between 0 and 254. Specifying spectral information is optional and the number
    of coefficients listed (model order) is variable.

    This option is applicable only to __CN__ packets generated from the silence
    detection mechanism described above. The configured CN parameters are used
    directly as payload of __CN__ packets sent by __rtpengine__.

    The default values are 32 (-32 dBov) for the noise level and no spectral
    information.

- __\-\-player-cache__

    Enable caching of encoded media packets for media player. This is applicable
    for media playback initiated through the *play media* command. When enabled
    __rtpengine__ will not simply decode given media files and then encode the media
    to RTP on demand and on the fly, but will rather decode and encode each media
    file in full the first time playback is requested, and then cache the resulting
    RTP packets in memory. This is done once for each media file and for each
    output RTP codec requested.

    Caching is done based on unique file name (with no consideration given to
    different file names that may point to the same file), or integer index for
    media files played from database. No verification of changing content of files
    or database entries is done. Media files provided as binary *blob* are also
    cached, although in this case a hash over the entire media file must be
    performed, therefore this usage is not recommended.

    It's not possible to choose a different *start-pos* for playback with this
    option enabled.

    RTP data is cached and retained in memory for the lifetime of the process.

- __\-\-moh-max-duration=__*INT*

    Music-on-hold max possible duration (in ms).
    When not defined (set to 0), it takes 1800000ms default value (half an hour).

- __\-\-moh-max-repeats=__*INT*

    Music-on-hold max possible repeats.
    moh-max-duration always takes a precedence over it.
    By default is always 999 if not defined otherwise.

- __\-\-moh-attr-name=__*STRING*

    Controls the value to be added to the session level of SDP whenever MoH is triggered.
    If not defined, then not in use.

- __\-\-kernel-player=__*INT*
- __\-\-kernel-player-media=__*INT*

    Enables and configures the kernel-based media player. Disabled by default
    and only available if the kernel module is in use, and requires
    __player-cache__ to also be enabled.

    When enabled, media playback will be handled by a set of kernel threads.
    The option __kernel-player__ defaults to zero and needs to set to non-zero
    to enable the feature. The number given to the option is the maximum number
    of concurrent kernel media players that can be used.

    The option __kernel-player-media__ configures the maximum number of unique
    media "files" that can be stored for playback in the kernel module. Media
    files requested for playback are first decoded by the __player-cache__
    feature, and then given to the kernel module in a pre-encoded format for
    quick playback. Defaults to 128.

    Both player slots and media slots are shared among all instances of
    *rtpengine* (using different kernel table IDs) running on a system using
    the same kernel module. Unused slots use minimal resources.

- __\-\-preload-media-files=__*FILE*

    Enables reading of media files at startup and caching them in memory for
    playback. Multiple files can be specified. On the command line, the option
    must be given multiple times to do so, while in the config file the option
    must be given only once, with the list of files separated by semicolons.

    All listed files will be read into memory at startup and cached there for
    the lifetime of the daemon. When playback of one such media file is
    requested, playback will be done from the cached contents instead of
    opening and reading the file. The file name given in the `play media`
    request must exactly match the file name given in the config option. If the
    file name differs (or an entirely different file is requested for playback)
    then playback will happen from file as usual.

    The special string `on-demand` can be used instead of a file name to enable
    on-demand loading and caching of media files. Any file requested for
    playback that wasn't already present in the memory cache will then be read
    only once and then retained in the cache for the lifetime of the daemon.

- __\-\-media-files-reload=__*SECONDS*

    Spawn a background thread to periodically check and, if needed, update
    media files kept in the memory cache. Each file's modification timestamp is
    checked against the last time it was read, and if the file was updated
    since then, it will be re-read and will replace the previous cached
    contents.

- __\-\-preload-db-media=__*INT*

    Similar to the __preload-media-files__ option, but preloads media from
    database instead of reading them from files. Each entry must be an integer
    corresponding to an index from the database. On-demand loading is also
    supported by supplying the special string `on-demand` instead of an index
    number.

- __\-\-db-media-reload=__*SECONDS*

    Similar to the __media-files-reload__ but applicable to media loaded from
    database. Note that media stored in a database doesn't have a modification
    timestamp, which means that all media will always be reloaded from the
    database in the given interval.

- __\-\-db-media-cache=__*PATH*

    Enables filesystem-backed caching of media entries from the database. The
    given path must be readable and writeable by *rtpengine*.

    Whenever playback of media from the database is requested, *rtpengine*
    first checks if a corresponding cached file within the given path exists.
    If it exists, media will be read from that file instead of from the
    database. If it doesn't exist, media will be read from the database, and
    then *rtpengine* will create the cache file for the next time the same
    media is requested.

- __\-\-preload-db-cache=__*INT*

    Similar to __preload-db-media__ but populates the filesystem-backed cache
    instead of storing the media in memory. On-demand loading is also
    supported.

- __\-\-cache-media-reload=__*SECONDS*

    Similar to the __db-media-reload__ but applicable to media stored in the
    filesystem-backed cache.

- __\-\-expiry-timer=__*SECONDS*
- __\-\-media-files-expire=__*SECONDS*
- __\-\-db-media-expire=__*SECONDS*
- __\-\-db-cache-expire=__*SECONDS*

    These options control the automatic removal of entries from the various
    media caches when and if the entries go unused for a certain amount of
    time. By default automatic removal is disabled.

    The option `expiry-timer` must be set to non-zero for any automatic removal
    to happen. It enables creation of a background thread and controls how
    often this thread should run to check for expired unused cache entries.

    The other options set the maximum allowed age for entries in the respective
    caches. If an entry was not used for longer than the given time, it will be
    removed from the cache.

- __\-\-audio-buffer-length=__*INT*

    Set the buffer length used by the audio player (see below) in milliseconds. The
    default is 500 milliseconds.

    The buffer must be long enough to accommodate at least two frames of audio from
    all contributing sources, which means at least 40 ms or 60 ms for most cases.
    If media playback (via the __play media__) command is desired, then the buffer
    must be able to accommodate at least one full frame from the source media file,
    whose length can vary depending on the format of the source media file. For 8
    kHz __.wav__ files this is 256 ms (2048 samples). Therefore 500 ms is the
    recommended value.

- __\-\-audio-buffer-delay=__*INT*

    Initial delay for new sources contributing to an audio buffer (used by the
    audio player, see below) in milliseconds. The default is 5 ms.

    The initial delay is meant to compensate for varying inter-arrival times of
    media packets (jitter). If set too low, intermittent high jitter will result in
    gaps in the output audio. If set too high, output audio will have an
    unnecessary latency added to it.

- __\-\-audio-player=on-demand__\|__play-media__\|__transcoding__\|__always__

    Define when to enable the audio player if not explicitly instructed otherwise.
    The default setting is __on-demand__.

    Enabling the audio player for a party to a call makes __rtpengine__ produce its
    own audio RTP stream (instead of just forwarding an audio stream received from
    elsewhere). The audio is generated from a circular audio buffer (see above) and
    all contributing audio sources are mixed into that one audio buffer.
    Contributing audio sources are audio streams received from elsewhere (that
    would otherwise simply be forwarded) and audio produced by the __play media__
    command.

    With this set to __on-demand__, the audio player is enabled only if explicitly
    requested by the user for a particular call via the __audio-player=__ option
    used in a signalling message.

    When set to __play-media__, the audio player is enabled only while media
    playback via the __play media__ command is active. After media playback is
    finished, the audio player is again disabled and audio goes back to simply
    being forwarded.

    Setting this option to __transcoding__ leaves the audio player disabled unless
    any sort of transcoding is required for a call.

    With a setting of __always__, the audio player is enabled for all calls, unless
    explicitly disabled via the __audio-player=__ option used in a signalling
    message. This forces all audio through the transcoding engine, even if input
    and output codecs are the same.

    Audio player usage can be changed on a call-by-call basis by including the
    __audio-player=__ option in a signalling message. This option supports the
    values __transcoding__ and __always__, which result in the behaviour described
    just above, and __off__ which forces the audio player to be disabled regardless
    of this setting.

- __\-\-poller-per-thread__

    Enable 'poller per thread' functionality: for every worker thread (see the
    \-\-num-threads option) a poller will be created. With this option on, it is
    guaranteed that only a single thread will ever read from a particular socket,
    thus maintaining the order of the packets. Might help when having issues with
    DTMF packets (RFC 2833).

- __\-\-io-uring__

    Enable **experimental** support for `io_uring`. Requires Linux kernel 6.0
    or later.

    When enabled, instead of the usual polling mechanism each worker thread
    will set up its own `io_uring` and use it for polling, as well as directly
    sending and receiving certain network data. In particular userspace media
    data is sent and received directly via `io_uring`.

    _NOTE: As of the time of writing, worker threads sleeping in an `io_uring`
    poll are attributed to the host system as _I/O wait_ CPU usage, with up to
    99% CPU time spent in _I/O wait_ (depending on the number of worker
    threads), but without being attributed to any process or thread. This is
    not actual CPU usage but rather indicates time spent waiting for a network
    event, and so should be considered the same as idle CPU time._

- __\-\-io-uring-buffers=__*INT*

    Number of `io_uring` entries in the buffer allocated from the kernel per
    thread. Defaults to 16384. Must be large enough so that submission entries
    and completion entries are always available when needed.

- __\-\-dtls-cert-cipher=prime256v1__\|__RSA__

    Choose the type of key to use for the signature used by the self-signed
    certificate used for DTLS. The previous default was __RSA__. The current default
    and the only other option is __prime256v1__ which is a 256-bit elliptic-curve
    key.

- __\-\-dtls-signature=SHA-256__\|__SHA-1__

    Choose the hash algorithm to use for the signature used by the self-signed
    certificate used for DTLS. The default is __SHA-256__. Not to be confused with
    the hash algorithm used for the certificate fingerprint inserted into the SDP
    (__a=fingerprint:__), which is independent of the certificate's signature and
    can be selected during runtime.

- __\-\-dtls-rsa-key-size=__*INT*

    Size in bits of the RSA key used by the DTLS certificate, if RSA is in use.
    Default is 2048 bits.

- __\-\-dtls-ciphers=__*STRING*

    Ciphers allowed during the DTLS key exchange (not to be confused with the
    cipher used by the DTLS certificate). The format of this string is an OpenSSL
    cipher list. The default is
    __DEFAULT:!NULL:!aNULL:!SHA256:!SHA384:!aECDH:!AESGCM+AES256:!aPSK__

- __\-\-dtls-mtu=__*INT*

    Set DTLS MTU to enable fragmenting of large DTLS packets. Defaults to 1200.
    Minimum value is 576 as the internet protocol requires that hosts must be able to
    process IP datagrams of at least 576 bytes (for IPv4) or 1280 bytes (for IPv6).
    This does not preclude link layers with an MTU smaller than this minimum MTU from
    conveying IP data. Internet IPv4 path MTU is 68 bytes.

- __\-\-mqtt-host=__*HOST*\|*IP*

    Host or IP address of the Mosquitto broker to connect to. Must be set to enable
    exporting stats to Mosquitto.

- __\-\-mqtt-port=__*INT*

    Port of the Mosquitto broker. Defaults to 1883.

- __\-\-mqtt-id=__*STRING*

    Client ID to use for Mosquitto. Default is a generated random string.

- __\-\-mqtt-keepalive=__*INT*

    Keepalive interval in seconds. Defaults to 30.

- __\-\-mqtt-user=__*USERNAME*
- __\-\-mqtt-pass=__*PASSWORD*

    Credentials to connect to Mosquitto broker. At least a username must be given
    to enable authentication.

- __\-\-mqtt-cafile=__*FILE*
- __\-\-mqtt-capath=__*PATH*
- __\-\-mqtt-certfile=__*FILE*
- __\-\-mqtt-keyfile=__*FILE*
- __\-\-mqtt-tls-alpn=__*STRING*

    Enable TLS to connect to Mosquitto broker, optionally with client certificate
    authentication. At least __cafile__ or __capath__ must be given to enable TLS. To
    enable client certificate authentication, both __certfile__ and __keyfile__ must
    be set. All files must be in PEM format. Password-proteted files are not
    supported. The __tls-alpn__ can be set (e.g. mqtt) if a service like AWS IoT
    Core shares the same TLS port for two different network protocols.

- __\-\-mqtt-publish-qos=0__\|__1__\|__2__

    QoS value to use for publishing to Mosquitto. See Mosquitto docs for details.

- __\-\-mqtt-publish-topic=__*STRING*

    Topic string to use for publishing to Mosquitto. Must be set to a non-empty
    string.

- __\-\-mqtt-publish-interval=__*MILLISECONDS*

    Interval in milliseconds to publish to Mosquitto. Defaults to 5000 (5 seconds).

- __\-\-mqtt-publish-scope=global__\|__summary__\|__call__\|__media__

    When set to __summary__, one message will be published to Mosquitto every
    *interval* milliseconds containing all global stats. A setting of __global__
    has the same effect as __summary__ but will also contain a list of all running
    calls with stats for each call. When set to __call__, one message per call will
    be published to Mosquitto with stats for that call every *interval*
    milliseconds, plus one message every *interval* milliseconds with global
    stats. When set to __media__, one message per call media (usually one media per
    call participant, so usually 2 media per call) will be published to Mosquitto
    with stats for that call media every *interval* milliseconds, plus one message
    every *interval* milliseconds with global stats.

- __\-\-mos=CQ__\|__LQ__\|__G.107__\|__G.107.2__\|__legacy__

    Options influencing the MOS (Mean Opinion Score) calculation formula.
    Multiple options can be listed, using multiple __\-\-mos=...__ arguments at
    the command line, or using a semicolon-separated list in a single
    __mos=...__ line in the config file.

    __CQ__ and __LQ__ are mutually exclusive and only one of them can be in
    effect. Defaults to __CQ__ (conversational quality) which takes RTT into
    account and therefore requires peers to correctly send RTCP. If set to
    __LQ__ (listening quality) RTT is ignored, allowing a MOS to be calculated
    in the absence of RTCP.

    The remaining options select a MOS formula and are mutually exclusive. The
    default is __G.107__, which uses a simplified version of the G.107 formula.
    The previous default (and only option) was __legacy__, which uses a custom
    formula which yields slightly higher MOS values than G.107.

    The option __G.107.2__ uses G.107.2 for fullband audio codecs and the
    simplified G.107 formula for all other audio codecs. The full G.107.2
    formula is somewhat math-heavy and yields higher MOS values for fullband
    audio codecs compared to G.107.

- __\-\-measure-rtp__

    Enable measuring RTP metrics even for plain RTP passthrough scenarios. Without
    that option, RTP metrics are measured only in transcoding scenarios.

- __\-\-rtcp-interval=__*INT*

    Delay in milliseconds between RTCP packets when generate-rtcp flag is on. The
    effective value includes the random dispersion between 0..1 seconds on top,
    so the timer execution period is randomized and up to 1 sec greater than given
    value in ms. Defaults to __5000__ ms (5 seconds).

- __\-\-socket-cpu-affinity=__*INT*

    Enables setting the socket CPU affinity via the __SO\*INCOMING\*CPU__ socket
    option if available. The default value is zero which disables this feature. If
    set to a positive number then the CPU affinity for all sockets belonging to the
    same call will be set to the same value. The number specifies the upper limit
    of the affinity to be set, and values will be used in a round-robin fashion
    (e.g. if set to __8__ then the values __0__ through __7__ will be used to set the
    affinity). If this option is set to a negative number, then the number of
    available CPU cores will be used.

## INTERFACES

The command-line options __-i__ or __\-\-interface__, or equivalently the
__interface__ config file option, specify local network interfaces for RTP.
At least one must be given, but multiple can be specified.
The format of the value is \[*NAME*/\]*IP*\[!*IP*\] with *IP* being
either an IPv4 address, an IPv6 address, the name of a system network interface
(such as *eth0*), a DNS host name (such as *test.example.com*), or __any__.

The possibility of configuring a network interface by name rather than
by address should not be confused with the logical interface name used
internally by __rtpengine__ (as described below).
The *NAME* token in the syntax above refers to the internal logical
interface name, while the name of a system network interface is used
in place of the first *IP* token in the syntax above.
For example, to configure a logical network interface called *int*
using all the addresses from the existing system network interface
*eth0*, you would use the syntax *int/eth0*.
(Unless omitted, the second *IP* token used for the advertised address
must be an actual network address and cannot be an interface name.)

If DNS host names are used instead of addresses or interface names, the lookup
will be done only once during daemon start-up.

The special keyword __any__ can be used to listen on any and all available local
interface addresses except from loopback devices. This keyword should only be
given once in place of a more explicit interface configuration.

To configure multiple interfaces using the command-line options,
simply present multiple __-i__ or __\-\-interface__ options.
When using the config file, only use a single __interface__ line,
but specify multiple values separated by semicolons (e.g.
*interface = internal/12.23.34.45;external/23.34.45.54*).

### System Network Interfaces

If an interface option is given using a system interface name in place
of a network address, and if multiple network address are found
configured on that network interface, then __rtpengine__ behaves as
if multiple __\-\-interface__ options had been specified.
For example, if interface *eth0* exists with both addresses
*192.168.1.120* and *2001:db8:85a3::7334* configured on it, and if
the option *\-\-interface=ext/eth0* is given, then __rtpengine__ would
behave as if both options *\-\-interface=ext/192.168.1.120* and
*\-\-interface=ext/2001:db8:85a3::7334* had been specified.

### Advertised Address

The second IP address after the exclamation point is optional and can
be used if the address to advertise in outgoing SDP bodies should be
different from the actual local address.
This can be useful in certain cases, such as your SIP proxy being behind NAT.
For example, *\-\-interface=10.65.76.2!192.0.2.4* means that *10.65.76.2*
is the actual local address on the server, but outgoing SDP bodies should
advertise *192.0.2.4* as the address that endpoints should talk to.
Note that you may have to escape the exclamation point from your shell
when using command-line options, e.g. using *\\!*.

### Interface Names

Giving an interface a name (separated from the address by a slash) is
optional; if omitted, the name __default__ is used.
Names are useful to create logical interfaces which consist of one or
more local addresses.
It is then possible to instruct __rtpengine__ to use particular interfaces
when processing an SDP message, to use different local addresses when
talking to different endpoints.
The most common use case for this is to bridge between one or more
private IP networks and the public internet.

For example, if clients coming from a private IP network must communicate
their RTP with the local address *10.35.2.75*, while clients coming from
the public internet must communicate with your other local address
*192.0.2.67*, you could create one logical interface *pub* and a second
one *priv* by using *\-\-interface=pub/192.0.2.67 \-\-interface=priv/10.35.2.75*.
You can then use the __direction__ option to tell __rtpengine__ which local
address to use for which endpoints (either *pub* or *priv*).

If multiple logical interfaces are configured, but the __direction__
option is not given in a particular call, then the first interface
given on the command line will be used.

### Multiple Addresses per Interface

It is possible to specify multiple addresses for the same logical
interface (the same name).
Most commonly this would be one IPv4 addrsess and one IPv6 address,
for example: *\-\-interface=192.168.63.1 \-\-interface=fe80::800:27ff:fe00:0*.
In this example, no interface name is given, therefore both addresses
will be added to a logical interface named __default__.
You would use the __address family__ option to tell __rtpengine__ which
address to use in a particular case.

It is also possible to have multiple addresses of the same family in a
logical network interface.
In this case, the first address (of a particular family) given for an
interface will be the primary address used by __rtpengine__ for most
purposes.
Any additional addresses will be advertised as additional ICE candidates
with increasingly lower priority.
This is useful on multi-homed systems and allows endpoints to choose the
best possible path to reach the RTP proxy.
If ICE is not being used, then additional addresses will go unused,
even though ports would still get allocated on those interfaces.

### Round-Robin Address Selection

Another option is to give interface names in the format *BASE:SUFFIX*.
This allows interfaces to be used in a round-robin fashion, useful
for load-balancing the port ranges of multiple interfaces.
For example, consider the following configuration:
*\-\-interface=pub:1/192.0.2.67 \-\-interface=pub:2/10.35.2.75*.
These two interfaces can still be referenced directly by name (e.g.
*direction=pub:1*), but it is now also possible to reference only
the base name (i.e. *direction=pub*).
If the base name is used, one of the two interfaces is selected in a
round-robin fashion, and only if the interface actually has enough
open ports available.
This makes it possible to effectively increase the number of available
media ports across multiple IP addresses.
There is no limit on how many interfaces can share the same base name.

It is possible to combine the *BASE:SUFFIX* notation with specifying
multiple addresses for the same interface name.
An advanced example could be (using config file notation, and omitting
actual network addresses):

    interface = pub:1/IPv4;pub:1/IPv4;pub:1/IPv6;pub:2/IPv4;pub:2/IPv6;pub:3/IPv6;pub:4/IPv4

In this example, when *direction=pub* is IPv4 is needed as a primary
address, either *pub:1*, *pub:2*, or *pub:4* might be selected.
When *pub:1* is selected, one IPv4 and one IPv6 address will be used
as additional ICE alternatives.
For *pub:2*, only one IPv6 is used as ICE alternative, and for *pub:4*
no alternatives would be used.
When IPv6 is needed as a primary address, either *pub:1*, *pub:2*, or
*pub:3* might be selected.
If at any given time not enough ports are available on any interface,
it will not be selected by the round-robin algorithm.

It is possible to use the round-robin algorithm even if the __direction__
is not given.
If the first given interface has the *BASE:SUFFIX* format then the
round-robin algorithm is used and will select interfaces with the
same *BASE* name.

### Alias Names

Interface alias names can be created using the *ALIAS=NAME* syntax. The alias
must be listed after the primary interface that it references. For example, to
create an actual logical interface *pub1* and then an alias *pub* for that
interface:

    interface = pub1/IPv4;pub=pub1

Interface aliases are useful in combination with Redis replication. If an
interface is referred to via an alias name (e.g. *direction=pub*), then the
interface's actual name (*pub1* in this example) is propagated into the Redis
storage and thus to any dependent standby instances. These standby instances
can then have different address configurations for that interface, which makes
it possible to facilitate failover with static addressing (for example behind
an IP load balancer).

### Legacy Protocols

If you are not using the NG protocol but rather the legacy UDP protocol
used by the __rtpproxy__ module, the interfaces must be named __internal__
and __external__ corresponding to the __i__ and __e__ flags if you wish to
use network bridging in this mode.

## SIGNALLING TEMPLATES

Since much of the behaviour of *rtpengine* is controlled by flags and
keys/values given to it during runtime as part of the signalling control
protocol that is used for communication between the controlling agent (e.g. a
SIP proxy) and the *rtpengine* process, there often is a need to repeatedly
give the same set of default flags and values to *rtpengine* for each message
sent to it. This can lead to controlling scripts that are hard to maintain or
hard to read. To alleviate this problem, *rtpengine* supports signalling
templates that can be configured in its main configuration file and can then be
referred to by short names.

To use this feature, a configuration file must be in use (by default
`/etc/rtpengine/rtpengine.conf`) and the configuration key __templates=...__
must be set to a non-empty string. The value gives the name of the section in
the configuration file to contain signalling templates. For example, if the
value is set to __templates=templates__, then the section __[templates]__ will
be used to read signalling templates.

Each key/value in this file section then corresponds to one signalling
template, and can be referred to via __template=...__ in any control message.

For example, in order to make an offer to a WebRTC-compliant client, a Kamailio
or OpenSIPS script may have used:

    rtpengine_offer("transport-protocol=UDP/TLS/RTP/SAVPF ICE=force trickle-ICE rtcp-mux=[offer require] no-rtcp-attribute SDES=off generate-mid");

This entire string of flags can now be converted into a signalling template in
the config file as such:

    [rtpengine]
    ...
    templates = templates
    ...

    [templates]
    WebRTC = transport-protocol=UDP/TLS/RTP/SAVPF ICE=force trickle-ICE rtcp-mux=[offer require] no-rtcp-attribute SDES=off generate-mid

The __offer__ command in Kamailio or OpenSIPS can then simply be turned into:

    rtpengine_offer("template=WebRTC");

In addition to named signalling templates, *rtpengine* supports default
signalling templates that are automatically applied. Default signalling
templates are templates using a name that matches a signalling command (e.g.
__offer__ or __start recording__), or the special name __default__ which is a
template that is applied to all signalling messages. These templates are
automatically applied without needing to refer to them by name using
__template=...__ from within the signalling message.

## EXIT STATUS

- __0__

    Successful termination.

- __1__

    An error occurred.

## ENVIRONMENT

- __RTPENGINE\_REDIS\_AUTH\_PW__

    Redis server password for persistent state storage.

- __RTPENGINE\_REDIS\_WRITE\_AUTH\_PW__

    Redis server password for write operations, if __\-\-redis__ has been
    specified, in which case the one specified in __\-\-redis__ will be used for
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
