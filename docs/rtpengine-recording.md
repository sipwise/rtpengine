---
title: rtpengine-recording
section: 8
header: NGCP rtpengine-recording
---

# rtpengine-recording(8) manual page

## NAME

rtpengine-recording - media recording daemon for Sipwise rtpengine

## SYNOPSIS

__rtpengine-recording__ \[*option*...\]

## DESCRIPTION

The Sipwise rtpengine media proxy has support for exporting media (RTP) packets
that it forwards. The rtpengine-recording daemon collects these exported
packets and decodes them into an audio format that can be listened to.

## OPTIONS

All options can (and should) be provided in a config file instead of
at the command line. See the __\-\-config-file__ option below for details.

If no options are given, then default values are assumed, which should be
sufficient for a standard installation of rtpengine.

- __\-\-help__

    Print the usage information.

- __-v__, __\-\-version__

    If called with this option, the __rtpengine-recording__ daemon will simply print
    its version number and exit.

- __\-\-config-file=__*FILE*

    Specifies the location of a config file to be used. The config file is an
    *.ini* style config file, with all command-line options listed here also
    being valid options in the config file.
    For all command-line options, the long name version instead of the
    single-character version (e.g. __table__ instead of just __t__) must be
    used in the config file.
    For boolean options that are either present or not (e.g. __output-mixed__), a
    boolean value (either __true__ or __false__) must be used in the config file.
    If an option is given in both the config file and at the command line,
    the command-line value overrides the value from the config file.

    As a special value, __none__ can be passed here to suppress loading of the
    default config file.

- __\-\-config-section=__*STRING*

    Specifies the *.ini* style section to be used in the config file.
    Multiple sections can be present in the config file, but only one can be
    used at a time.
    The default value is __rtpengine-recording__.
    A config file section is started in the config file using square brackets
    (e.g. __\[rtpengine-recording\]__).

- __-L__, __\-\-log-level=__*INT*

    Takes an integer as argument and controls the highest log level which
    will be sent to syslog.
    The log levels correspond to the ones found in the [syslog(3)](http://man.he.net/man3/syslog) man page.
    The default value is __6__, equivalent to LOG\_INFO.
    The highest possible value is __7__ (LOG\_DEBUG) which will log everything.

- __\-\-log-facilty=daemon__\|__local0__\|...\|__local7__\|...

    The syslog facilty to use when sending log messages to the syslog daemon.
    Defaults to __daemon__.

- __-E__, __\-\-log-stderr__

    Log to stderr instead of syslog.
    Only useful in combination with __\-\-foreground__.

- __\-\-split-logs__

    Split multi-line log messages into individual log messages so that each
    line receives its own log line prefix.

- __\-\-no-log-timestamps__

    Don't add timestamps to log lines written to stderr.
    Only useful in combination with __\-\-log-stderr__.

- __\-\-log-mark-prefix=__*STRING*

    Prefix to be added to particular data fields in log files that are deemed
    sensitive and/or private information. Defaults to an empty string.

- __\-\-log-mark-suffix=__*STRING*

    Suffix to be added to particular data fields in log files that are deemed
    sensitive and/or private information. Defaults to an empty string.

- __-p__, __\-\-pidfile=__*FILE*

    Specifies a path and file name to write the daemon's PID number to.

- __-f__, __\-\-foreground__

    If given, prevents the daemon from daemonizing, meaning it will stay in
    the foreground.
    Useful for debugging.

- __-t__, __\-\-table=__*INT*

    Takes an integer argument. The value must match the __table__ option given to
    the __rtpengine__ media proxy to use for in-kernel packet forwarding.
    Defaults to __0__ if not specified.

- __\-\-spool-dir=__*PATH*

    The path given here must match the __recording-dir__ path given to the
    __rtpengine__ media proxy. Defaults to `/var/spool/rtpengine`. The path must
    reside on a file system that supports the __inotify__ mechanism.

- __\-\-num-threads=__*INT*

    How many worker threads to launch. Defaults to the number of CPU cores
    available, or __8__ if there are fewer than that or if the number is not
    known.

- __\-\-thread-stack=__*INT*

    Set the stack size of each thread to the value given in kB. Defaults to 2048
    kB. Can be set to -1 to leave the default provided by the OS unchanged.

- __\-\-evs-lib-path=__*FILE*

    Points to the shared object file (__.so__) containing the reference
    implementation for the EVS codec. See the `README` for more details.

- __\-\-output-storage=file__\|__db__\|__both__

    Where to store media files. By default, media files are written directly to the
    file system (see __output-dir__). They can also be stored as a __BLOB__ in a
    MySQL database, either instead of, or in addition to, being written to the file
    system.

- __\-\-output-dir=__*PATH*

    Path for media files to be written to if file output is enabled. Defaults to
    `/var/lib/rtpengine-recording`. The path must not be the same as used for the
    __spool-dir__.

- __\-\-output-pattern=__*STRING*

    File name pattern to be used for recording files. The pattern can reference
    sub-directories. Parent directories will be created on demand. The default
    setting is __%c-%r-%t__.

    The pattern must include __printf__-style format sequences. Supported format
    sequences are:

    - __%%__

        A literal percent sign.

    - __%c__

        The call ID. It is mandatory for the output pattern to include this format
        sequence.

    - __%r__

        A random tag generated by __rtpengine__ to distinguish possibly
        repeated or duplicated call IDs.

    - __%t__

        The stream type. For __single__ streams this is the SSRC written as hexadecimal;
        for __mix__ stream this is the string __mix__. It is mandatory for the output
        pattern to include this format sequence.

    - __%l__

        The label for the participating party as communicated from the controlling
        daemon.

    - __%Y__
    - __%m__
    - __%d__
    - __%H__
    - __%M__
    - __%S__

        These format sequence reference the current system time (when the output file
        was created) and are the same as the format sequences supported by [date(1)](http://man.he.net/man1/date)
        or [strftime(3)](http://man.he.net/man3/strftime) (year, month, day, hours, minutes, and seconds,
        respectively).

    - __%u__

        Microseconds, expanded to 6 digits (__000000__ through __999999__).

    - __%__*INT*

        References a prefix from the call ID of the given length. If this format
        sequence is present more than once, then the prefixes are cumulative. For
        example, if the call ID is __abcdefgh__ and the output pattern is configured as
        __%2/%3/%c__, then the resulting output file name would be __ab/cde/abcdefgh__.

    - __%{__

        Take the string between the enclosing opening and closing brace
        (between this __{__ and the next __}__) and use it as a key to look up
        a corresponding value in the metadata string provided by *rtpengine*.
        The metadata string must be given as a pipe (__|__) separated list of
        `key:value` pairs, as described in the *rtpengine* documentation.

        Example: If the metadata string is given as __foo:bar|blah:baz__ and
        the pattern includes the format __%{foo}__ then __bar__ will be
        inserted into the file name at that position.

- __\-\-output-format=wav__\|__mp3__\|__none__

    File format to be used for media files that are produced. Defaults to PCM WAV
    (RIFF) files. Applicable for both files stored on the file system and in a
    database. If __none__ is selected then file output is disabled.

- __\-\-resample-to=__*INT*

    Resample all audio to the given sample rate (e.g. __48000__). Resampling is
    disabled by default, meaning that files will be written with the same sample
    rate as the source media.

- __\-\-mp3-bitrate=__*INT*

    If MP3 output is selected, use the given bitrate for the MP3 encoder (e.g.
    __64000__). There is no default value, so this option must be given if MP3
    output is selected. Note that not all bitrates are valid in combinations with
    all sample rates. For MP3 output it's therefore recommended to also set
    __resample-to__.

- __\-\-output-mixed__
- __\-\-output-single__

    Whether to produce __mixed__ audio files, or __single__ audio files, or both. If
    neither option is given, then by default both are enabled. If no file output is
    desired, set __output-format__ to __none__.

    A __single__ audio file contains the audio for a single RTP SSRC, which usually
    means an unidirectional audio stream. These are decoded directly from an RTP
    stream and do not take timestamping into account, meaning that gaps or pauses
    in the RTP stream are not reflected in the output audio file.

    A __mixed__ audio file consists of the first four RTP SSRC seen, mixed together
    into a single output file, which usually means that a bidirectional audio
    stream is produced. Audio mixing takes RTP timestamping into account, so gaps
    and pauses in the RTP media are reflected in the output audio to keep the
    multiple audio sources in sync.

- __\-\-mix-method=direct__\|__channels__

    Selects a method to mix multiple audio inputs into a single output file for
    __mixed__ output. The default is __direct__ which directly mixes all audio inputs
    together, producing a mixed output file with the same format as an audio file
    from a single input (__output-single__) would be.

    The __channels__ mixing method puts each audio input into its own audio channel
    in the output file, therefore producing a multi-channel output file. Up to four
    separate RTP SSRCs are supported for a mixed output, which means that if each
    input is mono audio, then the mixed output file would contain 4 audio channels.
    This mixing method requires an output file format which supports these kinds of
    multi-channel audio formats (e.g. __wav__).

- __\-\-mix-num-inputs=__*INT*

    Change the number of recording channel in the output file. The value is between 1 to 4 (e.g. __4__, which is also the default value).

- __\-\-output-chmod=__*INT*

    Change the file permissions of recording files to the given mode. Must be given
    as an octal integer, for example __0660__.

- __\-\-output-chmod-dir=__*INT*

    Change the file permissions of recording files to the given mode. Must be given
    as an octal integer, for example __0700__ (which is also the default value).

- __\-\-output-chown=__*USER*\|*UID*
- __\-\-output-chgrp=__*GROUP*\|*GID*

    Change the ownership of recording files. Either user/group names or numeric IDs
    are supported. If the value is blank or given as __-1__ then the user/group is
    left unchanged.

- __\-\-mysql-host=__*HOST*\|*IP*
- __\-\-mysql-port=__*INT*
- __\-\-mysql-user=__*USERNAME*
- __\-\-mysql-pass=__*PASSWORD*
- __\-\-mysql-db=__*STRING*

    Configuration for a MySQL storage backend. Details about calls and media files
    that are produced are stored into the database. Optionally the media files
    themselves can be stored as well (see __output-storage__).

- __\-\-forward-to=__*PATH*

    Forward raw RTP packets to a Unix socket. Disabled by default.

- __\-\-tcp-send-to=__*IP*:*PORT*
- __\-\-tcp-resample=__*INT*
- __\-\-tls-send-to=__*IP*:*PORT*
- __\-\-tls-resample=__*INT*

    Send decoded audio over a TCP or TLS connection to the specified destination.
    Audio is sent as raw mono 16-bit PCM in the given sample rate.

    Only one of these option combinations (TCP or TLS) can be active at the
    same time.

- __\-\-notify-uri=__*URI*

    Enable HTTP notification about finished recordings to the specified URI, which
    must be an HTTP or HTTPS URI. Information about the finished recording is
    provided via custom HTTP headers, all of which use a prefix of __X-Recording-__.

- __\-\-notify-post__

    Use HTTP POST instead of GET for the HTTP notification requests. The request
    body is empty even if POST is used.

- __\-\-notify-no-verify__

    Disable TLS peer certificate verification for HTTPS requests.

- __\-\-notify-concurrency=__*INT*

    The maximum number of HTTP requests to perform simultaneously.

- __\-\-notify-retries=__*INT*

    How many times to retry a failed HTTP notification before giving up. An
    exponential falloff time is used for each subsequent attempt, starting with 5
    seconds.

- __\-\-notify-record__

    Attach recorded file to HTTP notification request. If enabled, notification
    request behaves as HTTP POST (ignoring __\-\-notify-post__). Note that this option
    is incompatible with DB-only storage as no recording file exists on storage
    (see __output-storage__).

- __\-\-notify-purge__

    Remove the local file if the HTTP request was successful. Note that this
    option is only useful if __\-\-notify-record__ is also enabled.

- __\-\-output-mixed-per-media__

    Forces one channel per media instead of SSRC. Note that this
    option is only useful if __\-\-output-mixed__ is also enabled.

- __\-\-flush-packets__

    Forces that the output buffer will be flushed after every packet, ensuring that the recording file grows steadily and becomes available for processing without delays.
## EXIT STATUS

- __0__

    Successful termination.

- __1__

    An error occurred.

## FILES

- `/etc/rtpengine/rtpengine-recording.conf`

    Configuration file.

## SEE ALSO

[rtpengine(8)](http://man.he.net/man8/rtpengine).
