rtpengine-recording(8) - media recording daemon for Sipwise rtpengine
==========================================

## SYNOPSIS

**rtpengine-recording** \[_option_...\]

## DESCRIPTION

The Sipwise rtpengine media proxy has support for exporting media (RTP) packets
that it forwards. The rtpengine-recording daemon collects these exported
packets and decodes them into an audio format that can be listened to.

## OPTIONS

All options can (and should) be provided in a config file instead of
at the command line. See the **--config-file** option below for details.

If no options are given, then default values are assumed, which should be
sufficient for a standard installation of rtpengine.

- **--help**

    Print the usage information.

- **-v**, **--version**

    If called with this option, the **rtpengine-recording** daemon will simply print
    its version number and exit.

- **--config-file=**_FILE_

    Specifies the location of a config file to be used. The config file is an
    _.ini_ style config file, with all command-line options listed here also
    being valid options in the config file.
    For all command-line options, the long name version instead of the
    single-character version (e.g. **table** instead of just **t**) must be
    used in the config file.
    For boolean options that are either present or not (e.g. **output-mixed**), a
    boolean value (either **true** or **false**) must be used in the config file.
    If an option is given in both the config file and at the command line,
    the command-line value overrides the value from the config file.

    As a special value, **none** can be passed here to suppress loading of the
    default config file.

- **--config-section=**_STRING_

    Specifies the _.ini_ style section to be used in the config file.
    Multiple sections can be present in the config file, but only one can be
    used at a time.
    The default value is **rtpengine-recording**.
    A config file section is started in the config file using square brackets
    (e.g. **\[rtpengine-recording\]**).

- **-L**, **--log-level=**_INT_

    Takes an integer as argument and controls the highest log level which
    will be sent to syslog.
    The log levels correspond to the ones found in the [syslog(3)](http://man.he.net/man3/syslog) man page.
    The default value is **6**, equivalent to LOG\_INFO.
    The highest possible value is **7** (LOG\_DEBUG) which will log everything.

- **--log-facilty=****daemon**\|**local0**\|...\|**local7**\|...

    The syslog facilty to use when sending log messages to the syslog daemon.
    Defaults to **daemon**.

- **-E**, **--log-stderr**

    Log to stderr instead of syslog.
    Only useful in combination with **--foreground**.

- **--split-logs**

    Split multi-line log messages into individual log messages so that each
    line receives its own log line prefix.

- **--no-log-timestamps**

    Don't add timestamps to log lines written to stderr.
    Only useful in combination with **--log-stderr**.

- **--log-mark-prefix=**_STRING_

    Prefix to be added to particular data fields in log files that are deemed
    sensitive and/or private information. Defaults to an empty string.

- **--log-mark-suffix=**_STRING_

    Suffix to be added to particular data fields in log files that are deemed
    sensitive and/or private information. Defaults to an empty string.

- **-p**, **--pidfile=**_FILE_

    Specifies a path and file name to write the daemon's PID number to.

- **-f**, **--foreground**

    If given, prevents the daemon from daemonizing, meaning it will stay in
    the foreground.
    Useful for debugging.

- **-t**, **--table=**_INT_

    Takes an integer argument. The value must match the **table** option given to
    the **rtpengine** media proxy to use for in-kernel packet forwarding.
    Defaults to **0** if not specified.

- **--spool-dir=**_PATH_

    The path given here must match the **recording-dir** path given to the
    **rtpengine** media proxy. Defaults to `/var/spool/rtpengine`. The path must
    reside on a file system that supports the **inotify** mechanism.

- **--num-threads=**_INT_

    How many worker threads to launch. Defaults to the number of CPU cores
    available, or **8** if there are fewer than that or if the number is not
    known.

- **--thread-stack=**_INT_

    Set the stack size of each thread to the value given in kB. Defaults to 2048
    kB. Can be set to -1 to leave the default provided by the OS unchanged.

- **--evs-lib-path=**_FILE_

    Points to the shared object file (**.so**) containing the reference
    implementation for the EVS codec. See the `README` for more details.

- **--output-storage=****file**\|**db**\|**both**

    Where to store media files. By default, media files are written directly to the
    file system (see **output-dir**). They can also be stored as a **BLOB** in a
    MySQL database, either instead of, or in addition to, being written to the file
    system.

- **--output-dir=**_PATH_

    Path for media files to be written to if file output is enabled. Defaults to
    `/var/lib/rtpengine-recording`. The path must not be the same as used for the
    **spool-dir**.

- **--output-pattern=**_STRING_

    File name pattern to be used for recording files. The pattern can reference
    sub-directories. Parent directories will be created on demand. The default
    setting is **%c-%t**.

    The pattern must include **printf**-style format sequences. Supported format
    sequences are:

    - **%%**

        A literal percent sign.

    - **%c**

        The call ID. It is mandatory for the output pattern to include this format
        sequence.

    - **%t**

        The stream type. For **single** streams this is the SSRC written as hexadecimal;
        for **mix** stream this is the string **mix**. It is mandatory for the output
        pattern to include this format sequence.

    - **%l**

        The label for the participating party as communicated from the controlling
        daemon.

    - **%Y**
    - **%m**
    - **%d**
    - **%H**
    - **%M**
    - **%S**

        These format sequence reference the current system time (when the output file
        was created) and are the same as the format sequences supported by [date(1)](http://man.he.net/man1/date)
        or [strftime(3)](http://man.he.net/man3/strftime) (year, month, day, hours, minutes, and seconds,
        respectively).

    - **%u**

        Microseconds, expanded to 6 digits (**000000** through **999999**).

    - **%**_INT_

        References a prefix from the call ID of the given length. If this format
        sequence is present more than once, then the prefixes are cumulative. For
        example, if the call ID is **abcdefgh** and the output pattern is configured as
        **%2/%3/%c**, then the resulting output file name would be **ab/cde/abcdefgh**.

- **--output-format=****wav**\|**mp3**\|**none**

    File format to be used for media files that are produced. Defaults to PCM WAV
    (RIFF) files. Applicable for both files stored on the file system and in a
    database. If **none** is selected then file output is disabled.

- **--resample-to=**_INT_

    Resample all audio to the given sample rate (e.g. **48000**). Resampling is
    disabled by default, meaning that files will be written with the same sample
    rate as the source media.

- **--mp3-bitrate=**_INT_

    If MP3 output is selected, use the given bitrate for the MP3 encoder (e.g.
    **64000**). There is no default value, so this option must be given if MP3
    output is selected. Note that not all bitrates are valid in combinations with
    all sample rates. For MP3 output it's therefore recommended to also set
    **resample-to**.

- **--output-mixed**
- **--output-single**

    Whether to produce **mixed** audio files, or **single** audio files, or both. If
    neither option is given, then by default both are enabled. If no file output is
    desired, set **output-format** to **none**.

    A **single** audio file contains the audio for a single RTP SSRC, which usually
    means an unidirectional audio stream. These are decoded directly from an RTP
    stream and do not take timestamping into account, meaning that gaps or pauses
    in the RTP stream are not reflected in the output audio file.

    A **mixed** audio file consists of the first four RTP SSRC seen, mixed together
    into a single output file, which usually means that a bidirectional audio
    stream is produced. Audio mixing takes RTP timestamping into account, so gaps
    and pauses in the RTP media are reflected in the output audio to keep the
    multiple audio sources in sync.

- **--mix-method=****direct**\|**channels**

    Selects a method to mix multiple audio inputs into a single output file for
    **mixed** output. The default is **direct** which directly mixes all audio inputs
    together, producing a mixed output file with the same format as an audio file
    from a single input (**output-single**) would be.

    The **channels** mixing method puts each audio input into its own audio channel
    in the output file, therefore producing a multi-channel output file. Up to four
    separate RTP SSRCs are supported for a mixed output, which means that if each
    input is mono audio, then the mixed output file would contain 4 audio channels.
    This mixing method requires an output file format which supports these kinds of
    multi-channel audio formats (e.g. **wav**).

- **--mix-num-inputs=**_INT_

    Change the number of recording channel in the output file. The value is between 1 to 4 (e.g. **4**, which is also the default value).

- **--output-chmod=**_INT_

    Change the file permissions of recording files to the given mode. Must be given
    as an octal integer, for example **0660**.

- **--output-chmod-dir=**_INT_

    Change the file permissions of recording files to the given mode. Must be given
    as an octal integer, for example **0700** (which is also the default value).

- **--output-chown=**_USER_\|_UID_
- **--output-chgrp=**_GROUP_\|_GID_

    Change the ownership of recording files. Either user/group names or numeric IDs
    are supported. If the value is blank or given as **-1** then the user/group is
    left unchanged.

- **--mysql-host=**_HOST_\|_IP_
- **--mysql-port=**_INT_
- **--mysql-user=**_USERNAME_
- **--mysql-pass=**_PASSWORD_
- **--mysql-db=**_STRING_

    Configuration for a MySQL storage backend. Details about calls and media files
    that are produced are stored into the database. Optionally the media files
    themselves can be stored as well (see **output-storage**).

- **--forward-to=**_PATH_

    Forward raw RTP packets to a Unix socket. Disabled by default.

- **--tls-send-to=**_IP_**:**_PORT_
- **--tls-resample=**_INT_

    Send decoded audio over a TCP TLS connection to the specified destination.
    Audio is sent as raw mono 16-bit PCM in the given sample rate.

- **--notify-uri=**_URI_

    Enable HTTP notification about finished recordings to the specified URI, which
    must be an HTTP or HTTPS URI. Information about the finished recording is
    provided via custom HTTP headers, all of which use a prefix of **X-Recording-**.

- **--notify-post**

    Use HTTP POST instead of GET for the HTTP notification requests. The request
    body is empty even if POST is used.

- **--notify-no-verify**

    Disable TLS peer certificate verification for HTTPS requests.

- **--notify-concurrency=**_INT_

    The maximum number of HTTP requests to perform simultaneously.

- **--notify-retries=**_INT_

    How many times to retry a failed HTTP notification before giving up. An
    exponential falloff time is used for each subsequent attempt, starting with 5
    seconds.

- **--notify-record**

    Attach recorded file to HTTP notification request. If enabled, notification
    request behaves as HTTP POST (ignoring **--notify-post**). Note that this option
    is incompatible with DB-only storage as no recording file exists on storage
    (see **output-storage**).

## EXIT STATUS

- **0**

    Successful termination.

- **1**

    An error occurred.

## FILES

- `/etc/rtpengine/rtpengine-recording.conf`

    Configuration file.

## SEE ALSO

[rtpengine(8)](http://man.he.net/man8/rtpengine).
