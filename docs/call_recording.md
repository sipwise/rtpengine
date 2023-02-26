# Call Recording

Call recording can be accomplished in one of two ways: 

* The *rtpengine* daemon can write `libpcap`-formatted captures directly (`--recording-method=pcap`);

* The *rtpengine* daemon can write audio frames into a sink in `/proc/rtpengine` (`--recording-method=proc`). These frames must then be consumed within a short period by another process; while this can be any process, the packaged `rtpengine-recording` daemon is a useful ready implementation of a call recording solution. The recording daemon uses `ffmpeg` libraries to implement a variety of on-the-fly format conversion and mixing options, as well as metadata logging. See `rtpengine-recording -h` for details.

**Important note**: The *rtpengine* daemon emits data into a "spool directory" (`--recording-dir` option), by default `/var/spool/rtpengine`. The recording daemon is then configured to consume this using the `--spool-dir` option, and to store the final emitted recordings (in whatever desired target format, etc.) in `--output-dir`. Ensure that the `--spool-dir` and the `--output-dir` are **different** directories, or you will run into problems (as discussed in [#81](https://github.com/sipwise/rtpengine/issues/808)).
