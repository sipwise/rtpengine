**Synthetic AMR-WB content-age fixtures**

These files contain generated sine waves and silence, with AMR-WB VAD/DTX enabled.
They contain no recorded phone call, human speech, or third-party music.
The generator and fixture data follow the repository's GPL-3.0 license.

`source-0.awb` and `source-1.awb` are 80-second AMR-WB storage-format streams.
`profiles.json` records their hashes, tone markers, frame-type counts, and pacing parameters.

- Source 0: 220-ms speech bursts every 2 seconds, starting at 400 ms.
- Source 1: 160-ms speech bursts every 2.6 seconds, starting at 1.1 seconds.
- Each successive burst uses a distinct frequency, starting at 400 Hz and increasing by 50 Hz.
- Silence produces SID updates and no-data frames through the AMR-WB encoder's VAD/DTX.
- RTP transmission omits no-data frames but retains their elapsed RTP timestamp time.
- The first speech frame after silence carries the RTP talkspurt marker, as required by RFC 4867 section 4.1.
- Arrival jitter is deterministic and bounded to +/-15 ms and +/-20 ms, below the tested 50-ms DTX delay.

Regenerate with `python3 generate.py`. Regeneration requires FFmpeg with the `libvo_amrwbenc`
encoder; the checked-in fixtures avoid requiring regeneration when running the test.
The test explicitly skips when the daemon lacks full AMR-WB support or when its reference
decoder is unavailable. Otherwise it needs a daemon build with AMR-WB encoding/decoding and an `ffmpeg` executable
with an AMR-WB decoder to independently decode the actual AMR-WB phone outputs.
The tested generator used FFmpeg/libavcodec 58.134.100 and libvo-amrwbenc 0.1.3.
Regeneration with another encoder version may produce different bytes; the manifest hashes
are regenerated together with the streams.

Run only this extended test against unpatched upstream:

```sh
RTPENGINE_EXTENDED_TESTS=1 RTPENGINE_MIXER_DRIFT_ARTIFACTS=/tmp/mixer-dtx50 \
  ./auto-test-helper mixer-dtx50 perl -I../perl auto-daemon-tests-mixer-drift.pl
```

Run the same synthetic packets with only the daemon's DTX-delay setting changed:

```sh
RTPENGINE_EXTENDED_TESTS=1 RTPENGINE_MIXER_DRIFT_ARTIFACTS=/tmp/mixer-dtx0 \
  ./auto-test-helper mixer-dtx0 perl -I../perl auto-daemon-tests-mixer-drift.pl --dtx-delay=0
```

Both commands run from `t/` after building `daemon/rtpengine` and `t/tests-preload.so`.
Without `RTPENGINE_EXTENDED_TESTS` the test reports an explicit skip.
Artifacts default to an automatically removed temporary directory; set the artifacts variable
as above to retain them. `RTPENGINE_TEST_FFMPEG` selects a different decoder executable.

The test uses two bidirectional AMR-WB phone endpoints. Each receives the other source through
a permanent player. Two additional L16 taps capture each source's content independently.
Actual AMR-WB output is decoded after the call, so neither decoding nor spectral analysis can
stall the sender/receiver loop. All four sockets are drained throughout collection.

A marker requires four consecutive 20-ms frames dominated by its unique frequency. Delay is
measured from the actual send time of that marker's initial input frame. Every marker must arrive;
missing or reordered packets, clock discontinuities, and PCM frame-count errors are checked separately.
The initial three marker delays calibrate each stream's constant DTX/codec latency. The latency
assertion allows 250 ms of additional sustained delay, measured using a rolling median of three
markers. A constant 50-ms or 800-ms latency does not fail that growth assertion.
If the test sender falls more than 20 ms behind its schedule, the content-age conclusion is
skipped and the separate pacing check fails, so a stalled test driver is not reported as an
engine content-age failure.

Raw `.rtp` files are test-process observations, not network-interface captures. Each record is
an IEEE-754 big-endian double (monotonic seconds since send-loop start), a big-endian 32-bit
packet length, and the RTP packet bytes. `sent.csv` records actual source send times;
`results.json` records every detected marker, initial/final/worst sustained delays, and growth.
`daemon.log` contains the upstream debug log. The socket preload harness transports real RTP
bytes through isolated Unix datagrams; no live service or physical phone is contacted.
