# Conference admission latency regression

The regression recreates the missing control sequence from the October 4 conference
investigation: two AMR-WB phones, an Opus listener, and one shared mono L16/16000
recording endpoint. It measures decoded audio content age, not just RTP packet timing.

The original live call measured about 0.68 seconds of engine-local delay for one phone
and 2.58 seconds for the other. The old packet replay reached only 1.54 seconds and
omitted admission and private prompts. This test includes that control sequence using
synthetic audio; the original PCAP and recorded prompts are no longer available.
It is a reconstruction, not a byte-exact replay of the original call.

## Scenario

- Create the phone endpoints with permanent players, then answer them 330 ms and 630 ms
  into the test while their RTP timestamp and sequence progression continues normally.
- Add them using DTT's fresh-tag-safe bidirectional join meshes. An established Opus
  listener and recording anchor are present before the phone admissions.
- Change the L16 anchor from its discard destination to the recording socket, then
  answer it again after the second phone answer.
- Play a 700-ms private join tone and staggered 7.5-second private welcome prompts with
  `block egress`, followed by the second phone's join tone. These times approximate
  the relative offsets recovered from the original NG-control log.
- Continue sending AMR-WB speech, SID updates and omitted no-data frames throughout.
- Send 20 seconds of SID-only silence between two 80-second fixture cycles. All input
  RTP timestamps and sequence numbers remain continuous across that interval.
- Capture both phone outputs, the Opus output, and the shared L16 recording for the
  complete call; collect a further four seconds for delayed output.

Private prompt tones are generated as temporary WAV files at 3000/3100 Hz, outside the
speech-marker frequency range. The test verifies welcome audio at its intended phone
and verifies that it does not leak into either shared output. It checks one stable
SSRC and continuous RTP sequence/timestamp progression after prompt playback ends.

FFmpeg independently decodes the actual AMR-WB and Opus output packets. The marker
oracle identifies each phone's tones independently in the mixed browser and recording
streams, checking six source/output paths in total. Markers before 12 seconds are
excluded because admission and private playback deliberately replace conversation.
Every later marker must arrive. Its age is measured from its actual input send time.

Each path must stay below 250 ms of absolute content age after private prompts, and
its later 20-second window medians may add less than 40 ms relative to its first
settled window (40–60 seconds). This is a fixed total allowance, not a per-window
allowance. A constant multi-second backlog therefore cannot pass the test.
The source pacing check must also remain within 20 ms; otherwise latency conclusions
are skipped and the separate pacing assertion fails.

## Running

From `t/`, after building the daemon and preload helper:

```sh
RTPENGINE_EXTENDED_TESTS=1 \
  RTPENGINE_MIXER_DRIFT_ARTIFACTS=/tmp/conference-latency \
  make daemon-tests-mixer-drift
```

The replay lasts 184 seconds plus offline decoding/analysis. Without the extended-test
flag it explicitly skips. It requires full AMR-WB and Opus support in the daemon and
AMR-WB/Opus reference decoders in FFmpeg. `RTPENGINE_TEST_FFMPEG` selects that executable.
Artifacts otherwise use an automatically removed temporary directory.
`RTPENGINE_CONFERENCE_LATENCY_ARTIFACTS` is an alternate artifacts-directory variable.

Artifacts include `sent.csv`, `results.json`, `daemon.log`, prompt WAVs, raw RTP
observations, and independently decoded PCM. Raw `.rtp` records contain a big-endian
IEEE-754 double (monotonic seconds since the send loop started), a big-endian 32-bit
packet length, then the RTP bytes. These are isolated Unix-datagram observations
through the test preload harness; no live service or physical phone is contacted.

## Synthetic source fixtures

`source-0.awb` and `source-1.awb` each contain 80 seconds of generated sine waves and
silence encoded with AMR-WB VAD/DTX. No human speech, call recording or music is included.
The generator and fixture data follow the repository's GPL-3.0 license.

Source A has 220-ms bursts every two seconds starting at 400 ms; source B has 160-ms
bursts every 2.6 seconds starting at 1.1 seconds. Source A uses 400–2350 Hz and source B
uses 3400–4900 Hz, in 50-Hz steps, so markers cannot be confused between sources in a
shared mix. SID updates are transmitted; FT=15 no-data frames advance
the source timeline without sending RTP. The first speech frame after silence carries
the talkspurt marker. Arrival jitter is deterministic and bounded to +/-15/20 ms.

`profiles.json` records hashes, marker frequencies and pacing parameters. Regenerate
with `python3 generate.py`, which requires FFmpeg with `libvo_amrwbenc`. The recorded
encoder versions are libavcodec 58.134.100 and libvo-amrwbenc 0.1.3. Other encoder
versions may produce different bytes; regenerate the manifest together with the streams.

The short `auto-daemon-tests-dtx-rtcp.pl` remains a separate, codec-light regression for
report-only SSRC handling, configured comfort noise, and actual RTP source changes.
