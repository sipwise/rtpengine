# Transcoding

Currently transcoding is supported for audio streams. The feature can be disabled on a compile-time
basis, and is enabled by default.

Even though the transcoding feature is available by default, it is not automatically engaged for
normal calls. Normally *rtpengine* leaves codec negotiation up to the clients involved in the call
and does not interfere. In this case, if the clients fail to agree on a codec, the call will fail.

The transcoding feature can be engaged for a call by instructing *rtpengine* to do so by using
one of the transcoding options in the *ng* control protocol, such as `transcode` or `ptime` (see below).
If a codec is requested via the `transcode` option that was not originally offered, transcoding will
be engaged for that call.

With transcoding active for a call, all unsupported codecs will be removed from the SDP. Transcoding
happens in userspace only, so in-kernel packet forwarding will not be available for transcoded codecs.
However, even if the transcoding feature has been engaged for a call, not all codecs will necessarily
end up being transcoded. Codecs that are supported by both sides will simply be passed through
transparently (unless repacketization is active). In-kernel packet forwarding will still be available
for these codecs.

The following codecs are supported by *rtpengine*:

* G.711 (a-Law and µ-Law)
* G.722
* G.723.1
* G.729
* Speex
* GSM
* iLBC
* Opus
* AMR (narrowband and wideband)
* EVS (if supplied -- see below)

Codec support is dependent on support provided by the `ffmpeg` codec libraries, which may vary from
version to version. Use the `--codecs` command line option to have *rtpengine* print a list of codecs
and their supported status. The list includes some codecs that are not listed above. Some of these
are not actual VoIP codecs (such as MP3), while others lack support for encoding by *ffmpeg* at the
time of writing (such as QCELP or ATRAC). If encoding support for these codecs becomes available
in *ffmpeg*, *rtpengine* will be able to support them.

Audio format conversion including resampling and mono/stereo up/down-mixing happens automatically
as required by the codecs involved. For example, one side could be using stereo Opus at 48 kHz
sampling rate, and the other side could be using mono G.711 at 8 kHz, and *rtpengine* will perform
the necessary conversions.

If repacketization (using the `ptime` option) is requested, the transcoding feature will also be
engaged for the call, even if no additional codecs were requested.

## G.729 support

As *ffmpeg* does not currently provide an encoder for G.729, transcoding support for it is available
via the [bcg729](https://www.linphone.org/technical-corner/bcg729/) library
(mirror on [GitHub](https://github.com/BelledonneCommunications/bcg729)). The build system looks for
the *bcg729* headers in a few locations and uses the library if found. If the library is located
elsewhere, see `daemon/Makefile` to control where the build system is looking for it.

In a Debian build environment, `debian/control` lists a build-time dependency
on *bcg729*. Newer Debian releases (currently *bullseye*, *bookworm*, *sid*)
include *bcg729* as a package so nothing needs to be done there. Older Debian
releases do not currently include a *bcg729* package, but one can be built
locally using these instructions on
[GitHub](https://github.com/ossobv/bcg729-deb). *Sipwise* provides a
pre-packaged version of this as part of our [C5
CE](https://www.sipwise.com/products/class-5-softswitch-carrier-grade-for-voice-over-ip/)
product which is [available
here](https://deb.sipwise.com/spce/mr6.2.1/pool/main/b/bcg729/).

Alternatively the build dependency
can be removed from `debian/control` or by switching to a different Debian build profile.
Set the environment variable
`export DEB_BUILD_PROFILES="pkg.ngcp-rtpengine.nobcg729"` (or use the `-P` flag to the *dpkg* tools)
and then build the *rtpengine* packages.

## DTMF transcoding

*Rtpengine* supports transcoding between RFC 2833/4733 DTMF event packets (`telephone-event` payloads)
and in-band DTMF audio tones. When enabled, *rtpengine* translates DTMF event packets to in-band DTMF
audio by generating DTMF tones and injecting them into the audio stream, and translates in-band DTMF
tones by running the audio stream through a DSP, and generating DTMF event packets when a DTMF tone
is detected.

Support for DTMF transcoding can be enabled in one of two ways:

* In the forward direction, DTMF transcoding is enabled by adding the codec `telephone-event` to the
  list of codecs offered for transcoding. Specifically, if the incoming SDP body doesn't yet list
  `telephone-event` as a supported codec, adding the option *codec → transcode → telephone-event* would
  enable DTMF transcoding. The receiving RTP client can then accept this codec and start sending DTMF
  event packets, which *rtpengine* would translate into in-band DTMF audio. If the receiving RTP client
  also offers `telephone-event` in their behalf, *rtpengine* would then detect in-band DTMF audio coming
  from the originating RTP client and translate it to DTMF event packets.

* In the reverse direction, DTMF transcoding is enabled by adding the option `always transcode` to the
  `flags` if the incoming SDP body offers `telephone-event` as a supported codec. If the receiving RTP
  client then rejects the offered `telephone-event` codec, DTMF transcoding is then enabled and is
  performed in the same way as described above.

Enabling DTMF transcoding (in one of the two ways described above) implicitly enables the flag
`always transcode` for the call and forces all of the audio to pass through the transcoding engine.
Therefore, for performance reasons, this should only be done when really necessary.

## T.38

*Rtpengine* can translate between fax endpoints that speak T.38 over UDPTL and fax endpoints that speak
T.30 over regular audio channels. Any audio codec can theoretically be used for T.30 transmissions, but
codecs that are too compressed will make the fax transmission fail. The most commonly used audio codecs
for fax are the G.711 codecs (`PCMU` and `PCMA`), which are the default codecs *rtpengine* will use in
this case if no other codecs are specified.

For further information, see the section on the `T.38` dictionary key below.

## AMR and AMR-WB

As AMR supports dynamically adapting the encoder bitrate, as well as restricting the available bitrates,
there are some slight peculiarities about its usage when transcoding.

When setting the bitrate, for example as `AMR-WB/16000/1/23850` in either the `codec-transcode` or the
`codec-set` options, that bitrate will be used as the highest permitted bitrate for the encoder. If
no `mode-set` parameter is communicated in the SDP, then that is the bitrate that will be used.

If a `mode-set` is present, then the highest bitrate from that mode set which is lower or equal to the
given bitrate will be used. If only higher bitrates are allowed by the mode set, then the next higher
bitrate will be used.

To produce an SDP that includes the `mode-set` option (when adding AMR to the codec list via
`codec-transcode`), the full format parameter string can be appended to the codec specification, e.g.
`codec-transcode-AMR-WB/16000/1/23850//mode-set=0,1,2,3,4,5;octet-align=1`. In this example, the bitrate
23850 won't actually be used, as the highest permitted mode is 5 (18250 bps) and so that bitrate will
be used.

If a literal `=` cannot be used due to parsing constraints (i.e. being wrongly interpreted as a
key-value pair), it can be escaped by using two dashes instead, e.g.
`codec-transcode-AMR-WB/16000/1/23850//mode-set--0,1,2,3,4,5;octet-align--1`

The default (highest) bitrates for AMR and AMR-WB are 6700 and 14250, respectively.

If a Codec Mode Request (CMR) is received from the AMR peer, then *rtpengine* will adhere to the request
and switch encoder bitrate unconditionally, even if it's a higher bitrate than originally desired.

To enable sending CMRs to the AMR peer, the codec-specific option `CMR-interval` is provided. It takes
a number of milliseconds as argument. Throughout each interval, *rtpengine* will track which AMR frame
types were received from the peer, and then based on that will make a decision at the end of the
interval. If a higher bitrate is allowed by the mode set that was not received from the AMR peer at all,
then *rtpengine* will request switching to that bitrate per CMR. Only the next-highest bitrate mode that
was not received will ever be requested, and a CMR will be sent only once per interval. Full example to
specify a CMR interval of 500 milliseconds (with `=` escapes):
`codec-transcode-AMR-WB/16000/1/23850//mode-set--0,1,2/CMR-interval--500`

Similar to the `CMR-interval` option, *rtpengine* can optionally attempt to periodically increase the
outgoing bitrate without being requested to by the peer via a CMR. To enable this, set the option
`mode-change-interval` to the desired interval in milliseconds. If the last CMR from the AMR peer was
longer than this interval ago, *rtpengine* will increase the bitrate by one step if possible. Afterwards,
the interval starts over.

## EVS

Enhanced Voice Services (EVS) is a patent-encumbered codec for which (at the
time of writing) no implementation exists which can be freely used and
distributed. As such, support for EVS is only available if an implementation is
supplied separately. Currently the only implementation supported is the
ETSI/3GPP reference implementation (either floating-point or fixed-point). Any
licensing issues that might result from such usage are the responsibility of
the user of this software.

The EVS codec implementation can be provided as a shared object library (*.so*)
which is loaded in during runtime (at startup). The supported implementations
can be seen as subdirectories within the `evs/` directory. Currently supported
are version 17.0.0 of the ETSI/3GPP reference implementation, [*126.442*](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1464) for the
fixed-point implementation and [*126.443*](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1465) for the floating-point implementation.
(The floating-point implementation seems to be significantly faster, but is not
bit-precise.)

To supply the codec implementation as a shared object during runtime, extract
the reference implementation's *.zip* file and apply the provided `patch`
([from here](https://github.com/sipwise/rtpengine/tree/master/evs)) that is
appropriate for the chosen implementation. Run the build using `make`
(suggested build flags are `RELEASE=1 make`) and it should produce a file
`lib3gpp-evs.so`. Point *rtpengine* to this file using the `evs-lib-path=`
option to enable support for EVS.
