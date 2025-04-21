![Code Testing](https://github.com/sipwise/rtpengine/workflows/Code%20Testing/badge.svg)
![Debian Package CI](https://github.com/sipwise/rtpengine/workflows/Debian%20Packaging/badge.svg)
![Coverity](https://img.shields.io/coverity/scan/sipwise-rtpengine.svg)

# What is rtpengine?

The [Sipwise](http://www.sipwise.com/) NGCP rtpengine is a proxy for RTP traffic and other UDP based
media traffic. It's meant to be used with the [Kamailio SIP proxy](http://www.kamailio.org/)
and forms a drop-in replacement for any of the other available RTP and media
proxies.

Currently the only supported platform is GNU/Linux.

## Mailing List

For general questions, discussion, requests for support, and community chat,
join our [mailing list](https://rtpengine.com/mailing-list). Please do not use
the Github issue tracker for this purpose.

## Features

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
* HTTP, HTTPS, and WebSocket (WS and WSS) interfaces

When used through the *rtpengine* module (or its older counterpart called *rtpproxy-ng*),
the following additional features are available:

- Full SDP parsing and rewriting
- Supports non-standard RTCP ports (RFC 3605)
- ICE (RFC 5245) support:
  + Bridging between ICE-enabled and ICE-unaware user agents
  + Optionally acting only as additional ICE relay/candidate
  + Optionally forcing relay of media streams by removing other ICE candidates
  + Optionally act as an "ICE lite" peer only
- SRTP (RFC 3711) support:
  + Support for SDES (RFC 4568) and DTLS-SRTP (RFC 5764)
  + AES-CM and AES-F8 ciphers, both in userspace and in kernel
  + HMAC-SHA1 packet authentication
  + Bridging between RTP and SRTP user agents
  + Opportunistic SRTP (RFC 8643)
  + Legacy non-RFC (dual `m=` line) best-effort SRTP
  + AES-GCM Authenticated Encryption (AEAD) (RFC 7714)
  + `a=tls-id` as per RFC 8842
- Support for RTCP profile with feedback extensions (RTP/AVPF, RFC 4585 and 5124)
- Arbitrary bridging between any of the supported RTP profiles (RTP/AVP, RTP/AVPF,
  RTP/SAVP, RTP/SAVPF)
- RTP/RTCP multiplexing (RFC 5761) and demultiplexing
- Breaking of BUNDLE'd media streams (draft-ietf-mmusic-sdp-bundle-negotiation)
- Recording of media streams, decrypted if possible
- Transcoding and repacketization
- Transcoding between RFC 2833/4733 DTMF event packets and in-band DTMF tones (and vice versa)
- Injection of DTMF events or PCM DTMF tones into running audio streams
- Playback of pre-recorded streams/announcements
- Transcoding between T.38 and PCM (G.711 or other audio codecs)
- Silence detection and comfort noise (RFC 3389) payloads
* Media forking
* Publish/subscribe mechanism for N-to-N media forwarding

There is also limited support for *rtpengine* to be used as a drop-in
replacement for *Janus* using the native Janus control protocol (see below).

*Rtpengine* does not (yet) support:

* ZRTP, although ZRTP passes through *rtpengine* just fine

## Documentation

Check our general documentation here:
* [Read-the-Docs](https://rtpengine.readthedocs.io/en/latest/)

For quick access, documentation for usage:
* [Compiling and Installing](https://rtpengine.readthedocs.io/en/latest/compiling_and_installing.html)
* [Usage](https://rtpengine.readthedocs.io/en/latest/usage.html)
* [Transcoding](https://rtpengine.readthedocs.io/en/latest/transcoding.html)
* [Call recording](https://rtpengine.readthedocs.io/en/latest/call_recording.html)
* [The NG Control Protocol](https://rtpengine.readthedocs.io/en/latest/ng_control_protocol.html)
* [The TCP-NG Control Protocol](https://rtpengine.readthedocs.io/en/latest/tcpng_control_protocol.html)
* [HTTP/WebSocket support](https://rtpengine.readthedocs.io/en/latest/http_websocket_support.html)
* [Janus Interface and Replacement Functionality](https://rtpengine.readthedocs.io/en/latest/janus_interface_and_replacement.html)

For quick access, documentation for development:
* [Architecture Overview](https://rtpengine.readthedocs.io/en/latest/architecture.html)
* [Unit-tests](https://rtpengine.readthedocs.io/en/latest/tests.html)
* [Troubleshooting Overview](https://rtpengine.readthedocs.io/en/latest/troubleshooting.html)
* [Glossary](https://rtpengine.readthedocs.io/en/latest/glossary.html)

## Sponsors

* [Dataport AöR](https://www.dataport.de/)

## Contribution

Every bit matters. Join us. Make the rtpengine community stronger.

Latest mr13.2.1.1 branch merging with 3clogic master . 
