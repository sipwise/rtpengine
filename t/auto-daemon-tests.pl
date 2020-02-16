#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -c 12345 -f -L 7 -E -u 2222))
		or die;


my ($sock_a, $sock_b, $port_a, $port_b, $ssrc, $resp, $srtp_ctx_a, $srtp_ctx_b, @ret1, @ret2);




# github issue 850

new_call;

@ret1 = offer('gh 850',
	{
		ICE => 'force-relay', flags => [qw(SDES-off)], 'transport-protocol' => 'UDP/TLS/RTP/SAVPF',
		'rtcp-mux' => [qw(accept offer)], 'via-branch' => 'z9hG4bK9463.af303705.113',
	}, <<SDP);
v=0
o=- 9011363210357191088 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY
m=audio 14745 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126
c=IN IP4 38.104.167.182
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:661312077 1 udp 2122262783 2001:550:2200:205:fd25:1ca1:96cd:8c2e 61773 typ host generation 0 network-id 2 network-cost 10
a=candidate:2313719679 1 udp 2122194687 192.168.1.54 55343 typ host generation 0 network-id 1 network-cost 10
a=candidate:521932948 1 udp 2122131711 2607:fb90:5c0:3a15:b3ec:67e6:e268:b9e0 55344 typ host generation 0 network-id 3 network-cost 50
a=candidate:2982564287 1 udp 1686055167 2604:2000:0:8::f:111b 11344 typ srflx raddr 2001:550:2200:205:fd25:1ca1:96cd:8c2e rport 61773 generation 0 network-id 2 network-cost 10
a=candidate:2147022507 1 udp 1685987071 38.104.167.182 14745 typ srflx raddr 192.168.1.54 rport 55343 generation 0 network-id 1 network-cost 10
a=candidate:1776889533 1 tcp 1518283007 2001:550:2200:205:fd25:1ca1:96cd:8c2e 9 typ host tcptype active generation 0 network-id 2 network-cost 10
a=candidate:3345707919 1 tcp 1518214911 192.168.1.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:1369435236 1 tcp 1518151935 2607:fb90:5c0:3a15:b3ec:67e6:e268:b9e0 9 typ host tcptype active generation 0 network-id 3 network-cost 50
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
a=fingerprint:sha-256 32:62:C7:5E:79:69:2A:15:DC:EA:1D:13:18:4C:C9:92:44:71:8A:B7:38:73:88:F9:99:A3:7A:05:D1:EE:98:B8
a=setup:actpass
a=mid:0
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=sendrecv
a=msid:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY 7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=rtcp-fb:111 transport-cc
a=fmtp:111 minptime=10;useinbandfec=1
a=rtpmap:103 ISAC/16000
a=rtpmap:104 ISAC/32000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:106 CN/32000
a=rtpmap:105 CN/16000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:112 telephone-event/32000
a=rtpmap:113 telephone-event/16000
a=rtpmap:126 telephone-event/8000
a=ssrc:2628106563 cname:wMyHbPOf/cCq2tup
a=ssrc:2628106563 msid:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY 7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=ssrc:2628106563 mslabel:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY
a=ssrc:2628106563 label:7d669de6-65e9-4fbe-829e-e89dc4baf81c
--------------------------------------
v=0
o=- 9011363210357191088 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY
m=audio 14745 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126
c=IN IP4 38.104.167.182
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:661312077 1 udp 2122262783 2001:550:2200:205:fd25:1ca1:96cd:8c2e 61773 typ host generation 0 network-id 2 network-cost 10
a=candidate:2313719679 1 udp 2122194687 192.168.1.54 55343 typ host generation 0 network-id 1 network-cost 10
a=candidate:521932948 1 udp 2122131711 2607:fb90:5c0:3a15:b3ec:67e6:e268:b9e0 55344 typ host generation 0 network-id 3 network-cost 50
a=candidate:2982564287 1 udp 1686055167 2604:2000:0:8::f:111b 11344 typ srflx raddr 2001:550:2200:205:fd25:1ca1:96cd:8c2e rport 61773 generation 0 network-id 2 network-cost 10
a=candidate:2147022507 1 udp 1685987071 38.104.167.182 14745 typ srflx raddr 192.168.1.54 rport 55343 generation 0 network-id 1 network-cost 10
a=candidate:1776889533 1 tcp 1518283007 2001:550:2200:205:fd25:1ca1:96cd:8c2e 9 typ host tcptype active generation 0 network-id 2 network-cost 10
a=candidate:3345707919 1 tcp 1518214911 192.168.1.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:1369435236 1 tcp 1518151935 2607:fb90:5c0:3a15:b3ec:67e6:e268:b9e0 9 typ host tcptype active generation 0 network-id 3 network-cost 50
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
a=fingerprint:sha-256 32:62:C7:5E:79:69:2A:15:DC:EA:1D:13:18:4C:C9:92:44:71:8A:B7:38:73:88:F9:99:A3:7A:05:D1:EE:98:B8
a=setup:actpass
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=msid:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY 7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=rtcp-mux
a=rtcp-fb:111 transport-cc
a=ssrc:2628106563 cname:wMyHbPOf/cCq2tup
a=ssrc:2628106563 msid:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY 7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=ssrc:2628106563 mslabel:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY
a=ssrc:2628106563 label:7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=mid:0
a=rtpmap:111 opus/48000/2
a=rtpmap:103 ISAC/16000
a=rtpmap:104 ISAC/32000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:106 CN/32000
a=rtpmap:105 CN/16000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:112 telephone-event/32000
a=rtpmap:113 telephone-event/16000
a=rtpmap:126 telephone-event/8000
a=fmtp:111 minptime=10;useinbandfec=1
a=sendrecv
a=candidate:ICEBASE 1 UDP 16777215 203.0.113.1 PORT typ relay raddr 203.0.113.1 rport PORT
a=candidate:ICEBASE 1 UDP 16776959 2001:db8:4321::1 PORT typ relay raddr 2001:db8:4321::1 rport PORT
a=candidate:ICEBASE 2 UDP 16777214 203.0.113.1 PORT typ relay raddr 203.0.113.1 rport PORT
a=candidate:ICEBASE 2 UDP 16776958 2001:db8:4321::1 PORT typ relay raddr 2001:db8:4321::1 rport PORT
SDP

is $ret1[0], $ret1[6], 'ice base 1';
is $ret1[1], $ret1[2], 'rtp rport 1';
is $ret1[3], $ret1[9], 'ice base 2';
is $ret1[4], $ret1[5], 'rtp rport 2';
is $ret1[7], $ret1[8], 'rtcp rport 1';
is $ret1[10], $ret1[11], 'rtcp rport 2';

@ret1 = answer('gh 850',
	{
		ICE => 'force-relay', flags => [qw(SDES-off)], 'transport-protocol' => 'UDP/TLS/RTP/SAVPF', 
		'rtcp-mux' => [qw(accept offer)], 'via-branch' => 'z9hG4bK9463.af303705.113',
	}, <<SDP);
v=0
o=- 262597839645727503 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS 9z51ZTKhoszc7zqj5gxEX309ODe940YpMplv
m=audio 5308 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126
c=IN IP4 38.104.167.182
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:661312077 1 udp 2122262783 2001:550:2200:205:fd25:1ca1:96cd:8c2e 55347 typ host generation 0 network-id 2 network-cost 10
a=candidate:2313719679 1 udp 2122194687 192.168.1.54 52949 typ host generation 0 network-id 1 network-cost 10
a=candidate:521932948 1 udp 2122131711 2607:fb90:5c0:3a15:b3ec:67e6:e268:b9e0 52950 typ host generation 0 network-id 3 network-cost 50
a=candidate:2982564287 1 udp 1686055167 2604:2000:0:8::f:111b 27536 typ srflx raddr 2001:550:2200:205:fd25:1ca1:96cd:8c2e rport 55347 generation 0 network-id 2 network-cost 10
a=candidate:2147022507 1 udp 1685987071 38.104.167.182 5308 typ srflx raddr 192.168.1.54 rport 52949 generation 0 network-id 1 network-cost 10
a=ice-ufrag:Opvv
a=ice-pwd:nxh4YdcCu2rHq1h1aBOYzlqD
a=ice-options:trickle
a=fingerprint:sha-256 43:92:E2:A9:BC:FD:53:00:32:4D:EC:97:55:B5:C9:52:95:40:BE:CB:1A:26:4B:34:7A:48:42:96:09:F7:50:97
a=setup:active
a=mid:0
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=sendrecv
a=msid:9z51ZTKhoszc7zqj5gxEX309ODe940YpMplv 8a622ecc-1fff-4675-8bf4-7b924845b3fd
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=rtcp-fb:111 transport-cc
a=fmtp:111 minptime=10;useinbandfec=1
a=rtpmap:103 ISAC/16000
a=rtpmap:104 ISAC/32000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:106 CN/32000
a=rtpmap:105 CN/16000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:112 telephone-event/32000
a=rtpmap:113 telephone-event/16000
a=rtpmap:126 telephone-event/8000
a=ssrc:97254339 cname:d7zRWvteaW9fc2Yu
--------------------------------------
v=0
o=- 262597839645727503 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS 9z51ZTKhoszc7zqj5gxEX309ODe940YpMplv
m=audio 5308 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126
c=IN IP4 38.104.167.182
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:661312077 1 udp 2122262783 2001:550:2200:205:fd25:1ca1:96cd:8c2e 55347 typ host generation 0 network-id 2 network-cost 10
a=candidate:2313719679 1 udp 2122194687 192.168.1.54 52949 typ host generation 0 network-id 1 network-cost 10
a=candidate:521932948 1 udp 2122131711 2607:fb90:5c0:3a15:b3ec:67e6:e268:b9e0 52950 typ host generation 0 network-id 3 network-cost 50
a=candidate:2982564287 1 udp 1686055167 2604:2000:0:8::f:111b 27536 typ srflx raddr 2001:550:2200:205:fd25:1ca1:96cd:8c2e rport 55347 generation 0 network-id 2 network-cost 10
a=candidate:2147022507 1 udp 1685987071 38.104.167.182 5308 typ srflx raddr 192.168.1.54 rport 52949 generation 0 network-id 1 network-cost 10
a=ice-ufrag:Opvv
a=ice-pwd:nxh4YdcCu2rHq1h1aBOYzlqD
a=ice-options:trickle
a=fingerprint:sha-256 43:92:E2:A9:BC:FD:53:00:32:4D:EC:97:55:B5:C9:52:95:40:BE:CB:1A:26:4B:34:7A:48:42:96:09:F7:50:97
a=setup:active
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=msid:9z51ZTKhoszc7zqj5gxEX309ODe940YpMplv 8a622ecc-1fff-4675-8bf4-7b924845b3fd
a=rtcp-mux
a=rtcp-fb:111 transport-cc
a=ssrc:97254339 cname:d7zRWvteaW9fc2Yu
a=mid:0
a=rtpmap:111 opus/48000/2
a=rtpmap:103 ISAC/16000
a=rtpmap:104 ISAC/32000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:106 CN/32000
a=rtpmap:105 CN/16000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:112 telephone-event/32000
a=rtpmap:113 telephone-event/16000
a=rtpmap:126 telephone-event/8000
a=fmtp:111 minptime=10;useinbandfec=1
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=candidate:ICEBASE 1 UDP 16777215 203.0.113.1 PORT typ relay raddr 203.0.113.1 rport PORT
a=candidate:ICEBASE 1 UDP 16776959 2001:db8:4321::1 PORT typ relay raddr 2001:db8:4321::1 rport PORT
SDP

is $ret1[2], $ret1[3], 'rtp rport 1';
is $ret1[5], $ret1[6], 'rtp rport 2';




if (0) {

# github issue 854

($sock_a, $sock_b) = new_call([qw(198.51.100.1 7326)], [qw(198.51.100.3 7328)]);

($port_a) = offer('gh854 inbound 30 ms',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7326 RTP/AVP 96
c=IN IP4 198.51.100.1
a=rtpmap:96 iLBC/8000
a=fmtp:96 mode=30
a=ptime:30
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 iLBC/8000
a=rtpmap:8 PCMA/8000
a=fmtp:96 mode=30
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('gh854 inbound 30 ms',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7328 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 iLBC/8000
a=fmtp:96 mode=30
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

snd($sock_a, $port_b, rtp(96, 1000, 3000, 0x6543, "\xa2\xff\x30\x0e\x5b\x3e\xa0\xac\x40\x40\x00\x57\xff\xff\xfd\xa4\x58\x8b\x62\x10\xcf\xff\xb9\xaa\xbb\xff\xcc\xc0\x00\x00\x00\x00\x00\x0c\x31\x1c\xc1\x74\xaf\x85\x85\x9a\x32\x33\x63\x60\x21\x61\x58\x76"));
($ssrc) = rcv($sock_b, $port_a, rtpm(8, 1000, 3000, -1, "\xd5\x55\x57\x5e\x65\x03\x2a\x2a\x2a\xaa\xaa\xaa\xaa\x2a\xaa\x2a\xaa\x2a\x2a\xaa\xaa\xaa\xaa\xaa\xaa\x2a\xaa\xaa\xaa\xaa\xab\x2a\xaa\xa8\x2a\xaa\x2a\xaa\x2a\x2a\x2a\x2a\x2a\x2b\x2a\x2e\x2e\x2a\x2a\x2e\x26\xaa\xaa\xaa\x3c\x2a\x2a\xad\xad\xa3\xa7\xa7\xa3\xa2\xa1\xa3\xa4\xba\xbe\xb2\xb6\x8a\x86\x9f\x96\xee\x9b\x81\x84\x9d\x99\x9a\x85\x87\x84\x8f\x8d\x82\x83\xed\x97\x95\x87\x8b\xb1\x81\x81\x9b\x9c\xea\xcc\x79\x6c\x11\x13\x1b\x18\x19\x19\x1f\x12\x10\x12\x1d\x10\x16\x14\x6b\x68\x66\x64\x7a\x7e\x7d\x72\x72\x7c\x7f\x79\x65\x65\x60\x61\x61\x61\x7f\x7c\x72\x78\x67\x62\x78\x7a\x78\x7f\x71\x48\x44\x5c\x55\xd3\xd9\xc4\xc6\xc1\xc1\xc6\xc4\xda\xd8\xd8\xd9\xdc\xda\xdd\xdf\xd3\xd2\xd6\xda\xdd\xdf\xde\xd8\xdb\xda\xdb\xda\xdb\xda\xd8\xd9\xde\xdf\xdc\xdd\xdd\xd2\xd3\xd3\xd3\xd0\xd0\xd1\xd1\xd0\xd1\xd1\xd1\xd1\xd1\xd1\xd1\xd6\xd6\xd6\xd7\xd7\xd7\xd4\xd4\xd4\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\x55\xd5\x55\x55\x55\x55\x55\x55\x55\x55\x54\x54\x54\x54\x54\x54\x54\x54"));

# mode switch
snd($sock_a, $port_b, rtp(96, 1001, 3240, 0x6543, "\xa2\xff\x37\xd3\xe2\xb8\x50\x40\x00\x5f\xff\xff\xff\x89\xcc\xff\x76\x6a\xae\xff\xcc\x00\x00\x00\x00\x00\x00\x00\x36\x52\x9d\x93\xf8\x45\x45\x45\x12\x16"));
($ssrc) = rcv($sock_b, $port_a, rtpm(8, 1001, 3240, -1, "\xd5\xd5\x55\xaa\x2a\xaa\xaa\x2a\xaa\xaa\xaa\x2a\x2a\xaa\x2a\x2a\x2a\x2a\xaa\xaa\x2a\xaa\x2a\xaa\x2a\xaa\x2a\x2a\xa7\x2a\x2a\x2a\xaa\xaa\x2a\xaa\xaa\x2a\x2a\x2a\x2a\xaa\xaa\xaa\xaa\x2a\x2a\xaa\xaa\xaa\x2a\x2a\x2a\x2a\xaa\x2a\xaa\x2a\xaa\xaa\x2a\x2a\x2a\x2a\x2a\x2a\xaa\x2a\x2a\x2a\x2a\x28\xaa\x2a\x28\xaa\x3e\xaa\xaa\x2a\x2a\xaa\x2a\x2a\xaa\x2a\xaa\xaa\xaa\x81\x36\x2a\x2a\x2a\x2a\xaa\xaa\x2a\xaa\xaa\x2a\xaa\x2a\x2a\x2a\xa5\xaa\xaa\xaa\xaa\xaa\x2a\x2a\xaa\x2a\x2a\xaa\x2a\xaa\xaa\xaa\xaa\xa2\xa4\xaf\x7e\xec\x37\x26\x21\x2f\x28\x29\x2a\x28\x2e\x2f\x22\x20\x27\x25\x39\x32\x31\x34\x0b\x0e\x0c\x0d\x02\x03\x01\x01\x06\x06\x06\x07\x04\x05\x1e"));

snd($sock_b, $port_a, rtp(8, 1000, 3000, 0x1234, "\x00" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\xa2\xff\x30\x0e\x5b\x3e\xa0\xac\x40\x40\x00\x57\xff\xff\xfd\xa4\x58\x8b\x62\x10\xcf\xff\xb9\xaa\xbb\xff\xcc\xc0\x00\x00\x00\x00\x00\x0c\x31\x1c\xc1\x74\xaf\x85\x85\x9a\x32\x33\x63\x60\x21\x61\x58\x76"));



($sock_a, $sock_b) = new_call([qw(198.51.100.1 7322)], [qw(198.51.100.3 7324)]);

($port_a) = offer('gh854 inbound 20 ms',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7322 RTP/AVP 96
c=IN IP4 198.51.100.1
a=rtpmap:96 iLBC/8000
a=fmtp:96 mode=20
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 iLBC/8000
a=rtpmap:8 PCMA/8000
a=fmtp:96 mode=20
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

($port_b) = answer('gh854 inbound 20 ms',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7324 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 iLBC/8000
a=fmtp:96 mode=20
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

snd($sock_a, $port_b, rtp(96, 1000, 3000, 0x6543, "\xa2\xff\x37\xd3\xe2\xb8\x50\x40\x00\x5f\xff\xff\xff\x89\xcc\xff\x76\x6a\xae\xff\xcc\x00\x00\x00\x00\x00\x00\x00\x36\x52\x9d\x93\xf8\x45\x45\x45\x12\x16"));
($ssrc) = rcv($sock_b, $port_a, rtpm(8, 1000, 3000, -1, "\xd5\xd5\x55\xaa\x2a\xaa\xaa\x2a\xaa\xaa\xaa\x2a\x2a\xaa\x2a\x2a\x2a\x2a\xaa\xaa\x2a\xaa\x2a\xaa\x2a\xaa\x2a\x2a\xa7\x2a\x2a\x2a\xaa\xaa\x2a\xaa\xaa\x2a\x2a\x2a\x2a\xaa\xaa\xaa\xaa\x2a\x2a\xaa\xaa\xaa\x2a\x2a\x2a\x2a\xaa\x2a\xaa\x2a\xaa\xaa\x2a\x2a\x2a\x2a\x2a\x2a\xaa\x2a\x2a\x2a\x2a\x28\xaa\x2a\x28\xaa\x3e\xaa\xaa\x2a\x2a\xaa\x2a\x2a\xaa\x2a\xaa\xaa\xaa\x81\x36\x2a\x2a\x2a\x2a\xaa\xaa\x2a\xaa\xaa\x2a\xaa\x2a\x2a\x2a\xa5\xaa\xaa\xaa\xaa\xaa\x2a\x2a\xaa\x2a\x2a\xaa\x2a\xaa\xaa\xaa\xaa\xa2\xa4\xaf\x7e\xec\x37\x26\x21\x2f\x28\x29\x2a\x28\x2e\x2f\x22\x20\x27\x25\x39\x32\x31\x34\x0b\x0e\x0c\x0d\x02\x03\x01\x01\x06\x06\x06\x07\x04\x05\x1e"));

# mode switch
snd($sock_a, $port_b, rtp(96, 1001, 3160, 0x6543, "\xa2\xff\x30\x0e\x5b\x3e\xa0\xac\x40\x40\x00\x57\xff\xff\xfd\xa4\x58\x8b\x62\x10\xcf\xff\xb9\xaa\xbb\xff\xcc\xc0\x00\x00\x00\x00\x00\x0c\x31\x1c\xc1\x74\xaf\x85\x85\x9a\x32\x33\x63\x60\x21\x61\x58\x76"));
($ssrc) = rcv($sock_b, $port_a, rtpm(8, 1001, 3160, -1, "\xd5\x55\x57\x5e\x65\x03\x2a\x2a\x2a\xaa\xaa\xaa\xaa\x2a\xaa\x2a\xaa\x2a\x2a\xaa\xaa\xaa\xaa\xaa\xaa\x2a\xaa\xaa\xaa\xaa\xab\x2a\xaa\xa8\x2a\xaa\x2a\xaa\x2a\x2a\x2a\x2a\x2a\x2b\x2a\x2e\x2e\x2a\x2a\x2e\x26\xaa\xaa\xaa\x3c\x2a\x2a\xad\xad\xa3\xa7\xa7\xa3\xa2\xa1\xa3\xa4\xba\xbe\xb2\xb6\x8a\x86\x9f\x96\xee\x9b\x81\x84\x9d\x99\x9a\x85\x87\x84\x8f\x8d\x82\x83\xed\x97\x95\x87\x8b\xb1\x81\x81\x9b\x9c\xea\xcc\x79\x6c\x11\x13\x1b\x18\x19\x19\x1f\x12\x10\x12\x1d\x10\x16\x14\x6b\x68\x66\x64\x7a\x7e\x7d\x72\x72\x7c\x7f\x79\x65\x65\x60\x61\x61\x61\x7f\x7c\x72\x78\x67\x62\x78\x7a\x78\x7f\x71\x48\x44\x5c\x55\xd3\xd9\xc4\xc6\xc1\xc1\xc6\xc4\xda\xd8\xd8\xd9\xdc\xda\xdd\xdf\xd3\xd2\xd6\xda\xdd\xdf\xde\xd8\xdb\xda\xdb\xda\xdb\xda\xd8\xd9\xde\xdf\xdc\xdd\xdd\xd2\xd3\xd3\xd3\xd0\xd0\xd1\xd1\xd0\xd1\xd1\xd1\xd1\xd1\xd1\xd1\xd6\xd6\xd6\xd7\xd7\xd7\xd4\xd4\xd4\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\x55\xd5\x55\x55\x55\x55\x55\x55\x55\x55\x54\x54\x54\x54\x54\x54\x54\x54"));

snd($sock_b, $port_a, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\xa2\xff\x37\xd3\xe2\xb8\x50\x40\x00\x5f\xff\xff\xff\x89\xcc\xff\x76\x6a\xae\xff\xcc\x00\x00\x00\x00\x00\x00\x00\x36\x52\x9d\x93\xf8\x45\x45\x45\x12\x16"));


}




# github issue 829

($sock_a, $sock_b) = new_call([qw(198.51.100.1 7316)], [qw(198.51.100.3 7318)]);

($port_a) = offer('gh829 control',
	{ ICE => 'remove', replace => ['origin'], flags => ['pad crypto'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7316 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
a=crypto:4 AES_CM_128_HMAC_SHA1_32 inline:Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhH?
a=crypto:4 AES_CM_128_HMAC_SHA1_32 inline:Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q?
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192=
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192=
a=crypto:7 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256==
a=crypto:8 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256==
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b) = answer('gh829 control',
	{ ICE => 'remove', replace => ['origin'], flags => ['pad crypto'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7318 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:IDdiM2QzOWYzMjA2YzkwZWIxY2NmOWVhOTc4MjE1
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:IDdiM2QzOWYzMjA2YzkwZWIxY2NmOWVhOTc4MjE?
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'IDdiM2QzOWYzMjA2YzkwZWIxY2NmOWVhOTc4MjE1',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa',
};

srtp_snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_b);


($sock_a, $sock_b) = new_call([qw(198.51.100.1 7310)], [qw(198.51.100.3 7312)]);

($port_a) = offer('gh829',
	{ ICE => 'remove', replace => ['origin'], flags => ['pad crypto'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7310 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:EPm8bCW0w2BvozGK++QzjF4m6ARVCpXrn8GAMAoIiDW8BQRDZ+fFRwDjLFALJQ==
a=crypto:2 AES_256_CM_HMAC_SHA1_32 inline:7Io806fF2XLWT782TTPsrSQTptu9HPGRnJ3Y5QDwk9HbhRi+nNwJ/nqNQP+tDg==
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
a=crypto:4 AES_CM_128_HMAC_SHA1_32 inline:Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:EPm8bCW0w2BvozGK++QzjF4m6ARVCpXrn8GAMAoIiDW8BQRDZ+fFRwDjLFALJ?==
a=crypto:2 AES_256_CM_HMAC_SHA1_32 inline:7Io806fF2XLWT782TTPsrSQTptu9HPGRnJ3Y5QDwk9HbhRi+nNwJ/nqNQP+tD?==
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhH?
a=crypto:4 AES_CM_128_HMAC_SHA1_32 inline:Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q?
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192=
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192=
a=crypto:7 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b) = answer('gh829',
	{ ICE => 'remove', replace => ['origin'], flags => ['pad crypto'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7312 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:IDdiM2QzOWYzMjA2YzkwZWIxY2NmOWVhOTc4MjE1
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:IDdiM2QzOWYzMjA2YzkwZWIxY2NmOWVhOTc4MjE?
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'IDdiM2QzOWYzMjA2YzkwZWIxY2NmOWVhOTc4MjE1',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa',
};

srtp_snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_b);


# DTMF injection
#
# no transcoding, RFC payload type present

($sock_a, $sock_b) = new_call([qw(198.51.100.1 6010)], [qw(198.51.100.3 6012)]);

($port_a) = offer('no transcoding, RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6010 RTP/AVP 0 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('no transcoding, RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6012 RTP/AVP 0 8 96
c=IN IP4 198.51.100.3
a=rtpmap:96 telephone-event/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => '0', volume => 10, duration => 100 });

snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96 | 0x80, 1002, 3320, $ssrc, "\x00\x0a\x00\xa0"));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1003, 3320, $ssrc, "\x00\x0a\x01\x40"));
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1004, 3320, $ssrc, "\x00\x0a\x01\xe0"));
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1005, 3320, $ssrc, "\x00\x0a\x02\x80"));
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1006, 3320, $ssrc, "\x00\x0a\x03\x20"));
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1007, 3320, $ssrc, "\x00\x8a\x03\xc0"));
rcv($sock_b, $port_a, rtpm(96, 1008, 3320, $ssrc, "\x00\x8a\x03\xc0"));
rcv($sock_b, $port_a, rtpm(96, 1009, 3320, $ssrc, "\x00\x8a\x03\xc0"));
snd($sock_a, $port_b, rtp(0, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4280, $ssrc, "\x00" x 160));



snd($sock_b, $port_a, rtp(0, 4000, 8000, 0x6543, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 8000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 8160, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 8160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards A',
	{ 'from-tag' => tt(), code => '*', volume => 10, duration => 100 });

snd($sock_b, $port_a, rtp(0, 4002, 8320, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96 | 0x80, 4002, 8320, $ssrc, "\x0a\x0a\x00\xa0"));
snd($sock_b, $port_a, rtp(0, 4003, 8480, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 4003, 8320, $ssrc, "\x0a\x0a\x01\x40"));
snd($sock_b, $port_a, rtp(0, 4004, 8640, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 4004, 8320, $ssrc, "\x0a\x0a\x01\xe0"));
snd($sock_b, $port_a, rtp(0, 4005, 8800, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 4005, 8320, $ssrc, "\x0a\x0a\x02\x80"));
snd($sock_b, $port_a, rtp(0, 4006, 8960, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 4006, 8320, $ssrc, "\x0a\x0a\x03\x20"));
snd($sock_b, $port_a, rtp(0, 4007, 9120, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 4007, 8320, $ssrc, "\x0a\x8a\x03\xc0"));
rcv($sock_a, $port_b, rtpm(96, 4008, 8320, $ssrc, "\x0a\x8a\x03\xc0"));
rcv($sock_a, $port_b, rtpm(96, 4009, 8320, $ssrc, "\x0a\x8a\x03\xc0"));
snd($sock_b, $port_a, rtp(0, 4008, 9280, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4010, 9280, $ssrc, "\x00" x 160));





# transcoding, RFC payload type present on both sides

($sock_a, $sock_b) = new_call([qw(198.51.100.1 6110)], [qw(198.51.100.3 6112)]);

($port_a) = offer('transcoding, RFC payload type present on both sides',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'],
	codec => { transcode => ['PCMA'] }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6110 RTP/AVP 0 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 96 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:96 telephone-event/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('transcoding, RFC payload type present on both sides',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6112 RTP/AVP 8 96
c=IN IP4 198.51.100.3
a=rtpmap:96 telephone-event/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(8, 1000, 3000, -1, "\x2a" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1001, 3160, $ssrc, "\x2a" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => '0', volume => 10, duration => 100 });

snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96 | 0x80, 1002, 3320, $ssrc, "\x00\x0a\x00\xa0"));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1003, 3320, $ssrc, "\x00\x0a\x01\x40"));
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1004, 3320, $ssrc, "\x00\x0a\x01\xe0"));
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1005, 3320, $ssrc, "\x00\x0a\x02\x80"));
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1006, 3320, $ssrc, "\x00\x0a\x03\x20"));
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1007, 3320, $ssrc, "\x00\x8a\x03\xc0"));
rcv($sock_b, $port_a, rtpm(96, 1008, 3320, $ssrc, "\x00\x8a\x03\xc0"));
rcv($sock_b, $port_a, rtpm(96, 1009, 3320, $ssrc, "\x00\x8a\x03\xc0"));
snd($sock_a, $port_b, rtp(0, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1010, 4280, $ssrc, "\x2a" x 160));



snd($sock_b, $port_a, rtp(8, 4000, 8000, 0x6543, "\x2a" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 8000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(8, 4001, 8160, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 8160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards A',
	{ 'from-tag' => tt(), code => '#', volume => -10, duration => 100 });

snd($sock_b, $port_a, rtp(8, 4002, 8320, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(96 | 0x80, 4002, 8320, $ssrc, "\x0b\x0a\x00\xa0"));
snd($sock_b, $port_a, rtp(8, 4003, 8480, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(96, 4003, 8320, $ssrc, "\x0b\x0a\x01\x40"));
snd($sock_b, $port_a, rtp(8, 4004, 8640, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(96, 4004, 8320, $ssrc, "\x0b\x0a\x01\xe0"));
snd($sock_b, $port_a, rtp(8, 4005, 8800, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(96, 4005, 8320, $ssrc, "\x0b\x0a\x02\x80"));
snd($sock_b, $port_a, rtp(8, 4006, 8960, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(96, 4006, 8320, $ssrc, "\x0b\x0a\x03\x20"));
snd($sock_b, $port_a, rtp(8, 4007, 9120, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(96, 4007, 8320, $ssrc, "\x0b\x8a\x03\xc0"));
rcv($sock_a, $port_b, rtpm(96, 4008, 8320, $ssrc, "\x0b\x8a\x03\xc0"));
rcv($sock_a, $port_b, rtpm(96, 4009, 8320, $ssrc, "\x0b\x8a\x03\xc0"));
snd($sock_b, $port_a, rtp(8, 4008, 9280, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4010, 9280, $ssrc, "\x00" x 160));



# no transcoding, no RFC payload type present

($sock_a, $sock_b) = new_call([qw(198.51.100.1 6014)], [qw(198.51.100.3 6016)]);

($port_a) = offer('no transcoding, no RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6014 RTP/AVP 0 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('no transcoding, no RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6016 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => 'C', volume => 5, duration => 120, pause => 110 });

snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, $ssrc, "\xff\x93\x94\xbc\x2e\x56\xbf\x2b\x13\x1b\xa7\x8e\x98\x47\x25\x41\xe2\x24\x16\x2b\x99\x8e\x9f\x28\x1e\x3d\x5b\x23\x1c\xdf\x92\x8f\xb6\x1c\x1c\x40\x5d\x26\x25\xaa\x8f\x95\x3b\x15\x1d\x5e\xde\x2c\x38\x9d\x8f\x9e\x1f\x11\x20\xc0\xc1\x37\xdd\x99\x92\xb7\x15\x10\x2c\xac\xb5\x49\xb8\x97\x99\x37\x0f\x13\x58\xa0\xae\x67\xae\x99\xa4\x1f\x0d\x1a\xae\x9b\xad\x7b\xad\x9d\xbf\x16\x0e\x27\x9d\x98\xb0\x55\xb1\xa6\x3a\x11\x11\x63\x95\x98\xbf\x3e\xbb\xb4\x26\x10\x1a\xa9\x90\x9a\x4e\x30\xce\xd4\x1e\x12\x29\x99\x8e\xa1\x2d\x29\x6d\x4b\x1c\x18\xef\x91\x8f\xb6\x1f\x24\x57\x3e\x1d\x20\xa9\x8e\x95\x3e\x19\x23\x67\x3e\x21\x31\x9c\x8e\x9e\x22\x14\x26\xcd\x4a"));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3480, $ssrc, "\x2a\xdf\x96\x90\xb5\x17\x13\x2f\xb6\xf5\x36\xb1\x93\x96\x39\x10\x15\x55\xaa\xc8\x4c\xa7\x95\xa0\x1f\x0e\x1b\xb4\xa1\xbd\xed\xa4\x99\xbb\x15\x0e\x27\xa0\x9d\xbd\xda\xa4\x9f\x39\x10\x11\x58\x98\x9c\xc8\xf9\xa9\xac\x23\x0e\x19\xab\x92\x9e\x59\x4c\xb0\xca\x1b\x10\x27\x9a\x90\xa5\x35\x3a\xbe\x43\x18\x15\x6c\x92\x91\xb7\x26\x30\xd6\x32\x18\x1d\xa9\x8e\x96\x44\x1d\x2d\xfc\x2e\x1b\x2d\x9a\x8d\x9e\x25\x19\x2d\xe7\x2f\x20\xea\x94\x8f\xb3\x19\x17\x36\xc8\x36\x2c\xae\x90\x95\x3b\x12\x18\x55\xb7\x43\x3e\xa1\x91\x9e\x1f\x0f\x1d\xba\xac\x64\xe8\x9d\x95\xb7\x15\x0e\x29\xa6\xa6\xda\xc3\x9d\x9b\x39\x0f\x11\x51\x9c\xa2\xd8\xbe\x9f\xa7\x21\x0e\x18\xad"));
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1004, 3640, $ssrc, "\x96\xa3\x68\xc4\xa5\xc2\x19\x0e\x26\x9c\x93\xa9\x3f\xdb\xae\x3e\x14\x12\x5b\x93\x93\xb9\x2e\x51\xbe\x2c\x14\x1b\xa9\x8f\x97\x4c\x25\x3f\xde\x25\x16\x2a\x9a\x8e\x9e\x29\x1e\x3b\x5e\x24\x1b\x7b\x92\x8f\xb2\x1c\x1c\x3e\x61\x27\x25\xac\x8f\x94\x3e\x15\x1c\x59\xdb\x2d\x37\x9e\x8f\x9d\x20\x11\x1f\xc2\xbf\x38\xea\x99\x92\xb4\x16\x10\x2b\xad\xb4\x49\xba\x98\x98\x3a\x0f\x12\x4e\xa1\xad\x68\xaf\x99\xa3\x20\x0d\x19\xb0\x9b\xac\x7b\xae\x9d\xbc\x17\x0e\x25\x9e\x98\xaf\x55\xb2\xa6\x3d\x12\x11\x52\x96\x97\xbd\x3e\xbc\xb3\x28\x10\x19\xab\x90\x9a\x54\x2f\xd0\xcf\x1f\x12\x27\x9a\x8e\xa0\x2e\x28\x66\x4e\x1d\x18\x62\x92\x8f\xb2\x20\x23\x53\x3f\x1d\x1f"));
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1005, 3800, $ssrc, "\xab\x8e\x94\x44\x19\x22\x61\x40\x21\x2f\x9c\x8e\x9d\x23\x14\x25\xce\x4d\x2a\xf7\x96\x8f\xb1\x18\x13\x2e\xb7\xe8\x36\xb3\x94\x96\x3c\x10\x15\x4d\xaa\xc5\x4b\xa8\x95\x9f\x20\x0e\x1a\xb6\xa0\xbc\xf5\xa4\x99\xb8\x16\x0e\x26\xa1\x9d\xbb\xdd\xa5\x9f\x3c\x10\x10\x4c\x99\x9b\xc5\x78\xaa\xac\x24\x0f\x18\xac\x93\x9d\x5f\x4a\xb1\xc7\x1c\x0f\x25\x9b\x90\xa3\x36\x39\xbf\x47\x18\x14\x56\x92\x90\xb4\x27\x2f\xd7\x34\x18\x1c\xab\x8e\x95\x4b\x1d\x2c\xfe\x2f\x1b\x2c\x9b\x8d\x9d\x27\x19\x2c\xe7\x30\x20\x6d\x94\x8f\xaf\x1a\x17\x34\xc8\x37\x2b\xaf\x91\x94\x3f\x12\x18\x4e\xb6\x45\x3d\xa3\x91\x9e\x20\x0f\x1c\xbc\xab\x6c\xf5\x9e\x95\xb3\x16\x0e\x27\xa7\xa5"));
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3960, $ssrc, "\xd6\xc6\x9d\x9b\x3d\x0f\x11\x49\x9c\xa1\xd4\xbf\x9f\xa6\x22\x0e\x18\xaf\x96\xa2\x6e\xc6\xa5\xbe\x19\x0e\x24\x9d\x93\xa8\x40\xe1\xae\x42\x15\x12\x4e\x94\x93\xb7\x2e\x4e\xbe\x2d\x14\x1a\xab\x8f\x97\x52\x25\x3e\xdc\x26\x16\x28\x9b\x8e\x9e\x2b\x1e\x3a\x61\x25\x1b\x5d\x93\x8f\xaf\x1d\x1c\x3d\x67\x27\x24\xad\x8f\x93\x45\x15\x1c\x53\xd7\x2d\x35\x9f\x8f\x9c\x22\x11\x1f\xc5\xbe\x38\x7a\x9a\x91\xb0\x17\x10\x29\xad\xb3\x4a\xbc\x98\x98\x3e\x10\x12\x48\xa1\xad\x6a\xb1\x9a\xa1\x21\x0e\x18\xb3\x9b\xab\x7d\xaf\x9d\xb9\x18\x0e\x23\x9f\x97\xae\x55\xb4\xa5\x40\x12\x10\x49\x96\x97\xbb\x3d\xbd\xb2\x29\x10\x18\xac\x90\x99\x5d\x2f\xd4\xcd\x1f\x12\x25\x9b"));
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1007, 4120, $ssrc, "\x8e\x9f\x2f\x28\x5f\x51\x1d\x17\x52\x92\x8f\xaf\x20\x22\x50\x42\x1e\x1f\xad\x8e\x93\x4b\x19\x21\x5d\x42\x22\x2e\x9d\x8e\x9c\x25\x14\x24\xd0\x4f\x2a\x68\x97\x8f\xae\x18\x12\x2c\xb7\xdf\x36\xb6\x94\x95\x41\x11\x14\x48\xaa\xc3\x4a\xaa\x95\x9e\x21\x0e\x19\xb8\xa0\xba\xfe\xa5\x99\xb4\x17\x0e\x24\xa2\x9c\xba\xe0\xa6\x9e\x40\x10\x10\x45\x99\x9b\xc2\x6d\xaa\xab\x26\x0f\x17\xae\x93\x9c\x6a\x48\xb2\xc3\x1c\x0f\x23\x9c\x90\xa2\x37\x38\xbf\x4b\x19\x14\x4b\x93\x90\xb1\x27\x2e\xd8\x36\x19\x1c\xad\x8e\x94\x52\x1d\x2b\x7d\x30\x1b\x2a\x9c\x8d\x9c\x28\x19\x2b\xe7\x31\x20\x5a\x95\x8f\xad\x1a\x16\x32\xc8\x39\x2b\xb2\x91\x94\x46\x13\x17\x4a\xb6\x48\x3c"));
# pause
snd($sock_a, $port_b, rtp(0, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1008, 4280, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1009, 4440, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1009, 4440, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1011, 4760, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1012, 4920, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1013, 5080, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1013, 5080, $ssrc, "\xff" x 80 . "\x00" x 80));



snd($sock_b, $port_a, rtp(0, 4000, 8000, 0x6543, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 8000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 8160, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 8160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards A',
	{ 'from-tag' => tt(), code => '4', volume => 3, duration => 150, pause => 100 });

snd($sock_b, $port_a, rtp(0, 4002, 8320, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 8320, $ssrc, "\xff\x90\x8a\x93\xd9\x1b\x18\x27\x65\xe5\x33\x29\x4c\x9e\x8f\x91\xb8\x15\x09\x0d\x32\x98\x8e\x96\xbb\x2c\x2b\x4c\xd8\x34\x1c\x18\x2e\x9d\x8c\x8c\xa5\x1a\x0b\x0d\x27\xa3\x97\x9e\xbd\x4f\xc4\xaa\xb2\x2c\x12\x0e\x1e\xa1\x8b\x8a\x9c\x25\x0e\x10\x25\xb7\xa7\xb7\x5e\xcb\xa2\x98\x9f\x30\x0f\x0a\x16\xae\x8d\x8a\x98\x3a\x18\x19\x2c\xdd\xfd\x30\x2b\xce\x99\x8e\x95\x4c\x0f\x09\x10\xdf\x93\x8e\x9a\xec\x28\x2c\x56\xee\x2d\x1a\x1a\x48\x97\x8b\x8e\xba\x14\x0a\x0f\x39\x9d\x96\xa1\xcd\x4e\xbe\xab\xbe\x23\x10\x10\x2b\x99\x8a\x8c\xa7\x1b\x0d\x12\x2f\xad\xa7\xbc\x5e\xbd\x9f\x99\xa8\x23\x0d\x0b\x1d\x9f\x8b\x8c\x9f\x29\x16\x1b\x34\xcd\x60\x2f\x2f\xb6\x96"));
snd($sock_b, $port_a, rtp(0, 4003, 8480, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4003, 8480, $ssrc, "\x8e\x9b\x2b\x0c\x09\x17\xae\x8f\x8e\x9e\x3f\x25\x2e\x65\x5c\x28\x1a\x1e\xc2\x92\x8a\x92\x44\x0f\x0a\x14\xd6\x99\x97\xa6\x7c\x4e\xba\xad\xe5\x1d\x0f\x13\x49\x92\x89\x8e\xbe\x15\x0d\x16\x43\xa8\xa7\xc1\x66\xb5\x9d\x9a\xb6\x1b\x0c\x0d\x2b\x98\x8a\x8d\xab\x1f\x15\x1d\x3f\xc7\x52\x2e\x39\xaa\x93\x8f\xa3\x1e\x0b\x0b\x1e\x9f\x8d\x8f\xa7\x30\x23\x31\x7c\x4a\x24\x1a\x24\xac\x8e\x8b\x99\x28\x0c\x0a\x1a\xb0\x96\x98\xac\x4f\x53\xb7\xaf\x44\x19\x0f\x18\xba\x8e\x89\x93\x3f\x10\x0d\x1a\xd5\xa3\xa8\xca\xf9\xae\x9c\x9d\xec\x16\x0b\x10\x4e\x91\x89\x90\xc6\x1a\x14\x20\x55\xc3\x4a\x2f\x49\xa2\x91\x92\xb2\x17\x09\x0c\x2d\x99\x8d\x92\xb3\x29\x23\x36\xf2"));
snd($sock_b, $port_a, rtp(0, 4004, 8640, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4004, 8640, $ssrc, "\x3e\x20\x1b\x2d\xa0\x8d\x8c\xa1\x1c\x0a\x0c\x22\xa3\x94\x9a\xb5\x44\x5c\xb5\xb6\x32\x16\x0f\x1e\xa6\x8c\x8a\x99\x28\x0e\x0e\x20\xb7\xa1\xab\xd4\xdb\xaa\x9c\xa1\x38\x11\x0b\x15\xb5\x8d\x8a\x96\x3f\x16\x15\x26\xdd\xc2\x43\x31\xdf\x9d\x90\x96\x6d\x11\x09\x0f\x5a\x93\x8c\x97\xd2\x23\x23\x3b\xf6\x37\x1f\x1d\x40\x9a\x8c\x8e\xb2\x15\x09\x0e\x31\x9c\x93\x9c\xc2\x3e\x74\xb4\xbf\x29\x14\x11\x29\x9b\x8a\x8b\xa3\x1c\x0d\x0f\x2a\xab\x9f\xad\xe0\xcc\xa6\x9c\xa9\x28\x0e\x0c\x1c\xa2\x8b\x8b\x9c\x2a\x14\x17\x2c\xc6\xc4\x3e\x36\xbd\x99\x90\x9b\x30\x0d\x09\x15\xb3\x8f\x8d\x9b\x42\x1f\x25\x42\x70\x30\x1e\x1f\xcf\x95\x8b\x92\x58\x0f\x09\x12\x6f\x98\x93"));
snd($sock_b, $port_a, rtp(0, 4005, 8800, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 8800, $ssrc, "\x9f\xe5\x3b\xe2\xb5\xd9\x21\x12\x14\x3e\x95\x89\x8d\xb6\x16\x0c\x13\x3a\xa4\x9f\xb1\xf1\xc0\xa3\x9d\xb4\x1e\x0d\x0d\x27\x99\x8a\x8c\xa7\x1f\x12\x19\x37\xbc\xc8\x3c\x3c\xaf\x97\x91\xa2\x21\x0b\x0a\x1c\xa2\x8d\x8e\xa2\x2f\x1e\x28\x4c\x5d\x2c\x1e\x25\xb0\x90\x8c\x98\x2c\x0c\x0a\x18\xb4\x94\x94\xa6\x4d\x3a\xd4\xb8\x4f\x1d\x11\x18\xc5\x8f\x89\x91\x4d\x10\x0c\x17\xec\x9f\xa0\xb8\xff\xba\xa1\x9f\xd3\x19\x0c\x0f\x3f\x92\x89\x8f\xbb\x19\x11\x1c\x48\xb8\xce\x3b\x4a\xa8\x95\x93\xaf\x19\x0a\x0c\x29\x99\x8c\x8f\xad\x27\x1d\x2b\x59\x4f\x29\x1e\x2d\xa5\x8e\x8d\x9f\x1e\x0b\x0b\x1e\xa4\x91\x96\xad\x3e\x3b\xcc\xbc\x3a\x1a\x12\x1e\xaa\x8d\x8a\x98\x2b"));
snd($sock_b, $port_a, rtp(0, 4006, 8960, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4006, 8960, $ssrc, "\x0e\x0c\x1d\xb8\x9d\xa2\xbe\xf9\xb4\xa0\xa3\x3f\x14\x0c\x14\xbd\x8e\x89\x93\x49\x15\x12\x1f\xe7\xb5\xd9\x3c\x7c\xa1\x93\x97\xd5\x13\x09\x0e\x45\x93\x8b\x93\xc4\x20\x1d\x2e\x6b\x46\x26\x1f\x3d\x9d\x8d\x8e\xae\x17\x09\x0d\x2c\x9c\x90\x98\xba\x36\x3d\xc7\xc4\x2e\x17\x13\x27\x9e\x8b\x8b\x9f\x1e\x0c\x0e\x25\xaa\x9c\xa5\xc8\xe8\xae\xa0\xaa\x2d\x10\x0c\x1b\xa6\x8c\x8a\x9a\x2c\x12\x13\x27\xc3\xb3\xed\x3e\xc8\x9d\x93\x9b\x38\x0f\x09\x13\xba\x8f\x8b\x98\x4a\x1d\x1e\x34\xf9\x3e\x24\x23\xea\x98\x8c\x92\xdf\x10\x09\x0f\x4d\x97\x90\x9c\xd2\x31\x3f\xc5\xd6\x28\x16\x16\x39\x97\x8a\x8d\xaf\x17\x0b\x10\x32\xa2\x9b\xa8\xd6\xd9\xac\xa1\xb3\x22\x0e\x0e"));
snd($sock_b, $port_a, rtp(0, 4007, 9120, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4007, 9120, $ssrc, "\x24\x9b\x8a\x8b\xa2\x1f\x10\x15\x2f\xb8\xb4\x68\x43\xb8\x9a\x94\xa1\x25\x0c\x0a\x1a\xa5\x8d\x8c\x9e\x30\x1b\x1f\x3c\xee\x38\x23\x28\xb8\x93\x8d\x97\x31\x0d\x09\x15\xb9\x93\x90\xa0\x4f\x2f\x46\xc4\x5e\x21\x15\x19\xd7\x91\x89\x90\x7b\x10\x0b\x14\x5b\x9d\x9c\xad\xed\xcd\xa9\xa3\xca\x1c\x0d\x10\x38\x94\x89\x8e\xb3\x19\x0f\x18\x3e\xb0\xb5\x59\x4d\xae\x98\x95\xad\x1c\x0b\x0c\x25\x9b\x8b\x8e\xa9\x26\x1a\x22\x46\xf5\x33\x23\x2e\xaa\x90\x8d\x9e\x21\x0b\x0a\x1c\xa6\x90\x92\xa8\x3b\x2e\x4d\xc7\x43\x1e\x15\x1e\xaf\x8e\x8a\x96\x2e\x0e\x0b\x1a\xbb\x9b\x9d\xb2\x68\xc5\xa8\xa7\x4c\x17\x0d\x14\xcb\x8f\x89\x91\x5e\x14\x0f\x1c\x6e\xad\xb8\x52\x68\xa8"));
snd($sock_b, $port_a, rtp(0, 4008, 9280, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4008, 9280, $ssrc, "\x97\x98\xc7\x16\x0a\x0e\x3a\x94\x8a\x90\xbb\x1e\x1a\x27\x56\x6f\x2f\x25\x3b\xa0\x8e\x8f\xaa\x19\x09\x0c\x28\x9c\x8f\x95\xb2\x31\x2e\x59\xcc\x37\x1b\x16\x26\xa1\x8c\x8b\x9d\x1f\x0c\x0c\x20\xab\x99\x9e\xbb\x5d\xbe\xa7\xac\x32\x13\x0d\x1a\xab\x8c\x89\x97\x2e\x10\x10\x21\xc3\xab\xbc\x4f\xd4\xa2\x96\x9c\x3f\x10\x0a\x12\xc4\x8f\x8a\x95\x57\x1b\x1a\x2b\xfd\x5d\x2d\x27\x62\x9b\x8e\x92\xc9\x12\x09\x0e\x3f\x97\x8e\x98\xc6\x2c\x2f\x6b\xd9\x2e\x1a\x18\x34\x9a\x8b\x8d\xab\x18\x0a\x0e\x2d\xa1\x98\xa1\xc7\x5b\xb9\xa7\xb4\x27\x10\x0e\x22\x9d\x8a\x8b\x9f\x20\x0e\x12\x2a\xb4\xaa\xc0\x50\xc0\x9e\x97\xa1\x2a\x0e\x0a\x19\xa8\x8c\x8b\x9b\x31\x18\x1b\x31"));
snd($sock_b, $port_a, rtp(0, 4009, 9440, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4009, 9440, $ssrc, "\xda\x50\x2c\x2b\xc0\x97\x8e\x97\x39\x0e\x09\x13\xbf\x92\x8e\x9c\x57\x29\x31\xef\x72\x28\x19\x1b\x6d\x94\x8a\x8f\xce\x11\x0a\x11\x48\x9c\x98\xa5\xdc\x5e\xb5\xa9\xc6\x1f\x0f\x10\x31\x96\x89\x8d\xad\x19\x0e\x15\x37\xac\xaa\xc8\x57\xb7\x9c\x98\xac\x1e\x0c\x0c\x21\x9c\x8b\x8d\xa4\x25\x17\x1d\x3b\xcf\x48\x2b\x30\xae\x93\x8e" . "\xff" x 80));
# pause
snd($sock_b, $port_a, rtp(0, 4010, 9600, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4010, 9600, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(0, 4011, 9760, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4011, 9760, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(0, 4012, 9920, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4012, 9920, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(0, 4013, 10080, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4013, 10080, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(0, 4014, 10240, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4014, 10240, $ssrc, "\xff" x 80 . "\x00" x 80));




# transcoding, no RFC payload type present

($sock_a, $sock_b) = new_call([qw(198.51.100.1 6018)], [qw(198.51.100.3 6020)]);

($port_a) = offer('transcoding, no RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'],
	codec => { transcode => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6018 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('transcoding, no RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6020 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(8, 1000, 3000, -1, "\x2a" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1001, 3160, $ssrc, "\x2a" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => 'C', volume => 5, duration => 120 });

snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1002, 3320, $ssrc, "\xd5\xb9\xbe\x97\x05\x70\xea\x01\x3e\x31\x82\xa5\xb2\x63\x0f\x69\xc1\x0f\x3d\x06\xb3\xa4\x8a\x03\x35\x14\x75\x0e\x36\xcc\xb8\xa5\x9d\x36\x36\x68\x49\x0d\x0c\x81\xa5\xbf\x16\x3f\x37\x4f\xcf\x07\x13\xb4\xa5\xb4\x0a\x3b\x0b\xeb\xe9\x12\xc9\xb3\xb8\x92\x3c\x3a\x07\x87\x9c\x61\x93\xb2\xb3\x12\x25\x39\x76\x8b\x85\x5a\x85\xb3\x8e\x35\x24\x30\x85\xb1\x87\x57\x84\xb7\xeb\x3c\x24\x0d\xb4\xb2\x9b\x70\x98\x8c\x11\x3b\x38\x41\xbf\xb2\xeb\x15\x96\x9f\x0d\x3a\x30\x83\xba\xb1\x7b\x1b\xfa\xf2\x34\x39\x03\xb0\xa5\x88\x04\x03\x5f\x67\x37\x32\xdd\xb8\xba\x9d\x35\x0e\x71\x15\x37\x0a\x80\xa4\xbf\x15\x33\x09\x45\x15\x0b\x18\xb6\xa4\xb4\x08\x3f\x0d\xe5\x66"));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1003, 3480, $ssrc, "\x00\xcd\xbc\xba\x9c\x3d\x39\x1a\x9d\xd1\x1d\x98\xbe\xbd\x10\x3a\x3f\x73\x80\xe0\x64\x82\xbf\x8b\x35\x24\x31\x9f\x8b\x94\xdf\x8e\xb3\x96\x3c\x24\x02\x8b\xb7\x94\xf4\x8f\xb5\x10\x3a\x3b\x76\xb2\xb6\xe0\xd6\x80\x87\x09\x25\x33\x81\xb9\xb4\x74\x64\x9b\xe6\x31\x3a\x0d\xb1\xba\x8f\x1c\x11\x95\x6f\x32\x3f\x5e\xb8\xbb\x92\x0d\x1a\xf0\x19\x32\x37\x83\xa4\xbc\x6d\x37\x07\xd4\x04\x31\x07\xb1\xa4\xb4\x0c\x33\x04\xc5\x05\x0b\xd8\xbe\xa5\x9e\x30\x3d\x1d\xe0\x1d\x06\x84\xbb\xbf\x16\x38\x33\x73\x92\x6f\x15\x88\xbb\xb5\x35\x25\x37\x91\x86\x46\xda\xb7\xbf\x92\x3c\x25\x03\x8d\x8c\xf4\xef\xb7\xb6\x10\x25\x3b\x7f\xb6\x89\xf6\x95\xb5\x82\x0b\x24\x33\x84"));
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1004, 3640, $ssrc, "\xbd\x8e\x5a\xec\x8c\xee\x33\x24\x0c\xb6\xbe\x80\x6b\xf5\x85\x6a\x3f\x39\x4a\xbe\xbe\x90\x05\x7f\x95\x06\x3e\x31\x80\xa5\xbd\x64\x0f\x6b\xcc\x0c\x3d\x00\xb0\xa4\xb5\x00\x34\x16\x4e\x0e\x36\x57\xb9\xa5\x99\x36\x36\x6a\x43\x0d\x0f\x86\xa5\xbe\x15\x3f\x36\x77\xf5\x07\x12\xb4\xa5\xb4\x0b\x3b\x0a\xee\xeb\x13\xd8\xb0\xb8\x9f\x3c\x3a\x01\x87\x9f\x66\x91\xb2\xb3\x11\x25\x39\x7a\x8b\x84\x5b\x9a\xb0\x89\x0a\x24\x33\x9b\xb1\x87\x54\x85\xb7\x97\x3d\x24\x0c\xb4\xb2\x9a\x73\x99\x8c\x14\x38\x3b\x7c\xbc\xbd\x94\x15\x97\x9e\x02\x3a\x33\x81\xba\xb0\x73\x1a\xfe\xf9\x35\x39\x02\xb1\xa4\x8a\x05\x03\x44\x7a\x37\x32\x40\xb8\xa5\x99\x0a\x0e\x72\x6b\x34\x35"));
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1005, 3800, $ssrc, "\x81\xa4\xbe\x6c\x33\x08\x43\x68\x08\x1a\xb7\xa4\xb7\x0e\x3f\x0c\xfb\x65\x00\xd1\xbd\xba\x98\x32\x39\x04\x92\xdb\x1d\x9e\xbe\xbc\x17\x3a\x3f\x65\x80\xed\x67\x83\xbf\xb5\x0a\x24\x30\x9d\x8b\x97\xd0\x8f\xb3\x93\x3c\x24\x0c\x88\xb7\x96\xc9\x8c\xb5\x17\x3a\x3a\x64\xb3\xb6\xed\x56\x80\x86\x0f\x25\x32\x87\xb9\xb7\x4d\x66\x98\xe3\x36\x3a\x0c\xb1\xba\x8e\x1d\x10\xea\x63\x33\x3f\x70\xb9\xbb\x9f\x0d\x05\xf1\x1f\x33\x36\x81\xa4\xbf\x67\x34\x06\xd5\x05\x31\x06\xb6\xa4\xb7\x0d\x33\x07\xc5\x1a\x0a\x5f\xbe\xa5\x9a\x30\x3d\x1f\xe0\x12\x06\x9a\xbb\xbf\x6b\x39\x32\x7b\x9d\x62\x14\x89\xbb\xb4\x0b\x25\x36\x97\x86\x5e\xd1\xb4\xbf\x9e\x3c\x24\x0d\x82\x8c"));
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1006, 3960, $ssrc, "\xf0\xe2\xb7\xb1\x14\x3a\x3b\x61\xb6\x88\xf3\xeb\xb5\x8d\x09\x24\x32\x85\xbd\x89\x5c\xe2\x8c\x95\x30\x24\x0e\xb7\xb9\x83\x68\xc3\x85\x6e\x3f\x38\x7a\xbe\xb9\x92\x05\x7a\x95\x07\x3e\x30\x86\xa5\xbd\x7c\x0f\x15\xcb\x0d\x3d\x03\xb1\xa4\xb4\x01\x34\x11\x40\x0f\x36\x48\xb9\xa5\x85\x37\x36\x14\x45\x02\x0f\x84\xa5\xbe\x6d\x3c\x36\x7d\xf1\x04\x1c\xb5\xa5\xb7\x09\x3b\x35\xed\xea\x13\x57\xb0\xb8\x9b\x3d\x3a\x00\x84\x9e\x66\x97\xb2\xb2\x15\x3a\x38\x60\x8b\x87\x58\x98\xb0\x88\x08\x24\x32\x9e\xb1\x86\x54\x9a\xb7\x90\x32\x24\x0e\xb5\xb2\x84\x73\x9f\x8c\x68\x38\x3b\x61\xbc\xbd\x96\x14\x94\x99\x03\x3b\x32\x87\xba\xb3\x48\x1a\xf2\xe5\x0a\x39\x0c\xb1"));
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1007, 4120, $ssrc, "\xa4\xb5\x1a\x02\x4c\x7f\x37\x32\x7c\xb9\xa5\x9a\x0a\x09\x7e\x6e\x34\x35\x87\xa5\xbe\x67\x33\x0b\x48\x6e\x08\x05\xb7\xa4\xb6\x0f\x3f\x0e\xfe\x79\x00\x5a\xbd\xa5\x85\x32\x39\x07\x92\xcd\x1d\x9d\xbe\xbc\x69\x3b\x3e\x60\x80\xef\x66\x80\xbf\xb5\x08\x24\x30\x90\x8b\x91\xd5\x8c\xb3\x9f\x3d\x24\x0e\x89\xb7\x91\xc2\x8c\xb5\x68\x3b\x3a\x6d\xb3\xb1\xee\x5c\x81\x81\x0c\x25\x3d\x85\xb9\xb7\x58\x60\x99\xef\x37\x3a\x0e\xb6\xba\x89\x12\x13\xeb\x67\x33\x3e\x67\xb9\xba\x98\x02\x05\xf7\x1d\x33\x36\x87\xa4\xbe\x7c\x34\x01\x54\x1a\x31\x01\xb6\xa4\xb6\x03\x33\x06\xda\x18\x0a\x75\xbf\xa5\x84\x31\x3d\x19\xe0\x10\x01\x99\xbb\xbe\x62\x39\x3d\x66\x9d\x60\x17"));
# pause
snd($sock_a, $port_b, rtp(0, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1008, 4280, $ssrc, "\xd5" x 160));
snd($sock_a, $port_b, rtp(0, 1009, 4440, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1009, 4440, $ssrc, "\xd5" x 160));
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1010, 4600, $ssrc, "\xd5" x 160));
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1011, 4760, $ssrc, "\xd5" x 160));
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1012, 4920, $ssrc, "\xd5" x 160));
snd($sock_a, $port_b, rtp(0, 1013, 5080, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1013, 5080, $ssrc, "\x2a" x 160));




snd($sock_b, $port_a, rtp(8, 4000, 8000, 0x6543, "\x2a" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 8000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(8, 4001, 8160, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 8160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards A',
	{ 'from-tag' => tt(), code => '4', volume => 3, duration => 150 });

snd($sock_b, $port_a, rtp(8, 4002, 8320, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 8320, $ssrc, "\xff\x90\x8a\x93\xd9\x1b\x18\x27\x65\xe5\x33\x29\x4c\x9e\x8f\x91\xb8\x15\x09\x0d\x32\x98\x8e\x96\xbb\x2c\x2b\x4c\xd8\x34\x1c\x18\x2e\x9d\x8c\x8c\xa5\x1a\x0b\x0d\x27\xa3\x97\x9e\xbd\x4f\xc4\xaa\xb2\x2c\x12\x0e\x1e\xa1\x8b\x8a\x9c\x25\x0e\x10\x25\xb7\xa7\xb7\x5e\xcb\xa2\x98\x9f\x30\x0f\x0a\x16\xae\x8d\x8a\x98\x3a\x18\x19\x2c\xdd\xfd\x30\x2b\xce\x99\x8e\x95\x4c\x0f\x09\x10\xdf\x93\x8e\x9a\xec\x28\x2c\x56\xee\x2d\x1a\x1a\x48\x97\x8b\x8e\xba\x14\x0a\x0f\x39\x9d\x96\xa1\xcd\x4e\xbe\xab\xbe\x23\x10\x10\x2b\x99\x8a\x8c\xa7\x1b\x0d\x12\x2f\xad\xa7\xbc\x5e\xbd\x9f\x99\xa8\x23\x0d\x0b\x1d\x9f\x8b\x8c\x9f\x29\x16\x1b\x34\xcd\x60\x2f\x2f\xb6\x96"));
snd($sock_b, $port_a, rtp(8, 4003, 8480, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4003, 8480, $ssrc, "\x8e\x9b\x2b\x0c\x09\x17\xae\x8f\x8e\x9e\x3f\x25\x2e\x65\x5c\x28\x1a\x1e\xc2\x92\x8a\x92\x44\x0f\x0a\x14\xd6\x99\x97\xa6\x7c\x4e\xba\xad\xe5\x1d\x0f\x13\x49\x92\x89\x8e\xbe\x15\x0d\x16\x43\xa8\xa7\xc1\x66\xb5\x9d\x9a\xb6\x1b\x0c\x0d\x2b\x98\x8a\x8d\xab\x1f\x15\x1d\x3f\xc7\x52\x2e\x39\xaa\x93\x8f\xa3\x1e\x0b\x0b\x1e\x9f\x8d\x8f\xa7\x30\x23\x31\x7c\x4a\x24\x1a\x24\xac\x8e\x8b\x99\x28\x0c\x0a\x1a\xb0\x96\x98\xac\x4f\x53\xb7\xaf\x44\x19\x0f\x18\xba\x8e\x89\x93\x3f\x10\x0d\x1a\xd5\xa3\xa8\xca\xf9\xae\x9c\x9d\xec\x16\x0b\x10\x4e\x91\x89\x90\xc6\x1a\x14\x20\x55\xc3\x4a\x2f\x49\xa2\x91\x92\xb2\x17\x09\x0c\x2d\x99\x8d\x92\xb3\x29\x23\x36\xf2"));
snd($sock_b, $port_a, rtp(8, 4004, 8640, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4004, 8640, $ssrc, "\x3e\x20\x1b\x2d\xa0\x8d\x8c\xa1\x1c\x0a\x0c\x22\xa3\x94\x9a\xb5\x44\x5c\xb5\xb6\x32\x16\x0f\x1e\xa6\x8c\x8a\x99\x28\x0e\x0e\x20\xb7\xa1\xab\xd4\xdb\xaa\x9c\xa1\x38\x11\x0b\x15\xb5\x8d\x8a\x96\x3f\x16\x15\x26\xdd\xc2\x43\x31\xdf\x9d\x90\x96\x6d\x11\x09\x0f\x5a\x93\x8c\x97\xd2\x23\x23\x3b\xf6\x37\x1f\x1d\x40\x9a\x8c\x8e\xb2\x15\x09\x0e\x31\x9c\x93\x9c\xc2\x3e\x74\xb4\xbf\x29\x14\x11\x29\x9b\x8a\x8b\xa3\x1c\x0d\x0f\x2a\xab\x9f\xad\xe0\xcc\xa6\x9c\xa9\x28\x0e\x0c\x1c\xa2\x8b\x8b\x9c\x2a\x14\x17\x2c\xc6\xc4\x3e\x36\xbd\x99\x90\x9b\x30\x0d\x09\x15\xb3\x8f\x8d\x9b\x42\x1f\x25\x42\x70\x30\x1e\x1f\xcf\x95\x8b\x92\x58\x0f\x09\x12\x6f\x98\x93"));
snd($sock_b, $port_a, rtp(8, 4005, 8800, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 8800, $ssrc, "\x9f\xe5\x3b\xe2\xb5\xd9\x21\x12\x14\x3e\x95\x89\x8d\xb6\x16\x0c\x13\x3a\xa4\x9f\xb1\xf1\xc0\xa3\x9d\xb4\x1e\x0d\x0d\x27\x99\x8a\x8c\xa7\x1f\x12\x19\x37\xbc\xc8\x3c\x3c\xaf\x97\x91\xa2\x21\x0b\x0a\x1c\xa2\x8d\x8e\xa2\x2f\x1e\x28\x4c\x5d\x2c\x1e\x25\xb0\x90\x8c\x98\x2c\x0c\x0a\x18\xb4\x94\x94\xa6\x4d\x3a\xd4\xb8\x4f\x1d\x11\x18\xc5\x8f\x89\x91\x4d\x10\x0c\x17\xec\x9f\xa0\xb8\xff\xba\xa1\x9f\xd3\x19\x0c\x0f\x3f\x92\x89\x8f\xbb\x19\x11\x1c\x48\xb8\xce\x3b\x4a\xa8\x95\x93\xaf\x19\x0a\x0c\x29\x99\x8c\x8f\xad\x27\x1d\x2b\x59\x4f\x29\x1e\x2d\xa5\x8e\x8d\x9f\x1e\x0b\x0b\x1e\xa4\x91\x96\xad\x3e\x3b\xcc\xbc\x3a\x1a\x12\x1e\xaa\x8d\x8a\x98\x2b"));
snd($sock_b, $port_a, rtp(8, 4006, 8960, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4006, 8960, $ssrc, "\x0e\x0c\x1d\xb8\x9d\xa2\xbe\xf9\xb4\xa0\xa3\x3f\x14\x0c\x14\xbd\x8e\x89\x93\x49\x15\x12\x1f\xe7\xb5\xd9\x3c\x7c\xa1\x93\x97\xd5\x13\x09\x0e\x45\x93\x8b\x93\xc4\x20\x1d\x2e\x6b\x46\x26\x1f\x3d\x9d\x8d\x8e\xae\x17\x09\x0d\x2c\x9c\x90\x98\xba\x36\x3d\xc7\xc4\x2e\x17\x13\x27\x9e\x8b\x8b\x9f\x1e\x0c\x0e\x25\xaa\x9c\xa5\xc8\xe8\xae\xa0\xaa\x2d\x10\x0c\x1b\xa6\x8c\x8a\x9a\x2c\x12\x13\x27\xc3\xb3\xed\x3e\xc8\x9d\x93\x9b\x38\x0f\x09\x13\xba\x8f\x8b\x98\x4a\x1d\x1e\x34\xf9\x3e\x24\x23\xea\x98\x8c\x92\xdf\x10\x09\x0f\x4d\x97\x90\x9c\xd2\x31\x3f\xc5\xd6\x28\x16\x16\x39\x97\x8a\x8d\xaf\x17\x0b\x10\x32\xa2\x9b\xa8\xd6\xd9\xac\xa1\xb3\x22\x0e\x0e"));
snd($sock_b, $port_a, rtp(8, 4007, 9120, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4007, 9120, $ssrc, "\x24\x9b\x8a\x8b\xa2\x1f\x10\x15\x2f\xb8\xb4\x68\x43\xb8\x9a\x94\xa1\x25\x0c\x0a\x1a\xa5\x8d\x8c\x9e\x30\x1b\x1f\x3c\xee\x38\x23\x28\xb8\x93\x8d\x97\x31\x0d\x09\x15\xb9\x93\x90\xa0\x4f\x2f\x46\xc4\x5e\x21\x15\x19\xd7\x91\x89\x90\x7b\x10\x0b\x14\x5b\x9d\x9c\xad\xed\xcd\xa9\xa3\xca\x1c\x0d\x10\x38\x94\x89\x8e\xb3\x19\x0f\x18\x3e\xb0\xb5\x59\x4d\xae\x98\x95\xad\x1c\x0b\x0c\x25\x9b\x8b\x8e\xa9\x26\x1a\x22\x46\xf5\x33\x23\x2e\xaa\x90\x8d\x9e\x21\x0b\x0a\x1c\xa6\x90\x92\xa8\x3b\x2e\x4d\xc7\x43\x1e\x15\x1e\xaf\x8e\x8a\x96\x2e\x0e\x0b\x1a\xbb\x9b\x9d\xb2\x68\xc5\xa8\xa7\x4c\x17\x0d\x14\xcb\x8f\x89\x91\x5e\x14\x0f\x1c\x6e\xad\xb8\x52\x68\xa8"));
snd($sock_b, $port_a, rtp(8, 4008, 9280, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4008, 9280, $ssrc, "\x97\x98\xc7\x16\x0a\x0e\x3a\x94\x8a\x90\xbb\x1e\x1a\x27\x56\x6f\x2f\x25\x3b\xa0\x8e\x8f\xaa\x19\x09\x0c\x28\x9c\x8f\x95\xb2\x31\x2e\x59\xcc\x37\x1b\x16\x26\xa1\x8c\x8b\x9d\x1f\x0c\x0c\x20\xab\x99\x9e\xbb\x5d\xbe\xa7\xac\x32\x13\x0d\x1a\xab\x8c\x89\x97\x2e\x10\x10\x21\xc3\xab\xbc\x4f\xd4\xa2\x96\x9c\x3f\x10\x0a\x12\xc4\x8f\x8a\x95\x57\x1b\x1a\x2b\xfd\x5d\x2d\x27\x62\x9b\x8e\x92\xc9\x12\x09\x0e\x3f\x97\x8e\x98\xc6\x2c\x2f\x6b\xd9\x2e\x1a\x18\x34\x9a\x8b\x8d\xab\x18\x0a\x0e\x2d\xa1\x98\xa1\xc7\x5b\xb9\xa7\xb4\x27\x10\x0e\x22\x9d\x8a\x8b\x9f\x20\x0e\x12\x2a\xb4\xaa\xc0\x50\xc0\x9e\x97\xa1\x2a\x0e\x0a\x19\xa8\x8c\x8b\x9b\x31\x18\x1b\x31"));
snd($sock_b, $port_a, rtp(8, 4009, 9440, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4009, 9440, $ssrc, "\xda\x50\x2c\x2b\xc0\x97\x8e\x97\x39\x0e\x09\x13\xbf\x92\x8e\x9c\x57\x29\x31\xef\x72\x28\x19\x1b\x6d\x94\x8a\x8f\xce\x11\x0a\x11\x48\x9c\x98\xa5\xdc\x5e\xb5\xa9\xc6\x1f\x0f\x10\x31\x96\x89\x8d\xad\x19\x0e\x15\x37\xac\xaa\xc8\x57\xb7\x9c\x98\xac\x1e\x0c\x0c\x21\x9c\x8b\x8d\xa4\x25\x17\x1d\x3b\xcf\x48\x2b\x30\xae\x93\x8e" . "\xff" x 80));
# pause
snd($sock_b, $port_a, rtp(0, 4010, 9600, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4010, 9600, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(0, 4011, 9760, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4011, 9760, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(0, 4012, 9920, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4012, 9920, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(0, 4013, 10080, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4013, 10080, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(0, 4014, 10240, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4014, 10240, $ssrc, "\xff" x 80 . "\x00" x 80));




# multiple consecutive DTMF events

($sock_a, $sock_b) = new_call([qw(198.51.100.1 6024)], [qw(198.51.100.3 6026)]);

($port_a) = offer('multiple consecutive DTMF events',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6024 RTP/AVP 0 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('multiple consecutive DTMF events',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6026 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => 'C', volume => 5, duration => 100 });
$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => '4', volume => 5, duration => 100 });

snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, $ssrc, "\xff\x93\x94\xbc\x2e\x56\xbf\x2b\x13\x1b\xa7\x8e\x98\x47\x25\x41\xe2\x24\x16\x2b\x99\x8e\x9f\x28\x1e\x3d\x5b\x23\x1c\xdf\x92\x8f\xb6\x1c\x1c\x40\x5d\x26\x25\xaa\x8f\x95\x3b\x15\x1d\x5e\xde\x2c\x38\x9d\x8f\x9e\x1f\x11\x20\xc0\xc1\x37\xdd\x99\x92\xb7\x15\x10\x2c\xac\xb5\x49\xb8\x97\x99\x37\x0f\x13\x58\xa0\xae\x67\xae\x99\xa4\x1f\x0d\x1a\xae\x9b\xad\x7b\xad\x9d\xbf\x16\x0e\x27\x9d\x98\xb0\x55\xb1\xa6\x3a\x11\x11\x63\x95\x98\xbf\x3e\xbb\xb4\x26\x10\x1a\xa9\x90\x9a\x4e\x30\xce\xd4\x1e\x12\x29\x99\x8e\xa1\x2d\x29\x6d\x4b\x1c\x18\xef\x91\x8f\xb6\x1f\x24\x57\x3e\x1d\x20\xa9\x8e\x95\x3e\x19\x23\x67\x3e\x21\x31\x9c\x8e\x9e\x22\x14\x26\xcd\x4a"));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3480, $ssrc, "\x2a\xdf\x96\x90\xb5\x17\x13\x2f\xb6\xf5\x36\xb1\x93\x96\x39\x10\x15\x55\xaa\xc8\x4c\xa7\x95\xa0\x1f\x0e\x1b\xb4\xa1\xbd\xed\xa4\x99\xbb\x15\x0e\x27\xa0\x9d\xbd\xda\xa4\x9f\x39\x10\x11\x58\x98\x9c\xc8\xf9\xa9\xac\x23\x0e\x19\xab\x92\x9e\x59\x4c\xb0\xca\x1b\x10\x27\x9a\x90\xa5\x35\x3a\xbe\x43\x18\x15\x6c\x92\x91\xb7\x26\x30\xd6\x32\x18\x1d\xa9\x8e\x96\x44\x1d\x2d\xfc\x2e\x1b\x2d\x9a\x8d\x9e\x25\x19\x2d\xe7\x2f\x20\xea\x94\x8f\xb3\x19\x17\x36\xc8\x36\x2c\xae\x90\x95\x3b\x12\x18\x55\xb7\x43\x3e\xa1\x91\x9e\x1f\x0f\x1d\xba\xac\x64\xe8\x9d\x95\xb7\x15\x0e\x29\xa6\xa6\xda\xc3\x9d\x9b\x39\x0f\x11\x51\x9c\xa2\xd8\xbe\x9f\xa7\x21\x0e\x18\xad"));
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1004, 3640, $ssrc, "\x96\xa3\x68\xc4\xa5\xc2\x19\x0e\x26\x9c\x93\xa9\x3f\xdb\xae\x3e\x14\x12\x5b\x93\x93\xb9\x2e\x51\xbe\x2c\x14\x1b\xa9\x8f\x97\x4c\x25\x3f\xde\x25\x16\x2a\x9a\x8e\x9e\x29\x1e\x3b\x5e\x24\x1b\x7b\x92\x8f\xb2\x1c\x1c\x3e\x61\x27\x25\xac\x8f\x94\x3e\x15\x1c\x59\xdb\x2d\x37\x9e\x8f\x9d\x20\x11\x1f\xc2\xbf\x38\xea\x99\x92\xb4\x16\x10\x2b\xad\xb4\x49\xba\x98\x98\x3a\x0f\x12\x4e\xa1\xad\x68\xaf\x99\xa3\x20\x0d\x19\xb0\x9b\xac\x7b\xae\x9d\xbc\x17\x0e\x25\x9e\x98\xaf\x55\xb2\xa6\x3d\x12\x11\x52\x96\x97\xbd\x3e\xbc\xb3\x28\x10\x19\xab\x90\x9a\x54\x2f\xd0\xcf\x1f\x12\x27\x9a\x8e\xa0\x2e\x28\x66\x4e\x1d\x18\x62\x92\x8f\xb2\x20\x23\x53\x3f\x1d\x1f"));
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1005, 3800, $ssrc, "\xab\x8e\x94\x44\x19\x22\x61\x40\x21\x2f\x9c\x8e\x9d\x23\x14\x25\xce\x4d\x2a\xf7\x96\x8f\xb1\x18\x13\x2e\xb7\xe8\x36\xb3\x94\x96\x3c\x10\x15\x4d\xaa\xc5\x4b\xa8\x95\x9f\x20\x0e\x1a\xb6\xa0\xbc\xf5\xa4\x99\xb8\x16\x0e\x26\xa1\x9d\xbb\xdd\xa5\x9f\x3c\x10\x10\x4c\x99\x9b\xc5\x78\xaa\xac\x24\x0f\x18\xac\x93\x9d\x5f\x4a\xb1\xc7\x1c\x0f\x25\x9b\x90\xa3\x36\x39\xbf\x47\x18\x14\x56\x92\x90\xb4\x27\x2f\xd7\x34\x18\x1c\xab\x8e\x95\x4b\x1d\x2c\xfe\x2f\x1b\x2c\x9b\x8d\x9d\x27\x19\x2c\xe7\x30\x20\x6d\x94\x8f\xaf\x1a\x17\x34\xc8\x37\x2b\xaf\x91\x94\x3f\x12\x18\x4e\xb6\x45\x3d\xa3\x91\x9e\x20\x0f\x1c\xbc\xab\x6c\xf5\x9e\x95\xb3\x16\x0e\x27\xa7\xa5"));
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3960, $ssrc, "\xd6\xc6\x9d\x9b\x3d\x0f\x11\x49\x9c\xa1\xd4\xbf\x9f\xa6\x22\x0e\x18\xaf\x96\xa2\x6e\xc6\xa5\xbe\x19\x0e\x24\x9d\x93\xa8\x40\xe1\xae\x42\x15\x12\x4e\x94\x93\xb7\x2e\x4e\xbe\x2d\x14\x1a\xab\x8f\x97\x52\x25\x3e\xdc\x26\x16\x28\x9b\x8e\x9e\x2b\x1e\x3a\x61\x25\x1b\x5d\x93\x8f\xaf\x1d\x1c\x3d\x67\x27\x24\xad\x8f\x93\x45\x15\x1c\x53\xd7\x2d\x35\x9f\x8f\x9c\x22\x11\x1f\xc5\xbe\x38\x7a\x9a\x91\xb0\x17\x10\x29\xad\xb3\x4a\xbc\x98\x98\x3e\x10\x12\x48\xa1\xad\x6a\xb1\x9a\xa1\x21\x0e\x18\xb3\x9b\xab\x7d\xaf\x9d\xb9\x18\x0e\x23\x9f\x97\xae\x55\xb4\xa5\x40\x12\x10\x49\x96\x97\xbb\x3d\xbd\xb2\x29\x10\x18\xac\x90\x99\x5d\x2f\xd4\xcd\x1f\x12\x25\x9b"));
# pause
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1007, 4120, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1008, 4280, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1009, 4440, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1009, 4440, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1011, 4760, $ssrc, "\xff" x 160));
# next event
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1012, 4920, $ssrc, "\xff\x96\x8e\x99\xdd\x1f\x1d\x2c\x69\xe9\x39\x2d\x50\xa3\x95\x97\xbd\x1a\x0e\x12\x38\x9d\x93\x9b\xbf\x30\x2f\x4f\xdc\x39\x20\x1d\x33\xa2\x90\x91\xaa\x1f\x0f\x12\x2c\xa9\x9c\xa3\xc2\x55\xc9\xaf\xb8\x30\x18\x14\x24\xa7\x8f\x8e\xa0\x2a\x14\x16\x2a\xbc\xac\xbc\x61\xcf\xa8\x9d\xa6\x36\x15\x0f\x1b\xb4\x92\x8f\x9d\x3e\x1d\x1e\x31\xe0\xfe\x36\x30\xd3\x9e\x94\x9b\x50\x15\x0d\x17\xe3\x99\x93\x9e\xee\x2c\x30\x5b\xf0\x32\x1f\x1f\x4c\x9c\x8f\x94\xbe\x19\x0e\x15\x3d\xa2\x9b\xa7\xd2\x52\xc3\xaf\xc4\x29\x16\x16\x2f\x9e\x8e\x90\xac\x20\x13\x18\x34\xb2\xac\xc0\x61\xc2\xa5\x9d\xad\x29\x12\x10\x23\xa5\x8f\x90\xa5\x2d\x1b\x1f\x39\xd1\x65\x34\x36\xbb\x9b"));
snd($sock_a, $port_b, rtp(0, 1013, 5080, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1013, 5080, $ssrc, "\x94\x9f\x2f\x11\x0e\x1c\xb3\x95\x94\xa4\x45\x2a\x33\x69\x60\x2d\x1e\x23\xc7\x98\x8f\x98\x49\x15\x0e\x1a\xda\x9d\x9c\xab\x7d\x53\xbe\xb1\xe8\x22\x15\x19\x4d\x98\x8d\x94\xc3\x1b\x12\x1b\x48\xac\xac\xc7\x69\xba\xa2\x9f\xbb\x1f\x10\x12\x2f\x9c\x8e\x93\xb0\x25\x1a\x22\x44\xcb\x57\x34\x3d\xae\x99\x96\xa9\x23\x0f\x0f\x24\xa6\x93\x96\xac\x36\x29\x37\x7c\x4e\x29\x1e\x29\xb0\x94\x8f\x9e\x2d\x11\x0f\x1f\xb6\x9b\x9d\xb0\x55\x58\xbc\xb5\x49\x1e\x15\x1d\xbe\x94\x8e\x99\x45\x17\x12\x1f\xd9\xa9\xad\xce\xfa\xb3\xa0\xa2\xef\x1b\x0f\x16\x52\x97\x8e\x96\xcb\x1e\x1a\x26\x59\xc8\x4e\x35\x4d\xa8\x97\x98\xb8\x1c\x0e\x11\x31\x9d\x91\x98\xb9\x2d\x29\x3b\xf5"));
snd($sock_a, $port_b, rtp(0, 1014, 5240, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1014, 5240, $ssrc, "\x43\x27\x1f\x32\xa6\x92\x91\xa7\x21\x0f\x10\x28\xa9\x99\x9e\xba\x49\x60\xba\xbb\x38\x1b\x16\x23\xab\x90\x8e\x9e\x2d\x14\x13\x26\xbc\xa7\xaf\xd8\xde\xae\xa0\xa7\x3d\x17\x0f\x1a\xba\x93\x8e\x9b\x44\x1b\x1b\x2b\xe0\xc8\x48\x37\xe4\xa2\x96\x9b\x6f\x17\x0e\x15\x5d\x99\x91\x9c\xd7\x29\x29\x3f\xf8\x3c\x24\x21\x46\x9e\x90\x94\xb8\x1a\x0e\x14\x37\xa1\x99\xa1\xc8\x43\x76\xba\xc5\x2d\x19\x17\x2d\xa0\x8f\x8f\xa8\x21\x11\x16\x2e\xaf\xa6\xb2\xe5\xcf\xab\xa0\xad\x2d\x14\x10\x20\xa8\x90\x8f\xa1\x2e\x19\x1c\x31\xcb\xc9\x44\x3b\xc2\x9e\x96\x9f\x36\x13\x0e\x1a\xb8\x95\x92\xa0\x48\x26\x2a\x48\x73\x36\x23\x25\xd4\x9a\x90\x98\x5c\x15\x0e\x18\x72\x9c\x99"));
snd($sock_a, $port_b, rtp(0, 1015, 5400, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1015, 5400, $ssrc, "\xa6\xe8\x3f\xe7\xba\xdd\x27\x18\x1a\x43\x9a\x8e\x93\xbb\x1b\x10\x19\x3e\xaa\xa5\xb7\xf4\xc6\xa9\xa2\xba\x23\x12\x12\x2c\x9e\x8e\x91\xac\x25\x18\x1e\x3c\xc1\xcd\x41\x40\xb5\x9c\x97\xa8\x27\x10\x0f\x21\xa8\x92\x93\xa8\x35\x24\x2c\x50\x61\x30\x23\x2b\xb7\x97\x90\x9d\x31\x11\x0e\x1c\xb9\x9a\x9a\xab\x52\x3f\xd9\xbc\x54\x22\x18\x1d\xca\x96\x8e\x97\x52\x17\x10\x1c\xef\xa5\xa6\xbc\xff\xbe\xa7\xa5\xd8\x1d\x10\x16\x45\x98\x8e\x95\xbf\x1e\x17\x20\x4d\xbc\xd2\x3f\x4e\xad\x9a\x99\xb4\x1e\x0e\x10\x2d\x9e\x90\x96\xb2\x2c\x22\x2f\x5c\x54\x2d\x24\x32\xaa\x94\x91\xa5\x24\x0f\x0f\x24\xaa\x98\x9b\xb2\x43\x3f\xcf\xc0\x3e\x1e\x18\x23\xaf\x92\x8e\x9c\x2f"));
snd($sock_a, $port_b, rtp(0, 1016, 5560, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1016, 5560, $ssrc, "\x13\x11\x21\xbd\xa2\xa8\xc3\xfa\xb9\xa6\xa9\x45\x19\x10\x1a\xc2\x94\x8e\x99\x4e\x1a\x18\x26\xeb\xba\xdd\x40\x7d\xa7\x99\x9c\xda\x19\x0e\x14\x4a\x99\x90\x99\xc9\x26\x23\x34\x6d\x4b\x2b\x25\x41\xa1\x92\x94\xb3\x1c\x0e\x12\x30\xa0\x96\x9d\xbe\x3b\x41\xcc\xc9\x34\x1c\x19\x2c\xa3\x8f\x8f\xa5\x23\x10\x13\x2a\xaf\xa0\xaa\xcd\xeb\xb4\xa6\xae\x31\x16\x11\x1f\xab\x90\x8e\x9e\x30\x18\x19\x2c\xc8\xb9\xf0\x43\xcc\xa2\x99\x9f\x3c\x14\x0e\x19\xbe\x95\x90\x9d\x4e\x22\x24\x3a\xfa\x43\x2a\x28\xec\x9d\x91\x98\xe4\x16\x0d\x16\x51\x9c\x96\xa0\xd7\x37\x45\xca\xda\x2c\x1b\x1b\x3d\x9c\x8e\x92\xb4\x1c\x0f\x16\x38\xa8\xa0\xad\xda\xdd\xb0\xa7\xb9\x28\x14\x13"));
# pause
snd($sock_a, $port_b, rtp(0, 1017, 5720, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1017, 5720, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1018, 5880, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1018, 5880, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1019, 6040, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1019, 6040, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1020, 6200, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1020, 6200, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1021, 6360, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1021, 6360, $ssrc, "\xff" x 160));
# resume
snd($sock_a, $port_b, rtp(0, 1022, 6520, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1022, 6520, $ssrc, "\x00" x 160));




# RFC payload type present

($sock_a, $sock_b) = new_call([qw(198.51.100.1 6010)], [qw(198.51.100.3 6012)]);

($port_a) = offer('multi- no transcoding, RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6010 RTP/AVP 0 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('multi- no transcoding, RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6012 RTP/AVP 0 8 96
c=IN IP4 198.51.100.3
a=rtpmap:96 telephone-event/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => '0', volume => 10, duration => 100 });
$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => '1', volume => 6, duration => 100 });

snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96 | 0x80, 1002, 3320, $ssrc, "\x00\x0a\x00\xa0"));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1003, 3320, $ssrc, "\x00\x0a\x01\x40"));
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1004, 3320, $ssrc, "\x00\x0a\x01\xe0"));
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1005, 3320, $ssrc, "\x00\x0a\x02\x80"));
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1006, 3320, $ssrc, "\x00\x0a\x03\x20"));
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1007, 3320, $ssrc, "\x00\x8a\x03\xc0"));
rcv($sock_b, $port_a, rtpm(96, 1008, 3320, $ssrc, "\x00\x8a\x03\xc0"));
rcv($sock_b, $port_a, rtpm(96, 1009, 3320, $ssrc, "\x00\x8a\x03\xc0"));
snd($sock_a, $port_b, rtp(0, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4280, $ssrc, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1009, 4440, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1011, 4440, $ssrc, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1012, 4600, $ssrc, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1013, 4760, $ssrc, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96 | 0x80, 1014, 4920, $ssrc, "\x01\x06\x00\xa0"));
snd($sock_a, $port_b, rtp(0, 1013, 5080, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1015, 4920, $ssrc, "\x01\x06\x01\x40"));
snd($sock_a, $port_b, rtp(0, 1014, 5240, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1016, 4920, $ssrc, "\x01\x06\x01\xe0"));
snd($sock_a, $port_b, rtp(0, 1015, 5400, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1017, 4920, $ssrc, "\x01\x06\x02\x80"));
snd($sock_a, $port_b, rtp(0, 1016, 5560, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1018, 4920, $ssrc, "\x01\x06\x03\x20"));
snd($sock_a, $port_b, rtp(0, 1017, 5720, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1019, 4920, $ssrc, "\x01\x86\x03\xc0"));
rcv($sock_b, $port_a, rtpm(96, 1020, 4920, $ssrc, "\x01\x86\x03\xc0"));
rcv($sock_b, $port_a, rtpm(96, 1021, 4920, $ssrc, "\x01\x86\x03\xc0"));
snd($sock_a, $port_b, rtp(0, 1018, 5880, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1022, 5880, $ssrc, "\x00" x 160));





# SDP in/out tests, various ICE options

new_call;

offer('plain SDP, no ICE', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('plain SDP, no ICE', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('plain SDP, add default ICE', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('plain SDP, ICE removed', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
-------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('plain SDP, ICE removed', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('plain SDP, no ICE option given', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('ICE SDP, default ICE option', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=candidate:ICEBASE 1 UDP 2097152255 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 4294967295 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2097152254 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 4294967294 2001:db8:4321::1 PORT typ host
SDP

answer('plain SDP, ICE rejected, no ICE option given', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('ICE SDP with ICE force', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('plain SDP, ICE rejected, no ICE option given', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('ICE SDP with ICE force', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('ICE SDP, no ICE option given', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ice-ufrag:bmnhkfdf
a=ice-pwd:jetyhsdfgsdtjhtyjktrthsrhH
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfbhdcfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfbhdcfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=ice-ufrag:bmnhkfdf
a=ice-pwd:jetyhsdfgsdtjhtyjktrthsrhH
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfbhdcfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfbhdcfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=candidate:ICEBASE 1 UDP 2097152255 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 4294967295 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2097152254 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 4294967294 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('ICE SDP with ICE force', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('ICE SDP with ICE force', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ice-ufrag:bmnhkfdf
a=ice-pwd:jetyhsdfgsdtjhtyjktrthsrhH
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfbhdcfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfbhdcfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

# github issue #686

new_call;

offer('gh 686', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
c=IN IP4 198.51.100.1
m=audio 0 RTP/AVP 8 101
m=image 2000 udptl t38
c=IN IP4 198.51.100.1
a=T38FaxVersion:0
a=T38FaxRateManagement:transferredTCF
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
c=IN IP4 203.0.113.1
m=audio 0 RTP/AVP 8 101
m=image PORT udptl t38
c=IN IP4 203.0.113.1
a=T38FaxVersion:0
a=T38FaxRateManagement:transferredTCF
a=sendrecv
SDP

# github issue #661

new_call;

offer('gh 661 plain', { ICE => 'remove', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyH?
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8?
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 plain', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
SDP

new_call;

offer('gh 661 suppress one', { ICE => 'remove', DTLS => 'off', SDES => [ 'no-F8_128_HMAC_SHA1_80' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyH?
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8?
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:8 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 suppress one', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
SDP

new_call;

offer('gh 661 remove one', { ICE => 'remove', DTLS => 'off', SDES => [ 'no-AES_CM_128_HMAC_SHA1_32' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyH?
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8?
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 remove one', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
SDP

new_call;

offer('gh 661 remove first', { ICE => 'remove', DTLS => 'off', SDES => [ 'no-AES_CM_128_HMAC_SHA1_80' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyH?
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8?
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 remove first', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VdfhasfhsfghsrtjhasrtjhsartjhsM4Gw6chrFr
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VdfhasfhsfghsrtjhasrtjhsartjhsM4Gw6chrFr
SDP

# #661 for transcoding to RTP

offer('gh 661 plain to RTP', { ICE => 'remove', DTLS => 'off', 'transport protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('gh 661 plain to RTP', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

new_call;

offer('gh 661 remove one to RTP', { ICE => 'remove', DTLS => 'off', 'transport protocol' => 'RTP/AVP', SDES => [ 'no-AES_CM_128_HMAC_SHA1_32' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('gh 661 remove one to RTP', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

new_call;

offer('gh 661 remove first to RTP', { ICE => 'remove', DTLS => 'off', 'transport protocol' => 'RTP/AVP', SDES => [ 'no-AES_CM_128_HMAC_SHA1_80' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('gh 661 remove first to RTP', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
SDP

# #661 for transcoding from RTP

new_call;

offer('gh 661 plain from RTP', { ICE => 'remove', DTLS => 'off', 'transport protocol' => 'RTP/SAVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:3 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:4 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:5 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:6 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:7 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 plain from RTP', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('gh 661 from RTP suppress one', { ICE => 'remove', DTLS => 'off', 'transport protocol' => 'RTP/SAVP', SDES => [ 'no-F8_128_HMAC_SHA1_80' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:3 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:4 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:5 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:6 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:7 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:8 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 from RTP suppress one', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('gh 661 from RTP suppress first', { ICE => 'remove', DTLS => 'off', 'transport protocol' => 'RTP/SAVP', SDES => [ 'no-AES_CM_128_HMAC_SHA1_80' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:2 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:3 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:7 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:8 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 from RTP suppress first', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_32 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP





# codec masking gh#664

new_call;

offer('gh 664 codec masking plain', { ICE => 'remove', replace => [qw(origin session-connection)],
	flags => [qw(codec-mask-opus codec-mask-G722 codec-strip-G7221)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 120 8 0 101
c=IN IP4 198.51.100.1
a=rtpmap:120 opus/48000/2
a=fmtp:120 useinbandfec=1; usedtx=1; maxaveragebitrate=64000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

answer('gh 664 codec masking plain', { ICE => 'remove', replace => [qw(origin session-connection)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
c=IN IP4 198.51.100.3
t=0 0
m=audio 2002 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
c=IN IP4 203.0.113.1
t=0 0
m=audio PORT RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP


new_call;

offer('gh 664 codec masking a/t', { ICE => 'remove', replace => [qw(origin session-connection)],
	flags => [qw(codec-mask-opus codec-mask-G722 codec-strip-G7221 always-transcode)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 120 8 0 101
c=IN IP4 198.51.100.1
a=rtpmap:120 opus/48000/2
a=fmtp:120 useinbandfec=1; usedtx=1; maxaveragebitrate=64000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

answer('gh 664 codec masking a/t', { ICE => 'remove', replace => [qw(origin session-connection)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
c=IN IP4 198.51.100.3
t=0 0
m=audio 2002 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
c=IN IP4 203.0.113.1
t=0 0
m=audio PORT RTP/AVP 120 8 0 101
a=rtpmap:120 opus/48000/2
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:120 useinbandfec=1; usedtx=1; maxaveragebitrate=64000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP





# RTP sequencing tests

($sock_a, $sock_b) = new_call([qw(198.51.100.1 2010)], [qw(198.51.100.3 2012)]);

($port_a) = offer('two codecs, no transcoding', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2010 RTP/AVP 0 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('two codecs, no transcoding', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2012 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1010, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1001, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1001, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1010, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1010, 3000, 0x1234, "\x00" x 160));


($sock_a, $sock_b) = new_call([qw(198.51.100.1 2010)], [qw(198.51.100.3 2012)]);

($port_a) = offer('one codec with one for transcoding', { ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['PCMA'] }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2010 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('one codec with one for transcoding', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2012 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));

snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2001, 4000+160, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4000+160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2010, 4000+1600, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2010, 4000+1600, $ssrc, "\x00" x 160));

snd($sock_b, $port_a,  rtp(8, 2011, 4000+160*11, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2011, 4000+160*11, $ssrc, ")" x 160));
# #664 seq reset
snd($sock_b, $port_a,  rtp(8, 62011, 4000+160*12, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2012, 4000+160*12, $ssrc, ")" x 160));
snd($sock_b, $port_a,  rtp(8, 62012, 4000+160*13, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2013, 4000+160*13, $ssrc, ")" x 160));
snd($sock_b, $port_a,  rtp(0, 62013, 4000+160*14, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2014, 4000+160*14, $ssrc, "\x00" x 160));



($sock_a, $sock_b) = new_call([qw(198.51.100.1 2210)], [qw(198.51.100.3 2212)]);

($port_a) = offer('one codec with one for transcoding, lower case', { ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['PCMA'] }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2210 RTP/AVP 0
c=IN IP4 198.51.100.1
a=rtpmap:0 pcmu/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 pcmu/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('one codec with one for transcoding, lower case', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2212 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=rtpmap:0 pcmu/8000
a=rtpmap:8 pcma/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 pcmu/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));

snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2001, 4000+160, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4000+160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2010, 4000+1600, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2010, 4000+1600, $ssrc, "\x00" x 160));

snd($sock_b, $port_a,  rtp(8, 2011, 4000+160*11, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2011, 4000+160*11, $ssrc, ")" x 160));
# #664 seq reset
snd($sock_b, $port_a,  rtp(8, 62011, 4000+160*12, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2012, 4000+160*12, $ssrc, ")" x 160));
snd($sock_b, $port_a,  rtp(8, 62012, 4000+160*13, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2013, 4000+160*13, $ssrc, ")" x 160));
snd($sock_b, $port_a,  rtp(0, 62013, 4000+160*14, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2014, 4000+160*14, $ssrc, "\x00" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 2216)], [qw(198.51.100.3 2218)]);

($port_a) = offer('one codec with one for transcoding, lower case 2', { ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['pcma'] }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2216 RTP/AVP 0
c=IN IP4 198.51.100.1
a=rtpmap:0 pcmu/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 pcmu/8000
a=rtpmap:8 pcma/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('one codec with one for transcoding, lower case 2', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2218 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));

snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2001, 4000+160, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4000+160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2010, 4000+1600, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2010, 4000+1600, $ssrc, "\x00" x 160));

snd($sock_b, $port_a,  rtp(8, 2011, 4000+160*11, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2011, 4000+160*11, $ssrc, ")" x 160));
# #664 seq reset
snd($sock_b, $port_a,  rtp(8, 62011, 4000+160*12, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2012, 4000+160*12, $ssrc, ")" x 160));
snd($sock_b, $port_a,  rtp(8, 62012, 4000+160*13, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2013, 4000+160*13, $ssrc, ")" x 160));
snd($sock_b, $port_a,  rtp(0, 62013, 4000+160*14, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2014, 4000+160*14, $ssrc, "\x00" x 160));





# media playback

# 100 ms sine wave
my $wav_file = "\x52\x49\x46\x46\x64\x06\x00\x00\x57\x41\x56\x45\x66\x6d\x74\x20\x10\x00\x00\x00\x01\x00\x01\x00\x40\x1f\x00\x00\x80\x3e\x00\x00\x02\x00\x10\x00\x64\x61\x74\x61\x40\x06\x00\x00\x00\x00\xb0\x22\x45\x41\x25\x58\x95\x64\x24\x65\xbd\x59\xb6\x43\xb4\x25\x35\x03\x5e\xe0\x3b\xc1\x8c\xa9\x0f\x9c\x6a\x9a\xc2\xa4\xe7\xb9\x55\xd7\x92\xf9\x92\x1c\x30\x3c\xb2\x54\x2e\x63\xf3\x65\xa7\x5c\x68\x48\x9b\x2b\xa1\x09\x8a\xe6\x71\xc6\x28\xad\xab\x9d\xcc\x99\x06\xa2\x5c\xb5\x81\xd1\x2d\xf3\x53\x16\xe1\x36\xe8\x50\x64\x61\x59\x66\x36\x5f\xcf\x4c\x56\x31\x04\x10\xd0\xec\xe0\xcb\x19\xb1\xa9\x9f\x98\x99\xa8\x9f\x1a\xb1\xdf\xcb\xd1\xec\x04\x10\x54\x31\xd2\x4c\x33\x5f\x5c\x66\x61\x61\xeb\x50\xde\x36\x56\x16\x2b\xf3\x83\xd1\x59\xb5\x08\xa2\xcb\x99\xac\x9d\x28\xad\x70\xc6\x8a\xe6\xa3\x09\x98\x2b\x6a\x48\xa6\x5c\xf4\x65\x2d\x63\xb3\x54\x2e\x3c\x93\x1c\x93\xf9\x53\xd7\xe9\xb9\xc1\xa4\x69\x9a\x11\x9c\x8b\xa9\x3b\xc1\x5e\xe0\x36\x03\xb2\x25\xba\x43\xb7\x59\x2a\x65\x90\x64\x29\x58\x42\x41\xb2\x22\xff\xff\x50\xdd\xbb\xbe\xdb\xa7\x6b\x9b\xdd\x9a\x42\xa6\x4b\xbc\x4b\xda\xca\xfc\xa5\x1f\xc2\x3e\x77\x56\xed\x63\x9a\x65\x3b\x5b\x1b\x46\xa9\x28\x70\x06\x6c\xe3\xd2\xc3\x4d\xab\xd1\x9c\x10\x9a\x56\xa3\x99\xb7\x67\xd4\x5b\xf6\x79\x19\x8e\x39\xd7\x52\x58\x62\x30\x66\xfd\x5d\xa2\x4a\x81\x2e\xd1\x0c\xae\xe9\x1f\xc9\x17\xaf\x9e\x9e\xa4\x99\xce\xa0\x2c\xb3\xaf\xce\xf8\xef\x33\x13\x1e\x34\xe8\x4e\x57\x60\x68\x66\x57\x60\xe9\x4e\x1c\x34\x35\x13\xf6\xef\xb0\xce\x2d\xb3\xcc\xa0\xa6\x99\x9c\x9e\x17\xaf\x22\xc9\xa9\xe9\xd6\x0c\x7c\x2e\xa7\x4a\xf8\x5d\x36\x66\x52\x62\xdb\x52\x8c\x39\x79\x19\x5c\xf6\x67\xd4\x97\xb7\x59\xa3\x0e\x9a\xd1\x9c\x4e\xab\xd0\xc3\x6e\xe3\x6e\x06\xac\x28\x18\x46\x3d\x5b\x98\x65\xef\x63\x76\x56\xc3\x3e\xa4\x1f\xc9\xfc\x4e\xda\x49\xbc\x43\xa6\xdd\x9a\x69\x9b\xdd\xa7\xbb\xbe\x4f\xdd\x01\x00\xaf\x22\x47\x41\x23\x58\x96\x64\x24\x65\xbb\x59\xba\x43\xb0\x25\x39\x03\x59\xe0\x40\xc1\x87\xa9\x15\x9c\x65\x9a\xc4\xa4\xe7\xb9\x56\xd7\x90\xf9\x94\x1c\x2e\x3c\xb3\x54\x2f\x63\xf1\x65\xa8\x5c\x68\x48\x9a\x2b\xa2\x09\x8a\xe6\x71\xc6\x27\xad\xac\x9d\xcb\x99\x08\xa2\x59\xb5\x84\xd1\x2a\xf3\x56\x16\xe0\x36\xe7\x50\x65\x61\x59\x66\x35\x5f\xd1\x4c\x54\x31\x04\x10\xd2\xec\xdd\xcb\x1c\xb1\xa5\x9f\x9b\x99\xa8\x9f\x18\xb1\xe2\xcb\xcd\xec\x07\x10\x54\x31\xd1\x4c\x33\x5f\x5d\x66\x60\x61\xec\x50\xdd\x36\x57\x16\x29\xf3\x86\xd1\x57\xb5\x09\xa2\xcb\x99\xab\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9a\x2b\x69\x48\xa7\x5c\xf2\x65\x2e\x63\xb2\x54\x31\x3c\x91\x1c\x93\xf9\x53\xd7\xe9\xb9\xc1\xa4\x6a\x9a\x10\x9c\x8a\xa9\x3f\xc1\x59\xe0\x3a\x03\xb0\x25\xb8\x43\xbd\x59\x24\x65\x95\x64\x24\x58\x46\x41\xaf\x22\x02\x00\x4e\xdd\xbb\xbe\xdd\xa7\x68\x9b\xdf\x9a\x42\xa6\x48\xbc\x50\xda\xc6\xfc\xa7\x1f\xc2\x3e\x75\x56\xef\x63\x99\x65\x3c\x5b\x1a\x46\xaa\x28\x6e\x06\x6e\xe3\xd1\xc3\x4e\xab\xd1\x9c\x0e\x9a\x57\xa3\x9a\xb7\x64\xd4\x60\xf6\x75\x19\x90\x39\xd7\x52\x55\x62\x34\x66\xf9\x5d\xa8\x4a\x7a\x2e\xd8\x0c\xa7\xe9\x23\xc9\x16\xaf\x9d\x9e\xa6\x99\xcb\xa0\x2f\xb3\xad\xce\xfa\xef\x30\x13\x21\x34\xe6\x4e\x59\x60\x66\x66\x5a\x60\xe4\x4e\x23\x34\x2e\x13\xfc\xef\xab\xce\x30\xb3\xcb\xa0\xa5\x99\x9f\x9e\x14\xaf\x24\xc9\xa7\xe9\xd8\x0c\x7b\x2e\xa8\x4a\xf7\x5d\x36\x66\x53\x62\xda\x52\x8d\x39\x78\x19\x5d\xf6\x67\xd4\x97\xb7\x59\xa3\x0d\x9a\xd2\x9c\x4e\xab\xd1\xc3\x6d\xe3\x6f\x06\xaa\x28\x19\x46\x3f\x5b\x95\x65\xf2\x63\x74\x56\xc2\x3e\xa8\x1f\xc4\xfc\x52\xda\x45\xbc\x46\xa6\xdc\x9a\x6a\x9b\xdc\xa7\xba\xbe\x51\xdd\xff\xff\xb1\x22\x45\x41\x24\x58\x97\x64\x22\x65\xbd\x59\xb7\x43\xb3\x25\x37\x03\x5b\xe0\x3e\xc1\x89\xa9\x11\x9c\x6a\x9a\xc0\xa4\xeb\xb9\x51\xd7\x94\xf9\x91\x1c\x31\x3c\xb1\x54\x2f\x63\xf3\x65\xa5\x5c\x6c\x48\x95\x2b\xa7\x09\x86\xe6\x73\xc6\x28\xad\xa9\x9d\xcf\x99\x04\xa2\x5b\xb5\x84\xd1\x29\xf3\x57\x16\xde\x36\xe9\x50\x65\x61\x57\x66\x38\x5f\xcd\x4c\x57\x31\x04\x10\xd0\xec\xe1\xcb\x17\xb1\xaa\x9f\x97\x99\xaa\x9f\x18\xb1\xe1\xcb\xce\xec\x07\x10\x53\x31\xd0\x4c\x38\x5f\x55\x66\x68\x61\xe6\x50\xe0\x36\x56\x16\x2b\xf3\x81\xd1\x5d\xb5\x04\xa2\xce\x99\xaa\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9b\x2b\x67\x48\xa9\x5c\xf1\x65\x2e\x63\xb4\x54\x2e\x3c\x93\x1c\x92\xf9\x54\xd7\xe8\xb9\xc2\xa4\x69\x9a\x10\x9c\x8c\xa9\x3c\xc1\x5c\xe0\x37\x03\xb2\x25\xb8\x43\xbc\x59\x24\x65\x95\x64\x26\x58\x43\x41\xb2\x22\xff\xff\x50\xdd\xba\xbe\xde\xa7\x68\x9b\xdd\x9a\x45\xa6\x45\xbc\x52\xda\xc5\xfc\xa8\x1f\xbf\x3e\x79\x56\xec\x63\x9b\x65\x3b\x5b\x1a\x46\xaa\x28\x6f\x06\x6e\xe3\xd0\xc3\x4f\xab\xd0\x9c\x0f\x9a\x58\xa3\x97\xb7\x68\xd4\x5c\xf6\x78\x19\x8f\x39\xd6\x52\x57\x62\x32\x66\xfb\x5d\xa6\x4a\x7b\x2e\xd8\x0c\xa6\xe9\x25\xc9\x15\xaf\x9c\x9e\xa9\x99\xc7\xa0\x33\xb3\xa9\xce\xfd\xef\x2f\x13\x21\x34\xe6\x4e\x58\x60\x67\x66\x59\x60\xe5\x4e\x23\x34\x2c\x13\x00\xf0\xa6\xce\x35\xb3\xc7\xa0\xa8\x99\x9d\x9e\x15\xaf\x24\xc9\xa8\xe9\xd5\x0c\x7e\x2e\xa5\x4a\xfa\x5d\x35\x66\x52\x62\xdb\x52\x8d\x39\x77\x19\x5e\xf6\x66\xd4\x98\xb7\x59\xa3\x0c\x9a\xd3\x9c\x4d\xab\xd1\xc3\x6e\xe3\x6e\x06\xaa\x28\x1b\x46\x3b\x5b\x9a\x65\xed\x63\x76\x56\xc4\x3e\xa3\x1f\xcb\xfc\x4b\xda\x4a\xbc\x43\xa6\xdd\x9a\x6a\x9b\xdc\xa7\xba\xbe\x51\xdd\xff\xff\xb1\x22\x44\x41\x25\x58\x96\x64\x23\x65\xbd\x59\xb6\x43\xb4\x25\x36\x03\x5c\xe0\x3d\xc1\x8a\xa9\x12\x9c\x67\x9a\xc4\xa4\xe6\xb9\x55\xd7\x93\xf9\x91\x1c\x31\x3c\xb0\x54\x31\x63\xef\x65\xab\x5c\x66\x48\x9a\x2b\xa4\x09\x87\xe6\x73\xc6\x26\xad\xad\x9d\xcb\x99\x07\xa2\x5b\xb5\x81\xd1\x2c\xf3\x56\x16\xde\x36\xeb\x50\x62\x61\x59\x66\x38\x5f\xcc\x4c\x59\x31\x01\x10\xd3\xec\xdd\xcb\x1b\xb1\xa8\x9f\x98\x99\xa9\x9f\x18\xb1\xe0\xcb\xd1\xec\x03\x10\x57\x31\xce\x4c\x37\x5f\x58\x66\x63\x61\xec\x50\xdb\x36\x5a\x16\x27\xf3\x85\xd1\x5a\xb5\x05\xa2\xce\x99\xaa\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9a\x2b\x69\x48\xa6\x5c\xf4\x65\x2e\x63\xb1\x54\x32\x3c\x8e\x1c\x96\xf9\x52\xd7\xea\xb9\xc1\xa4\x67\x9a\x13\x9c\x8a\xa9\x3c\xc1\x5e\xe0\x33\x03\xb7\x25\xb4\x43\xbf\x59\x21\x65\x99\x64\x21\x58\x48\x41\xad\x22\x03\x00\x4f\xdd\xbb\xbe\xdb\xa7\x6a\x9b\xdd\x9a\x43\xa6\x4b\xbc\x4a\xda\xcb\xfc\xa4\x1f\xc3\x3e\x76\x56\xef\x63\x96\x65\x40\x5b\x17\x46\xac\x28\x6e\x06\x6d\xe3\xd2\xc3\x4d\xab\xd2\x9c\x0d\x9a\x59\xa3\x97\xb7\x68\xd4\x5c\xf6\x77\x19\x8f\x39\xd8\x52\x55\x62\x33\x66\xfb\x5d\xa4\x4a\x7f\x2e\xd4\x0c\xab\xe9\x20\xc9\x17\xaf\x9d\x9e\xa7\x99\xc9\xa0\x32\xb3\xa9\xce\xfd\xef\x2f\x13\x20\x34\xe8\x4e\x56\x60\x6a\x66\x55\x60\xe9\x4e\x1f\x34\x31\x13\xfa\xef\xad\xce\x2e\xb3\xcc\xa0\xa7\x99\x9b\x9e\x18\xaf\x20\xc9\xac\xe9\xd2\x0c\x81\x2e\xa1\x4a\xff\x5d\x30\x66\x56\x62\xd7\x52\x90\x39\x77\x19\x5d\xf6\x67\xd4\x96\xb7\x5a\xa3\x0e\x9a\xd0\x9c\x50\xab\xcf\xc3\x6e\xe3\x6f\x06\xaa\x28\x1a\x46\x3d\x5b\x98\x65\xee\x63\x77\x56\xc1\x3e\xa7\x1f\xc8\xfc\x4c\xda\x4b\xbc\x41\xa6\xdf\x9a\x68\x9b\xdd\xa7\xba\xbe\x51\xdd";
is length($wav_file), 1644, 'embedded binary wav file';

my $pcma_1 = "\xd5\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\x55\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c";
my $pcma_2 = "\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\xd5\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\xd5\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09";
my $pcma_3 = "\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\x55\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0";
my $pcma_4 = "\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\x55\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\x55\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1";
my $pcma_5 = "\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\xd5\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34";





($sock_a) = new_call([qw(198.51.100.1 2020)]);

offer('media playback, offer only', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2020 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$resp = rtpe_req('play media', 'media playback, offer only', { 'from-tag' => ft(), blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

my ($ts, $seq);
($seq, $ts, $ssrc) = rcv($sock_a, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_a, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_a, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_a, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_a, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 2020)], [qw(198.51.100.3 2022)]);

offer('media playback, side A', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2020 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('media playback, side A', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2022 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


$resp = rtpe_req('play media', 'media playback, side A', { 'from-tag' => ft(), blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

($seq, $ts, $ssrc) = rcv($sock_a, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_a, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_a, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_a, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_a, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 2030)], [qw(198.51.100.3 2032)]);

offer('media playback, side B', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2030 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('media playback, side B', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2032 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


$resp = rtpe_req('play media', 'media playback, side B', { 'from-tag' => tt(), blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

($seq, $ts, $ssrc) = rcv($sock_b, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_b, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_b, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_b, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_b, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));

$resp = rtpe_req('play media', 'restart media playback', { 'from-tag' => tt(), blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

$ts += 160 * 5;
my $old_ts = $ts;
($ts) = rcv($sock_b, -1, rtpm(8 | 0x80, $seq + 5, -1, $ssrc, $pcma_1));
print("ts $ts old $old_ts\n");
SKIP: {
	skip 'random timestamp too close to margin', 2 if $old_ts < 500 or $old_ts > 4294966795;
	cmp_ok($ts, '<', $old_ts + 500, 'ts within < range');
	cmp_ok($ts, '>', $old_ts - 500, 'ts within > range');
}
rcv($sock_b, -1, rtpm(8, $seq + 6, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_b, -1, rtpm(8, $seq + 7, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_b, -1, rtpm(8, $seq + 8, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_b, -1, rtpm(8, $seq + 9, $ts + 160 * 4, $ssrc, $pcma_5));




($sock_a, $sock_b) = new_call([qw(198.51.100.9 2020)], [qw(198.51.100.9 2022)]);

offer('media playback, side A, select by label', { ICE => 'remove', replace => ['origin'],
	label => 'foobar' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.9
s=tester
t=0 0
m=audio 2020 RTP/AVP 8
c=IN IP4 198.51.100.9
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('media playback, side A, select by label', { replace => ['origin'], label => 'blah' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.9
s=tester
t=0 0
m=audio 2022 RTP/AVP 8
c=IN IP4 198.51.100.9
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


$resp = rtpe_req('play media', 'media playback, side A, select by label', { label => 'foobar',
		blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

($seq, $ts, $ssrc) = rcv($sock_a, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_a, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_a, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_a, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_a, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));




($sock_a, $sock_b) = new_call([qw(198.51.100.9 2030)], [qw(198.51.100.9 2032)]);

offer('media playback, side B, select by label', { ICE => 'remove', replace => ['origin'],
	label => 'quux' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.9
s=tester
t=0 0
m=audio 2030 RTP/AVP 8
c=IN IP4 198.51.100.9
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('media playback, side B, select by label', { replace => ['origin'], label => 'meh' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.9
s=tester
t=0 0
m=audio 2032 RTP/AVP 8
c=IN IP4 198.51.100.9
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


$resp = rtpe_req('play media', 'media playback, side B, select by label', { label => 'meh', blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

($seq, $ts, $ssrc) = rcv($sock_b, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_b, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_b, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_b, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_b, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));





($sock_a, $sock_b) = new_call([qw(198.51.100.1 2050)], [qw(198.51.100.3 2052)]);

offer('media playback, SRTP', { ICE => 'remove', replace => ['origin'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2050 RTP/SAVP 8
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:eMlRvW8mWU4WodT9JOvAM+pn6I0/EXOhT9n0KeKk
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:eMlRvW8mWU4WodT9JOvAM+pn6I0/EXOhT9n0KeKk
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:3 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:4 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:5 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:6 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:7 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('media playback, SRTP', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2052 RTP/SAVP 8
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF
SDP


$resp = rtpe_req('play media', 'media playback, SRTP', { 'from-tag' => ft(), blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

my $srtp_ctx = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF',
};
($seq, $ts, $ssrc) = srtp_rcv($sock_a, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1), $srtp_ctx);
srtp_rcv($sock_a, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2), $srtp_ctx);
srtp_rcv($sock_a, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3), $srtp_ctx);
srtp_rcv($sock_a, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4), $srtp_ctx);
srtp_rcv($sock_a, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5), $srtp_ctx);






# ptime tests

($sock_a, $sock_b) = new_call([qw(198.51.100.1 3000)], [qw(198.51.100.3 3002)]);

($port_a) = offer('default ptime in/out', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('default ptime in/out', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4000, 5000, 0x4567, "\x88" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3000)], [qw(198.51.100.3 3002)]);

($port_a) = offer('mismatched ptime but no change requested', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:20
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

($port_b) = answer('mismatched ptime but no change requested', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:30
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 240));
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4000, 5000, 0x4567, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5160, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, 0x4567, "\x88" x 240));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3004)], [qw(198.51.100.3 3006)]);

($port_a) = offer('default ptime in, ptime=30 out, default response', {
	ICE => 'remove', replace => ['origin'], ptime => 30 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3004 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('default ptime in, ptime=30 out, default response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3006 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# A->B: 5x 20 ms packets -> 3x 30 ms
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));

# A->B: 60 ms packet -> 2x 30 ms
# also perform TS and seq reset
snd($sock_a, $port_b, rtp(0, 8000, 500000, 0x1234, "\x00" x 480));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1004, 3960, $ssrc, "\x00" x 240));

# B->A: 2x 60 ms packet -> 6x 20 ms
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 480));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 5320, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5480, 0x4567, "\x88" x 480));
rcv($sock_a, $port_b, rtpm(0, 4003, 5480, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4004, 5640, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 5800, $ssrc, "\x88" x 160));

# B->A: 4x 10 ms packet -> 2x 20 ms
# out of order packet input
snd($sock_b, $port_a, rtp(0, 4003, 6040, 0x4567, "\x88" x 80));
Time::HiRes::usleep(10000);
snd($sock_b, $port_a, rtp(0, 4002, 5960, 0x4567, "\x88" x 80));
rcv($sock_a, $port_b, rtpm(0, 4006, 5960, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4004, 6120, 0x4567, "\x88" x 80));
snd($sock_b, $port_a, rtp(0, 4005, 6200, 0x4567, "\x88" x 80));
rcv($sock_a, $port_b, rtpm(0, 4007, 6120, $ssrc, "\x88" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3008)], [qw(198.51.100.3 3010)]);

($port_a) = offer('default ptime in, no change, ptime=30 response', {
	ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3008 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('default ptime in, no change, ptime=30 response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3010 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:30
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

# A->B: 20 ms unchanged
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
# A->B: 30 ms unchanged
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, $ssrc, "\x00" x 240));

# B->A: 20 ms unchanged
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
# B->A: 30 ms unchanged
snd($sock_b, $port_a, rtp(0, 4001, 5160, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 240));



($sock_a, $sock_b) = new_call([qw(198.51.100.1 3012)], [qw(198.51.100.3 3014)]);

($port_a) = offer('ptime=50 in, change to 30, default response', {
	ICE => 'remove', replace => ['origin'], ptime => 30 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3012 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:50
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=50 in, change to 30, default response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3014 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:50
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\x00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));

# B->A: 4x 30 ms -> 2x 50 ms (plus 20 ms left)
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 400));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5400, $ssrc, "\x88" x 400));
# B->A: add another 30 ms for another full 50 ms
snd($sock_b, $port_a, rtp(0, 4004, 5960, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4002, 5800, $ssrc, "\x88" x 400));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3016)], [qw(198.51.100.3 3018)]);

($port_a) = offer('ptime=50 in, change to 30, reverse to 50, response 30', {
	ICE => 'remove', replace => ['origin'], ptime => 30, 'ptime-reverse' => 50 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3016 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:50
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=50 in, change to 30, reverse to 50, response 30',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:30
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:50
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\x00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));

# B->A: 4x 30 ms -> 2x 50 ms (plus 20 ms left)
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 400));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5400, $ssrc, "\x88" x 400));
# B->A: add another 30 ms for another full 50 ms
snd($sock_b, $port_a, rtp(0, 4004, 5960, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4002, 5800, $ssrc, "\x88" x 400));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3012)], [qw(198.51.100.3 3014)]);

($port_a) = offer('ptime=50 in, change to 30, response 30', {
	ICE => 'remove', replace => ['origin'], ptime => 30 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3012 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:50
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=50 in, change to 30, response 30',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3014 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:30
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:50
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\x00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));

# B->A: 4x 30 ms -> 2x 50 ms (plus 20 ms left)
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 400));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5400, $ssrc, "\x88" x 400));
# B->A: add another 30 ms for another full 50 ms
snd($sock_b, $port_a, rtp(0, 4004, 5960, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4002, 5800, $ssrc, "\x88" x 400));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3016)], [qw(198.51.100.3 3018)]);

($port_a) = offer('ptime=50 in, change to 30, reverse to 50, default response', {
	ICE => 'remove', replace => ['origin'], ptime => 30, 'ptime-reverse' => 50 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3016 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:50
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=50 in, change to 30, reverse to 50, default response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:50
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\x00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));

# B->A: 4x 30 ms -> 2x 50 ms (plus 20 ms left)
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 400));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5400, $ssrc, "\x88" x 400));
# B->A: add another 30 ms for another full 50 ms
snd($sock_b, $port_a, rtp(0, 4004, 5960, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4002, 5800, $ssrc, "\x88" x 400));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3016)], [qw(198.51.100.3 3018)]);

($port_a) = offer('ptime=50 in, change to 30, reverse to 20, default response', {
	ICE => 'remove', replace => ['origin'], ptime => 30, 'ptime-reverse' => 20 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3016 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:50
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=50 in, change to 30, reverse to 20, default response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\x00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));

# B->A: 4x 30 ms -> 6x 20 ms
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 5320, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4003, 5480, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4004, 5640, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 5800, $ssrc, "\x88" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3016)], [qw(198.51.100.3 3018)]);

($port_a) = offer('ptime=50 in, change to 30, reverse to 20, response 40', {
	ICE => 'remove', replace => ['origin'], ptime => 30, 'ptime-reverse' => 20 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3016 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:50
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=50 in, change to 30, reverse to 20, response 40',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:40
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\x00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));

# B->A: 4x 30 ms -> 6x 20 ms
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 5320, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4003, 5480, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4004, 5640, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 5800, $ssrc, "\x88" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3016)], [qw(198.51.100.3 3018)]);

($port_a) = offer('ptime=30 in, no change, reverse to 20, response 40', {
	ICE => 'remove', replace => ['origin'], 'ptime-reverse' => 20 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3016 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:30
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=30 in, no change, reverse to 20, response 40',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:40
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\x00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));

# B->A: 4x 30 ms -> 6x 20 ms
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 5320, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4003, 5480, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4004, 5640, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 5800, $ssrc, "\x88" x 160));




# gh #730

($sock_a, $sock_b) = new_call([qw(198.51.100.1 7300)], [qw(198.51.100.3 7302)]);

($port_a) = offer('gh 730', {
	ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7300 RTP/AVP 0 106 101 98
c=IN IP4 198.51.100.1
a=sendrecv
a=rtpmap:0 PCMU/8000
a=rtpmap:106 opus/48000/2
a=fmtp:106 maxplaybackrate=16000; sprop-maxcapturerate=16000; minptime=20; cbr=1; maxaveragebitrate=20000; useinbandfec=1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:98 telephone-event/48000
a=fmtp:98 0-16
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 106 101 98
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:106 opus/48000/2
a=rtpmap:101 telephone-event/8000
a=rtpmap:98 telephone-event/48000
a=fmtp:106 maxplaybackrate=16000; sprop-maxcapturerate=16000; minptime=20; cbr=1; maxaveragebitrate=20000; useinbandfec=1
a=fmtp:101 0-16
a=fmtp:98 0-16
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('gh 730',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7302 RTP/AVP 0 101
c=IN IP4 198.51.100.3
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, $ssrc, "\x00" x 160));
snd($sock_a, $port_b, rtp(101 | 0x80, 1002, 3320, 0x1234, "\x05\x0a\x00\xa0"));
rcv($sock_b, $port_a, rtpm(101 | 0x80, 1002, 3320, $ssrc, "\x05\x0a\x00\xa0"));
snd($sock_a, $port_b, rtp(101, 1003, 3320, 0x1234, "\x05\x0a\x01\x40"));
rcv($sock_b, $port_a, rtpm(101, 1003, 3320, $ssrc, "\x05\x0a\x01\x40"));

snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5160, 0x4567, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(101 | 0x80, 4002, 5320, 0x4567, "\x05\x0a\x00\xa0"));
rcv($sock_a, $port_b, rtpm(101 | 0x80, 4002, 5320, $ssrc, "\x05\x0a\x00\xa0"));
snd($sock_b, $port_a, rtp(101, 4003, 5320, 0x4567, "\x05\x0a\x01\x40"));
rcv($sock_a, $port_b, rtpm(101, 4003, 5320, $ssrc, "\x05\x0a\x01\x40"));




# gh #766

my $sock_c;
($sock_a, $sock_b, $sock_c) = new_call([qw(198.51.100.5 7300)], [qw(198.51.100.6 7302)], [qw(198.51.100.7 7304)]);

(undef, $port_a) = offer('gh 766 orig', {
	ICE => 'remove', replace => ['origin', 'session-connection'],
	flags => [ "loop-protect", "asymmetric" ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.5
s=tester
c=IN IP4 198.51.100.5
t=0 0
m=audio 7300 RTP/AVP 0 8 18 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=maxptime:20
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
c=IN IP4 203.0.113.1
t=0 0
a=rtpengine:LOOPER
m=audio PORT RTP/AVP 0 8 18 101
a=maxptime:20
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:18 G729/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:18 annexb=no
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

(undef, $port_b) = answer('gh 766 orig',
	{ ICE => 'remove', replace => ['origin', 'session-connection'],
	flags => [ "loop-protect", "asymmetric" ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.6
s=tester
c=IN IP4 198.51.100.6
t=0 0
m=audio 7302 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=ptime:20
a=xg726bitorder:big-endian
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
c=IN IP4 203.0.113.1
t=0 0
a=rtpengine:LOOPER
m=audio PORT RTP/AVP 0 101
a=xg726bitorder:big-endian
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));

snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));

# reverse re-invite
reverse_tags();

(undef, $port_b) = offer('gh 766 reinvite',
	{ 'to-tag' => tt(),
	ICE => 'remove', replace => ['origin', 'session-connection'],
	flags => [ "loop-protect", "asymmetric" ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.7
s=tester
c=IN IP4 198.51.100.7
t=0 0
m=audio 7304 udptl t38
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:200
a=T38FaxMaxDatagram:180
a=T38FaxUdpEC:t38UDPRedundancy
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
c=IN IP4 203.0.113.1
t=0 0
a=rtpengine:LOOPER
m=audio PORT udptl t38
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:200
a=T38FaxMaxDatagram:180
a=T38FaxUdpEC:t38UDPRedundancy
a=sendrecv
a=ptime:20
SDP

(undef, $port_a) = answer('gh 766 reinvite', {
	ICE => 'remove', replace => ['origin', 'session-connection'],
	flags => [ "loop-protect", "asymmetric" ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.5
s=tester
c=IN IP4 198.51.100.5
t=0 0
m=audio 7300 udptl t38
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:262
a=T38FaxMaxDatagram:176
a=T38FaxUdpEC:t38UDPRedundancy
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
c=IN IP4 203.0.113.1
t=0 0
a=rtpengine:LOOPER
m=audio PORT udptl t38
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:262
a=T38FaxMaxDatagram:176
a=T38FaxUdpEC:t38UDPRedundancy
a=sendrecv
a=ptime:20
SDP

snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));

snd($sock_a, $port_b, "\x00\x00\x01\x00\x00\x01\x01\x00");
rcv($sock_c, $port_a, qr/^\x00\x00\x01\x00\x00\x01\x01\x00$/s);




($sock_a, $sock_b) = new_call([qw(198.51.100.1 7010)], [qw(198.51.100.3 7012)]);

($port_a) = offer('PCM to RFC DTMF transcoding', { ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['telephone-event'] }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7010 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('PCM to RFC DTMF transcoding', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7012 RTP/AVP 0 96
c=IN IP4 198.51.100.3
a=rtpmap:0 PCMU/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($seq, $ssrc) = rcv($sock_b, $port_a, rtpm(0, -1, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq+1, 3160, $ssrc, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1002, 3000+160*2, 0x1234, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
# DTMF not detected yet
rcv($sock_b, $port_a, rtpm(0, $seq+2, 3000+160*2, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_a, $port_b,  rtp(0, 1003, 3000+160*3, 0x1234, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
# DTMF detection kicking in mid-frame
rcv($sock_b, $port_a, rtpm(0, $seq+3, 3000+160*3, $ssrc, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_a, $port_b,  rtp(0, 1004, 3000+160*4, 0x1234, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
# DTMF detected now
rcv($sock_b, $port_a, rtpm(96 | 0x80, $seq+4, 3000+160*4, $ssrc, "\x08\x0f\x00\xa0")); # start event 8, vol -15, duration 160
snd($sock_a, $port_b,  rtp(0, 1005, 3000+160*5, 0x1234, "\x00" x 160));
# reverting to audio, but DTMF event still progressing
rcv($sock_b, $port_a, rtpm(96, $seq+5, 3000+160*4, $ssrc, "\x08\x0f\x01\x40")); # event 8, vol -15, duration 320
snd($sock_a, $port_b,  rtp(0, 1006, 3000+160*6, 0x1234, "\x00" x 160));
# end event, 3 times
rcv($sock_b, $port_a, rtpm(96, $seq+6, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0")); # end event 8, vol -15, duration 480
rcv($sock_b, $port_a, rtpm(96, $seq+7, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0")); # end event 8, vol -15, duration 480
rcv($sock_b, $port_a, rtpm(96, $seq+8, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0")); # end event 8, vol -15, duration 480
# audio passing through again
snd($sock_a, $port_b,  rtp(0, 1007, 3000+160*7, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq+9, 3000+160*7, $ssrc, "\x00" x 160));

snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\x00" x 160));
($seq, $ssrc) = rcv($sock_a, $port_b, rtpm(0, -1, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2001, 4000+160, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+1, 4000+160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(96, 2002, 4000+320, 0x5678, "\x08\x10\x00\xa0"));
rcv($sock_a, $port_b, rtpm(0, $seq+2, 4000+320, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_b, $port_a,  rtp(96, 2003, 4000+320, 0x5678, "\x08\x10\x01\x40"));
rcv($sock_a, $port_b, rtpm(0, $seq+3, 4000+480, $ssrc, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_b, $port_a,  rtp(96, 2004, 4000+320, 0x5678, "\x08\x10\x01\xe0"));
rcv($sock_a, $port_b, rtpm(0, $seq+4, 4000+640, $ssrc, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
# test out of seq
snd($sock_b, $port_a,  rtp(0, 2006, 4000+160*5, 0x5678, "\x00" x 160)); # buffered
Time::HiRes::usleep(20000);
snd($sock_b, $port_a,  rtp(96, 2005, 4000+320, 0x5678, "\x08\x10\x01\xe0")); # repeat, no-op, consumed
rcv($sock_a, $port_b, rtpm(0, $seq+5, 4000+160*5, $ssrc, "\x00" x 160));
# resume normal
snd($sock_b, $port_a,  rtp(0, 2007, 4000+160*6, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+6, 4000+160*6, $ssrc, "\x00" x 160));
# test TS reset
snd($sock_b, $port_a,  rtp(0, 2008, 2000, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+7, 4000+160*7, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(96, 2009, 2160, 0x5678, "\x08\x10\x00\xa0"));
rcv($sock_a, $port_b, rtpm(0, $seq+8, 4000+160*8, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 7020)], [qw(198.51.100.3 7022)]);

($port_a) = offer('PCM to RFC DTMF transcoding w/ PCM transcoding', { ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['PCMA', 'telephone-event'] }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7020 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('PCM to RFC DTMF transcoding w/ PCM transcoding', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7022 RTP/AVP 8 96
c=IN IP4 198.51.100.3
a=rtpmap:0 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000+160*0, 0x1234, "\x00" x 160));
($seq, $ssrc) = rcv($sock_b, $port_a, rtpm(8, -1, 3000+160*0, -1, "\x2a" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3000+160*1, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, $seq+1, 3000+160*1, $ssrc, "\x2a" x 160));
snd($sock_a, $port_b,  rtp(0, 1002, 3000+160*2, 0x1234, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
# DTMF not detected yet
rcv($sock_b, $port_a, rtpm(8, $seq+2, 3000+160*2, $ssrc, "\xd5\x9b\x87\x97\x64\x10\x6b\x41\xdc\x73\x66\xd1\x91\x9a\x97\x6d\x07\x04\x67\x91\x9a\x96\x5c\x60\x7d\xd3\x4d\x6b\x11\x7c\x91\x87\x9e\x4f\x1a\x04\x15\xe0\x93\xe8\xda\x59\xf1\xe4\x44\x10\x1b\x6b\xeb\x87\x85\xfc\x12\x1a\x17\xc3\xe2\xfc\x51\xc9\xeb\x96\xcb\x13\x07\x1c\xff\x85\x84\xee\x6f\x12\x68\x5c\xc5\x76\x7b\xc9\x93\x98\xef\x14\x06\x1a\x4f\x9c\x9a\x95\x77\x6c\x7f\xd7\x75\x6b\x14\x59\x9d\x87\x93\x66\x04\x04\x63\xeb\x9d\xe9\xd7\x41\xf4\xff\x71\x12\x19\x61\x91\x86\x9b\xd5\x1e\x1a\x68\xfc\xee\xff\x55\xf4\xeb\x95\x53\x1c\x04\x11\xec\x87\x85\xe5\x14\x1d\x6f\xd1\xcd\x4b\x73\xfc\x92\x9f\xfb\x12\x06\x19\xcd\x98\x9a\xef\x65\x69\x7e\x55\x77\x68"));
snd($sock_a, $port_b,  rtp(0, 1003, 3000+160*3, 0x1234, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
# DTMF detection kicking in mid-frame
rcv($sock_b, $port_a, rtpm(8, $seq+3, 3000+160*3, $ssrc, "\x68\xc2\x9e\x84\x94\x6b\x07\x1a\x72\x96\x9c\xec\x59\x49\xcf\xf7\x7b\x12\x1c\x76\x9c\x86\x9f\x7c\x1a\x1a\x63\xe6\xeb\xfe\xd5\xf6\xe9\xef\x71\x19\x05\x68\x97\x86\x9b\xc2\x10\x1c\x62\xc1\xf5\x43\x49\xe4\x92\x92\xda\x1e\x06\x12\xe7\x85\x9b\xe7\x62\x6b\x7e\x55\x76\x69\x62\xf9\x98\x85\xe2\x10\x06\x18\x54\x92\x9c\xe0\x49\x76\xc7\xc3\x66\x12\x13\xd3\x98\x86\x91\x6c\x05\x1b\x79\xef\x95\xff\x54\xf6\xef\xe1\x67\x1b\x1a\x64\x9d\x86\x9e\x43\x1c\x1c\x67\xf6\xf0\x5a\x5a\xe0\x92\x91\x49\x1b\x07\x17\xeb\x84\x98\xf6\x68\x15\x7c\xd7\x76\x6c\x64\xe0\x9b\x9b\xf0\x1f\x06\x1c\xf3\x9e\x9c\xe5\x72\x72\xde\xdd\x63\x12\x17\xfd\x9a\x87\xe8\x17\x04\x1e\x41\x95"));
snd($sock_a, $port_b,  rtp(0, 1004, 3000+160*4, 0x1234, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
# DTMF detected now
rcv($sock_b, $port_a, rtpm(96 | 0x80, $seq+4, 3000+160*4, $ssrc, "\x08\x0f\x00\xa0")); # start event 8, vol -15, duration 160
snd($sock_a, $port_b,  rtp(0, 1005, 3000+160*5, 0x1234, "\x00" x 160));
# reverting to audio, but DTMF event still progressing
rcv($sock_b, $port_a, rtpm(96, $seq+5, 3000+160*4, $ssrc, "\x08\x0f\x01\x40")); # event 8, vol -15, duration 320
snd($sock_a, $port_b,  rtp(0, 1006, 3000+160*6, 0x1234, "\x00" x 160));
# end event, 3 times
rcv($sock_b, $port_a, rtpm(96, $seq+6, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0")); # end event 8, vol -15, duration 480
rcv($sock_b, $port_a, rtpm(96, $seq+7, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0")); # end event 8, vol -15, duration 480
rcv($sock_b, $port_a, rtpm(96, $seq+8, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0")); # end event 8, vol -15, duration 480
# audio passing through again
snd($sock_a, $port_b,  rtp(0, 1007, 3000+160*7, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, $seq+9, 3000+160*7, $ssrc, "\x2a" x 160));

snd($sock_b, $port_a,  rtp(8, 2000, 4000, 0x5678, "\x2a" x 160));
($seq, $ssrc) = rcv($sock_a, $port_b, rtpm(0, -1, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(8, 2001, 4000+160, 0x5678, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+1, 4000+160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(96, 2002, 4000+320, 0x5678, "\x08\x10\x00\xa0"));
rcv($sock_a, $port_b, rtpm(0, $seq+2, 4000+320, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_b, $port_a,  rtp(96, 2003, 4000+320, 0x5678, "\x08\x10\x01\x40"));
rcv($sock_a, $port_b, rtpm(0, $seq+3, 4000+480, $ssrc, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_b, $port_a,  rtp(96, 2004, 4000+320, 0x5678, "\x08\x10\x01\xe0"));
rcv($sock_a, $port_b, rtpm(0, $seq+4, 4000+640, $ssrc, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
# test out of seq
snd($sock_b, $port_a,  rtp(8, 2006, 4000+800, 0x5678, "\x2a" x 160)); # buffered
Time::HiRes::usleep(20000);
snd($sock_b, $port_a,  rtp(96, 2005, 4000+320, 0x5678, "\x08\x10\x01\xe0")); # repeat, no-op, consumed
rcv($sock_a, $port_b, rtpm(0, $seq+5, 4000+800, $ssrc, "\x00" x 160));





($sock_a, $sock_b) = new_call([qw(198.51.100.1 7030)], [qw(198.51.100.3 7032)]);

($port_a) = offer('PCM to RFC DTMF transcoding w/ forced PCM transcoding', { ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['telephone-event'] }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7030 RTP/AVP 0 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('PCM to RFC DTMF transcoding w/ forced PCM transcoding', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7032 RTP/AVP 8 96
c=IN IP4 198.51.100.3
a=rtpmap:0 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($seq, $ssrc) = rcv($sock_b, $port_a, rtpm(8, -1, 3000, -1, "\x2a" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, $seq+1, 3160, $ssrc, "\x2a" x 160));
snd($sock_a, $port_b,  rtp(0, 1002, 3000+160*2, 0x1234, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
# DTMF not detected yet
rcv($sock_b, $port_a, rtpm(8, $seq+2, 3000+160*2, $ssrc, "\xd5\x9b\x87\x97\x64\x10\x6b\x41\xdc\x73\x66\xd1\x91\x9a\x97\x6d\x07\x04\x67\x91\x9a\x96\x5c\x60\x7d\xd3\x4d\x6b\x11\x7c\x91\x87\x9e\x4f\x1a\x04\x15\xe0\x93\xe8\xda\x59\xf1\xe4\x44\x10\x1b\x6b\xeb\x87\x85\xfc\x12\x1a\x17\xc3\xe2\xfc\x51\xc9\xeb\x96\xcb\x13\x07\x1c\xff\x85\x84\xee\x6f\x12\x68\x5c\xc5\x76\x7b\xc9\x93\x98\xef\x14\x06\x1a\x4f\x9c\x9a\x95\x77\x6c\x7f\xd7\x75\x6b\x14\x59\x9d\x87\x93\x66\x04\x04\x63\xeb\x9d\xe9\xd7\x41\xf4\xff\x71\x12\x19\x61\x91\x86\x9b\xd5\x1e\x1a\x68\xfc\xee\xff\x55\xf4\xeb\x95\x53\x1c\x04\x11\xec\x87\x85\xe5\x14\x1d\x6f\xd1\xcd\x4b\x73\xfc\x92\x9f\xfb\x12\x06\x19\xcd\x98\x9a\xef\x65\x69\x7e\x55\x77\x68"));
snd($sock_a, $port_b,  rtp(0, 1003, 3000+160*3, 0x1234, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
# DTMF detection kicking in mid-frame
rcv($sock_b, $port_a, rtpm(8, $seq+3, 3000+160*3, $ssrc, "\x68\xc2\x9e\x84\x94\x6b\x07\x1a\x72\x96\x9c\xec\x59\x49\xcf\xf7\x7b\x12\x1c\x76\x9c\x86\x9f\x7c\x1a\x1a\x63\xe6\xeb\xfe\xd5\xf6\xe9\xef\x71\x19\x05\x68\x97\x86\x9b\xc2\x10\x1c\x62\xc1\xf5\x43\x49\xe4\x92\x92\xda\x1e\x06\x12\xe7\x85\x9b\xe7\x62\x6b\x7e\x55\x76\x69\x62\xf9\x98\x85\xe2\x10\x06\x18\x54\x92\x9c\xe0\x49\x76\xc7\xc3\x66\x12\x13\xd3\x98\x86\x91\x6c\x05\x1b\x79\xef\x95\xff\x54\xf6\xef\xe1\x67\x1b\x1a\x64\x9d\x86\x9e\x43\x1c\x1c\x67\xf6\xf0\x5a\x5a\xe0\x92\x91\x49\x1b\x07\x17\xeb\x84\x98\xf6\x68\x15\x7c\xd7\x76\x6c\x64\xe0\x9b\x9b\xf0\x1f\x06\x1c\xf3\x9e\x9c\xe5\x72\x72\xde\xdd\x63\x12\x17\xfd\x9a\x87\xe8\x17\x04\x1e\x41\x95"));
snd($sock_a, $port_b,  rtp(0, 1004, 3000+160*4, 0x1234, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
# DTMF detected now
rcv($sock_b, $port_a, rtpm(96 | 0x80, $seq+4, 3000+160*4, $ssrc, "\x08\x0f\x00\xa0")); # start event 8, vol -15, duration 160
snd($sock_a, $port_b,  rtp(0, 1005, 3000+160*5, 0x1234, "\x00" x 160));
# reverting to audio, but DTMF event still progressing
rcv($sock_b, $port_a, rtpm(96, $seq+5, 3000+160*4, $ssrc, "\x08\x0f\x01\x40")); # event 8, vol -15, duration 320
snd($sock_a, $port_b,  rtp(0, 1006, 3000+160*6, 0x1234, "\x00" x 160));
# end event, 3 times
rcv($sock_b, $port_a, rtpm(96, $seq+6, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0")); # end event 8, vol -15, duration 480
rcv($sock_b, $port_a, rtpm(96, $seq+7, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0")); # end event 8, vol -15, duration 480
rcv($sock_b, $port_a, rtpm(96, $seq+8, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0")); # end event 8, vol -15, duration 480
# audio passing through again
snd($sock_a, $port_b,  rtp(0, 1007, 3000+160*7, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, $seq+9, 3000+160*7, $ssrc, "\x2a" x 160));

snd($sock_b, $port_a,  rtp(8, 2000, 4000, 0x5678, "\x2a" x 160));
($seq, $ssrc) = rcv($sock_a, $port_b, rtpm(0, -1, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(8, 2001, 4000+160, 0x5678, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+1, 4000+160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(96, 2002, 4000+320, 0x5678, "\x08\x10\x00\xa0"));
rcv($sock_a, $port_b, rtpm(0, $seq+2, 4000+320, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_b, $port_a,  rtp(96, 2003, 4000+320, 0x5678, "\x08\x10\x01\x40"));
rcv($sock_a, $port_b, rtpm(0, $seq+3, 4000+480, $ssrc, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_b, $port_a,  rtp(96, 2004, 4000+320, 0x5678, "\x08\x10\x01\xe0"));
rcv($sock_a, $port_b, rtpm(0, $seq+4, 4000+640, $ssrc, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
# test out of seq
snd($sock_b, $port_a,  rtp(8, 2006, 4000+800, 0x5678, "\x2a" x 160)); # buffered
Time::HiRes::usleep(20000);
snd($sock_b, $port_a,  rtp(96, 2005, 4000+320, 0x5678, "\x08\x10\x01\xe0")); # repeat, no-op, consumed
rcv($sock_a, $port_b, rtpm(0, $seq+5, 4000+800, $ssrc, "\x00" x 160));




# test telephone-event synth options

new_call;

offer('several clock rates input w/ transcode DTMF',
	{ ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['telephone-event'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0 96 8 97 9
c=IN IP4 198.51.100.1
a=rtpmap:96 opus/48000
a=rtpmap:8 PCMA/8000
a=rtpmap:97 speex/16000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 96 8 97 9 98 99 100
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:96 opus/48000
a=rtpmap:8 PCMA/8000
a=rtpmap:97 speex/16000
a=rtpmap:9 G722/8000
a=rtpmap:98 telephone-event/8000
a=rtpmap:99 telephone-event/48000
a=rtpmap:100 telephone-event/16000
a=fmtp:98 0-15
a=fmtp:99 0-15
a=fmtp:100 0-15
a=sendrecv
a=rtcp:PORT
SDP




($sock_a, $sock_b) = new_call([qw(198.51.100.1 8050)], [qw(198.51.100.3 8052)]);

($port_a) = offer('reverse DTMF transcoding - no-op', { ICE => 'remove', replace => ['origin'],
	flags => ['always transcode'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 8050 RTP/AVP 0 101
c=IN IP4 198.51.100.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('reverse DTMF transcoding - no-op', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 8052 RTP/AVP 0 101
c=IN IP4 198.51.100.3
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1002, 3000+160*2, 0x1234, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
rcv($sock_b, $port_a, rtpm(0, 1002, 3000+160*2, 0x1234, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_a, $port_b,  rtp(0, 1003, 3000+160*3, 0x1234, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
rcv($sock_b, $port_a, rtpm(0, 1003, 3000+160*3, 0x1234, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_a, $port_b,  rtp(0, 1004, 3000+160*4, 0x1234, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
rcv($sock_b, $port_a, rtpm(0, 1004, 3000+160*4, 0x1234, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
snd($sock_a, $port_b,  rtp(0, 1005, 3000+160*5, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1005, 3000+160*5, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1006, 3000+160*6, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3000+160*6, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(101 | 0x80, 1007, 3000+160*7, 0x1234, "\x08\x10\x00\xa0"));
rcv($sock_b, $port_a, rtpm(101 | 0x80, 1007, 3000+160*7, 0x1234, "\x08\x10\x00\xa0"));

snd($sock_b, $port_a,  rtp(0, 1000, 3000, 0x3456, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 1001, 3160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 1001, 3160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 1002, 3000+160*2, 0x3456, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
rcv($sock_a, $port_b, rtpm(0, 1002, 3000+160*2, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_b, $port_a,  rtp(0, 1003, 3000+160*3, 0x3456, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
rcv($sock_a, $port_b, rtpm(0, 1003, 3000+160*3, $ssrc, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_b, $port_a,  rtp(0, 1004, 3000+160*4, 0x3456, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
rcv($sock_a, $port_b, rtpm(0, 1004, 3000+160*4, $ssrc, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
snd($sock_b, $port_a,  rtp(0, 1005, 3000+160*5, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 1005, 3000+160*5, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 1006, 3000+160*6, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 1006, 3000+160*6, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(101 | 0x80, 1007, 3000+160*7, 0x3456, "\x08\x10\x00\xa0"));
rcv($sock_a, $port_b, rtpm(101 | 0x80, 1007, 3000+160*7, $ssrc, "\x08\x10\x00\xa0"));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 7050)], [qw(198.51.100.3 7052)]);

($port_a) = offer('reverse DTMF transcoding - active', { ICE => 'remove', replace => ['origin'],
	flags => ['always transcode'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7050 RTP/AVP 0 101
c=IN IP4 198.51.100.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('reverse DTMF transcoding - active', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7052 RTP/AVP 0
c=IN IP4 198.51.100.3
a=rtpmap:0 PCMU/8000
a=fmtp:101 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($seq, $ssrc) = rcv($sock_b, $port_a, rtpm(0, -1, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq+1, 3160, $ssrc, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1002, 3000+160*2, 0x1234, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
rcv($sock_b, $port_a, rtpm(0, $seq+2, 3000+160*2, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_a, $port_b,  rtp(0, 1003, 3000+160*3, 0x1234, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
rcv($sock_b, $port_a, rtpm(0, $seq+3, 3000+160*3, $ssrc, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_a, $port_b,  rtp(0, 1004, 3000+160*4, 0x1234, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
rcv($sock_b, $port_a, rtpm(0, $seq+4, 3000+160*4, $ssrc, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
snd($sock_a, $port_b,  rtp(0, 1005, 3000+160*5, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq+5, 3000+160*5, $ssrc, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1006, 3000+160*6, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq+6, 3000+160*6, $ssrc, "\x00" x 160));
snd($sock_a, $port_b,  rtp(101 | 0x80, 1007, 3000+160*7, 0x1234, "\x08\x10\x00\xa0"));
rcv($sock_b, $port_a, rtpm(0, $seq+7, 3000+160*7, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));

snd($sock_b, $port_a,  rtp(0, 1000, 3000, 0x3456, "\x00" x 160));
($seq, $ssrc) = rcv($sock_a, $port_b, rtpm(0, -1, 3000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 1001, 3160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+1, 3160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 1002, 3000+160*2, 0x3456, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
# DTMF not detected yet
rcv($sock_a, $port_b, rtpm(0, $seq+2, 3000+160*2, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_b, $port_a,  rtp(0, 1003, 3000+160*3, 0x3456, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
# DTMF detection kicking in mid-frame
rcv($sock_a, $port_b, rtpm(0, $seq+3, 3000+160*3, $ssrc, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_b, $port_a,  rtp(0, 1004, 3000+160*4, 0x3456, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
# DTMF detected now
rcv($sock_a, $port_b, rtpm(101 | 0x80, $seq+4, 3000+160*4, $ssrc, "\x08\x0f\x00\xa0"));
snd($sock_b, $port_a,  rtp(0, 1005, 3000+160*5, 0x3456, "\x00" x 160));
# reverting to audio, but DTMF event still progressing
rcv($sock_a, $port_b, rtpm(101, $seq+5, 3000+160*4, $ssrc, "\x08\x0f\x01\x40"));
snd($sock_b, $port_a,  rtp(0, 1006, 3000+160*6, 0x3456, "\x00" x 160));
# end event, 3 times
rcv($sock_a, $port_b, rtpm(101, $seq+6, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0"));
rcv($sock_a, $port_b, rtpm(101, $seq+7, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0"));
rcv($sock_a, $port_b, rtpm(101, $seq+8, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0")); 
# audio passing through again
snd($sock_b, $port_a,  rtp(0, 1007, 3000+160*7, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+9, 3000+160*7, $ssrc, "\x00" x 160));





($sock_a, $sock_b) = new_call([qw(198.51.100.1 7060)], [qw(198.51.100.3 7062)]);

($port_a) = offer('DTMF scaling', { ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['PCMA', 'telephone-event/8000'] },
	flags => ['always transcode'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7060 RTP/AVP 100 101
c=IN IP4 198.51.100.1
a=rtpmap:100 PCMU/16000
a=rtpmap:101 telephone-event/16000
a=fmtp:101 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 100 101 8 96
c=IN IP4 203.0.113.1
a=rtpmap:100 PCMU/16000
a=rtpmap:101 telephone-event/16000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:101 0-15
a=fmtp:96 0-15
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('DTMF scaling', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7062 RTP/AVP 8 96
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 100 101
c=IN IP4 203.0.113.1
a=rtpmap:100 PCMU/16000
a=rtpmap:101 telephone-event/16000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(100, 1000, 3000+320*0, 0x1234, "\x00" x 320));
# resample buffer is stalling
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_a, $port_b,  rtp(100, 1001, 3000+320*1, 0x1234, "\x00" x 320));
($ssrc) = rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, -1, "\x2a" x 160));
snd($sock_a, $port_b,  rtp(100, 1002, 3000+320*2, 0x1234, "\x00" x 320));
rcv($sock_b, $port_a, rtpm(8, 1001, 3000+160*1, $ssrc, "\x2a" x 160));
# start dtmf
snd($sock_a, $port_b,  rtp(101 | 0x80, 1003, 3000+320*3, 0x1234, "\x08\x0f\x01\x40"));
rcv($sock_b, $port_a, rtpm(96 | 0x80, 1002, 3000+160*2, $ssrc, "\x08\x0f\x00\xa0"));
snd($sock_a, $port_b,  rtp(101, 1004, 3000+320*3, 0x1234, "\x08\x0f\x02\x80"));
rcv($sock_b, $port_a, rtpm(96, 1003, 3000+160*2, $ssrc, "\x08\x0f\x01\x40"));
# end event
snd($sock_a, $port_b,  rtp(101, 1005, 3000+320*3, 0x1234, "\x08\x8f\x03\xc0"));
rcv($sock_b, $port_a, rtpm(96, 1004, 3000+160*2, $ssrc, "\x08\x8f\x01\xe0"));
snd($sock_a, $port_b,  rtp(101, 1006, 3000+320*3, 0x1234, "\x08\x8f\x03\xc0"));
rcv($sock_b, $port_a, rtpm(96, 1005, 3000+160*2, $ssrc, "\x08\x8f\x01\xe0"));
snd($sock_a, $port_b,  rtp(101, 1007, 3000+320*3, 0x1234, "\x08\x8f\x03\xc0"));
rcv($sock_b, $port_a, rtpm(96, 1006, 3000+160*2, $ssrc, "\x08\x8f\x01\xe0"));
# back to audio
snd($sock_a, $port_b,  rtp(100, 1008, 3000+320*6, 0x1234, "\x00" x 320));
rcv($sock_b, $port_a, rtpm(8, 1007, 3000+160*5, $ssrc, "\x2a" x 160));






new_call;

offer('DTMF repacketising',
	{ ICE => 'remove', replace => ['origin', 'session-connection'],
	flags => ['strict-source'],
	ptime => 20, 'ptime-reverse' => 60, 'rtcp-mux' => ['demux'],
	}, <<SDP);
v=0
o=- 3768297181 3768297181 IN IP4 10.10.12.22
s=Blink Lite 4.6.0 (MacOSX)
t=0 0
m=audio 50036 RTP/AVP 0 8 101
c=IN IP4 10.10.12.22
a=rtcp:50037
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
----------------------------------
v=0
o=- 3768297181 3768297181 IN IP4 203.0.113.1
s=Blink Lite 4.6.0 (MacOSX)
t=0 0
m=audio PORT RTP/AVP 0 8 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP




# gh #793

new_call;

offer('gh #793 b1', { ICE => 'remove', 'via-branch' => 'x123', 'rtcp-mux' => ['demux'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=rtcp-mux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('gh #793 b1', { ICE => 'remove', 'via-branch' => 'x456', 'rtcp-mux' => ['offer'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=rtcp-mux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
SDP

answer('gh #793 b1', { ICE => 'remove', 'via-branch' => 'x123' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
SDP

new_call;

offer('gh #793 b2', { ICE => 'remove', 'via-branch' => 'x123', 'rtcp-mux' => ['demux'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=rtcp-mux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('gh #793 b2', { ICE => 'remove', 'via-branch' => 'x456', 'rtcp-mux' => ['offer'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=rtcp-mux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
SDP

answer('gh #793 b2', { ICE => 'remove', 'via-branch' => 'x456' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP




# media playback after a delete

($sock_a, $sock_b) = new_call([qw(198.51.100.1 3020)], [qw(198.51.100.3 3022)]);

offer('media playback after delete', { ICE => 'remove', replace => ['origin'],
	'rtcp-mux' => ['demux'], 'via-branch' => 'xxxx', flags => ['strict-source', 'record-call'],
	'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3020 RTP/AVP 98 97 8 0 3 101
c=IN IP4 198.51.100.1
a=rtpmap:98 speex/16000
a=rtpmap:97 speex/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=sendrecv
a=ptime:20
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 98 97 8 0 3 101
c=IN IP4 203.0.113.1
a=direction:both
a=rtpmap:98 speex/16000
a=rtpmap:97 speex/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

answer('media playback after delete', { replace => ['origin'], 'transport-protocol' => 'RTP/AVP',
	'rtcp-mux' => ['demux'], 'via-branch' => 'xxxx' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3022 RTP/AVP 8 0 3 101
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 3 101
c=IN IP4 203.0.113.1
a=direction:both
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

rtpe_req('delete', 'media playback after delete', { 'from-tag' => ft() });

# new to-tag
new_tt();

offer('media playback after delete', { ICE => 'remove', replace => ['origin'],
	'transport-protocol' => 'transparent', flags => ['strict-source', 'record-call'],
	'rtcp-mux' => ['demux'], 'via-branch' => 'xxxx' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3020 RTP/AVP 98 97 8 0 3 101
c=IN IP4 198.51.100.1
a=rtpmap:98 speex/16000
a=rtpmap:97 speex/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=sendrecv
a=ptime:20
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 98 97 8 0 3 101
c=IN IP4 203.0.113.1
a=direction:both
a=rtpmap:98 speex/16000
a=rtpmap:97 speex/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

answer('media playback after delete', { replace => ['origin'], 'transport-protocol' => 'RTP/AVP',
	'rtcp-mux' => ['demux'], 'via-branch' => 'xxxx' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3022 RTP/AVP 8 0 101
c=IN IP4 198.51.100.3
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=direction:both
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 101
c=IN IP4 203.0.113.1
a=direction:both
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

#rtpe_req('block media', 'media playback after delete', { });

$resp = rtpe_req('play media', 'media playback after delete', { 'from-tag' => tt(), 'to-tag' => tt(),
		blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

($seq, $ts, $ssrc) = rcv($sock_b, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_b, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_b, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_b, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_b, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));




done_testing();
