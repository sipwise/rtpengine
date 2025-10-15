#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use POSIX;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -f -L 7 -E --log-level-internals=7))
		or die;



my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $port_c, $ssrc_a, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx, $port_d, $port_dx, $sock_e, $port_e, $sock_cx, $port_cx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $tag_medias, $media_labels,
	$ftr, $ttr, $fts, $ttr2, $ice_ufrag_a, $ice_ufrag_b, $ice_pwd_a, $ice_pwd_b);



($sock_a, $sock_b) =
	new_call([qw(198.51.100.14 6438)],
		[qw(198.51.100.14 6440)]);

($port_a, undef, $port_b) = offer('optional bundle w DTLS',
	{ bundle => ['accept'], ICE => 'remove', 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6438 RTP/SAVPF 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=fingerprint:sha-256 43:92:E2:A9:BC:FD:53:00:32:4D:EC:97:55:B5:C9:52:95:40:BE:CB:1A:26:4B:34:7A:48:42:96:09:F7:50:97
a=setup:actpass
m=video 6440 RTP/SAVPF 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=fingerprint:sha-256 43:92:E2:A9:BC:FD:53:00:32:4D:EC:97:55:B5:C9:52:95:40:BE:CB:1A:26:4B:34:7A:48:42:96:09:F7:50:97
a=setup:actpass
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

rcv_no($sock_b);

rcv($sock_a, -1, qr/^\x16\xfe\xff\x00\x00\x00\x00\x00\x00\x00/s);




if ($ENV{RTPENGINE_EXTENDED_TESTS}) {

($sock_a, $sock_ax, $sock_b, $sock_bx) =
	new_call([qw(198.51.100.14 6414)],
		[qw(2001:db8:4321::3 6200)],
		[qw(198.51.100.14 6416)],
		[qw(2001:db8:4321::3 6202)]);

($port_a, undef, $port_b) = offer('optional bundle w ICE',
	{ bundle => ['accept'], ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6414 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=ice-ufrag:UXPd
a=ice-pwd:02K77oy8PHQ2tmz6RjF4gyWB
a=candidate:xxxxxxx 1 udp 2130706431 198.51.100.14 6414 typ host
a=candidate:aaaaaaa 1 udp 2130706175 2001:db8:4321::3 6200 typ host
a=candidate:xxxxxxx 2 UDP 2130706430 198.51.100.14 6415 typ host
a=candidate:aaaaaaa 2 UDP 2130706174 2001:db8:4321::3 6201 typ host
a=mid:a
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 6416 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=ice-ufrag:55Pd
a=ice-pwd:02K77oy8PHggggz6RjF4gyWB
a=candidate:xxxxxxx 1 udp 2130706431 198.51.100.14 6416 typ host
a=candidate:aaaaaaa 1 udp 2130706175 2001:db8:4321::3 6202 typ host
a=candidate:xxxxxxx 2 UDP 2130706430 198.51.100.14 6417 typ host
a=candidate:aaaaaaa 2 UDP 2130706174 2001:db8:4321::3 6203 typ host
a=mid:v
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $ice_ufrag_a, $ice_pwd_a, undef, $port_cx, undef, undef, undef, undef, undef, undef, $port_d, undef, $ice_ufrag_b, $ice_pwd_b, undef, $port_dx) = answer('optional bundle w ICE',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3696 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6398 RTP/AVP 105
a=rtpmap:105 H264/90000
c=IN IP4 198.51.100.14
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

is($port_c, $port_cx, "same port");
is($port_d, $port_dx, "same port");
is($port_c, $port_d, "same port");
is($ice_ufrag_a, $ice_ufrag_b, "same ufrag");
is($ice_pwd_a, $ice_pwd_b, "same ufrag");

rcv_no($sock_b);
rcv_no($sock_bx);

rcv($sock_a, -1, qr/^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine/s);
rcv($sock_ax, -1, qr/^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine/s);

}





new_call;

offer('reject video control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 4444 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 4444 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

answer('reject video control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2222 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 0 RTP/AVP 105
c=IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video 0 RTP/AVP 105
c=IN IP4 0.0.0.0
a=mid:v
SDP



new_call;

offer('invalid reject video control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 4444 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 4444 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

answer('invalid reject video control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2222 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 0.0.0.0
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP
# XXX ^ should disable the video media?



new_call;

offer('reject video control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 4444 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 4444 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

answer('reject video control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2222 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 0 RTP/AVP 105
c=IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video 0 RTP/AVP 105
c=IN IP4 0.0.0.0
a=mid:v
SDP



new_call;

offer('invalid reject video control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 4444 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 4444 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

answer('invalid reject video control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2222 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 0.0.0.0
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP
# XXX ^ should disable the video media?



new_call;

offer('reject video',
	{ bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 4444 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 4444 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

answer('reject video',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2222 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 0 RTP/AVP 105
c=IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video 0 RTP/AVP 105
c=IN IP4 0.0.0.0
a=mid:v
SDP



new_call;

offer('invalid reject video',
	{ bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 4444 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 4444 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

answer('invalid reject video',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2222 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 0.0.0.0
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP
# XXX ^ should disable the video media?



($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6150)],
		[qw(198.51.100.14 6152)],
		[qw(198.51.100.14 6154)],
		[qw(198.51.100.14 6156)]);

($port_a, undef, $port_b) = offer('control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6150 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6152 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6154 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6156 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
isnt($port_c, $port_d, 'different ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160));

snd($sock_b, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_b, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800));



($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6158)],
		[qw(198.51.100.14 6160)],
		[qw(198.51.100.14 6162)],
		[qw(198.51.100.14 6164)]);

($port_a, undef, $port_b) = offer('optional bundle offer',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6158 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6160 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('optional bundle offer',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6162 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6164 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
isnt($port_c, $port_d, 'different ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160));

snd($sock_b, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_b, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800));


# mix up bundle ports

snd($sock_a, $port_d,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_d, $port_b, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv_no($sock_c);

snd($sock_b, $port_c,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_c, $port_a, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv_no($sock_d);

($port_ax, undef, $port_bx) = offer('optional bundle offer reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6158 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6160 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_cx, undef, $port_dx) = answer('optional bundle offer reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6162 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6164 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

is($port_a, $port_ax, "same port");
is($port_b, $port_bx, "same port");
is($port_c, $port_cx, "same port");
is($port_d, $port_dx, "same port");

reverse_tags;

($port_cx, undef, $port_dx) = offer('optional bundle offer reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6162 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6164 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_ax, undef, $port_bx) = answer('optional bundle offer reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6158 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6160 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP






undef($sock_b);


($sock_a, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6166)],
		[qw(198.51.100.14 6168)],
		[qw(198.51.100.14 6170)]);

($port_a, undef, $port_b) = offer('same-port bundle offer',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6166 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6166 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('same-port bundle offer',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6168 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6170 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
isnt($port_c, $port_d, 'different ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160));

snd($sock_a, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_a, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800));

# mix up bundle ports

snd($sock_a, $port_d,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_d, $port_b, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv_no($sock_c);

snd($sock_a, $port_c,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_c, $port_a, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv_no($sock_d);




($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6200)],
		[qw(198.51.100.14 6202)],
		[qw(198.51.100.14 6204)],
		[qw(198.51.100.14 6206)]);

($port_a, undef, $port_b) = offer('optional bundle offer w bundle-accept',
	{ bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6200 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6202 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('optional bundle offer w bundle-accept',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6204 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6206 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
is($port_c, $port_d, 'same ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv_no($sock_b);

snd($sock_b, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_a, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv_no($sock_b);


# mix up bundle ports

snd($sock_a, $port_d,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv_no($sock_d);

snd($sock_b, $port_c,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv_no($sock_c);

($port_ax, undef, $port_bx) = offer('optional bundle offer w bundle-accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6200 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6200 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_cx, undef, $port_dx) = answer('optional bundle offer w bundle-accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6204 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6206 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

is($port_a, $port_ax, "same port");
is($port_b, $port_bx, "same port");
is($port_c, $port_cx, "same port");
is($port_d, $port_dx, "same port");

reverse_tags;

($port_cx, undef, $port_dx) = offer('optional bundle offer w bundle-accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6204 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6206 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=bundle-only
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_ax, undef, $port_bx) = answer('optional bundle offer w bundle-accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6200 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6200 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

is($port_a, $port_ax, "same port");
is($port_b, $port_bx, "same port");
is($port_c, $port_cx, "same port");
is($port_d, $port_dx, "same port");





undef($sock_b);


($sock_a, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6208)],
		[qw(198.51.100.14 6210)],
		[qw(198.51.100.14 6212)]);

($port_a, undef, $port_b) = offer('same-port bundle offer w bundle-accept',
	{ bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6208 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6208 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('same-port bundle offer w bundle-accept',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6210 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6212 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
is($port_c, $port_d, 'same ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160));

snd($sock_a, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_a, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800));

# mix up bundle ports

snd($sock_a, $port_d,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv_no($sock_c);



offer('same port bundle with non unique PT',
	{ bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6208 RTP/AVP 0 100
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=rtpmap:100 foo/8000
m=video 6208 RTP/AVP 105 100
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=rtpmap:100 bar/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 100
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=rtpmap:100 foo/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105 100
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=rtpmap:100 bar/90000
a=sendrecv
a=rtcp:PORT
SDP

answer('same port bundle with non unique PT',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6210 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6212 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP




offer('optional bundle with non unique PT',
	{ bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 7106 RTP/AVP 0 100
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=rtpmap:100 foo/8000
m=video 7108 RTP/AVP 105 100
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=rtpmap:100 bar/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 100
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=rtpmap:100 foo/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105 100
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=rtpmap:100 bar/90000
a=sendrecv
a=rtcp:PORT
SDP

answer('same port bundle with non unique PT',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7110 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 7112 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP





($sock_a, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6216)],
		[qw(198.51.100.14 6218)],
		[qw(198.51.100.14 6220)]);

($port_a, undef, $port_b) = offer('same-port bundle with extmap',
	{ bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6216 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 6216 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('same-port bundle with extmap',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6218 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6220 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
is($port_c, $port_d, 'same ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160, [[1, 'a']]));

snd($sock_a, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_a, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800, [[1, 'v']]));

# mix up bundle ports

snd($sock_a, $port_d,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv_no($sock_c);




($sock_a, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6224)],
		[qw(198.51.100.14 6226)],
		[qw(198.51.100.14 6228)]);

($port_a, undef, $port_b) = offer('same-port bundle with extmap & non unique PTs',
	{ bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6224 RTP/AVP 0 100
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=rtpmap:100 foobar/1000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 6224 RTP/AVP 105 100
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=rtpmap:100 bozo/90000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 100
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=rtpmap:100 foobar/1000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105 100
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=rtpmap:100 bozo/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('same-port bundle with extmap & non unique PTs',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6226 RTP/AVP 0 100
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=rtpmap:100 foobar/1000
m=video 6228 RTP/AVP 105 100
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=rtpmap:100 bozo/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio PORT RTP/AVP 0 100
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=rtpmap:100 foobar/1000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105 100
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=rtpmap:100 bozo/90000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
is($port_c, $port_d, 'same ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160, [[1, 'a']]));

snd($sock_a, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_a, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800, [[1, 'v']]));

# mix up bundle ports

snd($sock_a, $port_d,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv_no($sock_c);

snd($sock_a, $port_d,  rtp(100, 7000, 11000, 0x25bc, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(100, 7000, 11000, 0x25bc, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(100, 8000, 9000, 0x76a9, "\x33" x 800));
# recv on wrong sock
rcv($sock_c, $port_a, rtpm(100, 8000, 9000, 0x76a9, "\x33" x 800));
rcv_no($sock_d);

# with extension

snd($sock_a, $port_d,  rtp(0, 2001, 6160, 0x1234, "\x44" x 160, [[1, 'a']]));
rcv($sock_c, $port_a, rtpm(0, 2001, 6160, 0x1234, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(105, 3001, 4160, 0x6321, "\x33" x 800, [[1, 'v']]));
rcv($sock_d, $port_b, rtpm(105, 3001, 4160, 0x6321, "\x33" x 800));
rcv_no($sock_c);

snd($sock_a, $port_d,  rtp(100, 7001, 11160, 0x25bc, "\x44" x 160, [[1, 'a']]));
rcv($sock_c, $port_a, rtpm(100, 7001, 11160, 0x25bc, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(100, 8001, 9160, 0x76a9, "\x33" x 800, [[1, 'v']]));
# recv now on correct sock
rcv($sock_d, $port_b, rtpm(100, 8001, 9160, 0x76a9, "\x33" x 800));
rcv_no($sock_c);

# SSRCs are remembered

snd($sock_a, $port_d,  rtp(100, 7000, 11000, 0x25bc, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(100, 7000, 11000, 0x25bc, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(100, 8000, 9000, 0x76a9, "\x33" x 800));
# recv still in correct port
rcv($sock_d, $port_b, rtpm(100, 8000, 9000, 0x76a9, "\x33" x 800));
rcv_no($sock_c);






($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 7116)],
		[qw(198.51.100.14 7114)],
		[qw(198.51.100.14 7118)],
		[qw(198.51.100.14 7120)]);

($port_a, undef, $port_b) = offer('optional bundle with extmap',
	{ bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 7116 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 7114 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('optional bundle with extmap',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7118 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 7120 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
is($port_c, $port_d, 'same ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160, [[1, 'a']]));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160, [[1, 'a']]));
rcv_no($sock_b);

snd($sock_a, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_a, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800, [[1, 'v']]));
rcv_no($sock_b);

# mix up bundle ports

snd($sock_a, $port_d,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160, [[1, 'a']]));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv_no($sock_c);




($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 7124)],
		[qw(198.51.100.14 7122)],
		[qw(198.51.100.14 7126)],
		[qw(198.51.100.14 7128)]);

($port_a, undef, $port_b) = offer('optional bundle with extmap & non unique PTs',
	{ bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 7124 RTP/AVP 0 100
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=rtpmap:100 foobar/1000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 7122 RTP/AVP 105 100
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=rtpmap:100 bozo/90000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 100
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=rtpmap:100 foobar/1000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105 100
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=rtpmap:100 bozo/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('optional bundle with extmap & non unique PTs',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7126 RTP/AVP 0 100
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=rtpmap:100 foobar/1000
m=video 7128 RTP/AVP 105 100
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=rtpmap:100 bozo/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio PORT RTP/AVP 0 100
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=rtpmap:100 foobar/1000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105 100
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=rtpmap:100 bozo/90000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
is($port_c, $port_d, 'same ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160, [[1, 'a']]));
rcv_no($sock_b);

snd($sock_a, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_a, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800, [[1, 'v']]));
rcv_no($sock_b);

# mix up bundle ports

snd($sock_a, $port_d,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv_no($sock_c);

snd($sock_a, $port_d,  rtp(100, 7000, 11000, 0x25bc, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(100, 7000, 11000, 0x25bc, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(100, 8000, 9000, 0x76a9, "\x33" x 800));
# recv on wrong sock
rcv($sock_c, $port_a, rtpm(100, 8000, 9000, 0x76a9, "\x33" x 800));
rcv_no($sock_d);

# with extension

snd($sock_a, $port_d,  rtp(0, 2001, 6160, 0x1234, "\x44" x 160, [[1, 'a']]));
rcv($sock_c, $port_a, rtpm(0, 2001, 6160, 0x1234, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(105, 3001, 4160, 0x6321, "\x33" x 800, [[1, 'v']]));
rcv($sock_d, $port_b, rtpm(105, 3001, 4160, 0x6321, "\x33" x 800));
rcv_no($sock_c);

snd($sock_a, $port_d,  rtp(100, 7001, 11160, 0x25bc, "\x44" x 160, [[1, 'a']]));
rcv($sock_c, $port_a, rtpm(100, 7001, 11160, 0x25bc, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(100, 8001, 9160, 0x76a9, "\x33" x 800, [[1, 'v']]));
# recv now on correct sock
rcv($sock_d, $port_b, rtpm(100, 8001, 9160, 0x76a9, "\x33" x 800));
rcv_no($sock_c);






($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6236)],
		[qw(198.51.100.14 6234)],
		[qw(198.51.100.14 6238)],
		[qw(198.51.100.14 6240)]);

($port_a, undef, $port_b) = offer('optional bundle with extmap & non unique PTs & strict source',
	{ bundle => ['accept'], flags => ['strict source'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6236 RTP/AVP 0 100
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=rtpmap:100 foobar/1000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 6234 RTP/AVP 105 100
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=rtpmap:100 bozo/90000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 100
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=rtpmap:100 foobar/1000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105 100
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=rtpmap:100 bozo/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('optional bundle with extmap & non unique PTs & strict source',
	{ flags => ['strict source'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6238 RTP/AVP 0 100
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=rtpmap:100 foobar/1000
m=video 6240 RTP/AVP 105 100
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=rtpmap:100 bozo/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio PORT RTP/AVP 0 100
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=rtpmap:100 foobar/1000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105 100
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=rtpmap:100 bozo/90000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
is($port_c, $port_d, 'same ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160, [[1, 'a']]));
rcv_no($sock_b);

snd($sock_a, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_a, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800, [[1, 'v']]));
rcv_no($sock_b);

# mix up bundle ports

snd($sock_a, $port_d,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv_no($sock_c);

snd($sock_a, $port_d,  rtp(100, 7000, 11000, 0x25bc, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(100, 7000, 11000, 0x25bc, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(100, 8000, 9000, 0x76a9, "\x33" x 800));
# recv on wrong sock
rcv($sock_c, $port_a, rtpm(100, 8000, 9000, 0x76a9, "\x33" x 800));
rcv_no($sock_d);

# with extension

snd($sock_a, $port_d,  rtp(0, 2001, 6160, 0x1234, "\x44" x 160, [[1, 'a']]));
rcv($sock_c, $port_a, rtpm(0, 2001, 6160, 0x1234, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(105, 3001, 4160, 0x6321, "\x33" x 800, [[1, 'v']]));
rcv($sock_d, $port_b, rtpm(105, 3001, 4160, 0x6321, "\x33" x 800));
rcv_no($sock_c);

snd($sock_a, $port_d,  rtp(100, 7001, 11160, 0x25bc, "\x44" x 160, [[1, 'a']]));
rcv($sock_c, $port_a, rtpm(100, 7001, 11160, 0x25bc, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(100, 8001, 9160, 0x76a9, "\x33" x 800, [[1, 'v']]));
# recv now on correct sock
rcv($sock_d, $port_b, rtpm(100, 8001, 9160, 0x76a9, "\x33" x 800));
rcv_no($sock_c);





($sock_a, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6248)],
		[qw(198.51.100.14 6250)],
		[qw(198.51.100.14 6252)]);

($port_a, undef, $port_b) = offer('same port bundle with extmap & non unique PTs & strict source',
	{ bundle => ['accept'], flags => ['strict source'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6248 RTP/AVP 0 100
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=rtpmap:100 foobar/1000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 6248 RTP/AVP 105 100
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=rtpmap:100 bozo/90000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 100
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=rtpmap:100 foobar/1000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105 100
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=rtpmap:100 bozo/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('same port bundle with extmap & non unique PTs & strict source',
	{ flags => ['strict source'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6250 RTP/AVP 0 100
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=rtpmap:100 foobar/1000
m=video 6252 RTP/AVP 105 100
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=rtpmap:100 bozo/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio PORT RTP/AVP 0 100
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=rtpmap:100 foobar/1000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105 100
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=rtpmap:100 bozo/90000
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
is($port_c, $port_d, 'same ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160, [[1, 'a']]));

snd($sock_a, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_a, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800, [[1, 'v']]));

# mix up bundle ports

snd($sock_a, $port_d,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv_no($sock_c);

snd($sock_a, $port_d,  rtp(100, 7000, 11000, 0x25bc, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(100, 7000, 11000, 0x25bc, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(100, 8000, 9000, 0x76a9, "\x33" x 800));
# recv on wrong sock
rcv($sock_c, $port_a, rtpm(100, 8000, 9000, 0x76a9, "\x33" x 800));
rcv_no($sock_d);

# with extension

snd($sock_a, $port_d,  rtp(0, 2001, 6160, 0x1234, "\x44" x 160, [[1, 'a']]));
rcv($sock_c, $port_a, rtpm(0, 2001, 6160, 0x1234, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(105, 3001, 4160, 0x6321, "\x33" x 800, [[1, 'v']]));
rcv($sock_d, $port_b, rtpm(105, 3001, 4160, 0x6321, "\x33" x 800));
rcv_no($sock_c);

snd($sock_a, $port_d,  rtp(100, 7001, 11160, 0x25bc, "\x44" x 160, [[1, 'a']]));
rcv($sock_c, $port_a, rtpm(100, 7001, 11160, 0x25bc, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(100, 8001, 9160, 0x76a9, "\x33" x 800, [[1, 'v']]));
# recv now on correct sock
rcv($sock_d, $port_b, rtpm(100, 8001, 9160, 0x76a9, "\x33" x 800));
rcv_no($sock_c);






($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6190)],
		[qw(198.51.100.14 6192)],
		[qw(198.51.100.14 6194)],
		[qw(198.51.100.14 6196)]);

($port_a, undef, $port_b) = offer('make bundle, reject',
	{ bundle => ['offer'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6190 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
m=video 6192 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:2
a=rtpmap:105 H264/90000
a=extmap-allow-mixed
a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('make bundle, reject',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6194 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
m=video 6196 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
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
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
isnt($port_c, $port_d, 'different ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160));

snd($sock_b, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_b, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800));




undef($sock_d);

($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6374)],
		[qw(198.51.100.14 6376)],
		[qw(198.51.100.14 6378)]);

($port_a, undef, $port_b) = offer('make bundle, accept',
	{ bundle => ['offer'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6374 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
m=video 6376 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:2
a=rtpmap:105 H264/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('make bundle, accept',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio 6378 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:1
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 6378 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=mid:2
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
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
isnt($port_c, $port_d, 'different ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160, [[1, '1']]));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160));

snd($sock_b, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_c, $port_a, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800, [[1, '2']]));

snd($sock_c, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_b, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800));

($port_ax, undef, $port_bx) = offer('make bundle, accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6374 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
m=video 6376 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:2
a=bundle-only
a=rtpmap:105 H264/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

($port_cx, undef, $port_dx) = answer('make bundle, accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio 6378 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:1
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 6378 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=mid:2
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
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

is($port_a, $port_ax, "same port");
is($port_a, $port_bx, "same port");
is($port_c, $port_cx, "same port");
is($port_d, $port_dx, "same port");

reverse_tags;

($port_cx, undef, $port_dx) = offer('make bundle, accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio 6378 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:1
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 6378 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=mid:2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:2
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_ax, undef, $port_bx) = answer('make bundle, accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6374 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
m=video 6376 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:2
a=rtpmap:105 H264/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

is($port_a, $port_ax, "same port");
is($port_a, $port_bx, "same port");
is($port_c, $port_cx, "same port");
is($port_d, $port_dx, "same port");






($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6386)],
		[qw(198.51.100.14 6388)],
		[qw(198.51.100.14 6390)]);

($port_a, undef, $port_b) = offer('require bundle, accept',
	{ bundle => ['require'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6386 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
m=video 6388 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:2
a=bundle-only
a=rtpmap:105 H264/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('require bundle, accept',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio 6390 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:1
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 6390 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=mid:2
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
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

is($port_a, $port_b, 'same ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
isnt($port_c, $port_d, 'different ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160, [[1, '1']]));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160));

snd($sock_b, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_c, $port_a, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800, [[1, '2']]));

snd($sock_c, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_b, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800));

($port_ax, undef, $port_bx) = offer('require bundle, accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6386 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
m=video 6388 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:2
a=bundle-only
a=rtpmap:105 H264/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

($port_cx, undef, $port_dx) = answer('require bundle, accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio 6390 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:1
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 6390 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=mid:2
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
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

is($port_a, $port_ax, "same port");
is($port_b, $port_bx, "same port");
is($port_c, $port_cx, "same port");
is($port_d, $port_dx, "same port");

reverse_tags;

($port_cx, undef, $port_dx) = offer('require bundle, accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio 6390 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:1
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 6390 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=mid:2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:2
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_ax, undef, $port_bx) = answer('require bundle, accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6386 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
m=video 6388 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:2
a=rtpmap:105 H264/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

is($port_a, $port_ax, "same port");
is($port_b, $port_bx, "same port");
is($port_c, $port_cx, "same port");
is($port_d, $port_dx, "same port");





($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6470)],
		[qw(198.51.100.14 6472)],
		[qw(198.51.100.14 6474)]);

($port_a, undef, $port_b) = offer('strict bundle, accept',
	{ bundle => ['strict'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6470 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
m=video 6472 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:2
a=bundle-only
a=rtpmap:105 H264/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('strict bundle, accept',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio 6474 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:1
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 6474 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=mid:2
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
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

is($port_b, 0, 'zero port');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_c, $port_d, 'different ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160, [[1, '1']]));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160));

snd($sock_b, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_c, $port_a, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800, [[1, '2']]));

snd($sock_c, $port_a,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_b, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800));

($port_ax, undef, $port_bx) = offer('strict bundle, accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6470 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
m=video 6472 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:2
a=bundle-only
a=rtpmap:105 H264/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

($port_cx, undef, $port_dx) = answer('strict bundle, accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio 6474 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:1
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 6474 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=mid:2
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
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

is($port_a, $port_ax, "same port");
is($port_a, $port_bx, "same port");
is($port_c, $port_cx, "same port");
is($port_d, $port_dx, "same port");

reverse_tags;

($port_cx, undef, $port_dx) = offer('strict bundle, accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio 6474 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:1
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
m=video 6474 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=mid:2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:2
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_ax, undef, $port_bx) = answer('strict bundle, accept reinvite',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6470 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
m=video 6472 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:2
a=rtpmap:105 H264/90000
a=extmap-allow-mixed
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=rtcp:PORT
SDP

is($port_a, $port_ax, "same port");
is($port_a, $port_bx, "same port");
is($port_c, $port_cx, "same port");
is($port_d, $port_dx, "same port");





#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
