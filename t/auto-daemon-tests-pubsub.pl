#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use POSIX;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --log-level-internals=7))
		or die;



my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $port_c, $ssrc_a, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx, $port_d, $sock_e, $port_e, $sock_cx, $port_cx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $tag_medias, $media_labels,
	$ftr, $ttr, $fts, $ttr2);



use_json(1);




($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6150)], [qw(198.51.100.14 6152)], [qw(198.51.100.14 6154)]);

($port_a) = offer('SIPREC pause/resume',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=s-dummy
a=s-foo:bar
a=s-baz:quux blah
m=audio 6150 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=s-dummy
a=s-foo:bar
a=s-baz:quux blah
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('SIPREC pause/resume',
	{ }, <<SDP);
v=0
o=test 1545997028 2 IN IP4 198.51.100.1
s=tester
t=0 0
a=a-dummy
a=a-foo:bar
a=a-baz:quux blah
m=audio 6152 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=b-dummy
a=b-foo:bar
a=b-baz:quux blah
----------------------------------
v=0
o=test 1545997028 2 IN IP4 198.51.100.1
s=tester
t=0 0
a=a-dummy
a=a-foo:bar
a=a-baz:quux blah
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=b-dummy
a=b-foo:bar
a=b-baz:quux blah
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));
rcv_no($sock_c);

(undef, $ttr, undef, undef, undef, $port_c) = subscribe_request('SIPREC pause/resume',
	{ 'from-tag' => ft(), flags => ['SIPREC', 'replace-origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
a=s-dummy
a=s-foo:bar
a=s-baz:quux blah
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:0
a=rtpmap:0 PCMU/8000
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
a=sendonly
a=rtcp:PORT
SDP

subscribe_answer('SIPREC pause/resume',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6154 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));



(undef, $ttr, undef, undef, undef, $port_d) = subscribe_request('SIPREC pause w/ inactive',
	{ 'from-tag' => ft(), 'to-tag' => $ttr, flags => ['SIPREC'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=s-dummy
a=s-foo:bar
a=s-baz:quux blah
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:0
a=rtpmap:0 PCMU/8000
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
a=sendonly
a=rtcp:PORT
SDP

is $port_c, $port_d, 'same port';

subscribe_answer('SIPREC pause w/ inactive',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6154 RTP/AVP 0
c=IN IP4 198.51.100.14
a=inactive
SDP

snd($sock_b, $port_a, rtp(0, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2002, 4320, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4002, 7320, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4002, 7320, $ssrc_b, "\x00" x 160));
rcv_no($sock_c);

(undef, $ttr, undef, undef, undef, $port_d) = subscribe_request('SIPREC unpause',
	{ 'from-tag' => ft(), 'to-tag' => $ttr, flags => ['SIPREC'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=s-dummy
a=s-foo:bar
a=s-baz:quux blah
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:0
a=rtpmap:0 PCMU/8000
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
a=sendonly
a=rtcp:PORT
SDP

is $port_c, $port_d, 'same port';

subscribe_answer('SIPREC unpause',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6154 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2003, 4480, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2003, 4480, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4003, 7480, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4003, 7480, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4003, 7480, $ssrc_b, "\x00" x 160));


(undef, $ttr, undef, undef, undef, $port_d) = subscribe_request('SIPREC pause w/ flag',
	{ 'from-tag' => ft(), 'to-tag' => $ttr, flags => ['SIPREC', 'inactive'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=s-dummy
a=s-foo:bar
a=s-baz:quux blah
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:0
a=rtpmap:0 PCMU/8000
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
a=inactive
a=rtcp:PORT
SDP

is $port_c, $port_d, 'same port';

subscribe_answer('SIPREC pause w/ flag',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6154 RTP/AVP 0
c=IN IP4 198.51.100.14
a=inactive
SDP

snd($sock_b, $port_a, rtp(0, 2004, 4640, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2004, 4640, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4004, 7640, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4004, 7640, $ssrc_b, "\x00" x 160));
rcv_no($sock_c);

(undef, $ttr, undef, undef, undef, $port_d) = subscribe_request('SIPREC unpause',
	{ 'from-tag' => ft(), 'to-tag' => $ttr, flags => ['SIPREC'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=s-dummy
a=s-foo:bar
a=s-baz:quux blah
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:0
a=rtpmap:0 PCMU/8000
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
a=sendonly
a=rtcp:PORT
SDP

is $port_c, $port_d, 'same port';

subscribe_answer('SIPREC unpause',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6154 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2005, 4800, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2005, 4800, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4005, 7800, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4005, 7800, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4005, 7800, $ssrc_b, "\x00" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call(
		[qw(198.51.100.17 6146)],
		[qw(198.51.100.17 6148)],
		[qw(198.51.100.17 6150)],
	);

($port_a) = offer('egress sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6146 RTP/AVP 0
c=IN IP4 198.51.100.17
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

($port_b) = answer('egress sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6148 RTP/AVP 0
c=IN IP4 198.51.100.17
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4000, 7000, 0x6543, "\x00" x 160));


($ftr, $ttr, undef, undef, undef, $port_c, $port_cx) = subscribe_request('egress sub',
	{ 'from-tag' => ft(), flags => ['egress'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('egress sub',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6150 RTP/AVP 0
c=IN IP4 198.51.100.17
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv_no($sock_b);
rcv_no($sock_c);
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv_no($sock_a);
snd($sock_c, $port_c, rtp(0, 5000, 8160, 0x9876, "\x00" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);




($sock_a, $sock_b, $sock_c) =
	new_call(
		[qw(198.51.100.17 6152)],
		[qw(198.51.100.17 6154)],
		[qw(198.51.100.17 6156)],
	);

($port_a) = offer('egress sub w tc',
	{ codec => {transcode => ['PCMA']} }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6152 RTP/AVP 0
c=IN IP4 198.51.100.17
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('egress sub w tc',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6154 RTP/AVP 8
c=IN IP4 198.51.100.17
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


snd($sock_b, $port_a, rtp(8, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x29" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(8, 4000, 7000, -1, "\x2a" x 160));


($ftr, $ttr, undef, undef, undef, $port_c, $port_cx) = subscribe_request('egress sub w tc',
	{ 'from-tag' => ft(), flags => ['egress'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('egress sub w tc',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6156 RTP/AVP 0
c=IN IP4 198.51.100.17
a=recvonly
SDP

snd($sock_b, $port_a, rtp(8, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x29" x 160));
rcv_no($sock_b);
rcv_no($sock_c);
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 4001, 7160, $ssrc_b, "\x2a" x 160));
rcv($sock_c, $port_c, rtpm(8, 4001, 7160, $ssrc_b, "\x2a" x 160));
rcv_no($sock_a);
snd($sock_c, $port_c, rtp(0, 5000, 8160, 0x9876, "\x00" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);







($sock_a, $sock_ax, $sock_b, $sock_bx, $sock_c, $sock_cx) =
	new_call(
		[qw(198.51.100.17 6000)],
		[qw(198.51.100.17 6001)],
		[qw(198.51.100.17 6002)],
		[qw(198.51.100.17 6003)],
		[qw(198.51.100.17 6004)],
		[qw(198.51.100.17 6005)],
	);

($port_a, $port_ax) = offer('simple sub, no RTCP mirror',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6000 RTP/AVP 0
c=IN IP4 198.51.100.17
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

($port_b, $port_bx) = answer('simple sub, no RTCP mirror',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6002 RTP/AVP 0
c=IN IP4 198.51.100.17
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4000, 7000, 0x6543, "\x00" x 160));

snd($sock_bx, $port_ax, "\x81\xc8\x00\x0c\x00\x00\x34\x56xxxxyyyy\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x001234qwer\x81\xca\x00\x05\x00\x00\x34\x56\x01\x0cabcdefghijkl\x00\x00");
rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x34\x56xxxxyyyy\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x001234qwer\x81\xca\x00\x05\x00\x00\x34\x56\x01\x0cabcdefghijkl\x00\x00$/);

snd($sock_ax, $port_bx, "\x81\xc8\x00\x0c\x00\x00\x65\x43aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x34\x56\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x65\x43\x01\x0cqwertyuiopqw\x00\x00");
rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x65\x43aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x34\x56\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x65\x43\x01\x0cqwertyuiopqw\x00\x00$/);


($ftr, $ttr, undef, undef, undef, $port_c, $port_cx) = subscribe_request('simple sub, no RTCP mirror',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('simple sub, no RTCP mirror',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6004 RTP/AVP 0
c=IN IP4 198.51.100.17
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv_no($sock_b);
rcv_no($sock_c);
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv_no($sock_a);
snd($sock_c, $port_c, rtp(0, 5000, 8160, 0x9876, "\x00" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

snd($sock_bx, $port_ax, "\x81\xc8\x00\x0c\x00\x00\x34\x56xxxxyyyy\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x001234qwer\x81\xca\x00\x05\x00\x00\x34\x56\x01\x0cabcdefghijkl\x00\x00");
rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x34\x56xxxxyyyy\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x001234qwer\x81\xca\x00\x05\x00\x00\x34\x56\x01\x0cabcdefghijkl\x00\x00$/);
rcv_no($sock_bx);
rcv_no($sock_cx);

snd($sock_ax, $port_bx, "\x81\xc8\x00\x0c\x00\x00\x65\x43aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x34\x56\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x65\x43\x01\x0cqwertyuiopqw\x00\x00");
rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x65\x43aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x34\x56\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x65\x43\x01\x0cqwertyuiopqw\x00\x00$/);
rcv($sock_cx, $port_cx, qr/^\x81\xc8\x00\x0c\x00\x00\x65\x43aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x34\x56\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x65\x43\x01\x0cqwertyuiopqw\x00\x00$/);
rcv_no($sock_ax);

snd($sock_cx, $port_cx, "\x81\xc8\x00\x0c\x00\x00\x98\x76aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x98\x76\x01\x0cqwertyuiopqw\x00\x00");
rcv_no($sock_ax);
rcv_no($sock_bx);
rcv_no($sock_cx);

$resp = rtpe_req('unsubscribe', 'simple sub, no RTCP mirror', { 'from-tag' => ft(), 'to-tag' => $ttr });

snd($sock_b, $port_a, rtp(0, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2002, 4320, 0x3456, "\x00" x 160));
rcv_no($sock_b);
rcv_no($sock_c);
snd($sock_a, $port_b, rtp(0, 4002, 7320, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4002, 7320, 0x6543, "\x00" x 160));
rcv_no($sock_c);
rcv_no($sock_a);
snd($sock_c, $port_c, rtp(0, 5001, 8160, 0x9876, "\x00" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

snd($sock_bx, $port_ax, "\x81\xc8\x00\x0c\x00\x00\x34\x56xxxxyyyy\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x001234qwer\x81\xca\x00\x05\x00\x00\x34\x56\x01\x0cabcdefghijkl\x00\x00");
rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x34\x56xxxxyyyy\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x001234qwer\x81\xca\x00\x05\x00\x00\x34\x56\x01\x0cabcdefghijkl\x00\x00$/);
rcv_no($sock_bx);
rcv_no($sock_cx);

snd($sock_ax, $port_bx, "\x81\xc8\x00\x0c\x00\x00\x65\x43aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x34\x56\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x65\x43\x01\x0cqwertyuiopqw\x00\x00");
rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x65\x43aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x34\x56\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x65\x43\x01\x0cqwertyuiopqw\x00\x00$/);
rcv_no($sock_cx);
rcv_no($sock_ax);

snd($sock_cx, $port_cx, "\x81\xc8\x00\x0c\x00\x00\x98\x76aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x98\x76\x01\x0cqwertyuiopqw\x00\x00");
rcv_no($sock_ax);
rcv_no($sock_bx);
rcv_no($sock_cx);





($sock_a, $sock_ax, $sock_b, $sock_bx, $sock_c, $sock_cx) =
	new_call(
		[qw(198.51.100.17 6006)],
		[qw(198.51.100.17 6007)],
		[qw(198.51.100.17 6008)],
		[qw(198.51.100.17 6009)],
		[qw(198.51.100.17 6010)],
		[qw(198.51.100.17 6011)],
	);

($port_a, $port_ax) = offer('simple sub, RTCP mirror',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6006 RTP/AVP 0
c=IN IP4 198.51.100.17
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

($port_b, $port_bx) = answer('simple sub, RTCP mirror',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6008 RTP/AVP 0
c=IN IP4 198.51.100.17
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4000, 7000, 0x6543, "\x00" x 160));

snd($sock_bx, $port_ax, "\x81\xc8\x00\x0c\x00\x00\x34\x56xxxxyyyy\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x001234qwer\x81\xca\x00\x05\x00\x00\x34\x56\x01\x0cabcdefghijkl\x00\x00");
rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x34\x56xxxxyyyy\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x001234qwer\x81\xca\x00\x05\x00\x00\x34\x56\x01\x0cabcdefghijkl\x00\x00$/);

snd($sock_ax, $port_bx, "\x81\xc8\x00\x0c\x00\x00\x65\x43aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x34\x56\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x65\x43\x01\x0cqwertyuiopqw\x00\x00");
rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x65\x43aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x34\x56\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x65\x43\x01\x0cqwertyuiopqw\x00\x00$/);


($ftr, $ttr, undef, undef, undef, $port_c, $port_cx) = subscribe_request('simple sub, RTCP mirror',
	{ 'from-tag' => ft(), flags => ['mirror RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('simple sub, RTCP mirror',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6010 RTP/AVP 0
c=IN IP4 198.51.100.17
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv_no($sock_b);
rcv_no($sock_c);
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv_no($sock_a);
snd($sock_c, $port_c, rtp(0, 5000, 8160, 0x9876, "\x00" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

snd($sock_bx, $port_ax, "\x81\xc8\x00\x0c\x00\x00\x34\x56xxxxyyyy\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x001234qwer\x81\xca\x00\x05\x00\x00\x34\x56\x01\x0cabcdefghijkl\x00\x00");
rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x34\x56xxxxyyyy\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x001234qwer\x81\xca\x00\x05\x00\x00\x34\x56\x01\x0cabcdefghijkl\x00\x00$/);
rcv_no($sock_bx);
rcv_no($sock_cx);

snd($sock_ax, $port_bx, "\x81\xc8\x00\x0c\x00\x00\x65\x43aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x34\x56\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x65\x43\x01\x0cqwertyuiopqw\x00\x00");
rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x65\x43aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x34\x56\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x65\x43\x01\x0cqwertyuiopqw\x00\x00$/);
rcv($sock_cx, $port_cx, qr/^\x81\xc8\x00\x0c\x00\x00\x65\x43aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x34\x56\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x65\x43\x01\x0cqwertyuiopqw\x00\x00$/);
rcv_no($sock_ax);

snd($sock_cx, $port_cx, "\x81\xc8\x00\x0c\x00\x00\x98\x76aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x98\x76\x01\x0cqwertyuiopqw\x00\x00");
rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x98\x76aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x98\x76\x01\x0cqwertyuiopqw\x00\x00$/);
rcv_no($sock_bx);
rcv_no($sock_cx);

$resp = rtpe_req('unsubscribe', 'simple sub, RTCP mirror', { 'from-tag' => ft(), 'to-tag' => $ttr });

snd($sock_b, $port_a, rtp(0, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2002, 4320, 0x3456, "\x00" x 160));
rcv_no($sock_b);
rcv_no($sock_c);
snd($sock_a, $port_b, rtp(0, 4002, 7320, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4002, 7320, 0x6543, "\x00" x 160));
rcv_no($sock_c);
rcv_no($sock_a);
snd($sock_c, $port_c, rtp(0, 5001, 8320, 0x9876, "\x00" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

snd($sock_bx, $port_ax, "\x81\xc8\x00\x0c\x00\x00\x34\x56xxxxyyyy\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x001234qwer\x81\xca\x00\x05\x00\x00\x34\x56\x01\x0cabcdefghijkl\x00\x00");
rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x34\x56xxxxyyyy\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x001234qwer\x81\xca\x00\x05\x00\x00\x34\x56\x01\x0cabcdefghijkl\x00\x00$/);
rcv_no($sock_bx);
rcv_no($sock_cx);

snd($sock_ax, $port_bx, "\x81\xc8\x00\x0c\x00\x00\x65\x43aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x34\x56\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x65\x43\x01\x0cqwertyuiopqw\x00\x00");
rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x65\x43aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x34\x56\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x65\x43\x01\x0cqwertyuiopqw\x00\x00$/);
rcv_no($sock_cx);
rcv_no($sock_ax);

snd($sock_cx, $port_cx, "\x81\xc8\x00\x0c\x00\x00\x98\x76aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x98\x76\x01\x0cqwertyuiopqw\x00\x00");
rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x98\x76aaaabbbb\x00\x00\x22\xd8\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x65\x43\x06\x00\x00\x01\x00\x00\x07\xf5\x00\x00\x00\x00poiuytre\x81\xca\x00\x05\x00\x00\x98\x76\x01\x0cqwertyuiopqw\x00\x00$/);
rcv_no($sock_bx);
rcv_no($sock_cx);












new_call;

($port_a) = offer('SIPREC sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.2
s=tester
t=0 0
m=audio 6000 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('SIPREC sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.2
s=tester
t=0 0
m=audio 6002 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


($ftr, $ttr, $fts, $tag_medias, $media_labels) = subscribe_request('SIPREC sub',
	{ flags => ['all', 'SIPREC', 'replace-origin'] }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:0
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, undef, 'from-tag matches';
is_deeply $fts, [ft(), tt()], 'from-tags match';
is_deeply $tag_medias, [
	{
		tag => ft(),
		medias => [
			{
				index => 1,
				type => 'audio',
				label => '0',
				mode => 'sendrecv',
			},
		],
	},
	{
		tag => tt(),
		medias => [
			{
				index => 1,
				type => 'audio',
				label => '1',
				mode => 'sendrecv',
			},
		],
	},
], 'tag-medias match';
is_deeply $media_labels, {
	'1' => {
		index => 1,
		type => 'audio',
		tag => tt(),
		mode => 'sendrecv',
	},
	'0' => {
		index => 1,
		type => 'audio',
		tag => ft(),
		mode => 'sendrecv',
	},
}, 'media-labels match';



new_call;

($port_a) = offer('SIPREC sub w label',
	{ label => 'caller' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.2
s=tester
t=0 0
m=audio 6000 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('SIPREC sub w label',
	{ label => 'called' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.2
s=tester
t=0 0
m=audio 6002 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


($ftr, $ttr, $fts, $tag_medias, $media_labels) = subscribe_request('SIPREC sub',
	{ flags => ['all', 'SIPREC'] }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 198.51.100.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:0
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, undef, 'from-tag matches';
is_deeply $fts, [ft(), tt()], 'from-tags match';
is_deeply $tag_medias, [
	{
		tag => ft(),
		label => 'caller',
		medias => [
			{
				index => 1,
				type => 'audio',
				label => '0',
				mode => 'sendrecv',
			},
		],
	},
	{
		tag => tt(),
		label => 'called',
		medias => [
			{
				index => 1,
				type => 'audio',
				label => '1',
				mode => 'sendrecv',
			},
		],
	},
], 'tag-medias match';
is_deeply $media_labels, {
	'1' => {
		index => 1,
		type => 'audio',
		tag => tt(),
		label => 'called',
		mode => 'sendrecv',
	},
	'0' => {
		index => 1,
		type => 'audio',
		tag => ft(),
		label => 'caller',
		mode => 'sendrecv',
	},
}, 'media-labels match';



($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6080)], [qw(198.51.100.14 6082)], [qw(198.51.100.14 6084)],
			[qw(198.51.100.14 6086)]);

($port_a) = offer('"all" sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6080 RTP/AVP 0 8
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('"all" sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6082 RTP/AVP 0 8
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4000, 7000, 0x6543, "\x00" x 160));

($ftr, $ttr, $fts, undef, undef, $port_c, undef, $port_d) = subscribe_request('"all" sub',
	{ 'flags' => ['all'] }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, undef, 'from-tag matches';
is_deeply $fts, [ft(), tt()], 'from-tags match';

subscribe_answer('"all" sub',
	{ 'to-tag' => $ttr, flags => ['allow transcoding'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6084 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
m=audio 6086 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(8, 4001, 7160, -1, "\x2a" x 160));
rcv_no($sock_a);
rcv_no($sock_d);
snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_d, $port_d, rtpm(8, 2001, 4160, -1, "\x2a" x 160));
rcv_no($sock_b);
rcv_no($sock_c);
snd($sock_c, $port_c, rtp(0, 8001, 9160, 0x9876, "\x00" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);




($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6088)], [qw(198.51.100.14 6090)], [qw(198.51.100.14 6092)],
			[qw(198.51.100.14 6094)]);

($port_a) = offer('sub to multiple tags',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=s-dummy
a=s-foo:bar
a=s-baz:quux blah
m=audio 6088 RTP/AVP 0 8
c=IN IP4 198.51.100.14
a=sendrecv
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=s-dummy
a=s-foo:bar
a=s-baz:quux blah
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('sub to multiple tags',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=a-dummy
a=a-foo:bar
a=a-baz:quux blah
m=audio 6090 RTP/AVP 0 8
c=IN IP4 198.51.100.14
a=sendrecv
a=b-dummy
a=b-foo:bar
a=b-baz:quux blah
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=a-dummy
a=a-foo:bar
a=a-baz:quux blah
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=b-dummy
a=b-foo:bar
a=b-baz:quux blah
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4000, 7000, 0x6543, "\x00" x 160));

($ftr, $ttr, $fts, undef, undef, $port_c, undef, $port_d) = subscribe_request('sub to multiple tags',
	{ 'from-tags' => [ft(), tt()] }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
a=sendonly
a=rtcp:PORT
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=b-dummy
a=b-foo:bar
a=b-baz:quux blah
a=sendonly
a=rtcp:PORT
SDP

is $ftr, undef, 'from-tag matches';
is_deeply $fts, [ft(), tt()], 'from-tags match';

subscribe_answer('sub to multiple tags',
	{ 'to-tag' => $ttr, flags => ['allow transcoding'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6092 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
m=audio 6094 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(8, 4001, 7160, -1, "\x2a" x 160));
snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_d, $port_d, rtpm(8, 2001, 4160, -1, "\x2a" x 160));



($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6096)], [qw(198.51.100.14 6098)], [qw(198.51.100.14 6100)],
			[qw(198.51.100.14 6102)]);

($port_a) = offer('sub to multiple tags via flags',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6096 RTP/AVP 0 8
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('sub to multiple tags via flags',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6098 RTP/AVP 0 8
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4000, 7000, 0x6543, "\x00" x 160));

($ftr, $ttr, $fts, undef, undef, $port_c, undef, $port_d) = subscribe_request('sub to multiple tags via flags',
	{ flags => ['from-tags-' . ft(), 'from-tags-' . tt()] }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, undef, 'from-tag matches';
is_deeply $fts, [ft(), tt()], 'from-tags match';

subscribe_answer('sub to multiple tags via flags',
	{ 'to-tag' => $ttr, flags => ['allow transcoding'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6100 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
m=audio 6102 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(8, 4001, 7160, -1, "\x2a" x 160));
snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_d, $port_d, rtpm(8, 2001, 4160, -1, "\x2a" x 160));



($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6104)], [qw(198.51.100.14 6106)], [qw(198.51.100.14 6108)],
			[qw(198.51.100.14 6110)]);

($port_a) = offer('sub to multiple tags - reverse',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6104 RTP/AVP 0 8
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('sub to multiple tags - reverse',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6106 RTP/AVP 0 8
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4000, 7000, 0x6543, "\x00" x 160));

($ftr, $ttr, $fts, undef, undef, $port_c, undef, $port_d) = subscribe_request('sub to multiple tags - reverse',
	{ 'from-tags' => [tt(), ft()] }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, undef, 'from-tag matches';
is_deeply $fts, [tt(), ft()], 'from-tags match';

subscribe_answer('sub to multiple tags - reverse',
	{ 'to-tag' => $ttr, flags => ['allow transcoding'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6108 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
m=audio 6110 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_d, $port_d, rtpm(8, 4001, 7160, -1, "\x2a" x 160));
snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(8, 2001, 4160, -1, "\x2a" x 160));





($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6112)], [qw(198.51.100.14 6114)], [qw(198.51.100.14 6116)]);

($port_a) = offer('sub pause/resume',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6112 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('sub pause/resume',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6114 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

(undef, $ttr, undef, undef, undef, $port_c) = subscribe_request('sub pause/resume',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

subscribe_answer('sub pause/resume',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6116 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));


($port_b) = offer('sub pause/resume',
	{ 'from-tag' => tt(), 'to-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6114 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendonly
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

($port_a) = answer('sub pause/resume',
	{ 'from-tag' => tt(), 'to-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6112 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=recvonly
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4320, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4320, $ssrc_a, "\x00" x 160));

(undef, $ttr2, undef, undef, undef, $port_c) = subscribe_request('sub pause/resume',
	{ 'from-tag' => ft(), 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=inactive
a=rtcp:PORT
SDP

is $ttr, $ttr2, 'resubscribe to-tag matches';

subscribe_answer('sub pause/resume',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6116 RTP/AVP 0
c=IN IP4 198.51.100.14
a=inactive
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4480, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4480, $ssrc_a, "\x00" x 160));

($port_b) = offer('sub pause/resume',
	{ 'from-tag' => tt(), 'to-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6114 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_a) = answer('sub pause/resume',
	{ 'from-tag' => tt(), 'to-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6112 RTP/AVP 0
c=IN IP4 198.51.100.14
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

(undef, undef, undef, undef, undef, $port_c) = subscribe_request('sub pause/resume',
	{ 'from-tag' => ft(), 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

subscribe_answer('sub pause/resume',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6116 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4640, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4640, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7640, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7640, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7640, $ssrc_b, "\x00" x 160));




($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6118)], [qw(198.51.100.14 6120)], [qw(198.51.100.14 6122)],
			[qw(198.51.100.14 6124)]);

($port_a) = offer('SIPREC sub pause/resume',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6118 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('SIPREC sub pause/resume',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6120 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4000, 7000, 0x6543, "\x00" x 160));

(undef, $ttr, undef, undef, undef, $port_c, undef, $port_d) = subscribe_request('SIPREC sub pause/resume',
	{ flags => ['all', 'SIPREC'] }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:0
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

subscribe_answer('SIPREC sub pause/resume',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6122 RTP/AVP 0
c=IN IP4 198.51.100.14
a=label:0
a=recvonly
m=audio 6124 RTP/AVP 0
c=IN IP4 198.51.100.14
a=label:1
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_d, $port_d, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));

print("PORT_A: ".$port_a."\n");
print("PORT_B: ".$port_b."\n");
print("PORT_C: ".$port_c."\n");
print("PORT_D: ".$port_d."\n");

($port_b) = offer('SIPREC sub pause/resume',
	{ 'from-tag' => tt(), 'to-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6120 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendonly
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

($port_a) = answer('SIPREC sub pause/resume',
	{ 'from-tag' => tt(), 'to-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6118 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=recvonly
a=rtcp:PORT
SDP

(undef, undef, undef, $tag_medias, $media_labels, $port_c, undef, $port_d) = subscribe_request('SIPREC sub pause/resume',
	{ flags => ['all', 'SIPREC'], 'to-tag' => $ttr }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:0
a=rtpmap:0 PCMU/8000
a=inactive
a=rtcp:PORT
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is_deeply $tag_medias, [
	{
		tag => ft(),
		medias => [
			{
				index => 1,
				type => 'audio',
				label => '0',
				mode => 'sendonly',
			},
		],
	},
	{
		tag => tt(),
		medias => [
			{
				index => 1,
				type => 'audio',
				label => '1',
				mode => 'recvonly',
			},
		],
	},
], 'SIPREC sub pause/resume - tag-medias match';
is_deeply $media_labels, {
	'0' => {
		index => 1,
		type => 'audio',
		tag => ft(),
		mode => 'sendonly',
	},
	'1' => {
		index => 1,
		type => 'audio',
		tag => tt(),
		mode => 'recvonly',
	},
}, 'SIPREC sub pause/resume - media-labels match';

subscribe_answer('SIPREC sub pause/resume',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6122 RTP/AVP 0
c=IN IP4 198.51.100.14
a=label:0
a=inactive
m=audio 6124 RTP/AVP 0
c=IN IP4 198.51.100.14
a=label:1
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4320, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4320, 0x3456, "\x00" x 160));
rcv($sock_d, $port_d, rtpm(0, 2001, 4320, 0x3456, "\x00" x 160));

($port_b) = offer('SIPREC sub pause/resume',
	{ 'from-tag' => tt(), 'to-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6120 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_a) = answer('SIPREC sub pause/resume',
	{ 'from-tag' => tt(), 'to-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6118 RTP/AVP 0
c=IN IP4 198.51.100.14
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

(undef, $ttr, undef, $tag_medias, $media_labels, $port_c, undef, $port_d) = subscribe_request('SIPREC sub pause/resume',
	{ flags => ['all', 'SIPREC'], 'to-tag' => $ttr }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:0
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is_deeply $tag_medias, [
	{
		tag => ft(),
		medias => [
			{
				index => 1,
				type => 'audio',
				label => '0',
				mode => 'sendrecv',
			},
		],
	},
	{
		tag => tt(),
		medias => [
			{
				index => 1,
				type => 'audio',
				label => '1',
				mode => 'sendrecv',
			},
		],
	},
], 'SIPREC sub pause/resume - tag-medias match';
is_deeply $media_labels, {
	'0' => {
		index => 1,
		type => 'audio',
		tag => ft(),
		mode => 'sendrecv',
	},
	'1' => {
		index => 1,
		type => 'audio',
		tag => tt(),
		mode => 'sendrecv',
	},
}, 'SIPREC sub pause/resume - media-labels match';

subscribe_answer('SIPREC sub pause/resume',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6122 RTP/AVP 0
c=IN IP4 198.51.100.14
a=label:0
a=recvonly
m=audio 6124 RTP/AVP 0
c=IN IP4 198.51.100.14
a=label:1
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4480, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4480, 0x3456, "\x00" x 160));
rcv($sock_d, $port_d, rtpm(0, 2001, 4480, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7320, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7320, 0x6543, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7320, 0x6543, "\x00" x 160));


($port_a) = offer('SIPREC sub pause/resume',
	{ 'from-tag' => ft(), 'to-tag' => tt() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6118 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendonly
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

($port_b) = answer('SIPREC sub pause/resume',
	{ 'from-tag' => ft(), 'to-tag' => tt() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6120 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=recvonly
a=rtcp:PORT
SDP

(undef, undef, undef, $tag_medias, $media_labels, $port_d, undef, $port_c) = subscribe_request('SIPREC sub pause/resume',
	{ flags => ['all', 'SIPREC'], 'to-tag' => $ttr }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:0
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=label:1
a=rtpmap:0 PCMU/8000
a=inactive
a=rtcp:PORT
SDP

is_deeply $tag_medias, [
	{
		tag => ft(),
		medias => [
			{
				index => 1,
				type => 'audio',
				label => '0',
				mode => 'recvonly',
			},
		],
	},
	{
		tag => tt(),
		medias => [
			{
				index => 1,
				type => 'audio',
				label => '1',
				mode => 'sendonly',
			},
		],
	},
], 'tag-medias match';
is_deeply $media_labels, {
	'0' => {
		index => 1,
		type => 'audio',
		tag => ft(),
		mode => 'recvonly',
	},
	'1' => {
		index => 1,
		type => 'audio',
		tag => tt(),
		mode => 'sendonly',
	},
}, 'media-labels match';

subscribe_answer('SIPREC sub pause/resume',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6122 RTP/AVP 0
c=IN IP4 198.51.100.14
a=label:0
a=recvonly
m=audio 6124 RTP/AVP 0
c=IN IP4 198.51.100.14
a=label:1
a=inactive
SDP

snd($sock_a, $port_b, rtp(0, 4001, 7480, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7480, 0x6543, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7480, 0x6543, "\x00" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6060)], [qw(198.51.100.14 6062)], [qw(198.51.100.14 6064)]);

($port_a) = offer('sub, multi codec, sub w diff codec',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6060 RTP/AVP 0 8
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('sub, multi codec, sub w diff codec',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6062 RTP/AVP 0 8
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_c) = subscribe_request('sub, multi codec, sub w diff codec',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('sub, multi codec, sub w diff codec',
	{ 'to-tag' => $ttr, flags => ['allow transcoding'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6064 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(8, 4001, 7160, $ssrc_b, "\x2a" x 160));





($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6036)], [qw(198.51.100.14 6038)], [qw(198.51.100.14 6040)]);

($port_a) = offer('sub w tc - acc',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6036 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('sub w tc - acc',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6038 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4000, 7000, 0x6543, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_c) = subscribe_request('sub w tc - acc',
	{ 'from-tag' => ft(), codec => { transcode => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('sub w tc - acc',
	{ 'from-tag' => ft(), 'to-tag' => $ttr, flags => ['allow transcoding'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6040 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(8, 4001, 7160, -1, "\x2a" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6030)], [qw(198.51.100.14 6032)], [qw(198.51.100.14 6034)]);

($port_a) = offer('sub w tc - rej',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6030 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('sub w tc - rej',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6032 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_c) = subscribe_request('sub w tc - rej',
	{ 'from-tag' => ft(), codec => { transcode => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('sub w tc - rej',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6034 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));




($sock_a, $sock_b, $sock_c, $sock_d, $sock_e) =
	new_call([qw(198.51.100.14 6132)],
		[qw(198.51.100.14 6134)],
		[qw(198.51.100.14 6136)],
		[qw(198.51.100.14 6138)],
		[qw(198.51.100.14 6140)]);

($port_a) = offer('multi subs w diff codecs',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6132 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('multi subs w diff codecs',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6134 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4000, 7000, 0x6543, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_c) = subscribe_request('multi subs w diff codecs',
	{ 'from-tag' => ft(), codec => {transcode => ['PCMA', 'G722', 'G723'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 9 4
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:4 G723/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('multi subs w diff codecs',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6136 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, 0x6543, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_d) = subscribe_request('multi subs w diff codecs',
	{ 'from-tag' => ft(), codec => {transcode => ['PCMA', 'G722', 'G723'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 9 4
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:4 G723/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('multi subs w diff codecs',
	{ 'to-tag' => $ttr, flags => ['allow transcoding'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6138 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2002, 4320, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4002, 7320, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4002, 7320, 0x6543, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4002, 7320, 0x6543, "\x00" x 160));
rcv($sock_d, $port_d, rtpm(8, 4002, 7320, -1, "\x2a" x 160));


($ftr, $ttr, undef, undef, undef, $port_e) = subscribe_request('multi subs w diff codecs',
	{ 'from-tag' => ft(), codec => {transcode => ['PCMA', 'G722', 'G723'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 9 4
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:4 G723/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('multi subs w diff codecs',
	{ 'to-tag' => $ttr, flags => ['allow transcoding'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6140 RTP/AVP 9
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2003, 4480, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2003, 4480, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4003, 7480, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4003, 7480, 0x6543, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4003, 7480, 0x6543, "\x00" x 160));
($ssrc_a) = rcv($sock_d, $port_d, rtpm(8, 4003, 7480, -1, "\x2a" x 160));
rcv_no($sock_e); # resample/codec buffer

snd($sock_b, $port_a, rtp(0, 2004, 4640, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2004, 4640, 0x3456, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4004, 7640, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4004, 7640, 0x6543, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4004, 7640, 0x6543, "\x00" x 160));
rcv($sock_d, $port_d, rtpm(8, 4004, 7640, $ssrc_a, "\x2a" x 160));
rcv($sock_e, $port_e, rtpmre(9, 4003, 7480, $ssrc_a, "\x23..............................................................................................................................................................."));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6000)], [qw(198.51.100.14 6002)], [qw(198.51.100.14 6004)]);

($port_a) = offer('simple sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6000 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('simple sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6002 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_c) = subscribe_request('simple sub',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('simple sub',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6004 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6066)], [qw(198.51.100.14 6068)], [qw(198.51.100.14 6070)]);

($port_a) = offer('simple sub w label',
	{ label => 'foo' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6066 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('simple sub w label',
	{ label => 'bar' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6068 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_c) = subscribe_request('simple sub w label',
	{ label => 'foo' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('simple sub w label',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6070 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6072)], [qw(198.51.100.14 6074)], [qw(198.51.100.14 6076)]);

($port_a) = offer('simple sub w to-tag label',
	{ label => 'foo' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6072 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('simple sub w to-tag label',
	{ label => 'bar' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6074 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_c) = subscribe_request('simple sub w to-tag label',
	{ label => 'bar' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, tt(), 'from-tag matches';

subscribe_answer('simple sub w to-tag label',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6076 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6006)], [qw(198.51.100.14 6008)], [qw(198.51.100.14 6010)]);

($port_a) = offer('SRTP sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6006 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('SRTP sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6008 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_c, undef, $srtp_key_a) = subscribe_request('SRTP sub',
	{ 'from-tag' => ft(), 'transport-protocol' => 'RTP/SAVP',
	SDES => ['no-AEAD_AES_256_GCM', 'no-AEAD_AES_128_GCM'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:2 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:3 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:4 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:5 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:6 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:7 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('SRTP sub',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6010 RTP/SAVP 0
c=IN IP4 198.51.100.14
a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=recvonly
SDP


$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_256_CM_HMAC_SHA1_80},
	key => $srtp_key_a,
};

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
srtp_rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160), $srtp_ctx_a);




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6012)], [qw(198.51.100.14 6014)], [qw(198.51.100.14 6016)]);

($port_a) = offer('SRTP sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6012 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('SRTP sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6014 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_c, undef, undef, undef, undef, undef, $srtp_key_a) = subscribe_request('SRTP sub',
	{ 'from-tag' => ft(), 'transport-protocol' => 'RTP/SAVP',
	SDES => ['no-AEAD_AES_256_GCM', 'no-AEAD_AES_128_GCM'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:2 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:3 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:4 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:5 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:6 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:7 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('SRTP sub',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6016 RTP/SAVP 0
c=IN IP4 198.51.100.14
a=crypto:5 AES_CM_128_HMAC_SHA1_80 inline:DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF
a=recvonly
SDP


$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_a,
};

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
srtp_rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160), $srtp_ctx_a);




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6018)], [qw(198.51.100.14 6020)], [qw(198.51.100.14 6022)]);

($port_a) = offer('SRTP call RTP sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6018 RTP/SAVP 0
c=IN IP4 198.51.100.14
a=crypto:123 AES_CM_128_HMAC_SHA1_80 inline:DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF
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
a=crypto:123 AES_CM_128_HMAC_SHA1_80 inline:DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF
a=crypto:124 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:125 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:126 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:127 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:128 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:129 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:130 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:131 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:132 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:133 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:134 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

($port_b) = answer('SRTP call RTP sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6020 RTP/SAVP 0
c=IN IP4 198.51.100.14
a=crypto:123 AES_CM_128_HMAC_SHA1_80 inline:eMlRvW8mWU4WodT9JOvAM+pn6I0/EXOhT9n0KeKk
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
a=crypto:123 AES_CM_128_HMAC_SHA1_80 inline:eMlRvW8mWU4WodT9JOvAM+pn6I0/EXOhT9n0KeKk
SDP


$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'eMlRvW8mWU4WodT9JOvAM+pn6I0/EXOhT9n0KeKk',
};


srtp_snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_b);
($ssrc_a) = srtp_rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160), $srtp_ctx_a);
($ssrc_b) = srtp_rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160), $srtp_ctx_a);

($ftr, $ttr, undef, undef, undef, $port_c) = subscribe_request('SRTP call RTP sub',
	{ 'from-tag' => ft(), 'transport-protocol' => 'RTP/AVP', }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('SRTP call RTP sub',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6022 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP


srtp_snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160), $srtp_ctx_a);
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6024)], [qw(198.51.100.14 6026)], [qw(198.51.100.14 6028)]);

($port_a) = offer('ICE sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6024 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('ICE sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6026 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_c) = subscribe_request('ICE sub',
	{ 'from-tag' => ft(), ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('ICE sub',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6028 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
a=ice-ufrag:q2758e93
a=ice-pwd:bd5e845657ecb8d6dd8e1bc6
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.14 6028 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.14 6029 typ host
SDP

@ret1 = rcv($sock_c, -1, qr/^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine.*?\x00\x06\x00\x11q2758e93:(........)\x00\x00\x00\x80\x2a\x00\x08........\x00\x24\x00\x04\x6e\xff\xff\xff\x00\x08\x00\x14....................\x80\x28\x00\x04....$/s);
snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6042)], [qw(198.51.100.14 6044)], [qw(198.51.100.14 6046)]);

($port_a) = publish('publish/subscribe',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=s-dummy
a=s-foo:bar
a=s-baz:quux blah
m=audio 6042 RTP/AVP 0 8 9
c=IN IP4 198.51.100.14
a=sendonly
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
----------------------------------
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=recvonly
a=rtcp:PORT
SDP

snd($sock_a, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_b) = subscribe_request('publish/subscribe',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=s-dummy
a=s-foo:bar
a=s-baz:quux blah
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('publish/subscribe',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6044 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_b, $port_b, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_b) = subscribe_request('publish/subscribe',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=s-dummy
a=s-foo:bar
a=s-baz:quux blah
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('publish/subscribe',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6046 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_a, rtp(0, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_b, $port_b, rtpm(0, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 2002, 4320, 0x3456, "\x00" x 160));






($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6048)], [qw(198.51.100.14 6050)], [qw(198.51.100.14 6052)]);

($port_a) = publish('publish/subscribe w codec-accept',
	{ codec => { accept => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6048 RTP/AVP 0 8 9
c=IN IP4 198.51.100.14
a=sendonly
----------------------------------
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=recvonly
a=rtcp:PORT
SDP

snd($sock_a, $port_a, rtp(8, 2000, 4000, 0x3456, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_b) = subscribe_request('publish/subscribe w codec-accept',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('publish/subscribe w codec-accept',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6050 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_a, rtp(8, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_b, $port_b, rtpm(8, 2001, 4160, 0x3456, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_b) = subscribe_request('publish/subscribe w codec-accept',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('publish/subscribe w codec-accept',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6052 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_a, rtp(8, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_b, $port_b, rtpm(8, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(8, 2002, 4320, 0x3456, "\x00" x 160));





($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6054)], [qw(198.51.100.14 6056)], [qw(198.51.100.14 6058)]);

($port_a) = publish('publish/subscribe w unsupp and t/c',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6054 RTP/AVP 96 8 9
c=IN IP4 198.51.100.14
a=sendonly
a=rtpmap:96 foobar/8000
----------------------------------
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=recvonly
a=rtcp:PORT
SDP

snd($sock_a, $port_a, rtp(8, 2000, 4000, 0x3456, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_b) = subscribe_request('publish/subscribe w unsupp and t/c',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('publish/subscribe w unsupp and t/c',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6056 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_a, rtp(8, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_b, $port_b, rtpm(8, 2001, 4160, 0x3456, "\x00" x 160));

($ftr, $ttr, undef, undef, undef, $port_b) = subscribe_request('publish/subscribe w unsupp and t/c',
	{ 'from-tag' => ft(), codec => { strip => ['PCMA'], transcode => ['PCMU'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('publish/subscribe w unsupp and t/c',
	{ 'to-tag' => $ttr, flags => ['allow transcoding'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6058 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_a, rtp(8, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_b, $port_b, rtpm(8, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 2002, 4320, -1, "\x29" x 160));



new_call;

publish('multi publish/subscribe',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=s-dummy
a=s-foo:bar
a=s-baz:quux blah
m=audio 6078 RTP/AVP 0 8 9
c=IN IP4 198.51.100.14
a=sendonly
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
----------------------------------
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=recvonly
a=rtcp:PORT
SDP

$ftr = ft();
new_ft;

publish('multi publish/subscribe',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=a-dummy
a=a-foo:bar
a=a-baz:quux blah
m=audio 6126 RTP/AVP 0 8 9
c=IN IP4 198.51.100.14
a=sendonly
a=b-dummy
a=b-foo:bar
a=b-baz:quux blah
----------------------------------
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=recvonly
a=rtcp:PORT
SDP

$fts = ft();

subscribe_request('multi publish/subscribe',
	{ 'from-tags' => [ $ftr, $fts ] }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=m-dummy
a=m-foo:bar
a=m-baz:quux blah
a=sendonly
a=rtcp:PORT
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=b-dummy
a=b-foo:bar
a=b-baz:quux blah
a=sendonly
a=rtcp:PORT
SDP



done_testing();
#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
