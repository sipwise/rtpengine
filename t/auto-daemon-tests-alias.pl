#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use POSIX;
use JSON;


autotest_start(qw(--config-file=none -t -1
			-i def/203.0.113.1 -i def/2001:db8:4321::1
			-i alt/203.0.113.2 -i alt/2001:db8:4321::2
			-n 2223 -f -L 7 -E --log-level-internals=7))
		or die;



my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $port_c, $ssrc_a, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx, $port_d, $sock_e, $port_e, $sock_cx, $port_cx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $tag_medias, $media_labels,
	$ftr, $ttr, $fts, $ttr2, $cid, $ft, $tt, $ssrc, $cid1);

my $extended_tests = $ENV{RTPENGINE_EXTENDED_TESTS};


($sock_a, $sock_b) = new_call([qw(198.51.100.11 4070)], [qw(198.51.100.11 4072)]);

($port_a) = offer('delete alias', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4070 RTP/AVP 0 8
c=IN IP4 198.51.100.11
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('delete alias', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4072 RTP/AVP 0 8
c=IN IP4 198.51.100.11
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$cid1 = cid();
$ft = ft();
$tt = tt();

($sock_c, $sock_d) = new_call_nc([qw(198.51.100.11 4074)], [qw(198.51.100.11 4076)]);

($port_c) = offer('delete alias', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4074 RTP/AVP 0 8
c=IN IP4 198.51.100.11
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_d) = answer('delete alias', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4076 RTP/AVP 0 8
c=IN IP4 198.51.100.11
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_a, $port_b, rtp (0, 1000, 3000, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5000, 7000, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5000, 7000, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('mesh', 'delete alias', {
		flags => [],
		calls => [cid(), $cid1],
		tags => [
			{
				from => $ft,
				to => [$tt, ft(), tt()],
			},
			{
				from => $tt,
				to => [$ft, ft(), tt()],
			},
			{
				from => ft(),
				to => [$ft, $tt, tt()],
			},
			{
				from => tt(),
				to => [$ft, $tt, ft()],
			},
		],
});


snd($sock_a, $port_b, rtp (0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

rtpe_req('delete', 'delete alias', { 'delete-delay' => 0 });

snd($sock_a, $port_b, rtp (0, 1002, 3320, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd_no($sock_c, $port_d, rtp (0, 5002, 7320, 0x1234, "\x33" x 160));
snd_no($sock_d, $port_c, rtp (0, 7002, 9320, 0x1a04, "\x44" x 160));



($sock_a, $sock_b) = new_call([qw(198.51.100.12 4070)], [qw(198.51.100.12 4072)]);

($port_a) = offer('delete alias rev', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4070 RTP/AVP 0 8
c=IN IP4 198.51.100.12
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('delete alias rev', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4072 RTP/AVP 0 8
c=IN IP4 198.51.100.12
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$cid1 = cid();
$ft = ft();
$tt = tt();

($sock_c, $sock_d) = new_call_nc([qw(198.51.100.12 4074)], [qw(198.51.100.12 4076)]);

($port_c) = offer('delete alias rev', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4074 RTP/AVP 0 8
c=IN IP4 198.51.100.12
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_d) = answer('delete alias rev', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4076 RTP/AVP 0 8
c=IN IP4 198.51.100.12
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_a, $port_b, rtp (0, 1000, 3000, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5000, 7000, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5000, 7000, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('mesh', 'delete alias rev', {
		flags => [],
		calls => [cid(), $cid1],
		tags => [
			{
				from => $ft,
				to => [$tt, ft(), tt()],
			},
			{
				from => $tt,
				to => [$ft, ft(), tt()],
			},
			{
				from => ft(),
				to => [$ft, $tt, tt()],
			},
			{
				from => tt(),
				to => [$ft, $tt, ft()],
			},
		],
});


snd($sock_a, $port_b, rtp (0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

rtpe_req('delete', 'delete alias rev', { 'call-id' => $cid1, 'delete-delay' => 0 });

snd_no($sock_a, $port_b, rtp (0, 1002, 3320, 0x1234, "\x11" x 160));
snd_no($sock_b, $port_a, rtp (0, 3002, 5320, 0x1a04, "\x22" x 160));

snd($sock_c, $port_d, rtp (0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


done_testing();
#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
