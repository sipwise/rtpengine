#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use NGCP::Rtpclient::ICE;
use POSIX;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1 --measure-rtp --mos=LQ
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --silence-detect=1 --log-level-internals=7))
		or die;


my $extended_tests = $ENV{RTPENGINE_EXTENDED_TESTS};


my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $ssrc, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $has_recv);



if ($extended_tests) {

($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3000)], [qw(198.51.100.23 3001)],
							[qw(198.51.100.23 3002)], [qw(198.51.100.23 3003)]);

($port_a, $port_ax) = offer('MOS basic', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('MOS basic', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3002 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


# run 15 seconds = 750 packets
for my $iter (0 .. 750) {
	snd($sock_a, $port_b, rtp(0, 1000 + $iter, 3000 + 160 * $iter, 0x1234567, "\x00" x 160));
	rcv($sock_b, $port_a, rtpm(0, 1000 + $iter, 3000 + 160 * $iter, 0x1234567, "\x00" x 160));
	snd($sock_b, $port_a, rtp(0, 2000 + $iter, 4000 + 160 * $iter, 0x7654321, "\x00" x 160));
	rcv($sock_a, $port_b, rtpm(0, 2000 + $iter, 4000 + 160 * $iter, 0x7654321, "\x00" x 160));
	Time::HiRes::usleep(20000);
}

$resp = rtpe_req('delete', 'MOS basic', { });

cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, '>=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, '<=', 3, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, 43, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, '<=', 1, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, 0, 'metric matches';

cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, '>=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, '<=', 3, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, 43, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, '<=', 1, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, 0, 'metric matches';




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3004)], [qw(198.51.100.23 3005)],
							[qw(198.51.100.23 3006)], [qw(198.51.100.23 3007)]);

($port_a, $port_ax) = offer('MOS PL', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3004 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('MOS PL', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3006 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


# run 15 seconds = 750 packets, drop every 20th (5% PL)
for my $iter (0 .. 750) {
	if (($iter % 20) != 19) {
		snd($sock_a, $port_b, rtp(0, 1000 + $iter, 3000 + 160 * $iter, 0x1234567, "\x00" x 160));
		rcv($sock_b, $port_a, rtpm(0, 1000 + $iter, 3000 + 160 * $iter, 0x1234567, "\x00" x 160));
		snd($sock_b, $port_a, rtp(0, 2000 + $iter, 4000 + 160 * $iter, 0x7654321, "\x00" x 160));
		rcv($sock_a, $port_b, rtpm(0, 2000 + $iter, 4000 + 160 * $iter, 0x7654321, "\x00" x 160));
	}
	Time::HiRes::usleep(20000);
}

$resp = rtpe_req('delete', 'MOS PL', { });

cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, '>=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, '<=', 3, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, '>=', 35, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, '<=', 36, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, '<=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, '>=', 3, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, '<=', 4, 'metric matches';

cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, '>=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, '<=', 3, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, '>=', 35, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, '<=', 36, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, '<=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, '>=', 3, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, '<=', 4, 'metric matches';




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3008)], [qw(198.51.100.23 3009)],
							[qw(198.51.100.23 3010)], [qw(198.51.100.23 3011)]);

($port_a, $port_ax) = offer('MOS very degraded', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3008 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('MOS very degraded', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3010 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


# run 20 seconds = 1000 packets, drop every 10th (10% PL), add random jitter
srand(123456);
for my $iter (0 .. 1000) {
	if (($iter % 10) != 9) {
		snd($sock_a, $port_b, rtp(0, 1000 + $iter, 3000 + 160 * $iter, 0x1234567, "\x00" x 160));
		rcv($sock_b, $port_a, rtpm(0, 1000 + $iter, 3000 + 160 * $iter, 0x1234567, "\x00" x 160));
		snd($sock_b, $port_a, rtp(0, 2000 + $iter, 4000 + 160 * $iter, 0x7654321, "\x00" x 160));
		rcv($sock_a, $port_b, rtpm(0, 2000 + $iter, 4000 + 160 * $iter, 0x7654321, "\x00" x 160));
	}
	Time::HiRes::usleep(20000 + rand(40000) - 20000);
}

$resp = rtpe_req('delete', 'MOS very degraded', { });

cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, '>=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, '<=', 4, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, '>=', 27, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, '<=', 28, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, '>=', 4, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, '<=', 12, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, '>=', 8, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, '<=', 9, 'metric matches';

cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, '>=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, '<=', 4, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, '>=', 27, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, '<=', 28, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, '>=', 4, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, '<=', 12, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, '>=', 8, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, '<=', 9, 'metric matches';



}




#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
