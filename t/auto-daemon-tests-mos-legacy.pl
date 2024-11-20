#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use NGCP::Rtpclient::ICE;
use POSIX;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1 --mos=legacy
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --silence-detect=1 --log-level-internals=7))
		or die;


my $extended_tests = $ENV{RTPENGINE_MOS_TESTS};



my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $ssrc, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $has_recv);



if ($extended_tests) {

($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3000)], [qw(198.51.100.23 3001)],
							[qw(198.51.100.23 3002)], [qw(198.51.100.23 3003)]);

($port_a, $port_ax) = offer('MOS basic', { }, <<SDP);
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

($port_b, $port_bx) = answer('MOS basic', { }, <<SDP);
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


# populate known payload type
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x7654321, "\x00" x 160));

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100001,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	0 << 24      # fraction lost
	| 0,         # number of packets lost
	2000,        # extended highest sequence number received
	0,           # jitter
	0x00000000,  # last SR
	0 / 65536,   # delay since last SR
));

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100004,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	0 << 24      # fraction lost
	| 0,         # number of packets lost
	1010,        # extended highest sequence number received
	0,           # jitter
	0x00010020,  # last SR
	3 * 65536,   # delay since last SR
));
# no MOS calculated here as we don't have an opposite side RTT yet ^

Time::HiRes::usleep(2 * 1000000);

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100006,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	0 << 24      # fraction lost
	| 0,         # number of packets lost
	2020,        # extended highest sequence number received
	0,           # jitter
	0x00040020,  # last SR
	2 * 65536,   # delay since last SR
));
# CQ MOS for 0x1234567 calculated here ^

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100007,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	0 << 24      # fraction lost
	| 0,         # number of packets lost
	1030,        # extended highest sequence number received
	0,           # jitter
	0x00060020,  # last SR
	3 * 65536,   # delay since last SR
));
# CQ MOS for 0x7654321 calculated here ^

$resp = rtpe_req('delete', 'MOS basic', { });


my $processing_us = 10000; # allow for 10 ms processing time


is $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, 1, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, 44, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, 0, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '<', $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '<', $processing_us, 'metric matches';

is $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, 1, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, 44, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, 0, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '<', $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '<', $processing_us, 'metric matches';





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3004)], [qw(198.51.100.23 3005)],
							[qw(198.51.100.23 3006)], [qw(198.51.100.23 3007)]);

($port_a, $port_ax) = offer('MOS degraded', { }, <<SDP);
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

($port_b, $port_bx) = answer('MOS degraded', { }, <<SDP);
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


# populate known payload type
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x7654321, "\x00" x 160));

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100001,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	2000,        # extended highest sequence number received
	15 * 8000 / 1000, # jitter
	0x00000000,  # last SR
	0 / 65536,   # delay since last SR
));

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100004,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	1010,        # extended highest sequence number received
	15 * 8000 / 1000, # jitter
	0x00010020,  # last SR
	2.88 * 65536,# delay since last SR
));
# no MOS calculated here as we don't have an opposite side RTT yet ^

Time::HiRes::usleep(2 * 1000000);

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100006,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	2020,        # extended highest sequence number received
	15 * 8000 / 1000, # jitter
	0x00040020,  # last SR
	1.87 * 65536,#delay since last SR
));
# CQ MOS for 0x1234567 calculated here ^

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100007,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	1030,        # extended highest sequence number received
	15 * 8000 / 1000, # jitter
	0x00060020,  # last SR
	2.88 * 65536,# delay since last SR
));
# CQ MOS for 0x7654321 calculated here ^

$resp = rtpe_req('delete', 'MOS degraded', { });

is $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, '>=', 34, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, '<=', 35, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, 15, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, 3, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '>=', 250000, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '<', 250000 + $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '>=', 130000, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '<', 130000 + $processing_us, 'metric matches';

is $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, '>=', 34, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, '<=', 35, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, 15, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, 3, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '>=', 250000, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '<', 250000 + $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '>=', 120000, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '<', 120000 + $processing_us, 'metric matches';




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3008)], [qw(198.51.100.23 3009)],
							[qw(198.51.100.23 3010)], [qw(198.51.100.23 3011)]);

($port_a, $port_ax) = offer('MOS very degraded', { }, <<SDP);
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

($port_b, $port_bx) = answer('MOS very degraded', { }, <<SDP);
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


# populate known payload type
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x7654321, "\x00" x 160));

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100001,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	2000,        # extended highest sequence number received
	20 * 8000 / 1000, # jitter
	0x00000000,  # last SR
	0 / 65536,   # delay since last SR
));

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100004,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	(0.06*256) << 24 # fraction lost
	| 0,         # number of packets lost
	1010,        # extended highest sequence number received
	20 * 8000 / 1000, # jitter
	0x00010020,  # last SR
	2.80 * 65536,# delay since last SR
));
# no MOS calculated here as we don't have an opposite side RTT yet ^

Time::HiRes::usleep(2 * 1000000);

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100006,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	(0.06*256) << 24 # fraction lost
	| 0,         # number of packets lost
	2020,        # extended highest sequence number received
	20 * 8000 / 1000, # jitter
	0x00040020,  # last SR
	1.80 * 65536,#delay since last SR
));
# CQ MOS for 0x1234567 calculated here ^

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100007,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	(0.06*256) << 24 # fraction lost
	| 0,         # number of packets lost
	1030,        # extended highest sequence number received
	20 * 8000 / 1000, # jitter
	0x00060020,  # last SR
	2.80 * 65536,# delay since last SR
));
# CQ MOS for 0x7654321 calculated here ^

$resp = rtpe_req('delete', 'MOS very degraded', { });

is $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, 1, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, 24, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, 20, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, 5, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '>=', 400000, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '<', 400000 + $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '>=', 200000, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '<', 200000 + $processing_us, 'metric matches';

is $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, 1, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, 24, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, 20, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, 5, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '>=', 400000, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '<', 400000 + $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '>=', 200000, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '<', 200000 + $processing_us, 'metric matches';


}


#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
