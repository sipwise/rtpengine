#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use Test2::Tools::Compare qw();
use NGCP::Rtpclient::ICE;
use POSIX;
use Data::Dumper;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			--measure-rtp --mos=LQ -n 2223  -f -L 7 -E --log-level-internals=7))
		or die;


my ($sock_a, $sock_b, $sock_ax, $sock_bx,
	$port_a, $port_ax, $port_b, $port_bx,
	$resp);


($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7124)],
	[qw(198.51.100.1 7125)],
	[qw(198.51.100.3 7126)],
	[qw(198.51.100.3 7127)],
);

($port_a, $port_ax) = offer('RTCP generation', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7124 RTP/AVP 0
c=IN IP4 198.51.100.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
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

($port_b, $port_bx) = answer('RTCP generation', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7126 RTP/AVP 0
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

snd($sock_a, $port_b, rtp(0,  1000, 3000+160*0, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0,  1001, 3000+160*1, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3000+160*1, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0,  1002, 3000+160*2, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3000+160*2, 0x1234, "\x00" x 160));

snd($sock_b, $port_a, rtp(0,  4000, 8000+160*0, 0x6789, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4000, 8000+160*0, 0x6789, "\x00" x 160));
snd($sock_b, $port_a, rtp(0,  4001, 8000+160*1, 0x6789, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 8000+160*1, 0x6789, "\x00" x 160));
snd($sock_b, $port_a, rtp(0,  4002, 8000+160*2, 0x6789, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 8000+160*2, 0x6789, "\x00" x 160));

# wait for RTCP
sleep(6);

rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x04\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00\x00.{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s);
rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x04\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00\x00.{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s);

# wait for RTCP again
sleep(6);

rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x04\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00\x00.{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s);
rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x04\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00\x00.{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s);

$resp = rtpe_req('delete', 'delete');
is($resp->{SSRC}{4660}{packets}, 3, 'packet count');
is($resp->{SSRC}{4660}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{4660}{'average MOS'}{'packet loss'}, 0, 'packet loss');
is($resp->{SSRC}{26505}{packets}, 3, 'packet count');
is($resp->{SSRC}{26505}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{26505}{'average MOS'}{'packet loss'}, 0, 'packet loss');


#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
