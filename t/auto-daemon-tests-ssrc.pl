#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use POSIX;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -n 2223 -f -L 7 -E --log-level-internals=7))
		or die;


my ($sock_a, $sock_ax, $sock_b, $sock_bx, $port_a, $port_ax, $port_b, $port_bx, $resp, $ssrcs);


# the chosen egress SSRC is reported per media in the offer response

($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7000)],
	[qw(198.51.100.1 7001)],
	[qw(198.51.100.3 7002)],
	[qw(198.51.100.3 7003)],
);

($port_a, $port_ax) = offer('egress SSRC reported', { flags => ['fixed egress SSRC'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7000 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$resp = last_resp();
$ssrcs = $resp->{'egress SSRC'};

is ref($ssrcs), 'ARRAY', 'egress SSRC list present in offer response';
is scalar(@{$ssrcs // []}), 1, 'one egress SSRC entry per m= section';
is $ssrcs->[0]->{index}, 1, 'egress SSRC entry carries media index';
is $ssrcs->[0]->{type}, 'audio', 'egress SSRC entry carries media type';
ok(($ssrcs->[0]->{SSRC} // 0) > 0, 'egress SSRC entry carries a non-zero SSRC');


my $egress = $ssrcs->[0]->{SSRC};

($port_b, $port_bx) = answer('egress SSRC reported', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7002 RTP/AVP 8
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


# the same values are reported per media by `query`, before any media has flowed

$resp = rtpe_req('query', 'egress SSRC in query', { 'call-id' => cid() });

is $resp->{tags}{tt()}{medias}[0]{'fixed egress SSRC'}, $egress,
		'query reports the fixed egress SSRC facing the answerer';
ok(($resp->{tags}{ft()}{medias}[0]{'fixed egress SSRC'} // 0) > 0,
		'query reports a fixed egress SSRC facing the offerer as well');


# RTP towards the answerer carries the reported SSRC, not the one the sender used

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, $egress, "\x00" x 160));


# the egress SSRC and the sequence numbering survive a change of ingress SSRC

snd($sock_a, $port_b, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1001, 3160, $egress, "\x00" x 160));

snd($sock_a, $port_b, rtp(8, 5000, 90000, 0x4321, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1002, 90000, $egress, "\x00" x 160));


#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
