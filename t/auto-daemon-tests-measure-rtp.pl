#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use NGCP::Rtpclient::ICE;
use POSIX;
use Data::Dumper;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1 --measure-rtp --mos=LQ
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --silence-detect=1 --log-level-internals=7))
		or die;


my $extended_tests = $ENV{RTPENGINE_MOS_TESTS};


my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $ssrc, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $has_recv);



if ($extended_tests) {

($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7160)],
	[qw(198.51.100.1 7161)],
	[qw(198.51.100.3 7162)],
	[qw(198.51.100.3 7163)],
);

($port_a, $port_ax) = offer('stats delete w/o from-tag and w/o delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7160 RTP/AVP 8
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

($port_b, $port_bx) = answer('stats delete w/o from-tag and w/o delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7162 RTP/AVP 8
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

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x00" x 160));

# RTCP
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_ax, $port_bx, "\x81\xc8\x00\x08\x00\x00\x12\x34\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x65\x43\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_bx, $port_ax, qr/^.*$/s);
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_bx, $port_ax, "\x81\xc8\x00\x08\x00\x00\x65\x43\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_ax, $port_bx, qr/^.*$/s);

$resp = rtpe_req('delete', 'delete', { 'delete delay' => 0 } );
#print Dumper($resp);
is($resp->{SSRC}{0x1234}{'highest MOS'}{MOS}, '44', "0x1234 MOS");
is($resp->{SSRC}{0x6543}{'highest MOS'}{MOS}, '44', "0x6543 MOS");
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{SSRC}, 0x1234, 'ingress SSRC');
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{packets}, 1, '0x1234 packet count');
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{SSRC}, 0x6543, 'egress SSRC');
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{packets}, 1, '0x6543 packet count');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{SSRC}, 0x6543, 'ingress SSRC');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{packets}, 1, '0x6543 packet count');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{SSRC}, 0x1234, 'egress SSRC');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{packets}, 1, '0x1234 packet count');
is($resp->{totals}{RTP}{packets}, 2, 'RTP packet count');
is($resp->{totals}{RTP}{bytes}, 344, 'RTP octet count');
is($resp->{totals}{RTCP}{packets}, 2, 'RTCP packet count');
is($resp->{totals}{RTCP}{bytes}, 104, 'RTCP octet count');




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7164)],
	[qw(198.51.100.1 7165)],
	[qw(198.51.100.3 7166)],
	[qw(198.51.100.3 7167)],
);

($port_a, $port_ax) = offer('stats delete w/ from-tag and w/o delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7164 RTP/AVP 8
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

($port_b, $port_bx) = answer('stats delete w/ from-tag and w/o delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7166 RTP/AVP 8
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

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x00" x 160));

# RTCP
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_ax, $port_bx, "\x81\xc8\x00\x08\x00\x00\x12\x34\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x65\x43\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_bx, $port_ax, qr/^.*$/s);
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_bx, $port_ax, "\x81\xc8\x00\x08\x00\x00\x65\x43\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_ax, $port_bx, qr/^.*$/s);

$resp = rtpe_req('delete', 'delete', { 'delete delay' => 0, 'from-tag' => ft() } );
#print Dumper($resp);
is($resp->{SSRC}{0x1234}{'highest MOS'}{MOS}, '44', "0x1234 MOS");
is($resp->{SSRC}{0x6543}{'highest MOS'}{MOS}, '44', "0x6543 MOS");
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{SSRC}, 0x1234, 'ingress SSRC');
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{packets}, 1, '0x1234 packet count');
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{SSRC}, 0x6543, 'egress SSRC');
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{packets}, 1, '0x6543 packet count');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{SSRC}, 0x6543, 'ingress SSRC');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{packets}, 1, '0x6543 packet count');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{SSRC}, 0x1234, 'egress SSRC');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{packets}, 1, '0x1234 packet count');
is($resp->{totals}{RTP}{packets}, 2, 'RTP packet count');
is($resp->{totals}{RTP}{bytes}, 344, 'RTP octet count');
is($resp->{totals}{RTCP}{packets}, 2, 'RTCP packet count');
is($resp->{totals}{RTCP}{bytes}, 104, 'RTCP octet count');




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7168)],
	[qw(198.51.100.1 7169)],
	[qw(198.51.100.3 7170)],
	[qw(198.51.100.3 7171)],
);

($port_a, $port_ax) = offer('stats delete w/o from-tag and w/ delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7168 RTP/AVP 8
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

($port_b, $port_bx) = answer('stats delete w/o from-tag and w/ delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7170 RTP/AVP 8
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

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x00" x 160));

# RTCP
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_ax, $port_bx, "\x81\xc8\x00\x08\x00\x00\x12\x34\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x65\x43\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_bx, $port_ax, qr/^.*$/s);
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_bx, $port_ax, "\x81\xc8\x00\x08\x00\x00\x65\x43\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_ax, $port_bx, qr/^.*$/s);

$resp = rtpe_req('delete', 'delete', { 'delete delay' => 1 } );
#print Dumper($resp);
is($resp->{SSRC}{0x1234}{'highest MOS'}{MOS}, '44', "0x1234 MOS");
is($resp->{SSRC}{0x6543}{'highest MOS'}{MOS}, '44', "0x6543 MOS");
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{SSRC}, 0x1234, 'ingress SSRC');
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{packets}, 1, '0x1234 packet count');
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{SSRC}, 0x6543, 'egress SSRC');
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{packets}, 1, '0x6543 packet count');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{SSRC}, 0x6543, 'ingress SSRC');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{packets}, 1, '0x6543 packet count');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{SSRC}, 0x1234, 'egress SSRC');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{packets}, 1, '0x1234 packet count');
is($resp->{totals}{RTP}{packets}, 2, 'RTP packet count');
is($resp->{totals}{RTP}{bytes}, 344, 'RTP octet count');
is($resp->{totals}{RTCP}{packets}, 2, 'RTCP packet count');
is($resp->{totals}{RTCP}{bytes}, 104, 'RTCP octet count');




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7172)],
	[qw(198.51.100.1 7173)],
	[qw(198.51.100.3 7174)],
	[qw(198.51.100.3 7175)],
);

($port_a, $port_ax) = offer('stats delete w/ from-tag and w/ delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7172 RTP/AVP 8
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

($port_b, $port_bx) = answer('stats delete w/ from-tag and w/ delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7174 RTP/AVP 8
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

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x00" x 160));

# RTCP
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_ax, $port_bx, "\x81\xc8\x00\x08\x00\x00\x12\x34\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x65\x43\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_bx, $port_ax, qr/^.*$/s);
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_bx, $port_ax, "\x81\xc8\x00\x08\x00\x00\x65\x43\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_ax, $port_bx, qr/^.*$/s);

$resp = rtpe_req('delete', 'delete', { 'delete delay' => 1, 'from-tag' => ft() } );
#print Dumper($resp);
is($resp->{SSRC}{0x1234}{'highest MOS'}{MOS}, '44', "0x1234 MOS");
is($resp->{SSRC}{0x6543}{'highest MOS'}{MOS}, '44', "0x6543 MOS");
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{SSRC}, 0x1234, 'ingress SSRC');
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{packets}, 1, '0x1234 packet count');
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{SSRC}, 0x6543, 'egress SSRC');
is($resp->{tags}{ft()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{packets}, 1, '0x6543 packet count');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{SSRC}, 0x6543, 'ingress SSRC');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'ingress SSRCs'}[0]{packets}, 1, '0x6543 packet count');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{SSRC}, 0x1234, 'egress SSRC');
is($resp->{tags}{tt()}{medias}[0]{streams}[0]{'egress SSRCs'}[0]{packets}, 1, '0x1234 packet count');
is($resp->{totals}{RTP}{packets}, 2, 'RTP packet count');
is($resp->{totals}{RTP}{bytes}, 344, 'RTP octet count');
is($resp->{totals}{RTCP}{packets}, 2, 'RTCP packet count');
is($resp->{totals}{RTCP}{bytes}, 104, 'RTCP octet count');


}

#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
