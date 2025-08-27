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


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -n 2223 -f -L 7 -E --log-level-internals=7))
		or die;


my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $ssrc, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $has_recv);



($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7000)],
	[qw(198.51.100.1 7001)],
	[qw(198.51.100.3 7002)],
	[qw(198.51.100.3 7003)],
);

($port_a, $port_ax) = offer('control', { }, <<SDP);
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

($port_b, $port_bx) = answer('control', { }, <<SDP);
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

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50"));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50"));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50"));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50"));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7004)],
	[qw(198.51.100.1 7005)],
	[qw(198.51.100.3 7006)],
	[qw(198.51.100.3 7007)],
);

($port_a, $port_ax) = offer('unsolicited exts', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7004 RTP/AVP 8
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

($port_b, $port_bx) = answer('unsolicited exts', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7006 RTP/AVP 8
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

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7008)],
	[qw(198.51.100.1 7009)],
	[qw(198.51.100.3 7010)],
	[qw(198.51.100.3 7011)],
);

($port_a, $port_ax) = offer('dummy extmap', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7008 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('dummy extmap', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7010 RTP/AVP 8
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]));






($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7016)],
	[qw(198.51.100.1 7017)],
	[qw(198.51.100.3 7018)],
	[qw(198.51.100.3 7019)],
);

($port_a, $port_ax) = offer('control w tc', { codec => { transcode => ['PCMU'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7016 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('control w tc', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7018 RTP/AVP 0
c=IN IP4 198.51.100.3
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

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50"));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74"));
snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74"));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50"));





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7020)],
	[qw(198.51.100.1 7021)],
	[qw(198.51.100.3 7022)],
	[qw(198.51.100.3 7023)],
);

($port_a, $port_ax) = offer('unsolicited exts w tc', { codec => { transcode => ['PCMU'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7020 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('unsolicited exts w tc', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7022 RTP/AVP 0
c=IN IP4 198.51.100.3
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

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"]]));
snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[2, "blah"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7024)],
	[qw(198.51.100.1 7025)],
	[qw(198.51.100.3 7026)],
	[qw(198.51.100.3 7027)],
);

($port_a, $port_ax) = offer('dummy extmap w tc', { codec => { transcode => ['PCMU'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7024 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('dummy extmap w tc', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7026 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"]]));
snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[2, "blah"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7122)],
	[qw(198.51.100.1 7123)],
	[qw(198.51.100.3 7124)],
	[qw(198.51.100.3 7125)],
);

($port_a, $port_ax) = offer('extmap-strip', { extmap => { strip => ['blah'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7122 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('extmap-strip', { extmap => { strip => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7124 RTP/AVP 8
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "woot"], [3, "meh"], [4, "yugh"]]));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "woot"], [3, "meh"], [4, "yugh"]]));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "woot"], [3, "meh"], [4, "yugh"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "woot"], [3, "meh"], [4, "yugh"]]));



#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
