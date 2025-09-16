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
a=extmap-allow-mixed
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
a=extmap-allow-mixed
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
a=extmap-allow-mixed
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
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[2, "woot"]]));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "woot"], [3, "meh"], [4, "yugh"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "woot"]]));





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7040)],
	[qw(198.51.100.1 7041)],
	[qw(198.51.100.3 7042)],
	[qw(198.51.100.3 7043)],
);

($port_a, $port_ax) = offer('extmap-mask', { extmap => { mask => ['blah'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7040 RTP/AVP 8
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
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('extmap-mask', { extmap => { mask => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7042 RTP/AVP 8
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
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"]]));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7048)],
	[qw(198.51.100.1 7049)],
	[qw(198.51.100.3 7050)],
	[qw(198.51.100.3 7051)],
);

($port_a, $port_ax) = offer('extmap-mask w tc', {
		extmap => { mask => ['blah'] },
		codec => { transcode => [ 'PCMU' ] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7048 RTP/AVP 8
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
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('extmap-mask w tc', {
		extmap => { mask => ['foo'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7050 RTP/AVP 0
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
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a", [[1, "foo"], [2, "blah"]]));
snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "blah"]]));






($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7166)],
	[qw(198.51.100.1 7167)],
	[qw(198.51.100.3 7168)],
	[qw(198.51.100.3 7169)],
);

($port_a, $port_ax) = offer('extmap-mask long', { extmap => { mask => ['blah'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7166 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
a=extmap:18 foo
a=extmap:19 bar
a=extmap:20 blah
a=extmap:21 quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:18 foo
a=extmap:19 bar
a=extmap:21 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('extmap-mask long', { extmap => { mask => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7168 RTP/AVP 8
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:18 foo
a=extmap:19 bar
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:20 blah
a=extmap:18 foo
a=extmap:19 bar
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"], [21, "argh"], [20, "yikes"]]));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"]]));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"], [21, "argh"], [20, "yikes"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7174)],
	[qw(198.51.100.1 7175)],
	[qw(198.51.100.3 7176)],
	[qw(198.51.100.3 7177)],
);

($port_a, $port_ax) = offer('extmap-mask w tc long', {
		extmap => { mask => ['blah'] },
		codec => { transcode => [ 'PCMU' ] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7174 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
a=extmap:18 foo
a=extmap:19 bar
a=extmap:20 blah
a=extmap:21 quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:18 foo
a=extmap:19 bar
a=extmap:21 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('extmap-mask w tc long', {
		extmap => { mask => ['foo'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7176 RTP/AVP 0
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:18 foo
a=extmap:19 bar
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:20 blah
a=extmap:18 foo
a=extmap:19 bar
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"], [21, "argh"], [20, "yikes"]]));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a", [[18, "foo"], [19, "blah"]]));
snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"], [21, "argh"], [20, "yikes"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[18, "foo"], [19, "blah"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7134)],
	[qw(198.51.100.1 7135)],
	[qw(198.51.100.3 7136)],
	[qw(198.51.100.3 7137)],
);

($port_a, $port_ax) = offer('extmap-mask too long', { extmap => { mask => ['blah'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7134 RTP/AVP 8
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
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('extmap-mask too long', { extmap => { mask => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7136 RTP/AVP 8
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
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "oh no this is too long"]]));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"]]));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"], [4, "argh"], [3, "yikes"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7142)],
	[qw(198.51.100.1 7143)],
	[qw(198.51.100.3 7144)],
	[qw(198.51.100.3 7145)],
);

($port_a, $port_ax) = offer('extmap-mask w tc too long', {
		extmap => { mask => ['blah'] },
		codec => { transcode => [ 'PCMU' ] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7142 RTP/AVP 8
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
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('extmap-mask w tc too long', {
		extmap => { mask => ['foo'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7144 RTP/AVP 0
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
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "oh no this is too long"]]));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a", [[1, "foo"], [2, "blah"]]));
snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"], [4, "argh"], [3, "yikes"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]));





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7134)],
	[qw(198.51.100.1 7135)],
	[qw(198.51.100.3 7136)],
	[qw(198.51.100.3 7137)],
);

($port_a, $port_ax) = offer('extmap-mask mixed', { extmap => { mask => ['blah'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7134 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=extmap-allow-mixed
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('extmap-mask mixed', { extmap => { mask => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7136 RTP/AVP 8
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap-allow-mixed
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "way too long of an attribute"], [4, "argh"], [3, "oh no this is too long"]]));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "way too long of an attribute"]]));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"], [4, "argh"], [3, "yikes"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7142)],
	[qw(198.51.100.1 7143)],
	[qw(198.51.100.3 7144)],
	[qw(198.51.100.3 7145)],
);

($port_a, $port_ax) = offer('extmap-mask w tc mixed', {
		extmap => { mask => ['blah'] },
		codec => { transcode => [ 'PCMU' ] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7142 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=extmap-allow-mixed
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('extmap-mask w tc mixed', {
		extmap => { mask => ['foo'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7144 RTP/AVP 0
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap-allow-mixed
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "way too long of an attribute"], [4, "argh"], [3, "oh no this is too long"]]));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a", [[1, "foo"], [2, "way too long of an attribute"]]));
snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"], [4, "argh"], [3, "yikes"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "oh no this is too long"]]));






($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7678)],
	[qw(198.51.100.1 7679)],
	[qw(198.51.100.3 7680)],
	[qw(198.51.100.3 7681)],
);

($port_a, $port_ax) = offer('extmap-mask all', { extmap => { mask => ['all'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7678 RTP/AVP 8
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
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('extmap-mask all', { extmap => { mask => ['all'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7680 RTP/AVP 8
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
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74"));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74"));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7686)],
	[qw(198.51.100.1 7687)],
	[qw(198.51.100.3 7688)],
	[qw(198.51.100.3 7689)],
);

($port_a, $port_ax) = offer('extmap-mask all w tc', {
		extmap => { mask => ['all'] },
		codec => { transcode => [ 'PCMU' ] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7686 RTP/AVP 8
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
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('extmap-mask all w tc', {
		extmap => { mask => ['all'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7688 RTP/AVP 0
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
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a"));
snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50"));




# SRTP on A side

($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7000)],
	[qw(198.51.101.1 7001)],
	[qw(198.51.101.3 7002)],
	[qw(198.51.101.3 7003)],
);

($port_a, $port_ax) = offer('control', { 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7000 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7002 RTP/AVP 8
c=IN IP4 198.51.101.3
a=rtpmap:8 PCMA/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50"), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50"));
     snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50"));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50"), $srtp_ctx_b);




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7004)],
	[qw(198.51.101.1 7005)],
	[qw(198.51.101.3 7006)],
	[qw(198.51.101.3 7007)],
);

($port_a, $port_ax) = offer('unsolicited exts', { 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7004 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('unsolicited exts', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7006 RTP/AVP 8
c=IN IP4 198.51.101.3
a=rtpmap:8 PCMA/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]));
     snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]), $srtp_ctx_b);




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7008)],
	[qw(198.51.101.1 7009)],
	[qw(198.51.101.3 7010)],
	[qw(198.51.101.3 7011)],
);

($port_a, $port_ax) = offer('dummy extmap', { 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7008 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('dummy extmap', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7010 RTP/AVP 8
c=IN IP4 198.51.101.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]));
     snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]), $srtp_ctx_b);






($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7016)],
	[qw(198.51.101.1 7017)],
	[qw(198.51.101.3 7018)],
	[qw(198.51.101.3 7019)],
);

($port_a, $port_ax) = offer('control w tc', { codec => { transcode => ['PCMU'] }, 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7016 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('control w tc', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7018 RTP/AVP 0
c=IN IP4 198.51.101.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50"), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74"));
     snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74"));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50"), $srtp_ctx_b);





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7020)],
	[qw(198.51.101.1 7021)],
	[qw(198.51.101.3 7022)],
	[qw(198.51.101.3 7023)],
);

($port_a, $port_ax) = offer('unsolicited exts w tc', { codec => { transcode => ['PCMU'] }, 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7020 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('unsolicited exts w tc', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7022 RTP/AVP 0
c=IN IP4 198.51.101.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"]]));
     snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[2, "blah"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]), $srtp_ctx_b);




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7024)],
	[qw(198.51.101.1 7025)],
	[qw(198.51.101.3 7026)],
	[qw(198.51.101.3 7027)],
);

($port_a, $port_ax) = offer('dummy extmap w tc', { codec => { transcode => ['PCMU'] }, 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7024 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('dummy extmap w tc', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7026 RTP/AVP 0
c=IN IP4 198.51.101.3
a=sendrecv
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"]]));
     snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[2, "blah"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]), $srtp_ctx_b);




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7122)],
	[qw(198.51.101.1 7123)],
	[qw(198.51.101.3 7124)],
	[qw(198.51.101.3 7125)],
);

($port_a, $port_ax) = offer('extmap-strip', { extmap => { strip => ['blah'] }, 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7122 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('extmap-strip', { extmap => { strip => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7124 RTP/AVP 8
c=IN IP4 198.51.101.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "woot"], [3, "meh"], [4, "yugh"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[2, "woot"]]));
     snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "woot"], [3, "meh"], [4, "yugh"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "woot"]]), $srtp_ctx_b);





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7040)],
	[qw(198.51.101.1 7041)],
	[qw(198.51.101.3 7042)],
	[qw(198.51.101.3 7043)],
);

($port_a, $port_ax) = offer('extmap-mask', { extmap => { mask => ['blah'] }, 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7040 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('extmap-mask', { extmap => { mask => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7042 RTP/AVP 8
c=IN IP4 198.51.101.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"]]));
     snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"]]), $srtp_ctx_b);




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7048)],
	[qw(198.51.101.1 7049)],
	[qw(198.51.101.3 7050)],
	[qw(198.51.101.3 7051)],
);

($port_a, $port_ax) = offer('extmap-mask w tc', {
		extmap => { mask => ['blah'] },
		codec => { transcode => [ 'PCMU' ] }, 'transport-protocol' => 'RTP/AVP',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7048 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('extmap-mask w tc', {
		extmap => { mask => ['foo'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7050 RTP/AVP 0
c=IN IP4 198.51.101.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a", [[1, "foo"], [2, "blah"]]));
     snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "blah"]]), $srtp_ctx_b);






($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7166)],
	[qw(198.51.101.1 7167)],
	[qw(198.51.101.3 7168)],
	[qw(198.51.101.3 7169)],
);

($port_a, $port_ax) = offer('extmap-mask long', { extmap => { mask => ['blah'] }, 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7166 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=extmap:18 foo
a=extmap:19 bar
a=extmap:20 blah
a=extmap:21 quux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:18 foo
a=extmap:19 bar
a=extmap:21 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('extmap-mask long', { extmap => { mask => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7168 RTP/AVP 8
c=IN IP4 198.51.101.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:18 foo
a=extmap:19 bar
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:20 blah
a=extmap:18 foo
a=extmap:19 bar
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"], [21, "argh"], [20, "yikes"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"]]));
     snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"], [21, "argh"], [20, "yikes"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"]]), $srtp_ctx_b);




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7174)],
	[qw(198.51.101.1 7175)],
	[qw(198.51.101.3 7176)],
	[qw(198.51.101.3 7177)],
);

($port_a, $port_ax) = offer('extmap-mask w tc long', {
		extmap => { mask => ['blah'] },
		codec => { transcode => [ 'PCMU' ] }, 'transport-protocol' => 'RTP/AVP',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7174 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=extmap:18 foo
a=extmap:19 bar
a=extmap:20 blah
a=extmap:21 quux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:18 foo
a=extmap:19 bar
a=extmap:21 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('extmap-mask w tc long', {
		extmap => { mask => ['foo'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7176 RTP/AVP 0
c=IN IP4 198.51.101.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:18 foo
a=extmap:19 bar
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:20 blah
a=extmap:18 foo
a=extmap:19 bar
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"], [21, "argh"], [20, "yikes"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a", [[18, "foo"], [19, "blah"]]));
     snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"], [21, "argh"], [20, "yikes"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[18, "foo"], [19, "blah"]]), $srtp_ctx_b);




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7134)],
	[qw(198.51.101.1 7135)],
	[qw(198.51.101.3 7136)],
	[qw(198.51.101.3 7137)],
);

($port_a, $port_ax) = offer('extmap-mask too long', { extmap => { mask => ['blah'] }, 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7134 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('extmap-mask too long', { extmap => { mask => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7136 RTP/AVP 8
c=IN IP4 198.51.101.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "oh no this is too long"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"]]));
     snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"], [4, "argh"], [3, "yikes"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"]]), $srtp_ctx_b);




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7142)],
	[qw(198.51.101.1 7143)],
	[qw(198.51.101.3 7144)],
	[qw(198.51.101.3 7145)],
);

($port_a, $port_ax) = offer('extmap-mask w tc too long', {
		extmap => { mask => ['blah'] },
		codec => { transcode => [ 'PCMU' ] }, 'transport-protocol' => 'RTP/AVP',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7142 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('extmap-mask w tc too long', {
		extmap => { mask => ['foo'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7144 RTP/AVP 0
c=IN IP4 198.51.101.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "oh no this is too long"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a", [[1, "foo"], [2, "blah"]]));
     snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"], [4, "argh"], [3, "yikes"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]), $srtp_ctx_b);





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7134)],
	[qw(198.51.101.1 7135)],
	[qw(198.51.101.3 7136)],
	[qw(198.51.101.3 7137)],
);

($port_a, $port_ax) = offer('extmap-mask mixed', { extmap => { mask => ['blah'] }, 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7134 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=extmap-allow-mixed
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('extmap-mask mixed', { extmap => { mask => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7136 RTP/AVP 8
c=IN IP4 198.51.101.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap-allow-mixed
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "way too long of an attribute"], [4, "argh"], [3, "oh no this is too long"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "way too long of an attribute"]]));
     snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"], [4, "argh"], [3, "yikes"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"]]), $srtp_ctx_b);




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7142)],
	[qw(198.51.101.1 7143)],
	[qw(198.51.101.3 7144)],
	[qw(198.51.101.3 7145)],
);

($port_a, $port_ax) = offer('extmap-mask w tc mixed', {
		extmap => { mask => ['blah'] },
		codec => { transcode => [ 'PCMU' ] }, 'transport-protocol' => 'RTP/AVP',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7142 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=extmap-allow-mixed
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('extmap-mask w tc mixed', {
		extmap => { mask => ['foo'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7144 RTP/AVP 0
c=IN IP4 198.51.101.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap-allow-mixed
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "way too long of an attribute"], [4, "argh"], [3, "oh no this is too long"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a", [[1, "foo"], [2, "way too long of an attribute"]]));
     snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"], [4, "argh"], [3, "yikes"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "oh no this is too long"]]), $srtp_ctx_b);






($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7678)],
	[qw(198.51.101.1 7679)],
	[qw(198.51.101.3 7680)],
	[qw(198.51.101.3 7681)],
);

($port_a, $port_ax) = offer('extmap-mask all', { extmap => { mask => ['all'] }, 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7678 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('extmap-mask all', { extmap => { mask => ['all'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7680 RTP/AVP 8
c=IN IP4 198.51.101.3
a=rtpmap:8 PCMA/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74"));
     snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74"), $srtp_ctx_b);




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.101.1 7686)],
	[qw(198.51.101.1 7687)],
	[qw(198.51.101.3 7688)],
	[qw(198.51.101.3 7689)],
);

($port_a, $port_ax) = offer('extmap-mask all w tc', {
		extmap => { mask => ['all'] },
		codec => { transcode => [ 'PCMU' ] }, 'transport-protocol' => 'RTP/AVP',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7686 RTP/SAVP 8
c=IN IP4 198.51.101.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('extmap-mask all w tc', {
		extmap => { mask => ['all'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio 7688 RTP/AVP 0
c=IN IP4 198.51.101.3
a=rtpmap:8 PCMA/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a"));
     snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
srtp_rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50"), $srtp_ctx_b);





# SRTP on B side

($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7000)],
	[qw(198.51.105.1 7001)],
	[qw(198.51.105.3 7002)],
	[qw(198.51.105.3 7003)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('control', { 'transport-protocol' => 'RTP/SAVP', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7000 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7002 RTP/SAVP 8
c=IN IP4 198.51.105.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50"));
srtp_rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50"), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50"), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50"));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7004)],
	[qw(198.51.105.1 7005)],
	[qw(198.51.105.3 7006)],
	[qw(198.51.105.3 7007)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('unsolicited exts', { 'transport-protocol' => 'RTP/SAVP', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7004 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('unsolicited exts', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7006 RTP/SAVP 8
c=IN IP4 198.51.105.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]));
srtp_rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7008)],
	[qw(198.51.105.1 7009)],
	[qw(198.51.105.3 7010)],
	[qw(198.51.105.3 7011)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('dummy extmap', { 'transport-protocol' => 'RTP/SAVP', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7008 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('dummy extmap', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7010 RTP/SAVP 8
c=IN IP4 198.51.105.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
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

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]));
srtp_rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]));






($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7016)],
	[qw(198.51.105.1 7017)],
	[qw(198.51.105.3 7018)],
	[qw(198.51.105.3 7019)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('control w tc', { codec => { transcode => ['PCMU'] }, 'transport-protocol' => 'RTP/SAVP', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7016 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('control w tc', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7018 RTP/SAVP 0
c=IN IP4 198.51.105.3
a=sendrecv
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50"));
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74"), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74"), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50"));





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7020)],
	[qw(198.51.105.1 7021)],
	[qw(198.51.105.3 7022)],
	[qw(198.51.105.3 7023)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('unsolicited exts w tc', { codec => { transcode => ['PCMU'] }, 'transport-protocol' => 'RTP/SAVP', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7020 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('unsolicited exts w tc', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7022 RTP/SAVP 0
c=IN IP4 198.51.105.3
a=sendrecv
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]));
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"]]), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[2, "blah"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7024)],
	[qw(198.51.105.1 7025)],
	[qw(198.51.105.3 7026)],
	[qw(198.51.105.3 7027)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('dummy extmap w tc', { codec => { transcode => ['PCMU'] }, 'transport-protocol' => 'RTP/SAVP', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7024 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('dummy extmap w tc', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7026 RTP/SAVP 0
c=IN IP4 198.51.105.3
a=sendrecv
a=extmap:1 http://example.com/foobar
a=extmap:2 http://example.com/quux
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
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

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]));
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"]]), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[2, "blah"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "blah"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7122)],
	[qw(198.51.105.1 7123)],
	[qw(198.51.105.3 7124)],
	[qw(198.51.105.3 7125)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('extmap-strip', { extmap => { strip => ['blah'] }, 'transport-protocol' => 'RTP/SAVP', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7122 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('extmap-strip', { extmap => { strip => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7124 RTP/SAVP 8
c=IN IP4 198.51.105.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "woot"], [3, "meh"], [4, "yugh"]]));
srtp_rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x10" . ("\x00" x 158) . "\x50", [[2, "woot"]]), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "woot"], [3, "meh"], [4, "yugh"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[2, "woot"]]));





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7040)],
	[qw(198.51.105.1 7041)],
	[qw(198.51.105.3 7042)],
	[qw(198.51.105.3 7043)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('extmap-mask', { extmap => { mask => ['blah'] }, 'transport-protocol' => 'RTP/SAVP', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7040 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('extmap-mask', { extmap => { mask => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7042 RTP/SAVP 8
c=IN IP4 198.51.105.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
srtp_rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"]]), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7048)],
	[qw(198.51.105.1 7049)],
	[qw(198.51.105.3 7050)],
	[qw(198.51.105.3 7051)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('extmap-mask w tc', {
		extmap => { mask => ['blah'] },
		codec => { transcode => [ 'PCMU' ] }, 'transport-protocol' => 'RTP/SAVP', DTLS => 'off',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7048 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('extmap-mask w tc', {
		extmap => { mask => ['foo'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7050 RTP/SAVP 0
c=IN IP4 198.51.105.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a", [[1, "foo"], [2, "blah"]]), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "blah"]]));






($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7166)],
	[qw(198.51.105.1 7167)],
	[qw(198.51.105.3 7168)],
	[qw(198.51.105.3 7169)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('extmap-mask long', { extmap => { mask => ['blah'] }, 'transport-protocol' => 'RTP/SAVP', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7166 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
a=extmap:18 foo
a=extmap:19 bar
a=extmap:20 blah
a=extmap:21 quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:18 foo
a=extmap:19 bar
a=extmap:21 quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('extmap-mask long', { extmap => { mask => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7168 RTP/SAVP 8
c=IN IP4 198.51.105.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:18 foo
a=extmap:19 bar
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:20 blah
a=extmap:18 foo
a=extmap:19 bar
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"], [21, "argh"], [20, "yikes"]]));
srtp_rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"]]), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"], [21, "argh"], [20, "yikes"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7174)],
	[qw(198.51.105.1 7175)],
	[qw(198.51.105.3 7176)],
	[qw(198.51.105.3 7177)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('extmap-mask w tc long', {
		extmap => { mask => ['blah'] },
		codec => { transcode => [ 'PCMU' ] }, 'transport-protocol' => 'RTP/SAVP', DTLS => 'off',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7174 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
a=extmap:18 foo
a=extmap:19 bar
a=extmap:20 blah
a=extmap:21 quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:18 foo
a=extmap:19 bar
a=extmap:21 quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('extmap-mask w tc long', {
		extmap => { mask => ['foo'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7176 RTP/SAVP 0
c=IN IP4 198.51.105.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:18 foo
a=extmap:19 bar
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:20 blah
a=extmap:18 foo
a=extmap:19 bar
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"], [21, "argh"], [20, "yikes"]]));
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a", [[18, "foo"], [19, "blah"]]), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[18, "foo"], [19, "blah"], [21, "argh"], [20, "yikes"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[18, "foo"], [19, "blah"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7134)],
	[qw(198.51.105.1 7135)],
	[qw(198.51.105.3 7136)],
	[qw(198.51.105.3 7137)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('extmap-mask too long', { extmap => { mask => ['blah'] }, 'transport-protocol' => 'RTP/SAVP', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7134 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('extmap-mask too long', { extmap => { mask => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7136 RTP/SAVP 8
c=IN IP4 198.51.105.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "oh no this is too long"]]));
srtp_rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"]]), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"], [4, "argh"], [3, "yikes"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7142)],
	[qw(198.51.105.1 7143)],
	[qw(198.51.105.3 7144)],
	[qw(198.51.105.3 7145)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('extmap-mask w tc too long', {
		extmap => { mask => ['blah'] },
		codec => { transcode => [ 'PCMU' ] }, 'transport-protocol' => 'RTP/SAVP', DTLS => 'off',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7142 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('extmap-mask w tc too long', {
		extmap => { mask => ['foo'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7144 RTP/SAVP 0
c=IN IP4 198.51.105.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "oh no this is too long"]]));
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a", [[1, "foo"], [2, "blah"]]), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"], [4, "argh"], [3, "yikes"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"]]));





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7134)],
	[qw(198.51.105.1 7135)],
	[qw(198.51.105.3 7136)],
	[qw(198.51.105.3 7137)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('extmap-mask mixed', { extmap => { mask => ['blah'] }, 'transport-protocol' => 'RTP/SAVP', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7134 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=extmap-allow-mixed
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('extmap-mask mixed', { extmap => { mask => ['foo'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7136 RTP/SAVP 8
c=IN IP4 198.51.105.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap-allow-mixed
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "way too long of an attribute"], [4, "argh"], [3, "oh no this is too long"]]));
srtp_rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "way too long of an attribute"]]), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"], [4, "argh"], [3, "yikes"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"]]));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7142)],
	[qw(198.51.105.1 7143)],
	[qw(198.51.105.3 7144)],
	[qw(198.51.105.3 7145)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('extmap-mask w tc mixed', {
		extmap => { mask => ['blah'] },
		codec => { transcode => [ 'PCMU' ] }, 'transport-protocol' => 'RTP/SAVP', DTLS => 'off',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7142 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=extmap-allow-mixed
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=extmap-allow-mixed
a=extmap:1 foo
a=extmap:2 bar
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('extmap-mask w tc mixed', {
		extmap => { mask => ['foo'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7144 RTP/SAVP 0
c=IN IP4 198.51.105.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap-allow-mixed
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap-allow-mixed
a=extmap:3 blah
a=extmap:1 foo
a=extmap:2 bar
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "way too long of an attribute"], [4, "argh"], [3, "oh no this is too long"]]));
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a", [[1, "foo"], [2, "way too long of an attribute"]]), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "oh no this is too long"], [4, "argh"], [3, "yikes"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50", [[1, "foo"], [2, "oh no this is too long"]]));






($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7678)],
	[qw(198.51.105.1 7679)],
	[qw(198.51.105.3 7680)],
	[qw(198.51.105.3 7681)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('extmap-mask all', { extmap => { mask => ['all'] }, 'transport-protocol' => 'RTP/SAVP', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7678 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('extmap-mask all', { extmap => { mask => ['all'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7680 RTP/SAVP 8
c=IN IP4 198.51.105.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
srtp_rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74"), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74"));




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.105.1 7686)],
	[qw(198.51.105.1 7687)],
	[qw(198.51.105.3 7688)],
	[qw(198.51.105.3 7689)],
);

($port_a, $port_ax, undef, undef, undef, undef, undef, undef, $srtp_key_b) = offer('extmap-mask all w tc', {
		extmap => { mask => ['all'] },
		codec => { transcode => [ 'PCMU' ] }, 'transport-protocol' => 'RTP/SAVP', DTLS => 'off',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio 7686 RTP/AVP 8
c=IN IP4 198.51.105.1
a=sendrecv
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('extmap-mask all w tc', {
		extmap => { mask => ['all'] },
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio 7688 RTP/SAVP 0
c=IN IP4 198.51.105.3
a=rtpmap:8 PCMA/8000
a=sendrecv
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.105.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=extmap:1 foo
a=extmap:2 bar
a=extmap:3 blah
a=extmap:4 quux
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

     snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]));
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x13" . ("\x03" x 158) . "\x5a"), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp( 0, 8000, 7000+160*0, 0x6543, "\x39" . ("\x29" x 158) . "\x74", [[1, "foo"], [2, "blah"], [4, "argh"], [3, "yikes"]]), $srtp_ctx_a);
     rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x10" . ("\x00" x 158) . "\x50"));




#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
