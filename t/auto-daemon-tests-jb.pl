#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --jitter-buffer=10))
		or die;


my ($sock_a, $sock_b, $port_a, $port_b, $ssrc, $resp, $srtp_ctx_a, $srtp_ctx_b, @ret1, @ret2);




# RTP sequencing tests

($sock_a, $sock_b) = new_call([qw(198.51.100.1 2010)], [qw(198.51.100.3 2012)]);

($port_a) = offer('two codecs, no transcoding', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2010 RTP/AVP 0 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('two codecs, no transcoding', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2012 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1010, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1001, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1001, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1010, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1010, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1011, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1011, 3160, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1012, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1012, 3320, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1013, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1013, 3480, 0x1234, "\x00" x 160));





done_testing();
