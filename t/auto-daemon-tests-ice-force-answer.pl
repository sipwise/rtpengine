#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;

# Regression coverage for issue #2161: forced ICE towards a plain-RTP peer
# that explicitly rejects ICE in its answer. The answer towards the
# originating plain-RTP peer must not invent ICE, even when the answer
# control request specifies ICE=force.
autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
                -n 2223 -f -L 7 -E)) or die;

my ($sock_a, $sock_b, $port_a, $port_b);
($sock_a, $sock_b) = new_call(
    [qw(198.51.100.1 7320)],
    [qw(198.51.100.3 7322)],
);

($port_a) = offer('forced ICE offer, plain RTP peer', {
    ICE => 'force',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7320 RTP/AVP 0
c=IN IP4 198.51.100.1
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
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
SDP

($port_b) = answer('plain RTP answer rejects offered ICE', {
    ICE => 'force',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7322 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
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

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 6000, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 6000, 0x5678, "\x00" x 160));

rtpe_req('delete', 'delete');
done_testing();
