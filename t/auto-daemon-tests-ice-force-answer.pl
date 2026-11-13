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

my ($sock_a, $sock_ax, $sock_b, $port_a, $port_ax, $port_b);


($sock_a, $sock_ax, $sock_b) = new_call(
    [qw(198.51.100.1 7320)],
    [qw(198.51.100.1 7321)],
    [qw(198.51.100.3 7322)],
);

($port_a, $port_ax) = offer('forced ICE offer, plain RTP peer', {
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
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
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

rcv_no($sock_a);
rcv_no($sock_ax);
rcv_no($sock_b);

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 6000, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 6000, 0x5678, "\x00" x 160));

rcv_no($sock_a);
rcv_no($sock_ax);
rcv_no($sock_b);



($sock_a, $sock_ax, $sock_b) = new_call(
    [qw(198.51.100.1 7328)],
    [qw(198.51.100.1 7329)],
    [qw(198.51.100.3 7330)],
);

($port_a, $port_ax) = offer('stray ICE answer', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7328 RTP/AVP 0
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
SDP

($port_b) = answer('stray ICE answer', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7330 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ice-ufrag:yolo
a=ice-pwd:foobar
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.3 7330 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.3 7331 typ host
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

rcv_no($sock_a);
rcv_no($sock_ax);
rcv_no($sock_b);

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 6000, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 6000, 0x5678, "\x00" x 160));

rcv_no($sock_a);
rcv_no($sock_ax);
rcv_no($sock_b);




($sock_a, $sock_ax, $sock_b) = new_call(
    [qw(198.51.100.1 7340)],
    [qw(198.51.100.1 7341)],
    [qw(198.51.100.3 7342)],
);

($port_a, $port_ax) = offer('rejected ICE offer and stray ICE answer', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7340 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:argh
a=ice-pwd:yowzer
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.1 7340 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.1 7341 typ host
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

# consume initial ICE checks
rcv($sock_a, -1, qr/^\x00\x01\x00\x6c\x21\x12/s);
rcv($sock_ax, -1, qr/^\x00\x01\x00\x6c\x21\x12/s);
rcv($sock_a, -1, qr/^\x00\x01\x00\x6c\x21\x12/s);
rcv($sock_ax, -1, qr/^\x00\x01\x00\x6c\x21\x12/s);

($port_b) = answer('rejected ICE offer and stray ICE answer', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7342 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ice-ufrag:yolo
a=ice-pwd:foobar
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.3 7342 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.3 7343 typ host
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

rcv_no($sock_a);
rcv_no($sock_ax);
rcv_no($sock_b);

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 6000, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 6000, 0x5678, "\x00" x 160));

rcv_no($sock_a);
rcv_no($sock_ax);
rcv_no($sock_b);



($sock_a, $sock_ax, $sock_b) = new_call(
    [qw(198.51.100.1 7352)],
    [qw(198.51.100.1 7353)],
    [qw(198.51.100.3 7354)],
);

($port_a, $port_ax) = offer('rejected ICE offer and stray ICE answer', { ICE => ['remove', 'reject'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7352 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:argh
a=ice-pwd:yowzer
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.1 7352 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.1 7353 typ host
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

rcv_no($sock_a);
rcv_no($sock_ax);
rcv_no($sock_b);

($port_b) = answer('rejected ICE offer and stray ICE answer', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7354 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ice-ufrag:yolo
a=ice-pwd:foobar
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.3 7354 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.3 7355 typ host
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

rcv_no($sock_a);
rcv_no($sock_ax);
rcv_no($sock_b);

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 6000, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 6000, 0x5678, "\x00" x 160));

rcv_no($sock_a);
rcv_no($sock_ax);
rcv_no($sock_b);




rtpe_req('delete', 'delete');
done_testing();
