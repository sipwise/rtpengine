#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;

# Run without extended codec dependencies: G.711 also supports DTX buffering.
autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
	-n 2223 -f -L 7 -E --silence-detect=1 --dtx-delay=50)) or die;

my ($sock_a, $sock_b) = new_call([qw(198.51.100.10 5000)], [qw(198.51.100.10 5002)]);
my $name = 'DTMF suppression before first DTX audio packet';

my ($port_a) = offer($name, { codec => { transcode => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 5000 RTP/AVP 0 101
c=IN IP4 198.51.100.10
a=rtpmap:101 telephone-event/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

my ($port_b) = answer($name, {}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 5002 RTP/AVP 8 101
c=IN IP4 198.51.100.10
a=rtpmap:101 telephone-event/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

# Learn the primary payload type while media is blocked, as in a listening room.
rtpe_req('block media', $name, { 'from-tag' => ft(), flags => ['directional'] });
snd($sock_a, $port_b, rtp(0, 1999, 3840, 0x5678, "\x40" x 160));
rcv_no($sock_b);
rtpe_req('unblock media', $name, { 'from-tag' => ft(), flags => ['directional'] });

# Block the event itself so it cannot initialize the output RTP sequence.
rtpe_req('block DTMF', $name, { 'from-tag' => ft() });
snd($sock_a, $port_b, rtp(101 | 0x80, 2000, 4000, 0x5678, "\x0a\x07\x00\xa0"));
# The first audio packets overlap the active event and become null discard entries.
snd($sock_a, $port_b, rtp(0, 2001, 4000, 0x5678, "\x40" x 160));
snd($sock_a, $port_b, rtp(0, 2002, 4160, 0x5678, "\x40" x 160));
rcv_no($sock_b);
rtpe_req('query', $name, { 'from-tag' => ft() });

# End the event, then verify that the first real audio packet supplies the sequence
# and subsequent packets continue normally rather than starting from zero.
snd($sock_a, $port_b, rtp(101, 2003, 4000, 0x5678, "\x0a\x87\x01\x40"));
snd($sock_a, $port_b, rtp(0, 2004, 4320, 0x5678, "\x40" x 160));
snd($sock_a, $port_b, rtp(0, 2005, 4480, 0x5678, "\x40" x 160));
# The output timestamp origin includes the suppressed interval.
my ($ssrc) = rcv($sock_b, $port_a, rtpm(8, 2004, 4000, -1, "\x68" x 160));
rcv($sock_b, $port_a, rtpm(8, 2005, 4160, $ssrc, "\x68" x 160));
rtpe_req('delete', $name, { 'from-tag' => ft() });

done_testing();
