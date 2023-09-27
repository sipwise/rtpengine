#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use NGCP::Rtpclient::ICE;
use POSIX;


$ENV{RTPENGINE_EXTENDED_TESTS} or exit(); # timing sensitive tests


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --audio-buffer-length=500 --audio-buffer-delay=5
			--audio-player=on-demand))
		or die;


my ($sock_a, $sock_b, $port_a, $port_b, $ssrc_a, $ssrc_b, $seq_a, $seq_b, $ts_a, $ts_b);



($sock_a, $sock_b) = new_call([qw(198.51.100.14 6008)], [qw(198.51.100.14 6010)]);

($port_a) = offer('control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6008 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6010 RTP/AVP 0
c=IN IP4 198.51.100.14
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


rcv_no($sock_a);
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
rcv_no($sock_a);

rcv_no($sock_b);
snd($sock_a, $port_b, rtp(0, 3000, 5000, 0x3456, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 3000, 5000, -1, "\x00" x 160));
rcv_no($sock_b);




($sock_a, $sock_b) = new_call([qw(198.51.100.14 6012)], [qw(198.51.100.14 6014)]);

($port_a) = offer('player=on',
	{ 'audio-player' => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6012 RTP/AVP 0
c=IN IP4 198.51.100.14
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

# no early media
rcv_no($sock_a);
rcv_no($sock_b);

($port_b) = answer('player=on',
	{ 'audio-player' => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6014 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($seq_a, $ts_a, $ssrc_a) = rcv($sock_b, $port_a, rtpm(0 | 0x80, -1, -1, -1, "\xff" x 160));
($seq_b, $ts_b, $ssrc_b) = rcv($sock_a, $port_b, rtpm(0 | 0x80, -1, -1, -1, "\xff" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq_a + 1, $ts_a + 160 * 1, $ssrc_a, "\xff" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq_b + 1, $ts_b + 160 * 1, $ssrc_b, "\xff" x 160));

# insert audio
snd($sock_a, $port_b, rtp(0, 3000, 5000, 0x3456, "\x42" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq_a + 2, $ts_a + 160 * 2, $ssrc_a, ("\xff" x 40) . ("\x42" x 120)));
rcv($sock_a, $port_b, rtpm(0, $seq_b + 2, $ts_b + 160 * 2, $ssrc_b, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 3001, 5160, 0x3456, "\x42" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq_a + 3, $ts_a + 160 * 3, $ssrc_a, "\x42" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq_b + 3, $ts_b + 160 * 3, $ssrc_b, "\xff" x 160));

# back to silence
rcv($sock_b, $port_a, rtpm(0, $seq_a + 4, $ts_a + 160 * 4, $ssrc_a, ("\x42" x 40) . ("\xff" x 120)));
rcv($sock_a, $port_b, rtpm(0, $seq_b + 4, $ts_b + 160 * 4, $ssrc_b, "\xff" x 160));





($sock_a, $sock_b) = new_call([qw(198.51.100.14 6016)], [qw(198.51.100.14 6018)]);

($port_a) = offer('early media',
	{ 'audio-player' => 'force', flags => ['early media'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6016 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($seq_b, $ts_b, $ssrc_b) = rcv($sock_a, $port_b, rtpm(0 | 0x80, -1, -1, -1, "\xff" x 160));

($port_b) = answer('early media',
	{ 'audio-player' => 'force', flags => ['early media'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6018 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($seq_a, $ts_a, $ssrc_a) = rcv($sock_b, $port_a, rtpm(0 | 0x80, -1, -1, -1, "\xff" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq_a + 1, $ts_a + 160 * 1, $ssrc_a, "\xff" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq_b + 1, $ts_b + 160 * 1, $ssrc_b, "\xff" x 160));

# insert audio
snd($sock_a, $port_b, rtp(0, 3000, 5000, 0x3456, "\x42" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq_a + 2, $ts_a + 160 * 2, $ssrc_a, ("\xff" x 40) . ("\x42" x 120)));
rcv($sock_a, $port_b, rtpm(0, $seq_b + 2, $ts_b + 160 * 2, $ssrc_b, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 3001, 5160, 0x3456, "\x42" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq_a + 3, $ts_a + 160 * 3, $ssrc_a, "\x42" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq_b + 3, $ts_b + 160 * 3, $ssrc_b, "\xff" x 160));

# back to silence
rcv($sock_b, $port_a, rtpm(0, $seq_a + 4, $ts_a + 160 * 4, $ssrc_a, ("\x42" x 40) . ("\xff" x 120)));
rcv($sock_a, $port_b, rtpm(0, $seq_b + 4, $ts_b + 160 * 4, $ssrc_b, "\xff" x 160));






#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
