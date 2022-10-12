#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use POSIX;
use Time::HiRes qw(usleep gettimeofday time sleep);

$ENV{RTPENGINE_EXTENDED_TESTS} or exit(); # timing sensitive tests


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -c 12345 -f -L 7 -E -u 2222))
		or die;


my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $ssrc, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $rseq, $sseq,
	$send_start, $diff);





($sock_a, $sock_b) = new_call([qw(198.51.100.1 4008)], [qw(198.51.100.1 5008)]);

($port_a) = offer('DTMF trigger', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 4008 RTP/AVP 0 101
c=IN IP4 198.51.100.1
a=sendrecv
a=rtpmap:101 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('DTMF trigger', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 5008 RTP/AVP 0 101
c=IN IP4 198.51.100.1
a=sendrecv
a=rtpmap:101 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

rtpe_req('block DTMF', 'DTMF block',
	{ 'from-tag' => ft(), 'trigger' => '##', 'trigger-end' => '#', 'DTMF-security-trigger' => 'silence',
		'delay-buffer' => 2000 });

$seq = 0;
$rseq = $seq;

# first packet out determines start TS

$send_start = time();
snd($sock_a, $port_b, rtp(0, 1000 + $seq, 3000 + 160 * $seq, 0x1234, "\x00" x 160));
$seq++;

# 100 packets = 2000 ms

for (1 .. 99) {
	$diff = ($send_start + 0.02 * $seq) - time();
	print("send diff $diff\n");
	ok($diff > 0.015, 'diff > 0.015');
	ok($diff < 0.020, 'diff < 0.020');
	sleep($diff);

	snd($sock_a, $port_b, rtp(0, 1000 + $seq, 3000 + 160 * $seq, 0x1234, "\x00" x 160));
	$seq++;
}

# final 20 ms sleep replaced by waiting for the first packet out of the buffer. switch to receiver driven mode:

for (1 .. 100) {
	rcv($sock_b, $port_a, rtpm(0, 1000 + $rseq, 3000 + 160 * $rseq, 0x1234, "\x00" x 160));
	$rseq++;

	# reception timestamp should line up with what is expected
	$diff = ($send_start + 0.02 * $seq) - time();
	print("send diff $diff\n");
	ok($diff > -0.01, 'diff > -0.01');
	ok($diff < +0.01, 'diff < +0.01');

	snd($sock_a, $port_b, rtp(0, 1000 + $seq, 3000 + 160 * $seq, 0x1234, "\x00" x 160));
	$seq++;
}

# send 10 DTMF packets while still receiving PCM
$sseq = $seq;

for my $iter (1 .. 10) {
	rcv($sock_b, $port_a, rtpm(0, 1000 + $rseq, 3000 + 160 * $rseq, 0x1234, "\x00" x 160));
	$rseq++;

	$diff = ($send_start + 0.02 * $seq) - time();
	print("send diff $diff\n");
	ok($diff > -0.01, 'diff > -0.01');
	ok($diff < +0.01, 'diff < +0.01');

	my $vol = 10;
	if ($iter != 10) {
		my $dtmf = pack("CCn", 5, $vol, 160 * ($seq - $sseq + 1));
		snd($sock_a, $port_b, rtp(101 | ($seq == $sseq ? 0x80 : 0),
				1000 + $seq, 3000 + 160 * $sseq, 0x1234, $dtmf));
	}
	else {
		# send end x3
		$vol |= 0x80;
		my $dtmf = pack("CCn", 5, $vol, 160 * ($seq - $sseq + 1));
		snd($sock_a, $port_b, rtp(101 | ($seq == $sseq ? 0x80 : 0),
				1000 + $seq, 3000 + 160 * $sseq, 0x1234, $dtmf));
		$seq++;
		snd($sock_a, $port_b, rtp(101 | ($seq == $sseq ? 0x80 : 0),
				1000 + $seq, 3000 + 160 * $sseq, 0x1234, $dtmf));
		$seq++;
		snd($sock_a, $port_b, rtp(101 | ($seq == $sseq ? 0x80 : 0),
				1000 + $seq, 3000 + 160 * $sseq, 0x1234, $dtmf));
	}
	$seq++;
}

# 90 more PCM packets

for (1 .. 90) {
	rcv($sock_b, $port_a, rtpm(0, 1000 + $rseq, 3000 + 160 * $rseq, 0x1234, "\x00" x 160));
	$rseq++;

	$diff = ($send_start + 0.02 * ($seq - 2)) - time();
	print("send diff $diff\n");
	ok($diff > -0.01, 'diff > -0.01');
	ok($diff < +0.01, 'diff < +0.01');

	snd($sock_a, $port_b, rtp(0, 1000 + $seq, 3000 + 160 * $seq, 0x1234, "\x00" x 160));
	$seq++;
}

# now DTMF

$sseq = $rseq;

for my $iter (1 .. 10) {
	my $vol = 10;
	if ($iter != 10) {
		my $dtmf = pack("CCn", 5, $vol, 160 * ($rseq - $sseq + 1));
		rcv($sock_b, $port_a, rtpm(101 | ($rseq == $sseq ? 0x80 : 0),
				1000 + $rseq, 3000 + 160 * $sseq, 0x1234, $dtmf));
	}
	else {
		# recv x3
		$vol |= 0x80;
		my $dtmf = pack("CCn", 5, $vol, 160 * ($rseq - $sseq + 1));
		rcv($sock_b, $port_a, rtpm(101 | ($rseq == $sseq ? 0x80 : 0),
				1000 + $rseq, 3000 + 160 * $sseq, 0x1234, $dtmf));
		$rseq++;
		rcv($sock_b, $port_a, rtpm(101 | ($rseq == $sseq ? 0x80 : 0),
				1000 + $rseq, 3000 + 160 * $sseq, 0x1234, $dtmf));
		$rseq++;
		rcv($sock_b, $port_a, rtpm(101 | ($rseq == $sseq ? 0x80 : 0),
				1000 + $rseq, 3000 + 160 * $sseq, 0x1234, $dtmf));
	}

	$rseq++;

	$diff = ($send_start + 0.02 * ($seq - 2)) - time();
	print("send diff $diff\n");
	ok($diff > -0.01, 'diff > -0.01');
	ok($diff < +0.01, 'diff < +0.01');

	snd($sock_a, $port_b, rtp(0, 1000 + $seq, 3000 + 160 * $seq, 0x1234, "\x00" x 160));
	$seq++;
}

#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;






($sock_a, $sock_b) = new_call([qw(198.51.100.1 4012)], [qw(198.51.100.1 5012)]);

($port_a) = offer('DTMF trigger w inject-DTMF', { flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 4012 RTP/AVP 0 101
c=IN IP4 198.51.100.1
a=sendrecv
a=rtpmap:101 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('DTMF trigger w inject-DTMF', { flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 5012 RTP/AVP 0 101
c=IN IP4 198.51.100.1
a=sendrecv
a=rtpmap:101 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

rtpe_req('block DTMF', 'DTMF block w inject-DTMF',
	{ 'from-tag' => ft(), 'trigger' => '##', 'trigger-end' => '#', 'DTMF-security-trigger' => 'silence',
		'delay-buffer' => 2000 });

$seq = 0;
$rseq = $seq;

# first packet out determines start TS

$send_start = time();
snd($sock_a, $port_b, rtp(0, 1000 + $seq, 3000 + 160 * $seq, 0x1234, "\x00" x 160));
$seq++;

# 100 packets = 2000 ms

for (1 .. 99) {
	$diff = ($send_start + 0.02 * $seq) - time();
	print("send diff $diff\n");
	ok($diff > 0.015, 'diff > 0.015');
	ok($diff < 0.020, 'diff < 0.020');
	sleep($diff);

	snd($sock_a, $port_b, rtp(0, 1000 + $seq, 3000 + 160 * $seq, 0x1234, "\x00" x 160));
	$seq++;
}

# final 20 ms sleep replaced by waiting for the first packet out of the buffer. switch to receiver driven mode:

for (1 .. 100) {
	($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000 + $rseq, 3000 + 160 * $rseq, -1, "\x00" x 160));
	$rseq++;

	# reception timestamp should line up with what is expected
	$diff = ($send_start + 0.02 * $seq) - time();
	print("send diff $diff\n");
	ok($diff > -0.01, 'diff > -0.01');
	ok($diff < +0.01, 'diff < +0.01');

	snd($sock_a, $port_b, rtp(0, 1000 + $seq, 3000 + 160 * $seq, 0x1234, "\x00" x 160));
	$seq++;
}

# send 10 DTMF packets while still receiving PCM
$sseq = $seq;

for my $iter (1 .. 10) {
	rcv($sock_b, $port_a, rtpm(0, 1000 + $rseq, 3000 + 160 * $rseq, $ssrc, "\x00" x 160));
	$rseq++;

	$diff = ($send_start + 0.02 * $seq) - time();
	print("send diff $diff\n");
	ok($diff > -0.01, 'diff > -0.01');
	ok($diff < +0.01, 'diff < +0.01');

	my $vol = 10;
	if ($iter != 10) {
		my $dtmf = pack("CCn", 5, $vol, 160 * ($seq - $sseq + 1));
		snd($sock_a, $port_b, rtp(101 | ($seq == $sseq ? 0x80 : 0),
				1000 + $seq, 3000 + 160 * $sseq, 0x1234, $dtmf));
	}
	else {
		# send end x3
		$vol |= 0x80;
		my $dtmf = pack("CCn", 5, $vol, 160 * ($seq - $sseq + 1));
		snd($sock_a, $port_b, rtp(101 | ($seq == $sseq ? 0x80 : 0),
				1000 + $seq, 3000 + 160 * $sseq, 0x1234, $dtmf));
		$seq++;
		snd($sock_a, $port_b, rtp(101 | ($seq == $sseq ? 0x80 : 0),
				1000 + $seq, 3000 + 160 * $sseq, 0x1234, $dtmf));
		$seq++;
		snd($sock_a, $port_b, rtp(101 | ($seq == $sseq ? 0x80 : 0),
				1000 + $seq, 3000 + 160 * $sseq, 0x1234, $dtmf));
	}
	$seq++;
}

# 90 more PCM packets

for (1 .. 90) {
	rcv($sock_b, $port_a, rtpm(0, 1000 + $rseq, 3000 + 160 * $rseq, $ssrc, "\x00" x 160));
	$rseq++;

	$diff = ($send_start + 0.02 * ($seq - 2)) - time();
	print("send diff $diff\n");
	ok($diff > -0.01, 'diff > -0.01');
	ok($diff < +0.01, 'diff < +0.01');

	snd($sock_a, $port_b, rtp(0, 1000 + $seq, 3000 + 160 * $seq, 0x1234, "\x00" x 160));
	$seq++;
}

# now DTMF

$sseq = $rseq;

for my $iter (1 .. 10) {
	my $vol = 10;
	if ($iter != 10) {
		my $dtmf = pack("CCn", 5, $vol, 160 * ($rseq - $sseq + 1));
		rcv($sock_b, $port_a, rtpm(101 | ($rseq == $sseq ? 0x80 : 0),
				1000 + $rseq, 3000 + 160 * $sseq, $ssrc, $dtmf));
	}
	else {
		# recv x3
		$vol |= 0x80;
		my $dtmf = pack("CCn", 5, $vol, 160 * ($rseq - $sseq + 1));
		rcv($sock_b, $port_a, rtpm(101 | ($rseq == $sseq ? 0x80 : 0),
				1000 + $rseq, 3000 + 160 * $sseq, $ssrc, $dtmf));
		$rseq++;
		rcv($sock_b, $port_a, rtpm(101 | ($rseq == $sseq ? 0x80 : 0),
				1000 + $rseq, 3000 + 160 * $sseq, $ssrc, $dtmf));
		$rseq++;
		rcv($sock_b, $port_a, rtpm(101 | ($rseq == $sseq ? 0x80 : 0),
				1000 + $rseq, 3000 + 160 * $sseq, $ssrc, $dtmf));
	}

	$rseq++;

	$diff = ($send_start + 0.02 * ($seq - 2)) - time();
	print("send diff $diff\n");
	ok($diff > -0.01, 'diff > -0.01');
	ok($diff < +0.01, 'diff < +0.01');

	snd($sock_a, $port_b, rtp(0, 1000 + $seq, 3000 + 160 * $seq, 0x1234, "\x00" x 160));
	$seq++;
}





done_testing();
#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
