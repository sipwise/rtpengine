#!/usr/bin/perl

# Conference mixer timing regression.

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use Time::HiRes qw(time);
use IO::Select;

# A deliberately large DTX delay makes clock ownership observable without AMR fixtures or long calls.
autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -n 2223 -f -L 7 -E
	--dtx-delay=200 --max-dtx=1), @ARGV) or die;

# Reuse the call and SSRC to cover decoder/DTX cleanup when clock ownership changes.
my ($source, $listener) = new_call([qw(198.51.100.10 5000)], [qw(198.51.100.10 5002)]);
my $phase = 0;
for my $mode ('always', 'transcoding', 'always', 'off', 'always') {
	my $name = "DTX clock ownership: $phase $mode";
	my $offer = rtpe_req('offer', $name, {
		'from-tag' => ft(),
		'audio player' => $mode,
		codec => { transcode => ['L16/16000/1'] },
		sdp => "v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=test\r\nt=0 0\r\n" .
			"c=IN IP4 198.51.100.10\r\nm=audio 5000 RTP/AVP 0\r\na=sendrecv\r\n",
	});
	my $answer = rtpe_req('answer', $name, {
		'from-tag' => ft(),
		'to-tag' => tt(),
		'audio player' => $mode,
		sdp => "v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=test\r\nt=0 0\r\n" .
			"c=IN IP4 198.51.100.10\r\nm=audio 5002 RTP/AVP 96\r\n" .
			"a=rtpmap:96 L16/16000/1\r\na=sendrecv\r\n",
	});
	my ($input_port) = $answer->{sdp} =~ /m=audio (\d+)/;
	ok($input_port, 'source media address was negotiated');
	my $select = IO::Select->new($listener);
	while ($select->can_read(0)) {
		my $discard;
		$listener->recv($discard, 65535);
	}
	my $start = time();
	my $seq = 100 + $phase * 100;
	my $ts = 100000 + $phase * 16000;
	# Two paced frames also populate the recent payload tracker used by the DTX timer.
	snd($source, $input_port, rtp(0, $seq, $ts, 0x5678, "\x40" x 160));
	Time::HiRes::sleep(0.02);
	snd($source, $input_port, rtp(0, $seq + 1, $ts + 160, 0x5678, "\x40" x 160));
	my ($delay, $last_ts);
	while (time() - $start < 0.6) {
		next unless $select->can_read(0.02);
		my $packet;
		$listener->recv($packet, 65535);
		next unless length($packet) >= 12;
		my ($pt, $ts) = unpack('x C x2 N', $packet);
		next unless ($pt & 0x7f) == 96;
		if (defined $last_ts && $mode ne 'off') {
			is(($ts - $last_ts) & 0xffffffff, 320, 'mixer output clock remains continuous');
		}
		$last_ts = $ts;
		my @samples = unpack('s>*', substr($packet, 12));
		if (grep { abs($_) > 500 } @samples) {
			$delay = time() - $start;
			last;
		}
	}
	ok(defined $delay, 'speech reaches the listener');
	if (defined $delay) {
		if ($mode eq 'always') {
			cmp_ok($delay, '<', 0.14, 'permanent mixer does not queue input behind the DTX timer');
		}
		else {
			cmp_ok($delay, '>=', 0.18, 'ordinary and implicit transcoders retain configured DTX handling');
		}
	}
	# Let both tone frames leave the mixer before measuring the next signalling update.
	Time::HiRes::sleep(0.3);
	$phase++;
}

rtpe_req('delete', 'DTX clock ownership cleanup', {'from-tag' => ft()});
done_testing();
