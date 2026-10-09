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

# Leave a wide gap between prompt mixer output and the configured DTX wait.
# The observation includes scheduling of both the daemon and this test on shared CI runners.
my $dtx_delay = 0.8; # seconds
autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -n 2223 -f -L 7 -E
	--max-dtx=1), '--dtx-delay=' . ($dtx_delay * 1000), @ARGV) or die;

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
	# Distinct PCMU levels decode to -3900, -3388, -2876, -2364 and -1884 respectively.
	# Recognise this phase's audio instead of accepting late speech from the previous configuration.
	my $payload = chr(0x30 + $phase * 4) x 160;
	my $sample = (-3900, -3388, -2876, -2364, -1884)[$phase];
	# Two paced frames also populate the recent payload tracker used by the DTX timer.
	snd($source, $input_port, rtp(0, $seq, $ts, 0x5678, $payload));
	Time::HiRes::sleep(0.02);
	snd($source, $input_port, rtp(0, $seq + 1, $ts + 160, 0x5678, $payload));
	my ($delay, $speech_ssrc, $last_seq, $last_ts);
	my $clock_intervals = 0;
	while (time() - $start < $dtx_delay + 0.8) {
		next unless $select->can_read(0.02);
		my $packet;
		$listener->recv($packet, 65535);
		next unless length($packet) >= 12;
		my ($pt, $out_seq, $out_ts, $ssrc) = unpack('x C n N N', $packet);
		next unless ($pt & 0x7f) == 96;
		my @samples = unpack('s>*', substr($packet, 12));
		if (!defined $delay && (grep { abs($_ - $sample) < 20 } @samples) >= 16) {
			$delay = time() - $start;
			$speech_ssrc = $ssrc;
		}
		next unless defined $delay && $ssrc == $speech_ssrc;
		last if $mode eq 'off';
		# A replacement mixer and the old transcoder have independent SSRCs and timestamp origins.
		# Check the stream carrying current speech, including its silence after the two input frames.
		if (defined $last_seq) {
			my $seq_delta = ($out_seq - $last_seq) & 0xffff;
			my $ts_delta = ($out_ts - $last_ts) & 0xffffffff;
			my $context = sprintf('%s SSRC=%08x seq=%u->%u timestamp=%u->%u',
				$name, $ssrc, $last_seq, $out_seq, $last_ts, $out_ts);
			is($seq_delta, 1, 'mixer output sequence remains continuous') or diag($context);
			if ($seq_delta == 1) {
				is($ts_delta, 320, 'mixer output clock remains continuous') or diag($context);
				$clock_intervals++;
			}
		}
		$last_seq = $out_seq;
		$last_ts = $out_ts;
		last if $clock_intervals >= 3;
	}
	ok(defined $delay, 'speech reaches the listener');
	if ($mode ne 'off') {
		cmp_ok($clock_intervals, '>=', 3, 'checked multiple mixer clock intervals after speech');
	}
	if (defined $delay) {
		if ($mode eq 'always') {
			cmp_ok($delay, '<', $dtx_delay / 2, 'permanent mixer does not queue input behind the DTX timer')
				or diag(sprintf('%s: observed %.3f s with configured DTX delay %.3f s',
					$name, $delay, $dtx_delay));
		}
		else {
			cmp_ok($delay, '>=', $dtx_delay - 0.05, 'ordinary and implicit transcoders retain configured DTX handling')
				or diag(sprintf('%s: observed %.3f s with configured DTX delay %.3f s',
					$name, $delay, $dtx_delay));
		}
	}
	# Let both tone frames leave the mixer before measuring the next signalling update.
	Time::HiRes::sleep(0.3);
	$phase++;
}

rtpe_req('delete', 'DTX clock ownership cleanup', {'from-tag' => ft()});
done_testing();
