#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;

# Check continuous DTX output separately from restarts after playback.
autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
	-n 2223 -f -L 7 -E --silence-detect=1 --dtx-delay=50 --max-dtx=1 --codec-num-threads=2)) or die;

use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC sleep);
use IO::Select;

# Exercise equal rates, different RTP rates, and the G.722 sample/RTP rate factor.
for my $profile (
	['PCMA/8000', 8, 8000, 100000],
	['opus/48000/2', 96, 48000, 100000],
	['G722/8000', 9, 8000, 0xfffffa00],
) {
	my ($codec, $pt, $rate, $origin) = @$profile;
	my $offer_pts = $pt == 96 ? '96 97' : $pt;
	my $offer_attrs = "a=rtpmap:$pt $codec";
	if ($pt == 96) {
		$offer_attrs .= "\na=fmtp:96 useinbandfec=1\na=rtpmap:97 telephone-event/48000\na=fmtp:97 0-15";
	}
	my ($sock_a, $sock_b) = new_call([qw(198.51.100.10 5000)], [qw(198.51.100.10 5002)]);
	my $name = "DTX output clock across playback: $codec";

	my ($port_a) = offer($name, { codec => { transcode => [$codec] } }, <<SDP);
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
m=audio PORT RTP/AVP 0 $offer_pts 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
$offer_attrs
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

	my ($port_b) = answer($name, {}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 5002 RTP/AVP $pt 101
a=rtpmap:$pt $codec
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


	# A short prompt on its own SSRC interrupts the transcoder between bursts.
	my $pcm = "\0" x 1600;
	my $wav = pack('a4Va4a4VvvVVvva4V', 'RIFF', 36 + length($pcm), 'WAVE',
			'fmt ', 16, 1, 1, 8000, 16000, 2, 16, 'data', length($pcm)) . $pcm;
	my $sel = IO::Select->new($sock_b);
	my ($seq, $audio_ssrc, $last_ts, $last_seq) = (100);
	my $start = clock_gettime(CLOCK_MONOTONIC);
	my $wrapped = 0;
	for my $burst (0..2) {
		# Keep the sender clock advancing between bursts. Do not prescribe the
		# receiver's timestamp offset or compare receive times with RTP timestamps.
		my $input_ts = ($origin + int((clock_gettime(CLOCK_MONOTONIC) - $start) * 50) * 160)
				& 0xffffffff;
		for my $i (0..9) {
			snd($sock_a, $port_b, rtp(0, $seq++, ($input_ts + $i * 160) & 0xffffffff,
					0x5678, "\x40" x 160));
			sleep(0.02);
		}

		# Bursts 0 and 2 include ten DTX fill frames. Interrupt burst 1 just
		# after its last input frame: async output must refresh the restart
		# timestamp before another DTX tick can save the encoder state.
		my $frames = $burst == 1 ? 10 : 20;
		for my $i (0 .. $frames - 1) {
			unless ($sel->can_read(2)) {
				fail("$codec burst $burst: missing output frame $i");
				last;
			}
			my $p;
			$sock_b->recv($p, 65535) or die "recv: $!";
			my ($out_pt, $q, $ts, $ssrc) = unpack('x C n N N', $p);
			is($out_pt & 0x7f, $pt, "$codec burst $burst: negotiated payload type");
			$audio_ssrc //= $ssrc;
			is($ssrc, $audio_ssrc, "$codec burst $burst: speech SSRC");
			if (defined $last_ts) {
				my $delta = ($ts - $last_ts) & 0xffffffff;
				my $seq_delta = ($q - $last_seq) & 0xffff;
				if ($i == 0) {
					# Some packets were drained during playback. Across this gap
					# require forward progress, without choosing a restart origin.
					ok($delta > 0 && $delta < 0x80000000,
							"$codec burst $burst: restart timestamp advances")
							or diag("previous TS=$last_ts, resumed TS=$ts, delta=$delta");
					ok($seq_delta > 0 && $seq_delta < 0x8000,
							"$codec burst $burst: restart sequence advances")
							or diag("previous seq=$last_seq, resumed seq=$q");
				}
				else {
					is($seq_delta, 1, "$codec burst $burst: consecutive output sequence");
					is($delta, $rate / 50, "$codec burst $burst: 20 ms output timestamp increment")
							or diag("seq=$q, previous TS=$last_ts, TS=$ts");
					$wrapped = 1 if $ts < $last_ts && $delta == $rate / 50;
				}
			}
			($last_ts, $last_seq) = ($ts, $q);
		}
		last if $burst == 2;

		rtpe_req('block media', $name, {'from-tag' => ft(), flags => ['directional']});
		rtpe_req('play media', $name, {'from-tag' => tt(), blob => $wav});
		sleep(0.2);
		rtpe_req('stop media', $name, {'from-tag' => tt()});
		# Drain prompt and in-flight packets, then wait beyond max-dtx so
		# the next observation belongs to the resumed speech stream.
		my $end = clock_gettime(CLOCK_MONOTONIC) + 1.4;
		while (clock_gettime(CLOCK_MONOTONIC) < $end) {
			if ($sel->can_read(0.02)) {
				my $p;
				$sock_b->recv($p, 65535) or die "recv: $!";
				my ($out_pt, $q, $ts, $ssrc) = unpack('x C n N N', $p);
				# Include every observed speech packet in the restart comparison,
				# but never compare the prompt's independent RTP timeline.
				($last_ts, $last_seq) = ($ts, $q)
						if $ssrc == $audio_ssrc && ($out_pt & 0x7f) == $pt;
			}
		}
		rtpe_req('unblock media', $name, {'from-tag' => ft(), flags => ['directional']});
	}
	ok($wrapped, 'G.722 timestamps cross the 32-bit boundary with 20 ms increments') if $pt == 9;
	rtpe_req('delete', $name, {'from-tag' => ft()});
}

done_testing();
