#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;

# Repeated floor bursts must retain each output encoder clock through prompt playback.
autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
	-n 2223 -f -L 7 -E --silence-detect=1 --dtx-delay=50 --max-dtx=1)) or die;

use Time::HiRes qw(time sleep);
use IO::Select;

# Exercise equal rates, different RTP rates, and the G.722 sample/RTP rate factor.
for my $profile (
	['PCMA/8000', 8, 8000, 100000],
	['opus/48000/2', 96, 48000, 100000],
	['G722/8000', 9, 8000, 0xfffff000],
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
	my ($seq, $last_ts, $last_time, $audio_ssrc) = (100, undef, undef, undef);
	for my $burst (0..2) {
		for my $i (0..9) {
			snd($sock_a, $port_b, rtp(0, $seq++, $origin + $burst * 16000 + $i * 160,
					0x5678, "\x40" x 160));
			sleep(0.02);
		}
		my $sel = IO::Select->new($sock_b);
		my $end = time() + 0.3;
		my $received = 0;
		while (time() < $end && $sel->can_read(0.1)) {
			my $p;
			$sock_b->recv($p, 65535);
			my ($out_pt, $q, $ts, $ssrc) = unpack('x C n N N', $p);
			is($out_pt & 0x7f, $pt, 'burst uses the negotiated output codec');
			$audio_ssrc //= $ssrc;
			is($ssrc, $audio_ssrc, 'speech SSRC survives playback transitions');
			my $now = time();
			if (defined $last_ts) {
				my $delta = ($ts - $last_ts) & 0xffffffff;
				cmp_ok($delta, '<', 0x80000000, 'output clock does not rewind');
				if ($now - $last_time > 1) {
					# Receive after sending a 200 ms batch; allow that batching skew.
					cmp_ok(abs($delta / $rate - ($now - $last_time)), '<', 0.3,
							'RTP clock includes elapsed playback and silence');
				}
			}
			$last_ts = $ts;
			$last_time = $now;
			$received++;
		}
		cmp_ok($received, '>=', 10, 'each burst produces output promptly');
		rtpe_req('block media', $name, {'from-tag' => ft(), flags => ['directional']});
		rtpe_req('play media', $name, {'from-tag' => tt(), blob => $wav});
		sleep(0.2);
		rtpe_req('stop media', $name, {'from-tag' => tt()});
		while ($sel->can_read(0.01)) {
			my $p;
			$sock_b->recv($p, 65535);
		}
		sleep(1.4);
		rtpe_req('unblock media', $name, {'from-tag' => ft(), flags => ['directional']});
	}
	rtpe_req('delete', $name, {'from-tag' => ft()});
}

done_testing();
