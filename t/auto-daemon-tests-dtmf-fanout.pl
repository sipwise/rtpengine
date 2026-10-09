#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use Time::HiRes qw(time sleep);
use IO::Select;

plan skip_all => 'requires AMR-WB encoding; enable RTPENGINE_EXTENDED_TESTS'
	unless $ENV{RTPENGINE_EXTENDED_TESTS};

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
	-n 2223 -f -L 7 -E --dtx-delay=50)) or die;

# Convert the AMR-WB fixture from auto-daemon-tests-dtx.pl to bandwidth-efficient RTP.
my $speech = pack('H*', 'f1f41182687c5cc09c5c400285a1dd3a9aa30199d9bb3d59db151b51531f16635f15711b14');
my $pcm = "\0" x 1600;
my $wav = pack('a4Va4a4VvvVVvva4V', 'RIFF', 36 + length($pcm), 'WAVE',
		'fmt ', 16, 1, 1, 8000, 16000, 2, 16, 'data', length($pcm)) . $pcm;

# The per-media event deduplication must not leave a later destination suppressed.
for my $order (['phone', 'browser'], ['browser', 'phone']) {
	my $name = 'DTMF end fan-out: ' . join(', ', @$order);
	my @tags = ('source', 'phone', 'browser', 'sink');
	my @codecs = ('AMR-WB/16000', 'AMR-WB/16000', 'opus/48000/2', 'PCMU/8000');
	my @socks = new_call([qw(198.51.100.10 5000)], [qw(198.51.100.10 5002)],
			[qw(198.51.100.10 5004)], [qw(198.51.100.10 5006)]);
	my @ports;
	for my $i (0..3) {
		my $pt = $i == 3 ? 0 : 104;
		my $port = 5000 + $i * 2;
		my $sdp = "v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=fanout\r\nt=0 0\r\n"
				. "m=audio $port RTP/AVP $pt 105\r\nc=IN IP4 198.51.100.10\r\n"
				. "a=rtpmap:$pt $codecs[$i]\r\na=rtpmap:105 telephone-event/16000\r\na=sendrecv\r\n";
		my $resp = rtpe_req('publish', $name, {
			'from-tag' => $tags[$i],
			sdp => $sdp,
			flags => ['bidirectional', 'detect DTMF'],
			'DTMF-security' => 'silence',
			'delay buffer' => 100,
			'audio-player' => 'off',
		});
		($ports[$i]) = $resp->{sdp} =~ /m=audio (\d+)/;
	}
	rtpe_req('block DTMF', $name, {'from-tag' => 'source', 'DTMF-security' => 'silence'});
	rtpe_req('mesh', $name, {
		calls => [cid()],
		tags => [{from => 'source', to => [@$order, 'sink']}],
		flags => ['unsubscribe'],
	});
	my $select = IO::Select->new(@socks[1..3]);
	my $seq = 1000;
	my $ts = 100000;

	# Prime every primary audio handler before the blocked event, as in a live call.
	for my $i (0..19) {
		snd($socks[0], $ports[0], rtp(104, $seq++, $ts, 0x5678, $speech));
		$ts += 320;
		sleep(0.02);
	}
	my $drain_until = time() + 0.1;
	while (time() < $drain_until) {
		my @ready = $select->can_read(0.01);
		for my $sock (@ready) { my $packet; $sock->recv($packet, 65535); }
	}

	for my $burst (0..1) {
		rtpe_req('block media', $name, {'from-tag' => 'source', flags => ['directional']});
		for my $i (1..2) {
			rtpe_req('play media', $name, {'from-tag' => $tags[$i], blob => $wav, flags => ['block egress']});
		}
		my $event_ts = $ts;
		for my $i (0..9) {
			snd($socks[0], $ports[0], rtp(105, $seq++, $event_ts, 0x5678,
					pack('CCn', 10, 7, 320 * ($i + 1))));
			snd($socks[0], $ports[0], rtp(104, $seq++, $ts, 0x5678, $speech));
			$ts += 320;
			sleep(0.02);
		}
		# Repeated end packets are deduplicated globally but must clear every leg.
		for my $i (1..3) {
			snd($socks[0], $ports[0], rtp(105, $seq++, $event_ts, 0x5678, pack('CCn', 10, 135, 3200)));
			sleep(0.02);
		}
		sleep(0.15);
		for my $i (1..2) { rtpe_req('stop media', $name, {'from-tag' => $tags[$i]}); }
		rtpe_req('unblock media', $name, {'from-tag' => 'source', flags => ['directional']});
		my $start = time();
		my $next = $start;
		my (%first, %count, %last, %gap);
		while (time() < $start + 1.2) {
			if (time() >= $next) {
				snd($socks[0], $ports[0], rtp(104, $seq++, $ts, 0x5678, $speech));
				$ts += 320;
				$next += 0.02;
			}
			for my $sock ($select->can_read(0.001)) {
				my $packet;
				$sock->recv($packet, 65535);
				my ($pt, $out_seq, $out_ts, $ssrc) = unpack('x C n N N', $packet);
				next unless $ssrc == 0x5678;
				my $leg = $sock == $socks[1] ? 'phone' : $sock == $socks[2] ? 'browser' : 'sink';
				my $now = time();
				$first{$leg} //= $now - $start;
				$count{$leg}++;
				if (exists $last{$leg}) {
					my $delta = $now - $last{$leg};
					$gap{$leg} = $delta if $delta > ($gap{$leg} // 0);
				}
				$last{$leg} = $now;
			}
		}
		for my $leg ('phone', 'browser', 'sink') {
			cmp_ok($count{$leg} // 0, '>=', 20, "$name burst $burst: $leg keeps receiving speech RTP");
			cmp_ok($first{$leg} // 10, '<', 0.4, "$name burst $burst: $leg resumes promptly after DTMF end");
			cmp_ok($gap{$leg} // 10, '<', 0.3, "$name burst $burst: $leg has no suppression gap");
		}
	}
	rtpe_req('delete', $name, {'from-tag' => 'source'});
}

done_testing();
