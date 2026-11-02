#!/usr/bin/perl

# Report-only SSRCs must not stop comfort-noise generation during an RTP gap.
use strict;
use warnings;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);
use IO::Select;

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -n 2223 -f -L 7 -E
	--dtx-delay=50 --max-dtx=2 --dtx-cn-params=10)) or die;

for my $player ('off', 'always') {
	my ($source, $source_rtcp, $listener) = new_call(
		['198.51.100.10',5000], ['198.51.100.10',5001], ['198.51.100.10',5002]);
	rtpe_req('offer', "$player player PCMU source", {
		'from-tag'=>ft(), 'audio-player'=>$player, codec=>{transcode=>['L16/16000/1']},
		sdp=>"v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=DTX RTCP\r\nt=0 0\r\n"
			. "c=IN IP4 198.51.100.10\r\nm=audio 5000 RTP/AVP 0\r\na=sendrecv\r\n",
	});
	my $answer = rtpe_req('answer', "$player player L16 listener", {
		'from-tag'=>ft(), 'to-tag'=>tt(), 'audio-player'=>$player,
		sdp=>"v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=DTX RTCP\r\nt=0 0\r\n"
			. "c=IN IP4 198.51.100.10\r\nm=audio 5002 RTP/AVP 96\r\n"
			. "a=rtpmap:96 L16/16000/1\r\na=sendrecv\r\n",
	});
	my ($port) = $answer->{sdp} =~ /m=audio (\d+)/;
	my ($rtcp_port) = $answer->{sdp} =~ /a=rtcp:(\d+)/;
	ok($port && $rtcp_port, "$player player RTP and RTCP ports negotiated");
	my $selector = IO::Select->new($source, $source_rtcp, $listener);
	my $started = clock_gettime(CLOCK_MONOTONIC);
	my ($frame, $report_sent) = (0, 0);
	my @noise = ([], []);
	while (clock_gettime(CLOCK_MONOTONIC)-$started < 1.5) {
		my $now = clock_gettime(CLOCK_MONOTONIC)-$started;
		if ($frame < 20 && $now >= $frame*0.02) {
			snd($source, $port, rtp($frame ? 0 : 128, 100+$frame,
				100000+160*$frame, 0x5678, "\x30" x 160));
			$frame++;
		}
		if (!$report_sent && $now >= 0.9) {
			# A valid compound SR/SDES with an SSRC that has never sent RTP.
			my $report = pack('CCnNNNNNN', 0x80, 200, 6, 0xabcdef02,
				time()+2208988800, 0, 100000, 0, 0)
				. pack('CCnNCCa4n', 0x81, 202, 3, 0xabcdef02, 1, 4, 'test', 0);
			snd($source_rtcp, $rtcp_port, $report);
			$report_sent = 1;
		}
		for my $socket ($selector->can_read(0.001)) {
			my $packet;
			$socket->recv($packet, 65535);
			next unless $socket == $listener && length($packet) == 652
				&& (ord(substr($packet,1,1)) & 127) == 96;
			my $at = clock_gettime(CLOCK_MONOTONIC)-$started;
			my $window = $at > 0.6 && $at < 0.85 ? 0 : $at > 1.1 && $at < 1.4 ? 1 : undef;
			next unless defined $window;
			my @samples = unpack('s>*', substr($packet,12));
			my $energy = 0;
			$energy += $_*$_ for @samples;
			push @{$noise[$window]}, sqrt($energy/@samples);
		}
	}
	like(rtpe_log(), qr/SR from abcdef02:/, "$player player report-only SSRC processed");
	for my $window (0..1) {
		my $label = $window ? 'after RTCP' : 'before RTCP';
		cmp_ok(scalar(@{$noise[$window]}), '>=', 10, "$player player receives media $label");
		my $audible = grep {$_ > 50} @{$noise[$window]};
		cmp_ok($audible, '>=', 10, "$player player generates comfort noise $label");
	}
	# A real RTP source replacement must still stop the previous source's DTX timer.
	my $before = () = rtpe_log() =~ /DTX buffer for 5678\/0 has been shut down/g;
	my $switched = clock_gettime(CLOCK_MONOTONIC);
	$frame = 0;
	while (clock_gettime(CLOCK_MONOTONIC)-$switched < 0.4) {
		my $now = clock_gettime(CLOCK_MONOTONIC)-$switched;
		if ($frame < 10 && $now >= $frame*0.02) {
			snd($source, $port, rtp($frame ? 0 : 128, 200+$frame,
				200000+160*$frame, 0x5679, "\x30" x 160));
			$frame++;
		}
		for my $socket ($selector->can_read(0.001)) {
			my $packet;
			$socket->recv($packet, 65535);
		}
	}
	my $after = () = rtpe_log() =~ /DTX buffer for 5678\/0 has been shut down/g;
	cmp_ok($after, '>', $before, "$player player stops old DTX source after an RTP SSRC change");
	rtpe_req('delete', "$player player DTX RTCP cleanup", {});
}
done_testing();
