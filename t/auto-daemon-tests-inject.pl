#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::AutoTest;
use NGCP::Rtpclient::SRTP;
use Test::More;
use IO::Select;
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC sleep);
use Socket qw(MSG_DONTWAIT);
use POSIX ();
use File::Temp qw(tempfile);


$ENV{RTPENGINE_EXTENDED_TESTS} or exit();


sub start_daemon {
	my ($policy, $delay) = @_;
	my @buffer_delay = defined $delay ? ("--audio-buffer-delay=$delay") : ();
	autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E --audio-buffer-length=500),
			"--audio-player=$policy", @buffer_delay) or die;
}


sub sdp {
	my ($port, $direction, $key) = @_;
	my $protocol = $key ? 'RTP/SAVP' : 'RTP/AVP';
	return "v=0\no=- 1 1 IN IP4 198.51.100.14\ns=inject test\nt=0 0\n"
		. "m=audio $port $protocol 0\nc=IN IP4 198.51.100.14\n"
		. "a=rtpmap:0 PCMU/8000\na=$direction\n"
		. ($key ? "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:$key\n" : '');
}


sub negotiate {
	my ($command, $name, $request, $port, $direction, $key) = @_;
	my $response = rtpe_req($command, $name, { %$request, sdp => sdp($port, $direction, $key) });
	my ($relay_port) = ($response->{sdp} // '') =~ /m=audio (\d+) RTP\/S?AVP 0\r?\n/;
	ok $relay_port, "$name - PCMU media port returned";
	die "missing PCMU media port" unless $relay_port;
	like $response->{sdp}, qr/a=rtpmap:0 PCMU\/8000/, "$name - PCMU negotiated";
	my ($receive_key) = $response->{sdp} =~ /a=crypto:\d+ AES_CM_128_HMAC_SHA1_80 inline:([^\s|]+)/;
	return ($relay_port, $receive_key);
}


sub srtp_context {
	my ($key) = @_;
	return { cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80}, key => $key };
}


sub send_audio {
	my ($peers, $control) = @_;
	my $selector = IO::Select->new($control);
	my $next_send = clock_gettime(CLOCK_MONOTONIC);
	while (1) {
		if (clock_gettime(CLOCK_MONOTONIC) >= $next_send) {
			for my $peer (@$peers) {
				next if $peer->{paused};
				my $now = clock_gettime(CLOCK_MONOTONIC);
				my $gap = defined $peer->{last_send} ? $now - $peer->{last_send} : 0;
				$peer->{max_gap} = $gap if $gap > ($peer->{max_gap} // 0);
				$peer->{last_send} = $now;
				my $packet = rtp(0, $peer->{sequence}++, $peer->{timestamp}, $peer->{ssrc}, $peer->{payload} x 160);
				if ($peer->{send_crypto}) {
					srtp_snd($peer->{socket}, $peer->{port}, $packet, $peer->{send_crypto});
				}
				else {
					snd($peer->{socket}, $peer->{port}, $packet);
				}
				$peer->{timestamp} += 160;
				$peer->{sent}++;
			}
			$next_send += 0.02;
		}
		my $wait = $next_send - clock_gettime(CLOCK_MONOTONIC);
		$wait = 0 if $wait < 0;
		if ($selector->can_read($wait)) {
			my $length = sysread($control, my $command, 16);
			die "sender control read: $!" unless defined $length;
			last unless $length;
			for my $index (0 .. $#$peers) {
				$peers->[$index]{paused} = 1 if index($command, chr(65 + $index)) >= 0;
			}
		}
	}
	return join(', ', map {
		sprintf('%s=%d packets/max-gap %.3fms', $peers->[$_]{label} // chr(65 + $_), $peers->[$_]{sent} // 0,
			1000 * ($peers->[$_]{max_gap} // 0))
	} (0 .. $#$peers));
}


sub start_sender {
	my ($peers) = @_;
	pipe(my $control_read, my $control_write) or die "sender control pipe: $!";
	pipe(my $status_read, my $status_write) or die "sender status pipe: $!";
	my $pid = fork();
	die "sender fork: $!" unless defined $pid;
	if (!$pid) {
		close $control_write;
		close $status_read;
		local $SIG{__DIE__};
		local $SIG{PIPE} = 'IGNORE';
		local $SIG{ALRM} = sub { die "sender exceeded 15 seconds\n"; };
		my $summary;
		my $ok = eval {
			open STDOUT, '>', '/dev/null' or die "sender stdout: $!";
			alarm(15);
			$summary = send_audio($peers, $control_read);
			alarm(0);
			1;
		};
		my $message = substr($ok ? $summary : $@, 0, 4096);
		my $written = syswrite($status_write, $message);
		POSIX::_exit($ok && defined $written && $written == length($message) ? 0 : 1);
	}
	close $control_read;
	close $status_write;
	return { pid => $pid, control => $control_write, status => $status_read };
}


sub stop_sender {
	my ($sender) = @_;
	close $sender->{control};
	my $pid;
	my $deadline = clock_gettime(CLOCK_MONOTONIC) + 2;
	while (1) {
		$pid = waitpid($sender->{pid}, POSIX::WNOHANG());
		next if $pid < 0 && $!{EINTR};
		last if $pid != 0 || clock_gettime(CLOCK_MONOTONIC) >= $deadline;
		sleep(0.01);
	}
	my $timed_out = $pid == 0;
	if ($timed_out) {
		kill 'KILL', $sender->{pid};
		do { $pid = waitpid($sender->{pid}, 0); } while ($pid < 0 && $!{EINTR});
	}
	my $status = $?;
	ok !$timed_out, 'continuous sender stopped before deadline';
	is $pid, $sender->{pid}, 'continuous sender reaped';
	is $status, 0, 'continuous sender exited cleanly';
	my $summary = do { local $/; readline($sender->{status}) };
	diag "continuous sender: $summary" if defined $summary && length $summary;
	close $sender->{status};
}


sub receive_audio {
	my ($socket, $observation) = @_;
	while (defined $socket->recv(my $packet, 2048, MSG_DONTWAIT)) {
		$observation->{packets}++;
		next unless defined $observation->{expected};
		if (my $crypto = $observation->{crypto}) {
			my $ssrc = unpack('x8 N', $packet);
			my $context = $crypto->{ssrcs}{$ssrc} //= srtp_context($crypto->{key});
			$packet = NGCP::Rtpengine::AutoTest::srtp_dec(undef, undef, undef, undef, undef, undef,
				$packet, $context);
		}
		my ($header, $pt, $sequence, $timestamp, $ssrc, $payload) = unpack('CCnNN a*', $packet);
		if (length($packet) != 172 || $header != 0x80 || ($pt & 0x7f) != 0) {
			$observation->{invalid}++;
			$observation->{consecutive} = 0;
			next;
		}
		$observation->{ssrcs}{$ssrc}++ if clock_gettime(CLOCK_MONOTONIC) >= $observation->{settle_after};
		$observation->{payloads}{unpack('H2', $payload)}++;
		$observation->{samples}{$_}++ for unpack('(H2)*', $payload);
		if ($payload eq $observation->{expected} x 160) {
			$observation->{consecutive}++;
		}
		else {
			my $components = $observation->{allowed_components};
			my $allowed = $observation->{expected} . $components;
			my $unrelated = $payload =~ /[^\Q$allowed\E\xff\x7f]/;
			$observation->{unrelated}++ if $unrelated;
			$observation->{partial_mix_frames}++ if length($components) && !$unrelated && $payload =~ /[^\xff\x7f]/;
			$observation->{consecutive} = 0;
			push @{$observation->{mismatches}}, "$sequence/$timestamp " . unpack('H*', $payload);
		}
	}
}


sub check_audio {
	my ($name, $peers, $expected, $options) = @_;
	$options //= {};
	my %unchanged = map { $_ => 1 } @{$options->{unchanged} // []};
	my $components = $options->{allowed_components} // {};
	my $deadline = clock_gettime(CLOCK_MONOTONIC) + ($options->{duration} // 0.6);
	my @observations = map {
		{ expected => $expected->[$_], crypto => $peers->[$_]{receive_crypto},
			packets => 0, consecutive => 0, unrelated => 0, invalid => 0, partial_mix_frames => 0,
			allowed_components => join('', @{$components->{$_} // []}),
			payloads => {}, samples => {}, mismatches => [], ssrcs => {}, settle_after => $deadline - 0.25 }
	} (0 .. $#$peers);
	my $selector = IO::Select->new(map { $_->{socket} } @$peers);
	my %observer = map { fileno($peers->[$_]{socket}) => $observations[$_] } (0 .. $#$peers);
	while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
		my $wait = $deadline - clock_gettime(CLOCK_MONOTONIC);
		$wait = 0 if $wait < 0;
		for my $socket ($selector->can_read($wait)) {
			receive_audio($socket, $observer{fileno($socket)});
		}
	}
	for my $index (0 .. $#$peers) {
		my $observation = $observations[$index];
		my $label = $peers->[$index]{label} // chr(65 + $index);
		if (!defined $expected->[$index]) {
			is $observation->{packets}, 0, "$name - no audio returned to $label";
			next;
		}
		is $observation->{invalid}, 0, "$name - $label received PCMU RTP";
		is scalar(keys %{$observation->{ssrcs}}), 1, "$name - $label receives one settled RTP stream";
		cmp_ok $observation->{consecutive}, '>=', 10, "$name - $label has ten consecutive expected PCM frames";
		if ($unchanged{$index}) {
			is $observation->{unrelated}, 0, "$name - $label receives no unrelated PCM throughout";
		}
		diag "$name - $label partial mixed PCM frames: $observation->{partial_mix_frames}"
			if $observation->{partial_mix_frames};
		if ($observation->{consecutive} < 10 || $observation->{invalid}
				|| keys(%{$observation->{ssrcs}}) != 1 || ($unchanged{$index} && $observation->{unrelated})) {
			diag "$name - $label settled SSRC counts: " . join(', ', map {
				"$_=$observation->{ssrcs}{$_}"
			} sort keys %{$observation->{ssrcs}});
			diag "$name - $label payload first-byte counts: " . join(', ', map {
				"$_=$observation->{payloads}{$_}"
			} sort keys %{$observation->{payloads}});
			diag "$name - $label sample counts: " . join(', ', map {
				"$_=$observation->{samples}{$_}"
			} sort keys %{$observation->{samples}});
			diag "$name - $label differing sequence/timestamp/payload: $_" for @{$observation->{mismatches}};
		}
	}
}


sub inject {
	my ($command, $name, $main_call, $destination, $source, $source_call) = @_;
	my %request = ('call-id' => $main_call, 'to-tag' => $destination, 'source-tag' => $source);
	$request{'source-call-id'} = $source_call if defined $source_call;
	return rtpe_req($command, $name, \%request);
}


sub inject_error {
	my ($command, $name, $request, $expected) = @_;
	my $response = rtpe_raw_req({ %$request, command => $command });
	like $response, qr/Error reason: "\Q$expected\E"/, "$name - '$command' rejected";
}


sub check_player {
	my ($name, $call, $tag, $expected) = @_;
	my $response = rtpe_req('query', $name, { 'call-id' => $call });
	my $flags = $response->{tags}{$tag}{medias}[0]{flags};
	is scalar(grep { $_ eq 'audio player' } @$flags), $expected, "$name - explicit audio player policy";
}


sub exercise_injection {
	my ($options) = @_;
	my $settings = $options->{settings} // {};
	my $explicit_player = $options->{explicit_player} // 0;
	my @sockets = new_call(map { ['198.51.100.14', $_] } (6000, 6002, 6004, 6006));
	my ($main_call, $a_tag, $b_tag) = (cid(), ft(), tt());
	my ($c_tag, $d_tag) = ("$a_tag-c", "$a_tag-d");
	my $c_call = $options->{external} ? "$main_call-c" : $main_call;
	my $d_call = $options->{external} ? "$main_call-d" : $main_call;
	my $a_key = $options->{srtp} ? 'DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF' : undef;
	my $c_key = $options->{srtp} ? 'eMlRvW8mWU4WodT9JOvAM+pn6I0/EXOhT9n0KeKk' : undef;
	my ($port_b) = negotiate('offer', 'main offer',
		{ %$settings, 'call-id' => $main_call, 'from-tag' => $a_tag, 'transport-protocol' => 'RTP/AVP' },
		6000, 'sendrecv', $a_key);
	my ($port_a, $a_receive_key) = negotiate('answer', 'main answer',
		{ %$settings, 'call-id' => $main_call, 'from-tag' => $a_tag, 'to-tag' => $b_tag }, 6002, 'sendrecv');
	my ($port_c) = negotiate('publish', 'source C',
		{ 'call-id' => $c_call, 'from-tag' => $c_tag }, 6004, 'sendonly', $c_key);
	my ($port_d) = negotiate('publish', 'source D',
		{ 'call-id' => $d_call, 'from-tag' => $d_tag }, 6006, 'sendonly');
	my @ports = ($port_a, $port_b, $port_c, $port_d);
	my @payloads = ("\xef", "\xdf", "\xcf", "\xbf");
	my @peers = map {
		{ socket => $sockets[$_], port => $ports[$_], payload => $payloads[$_],
			sequence => 1000, timestamp => 8000, ssrc => 0x12340000 + $_ }
	} (0 .. 3);
	if ($options->{srtp}) {
		ok $a_receive_key, 'SRTP receive key negotiated for A';
		die 'missing SRTP receive key' unless $a_receive_key;
		$peers[0]{send_crypto} = srtp_context($a_key);
		$peers[0]{receive_crypto} = { key => $a_receive_key, ssrcs => {} };
		$peers[2]{send_crypto} = srtp_context($c_key);
	}
	my $c_source_call = $options->{external} ? $c_call : undef;
	my $d_source_call = $options->{external} ? $d_call : undef;

	my $sender = start_sender(\@peers);
	my $ok = eval {
		inject_error('inject start', 'self injection',
			{ 'call-id' => $main_call, 'to-tag' => $a_tag, 'source-tag' => $a_tag }, 'Trying to inject to self');
		inject_error('inject start', 'ordinary subscription cannot become inject',
			{ 'call-id' => $main_call, 'to-tag' => $a_tag, 'source-tag' => $b_tag }, 'Failed to start inject');
		check_audio('ordinary', \@peers, ["\xdf", "\xef", undef, undef], { unchanged => [1] });
		check_player('ordinary', $main_call, $a_tag, $explicit_player);
		inject('inject start', 'start C', $main_call, $a_tag, $c_tag, $c_source_call);
		check_audio('B+C', \@peers, ["\xc9", "\xef", undef, undef], { unchanged => [1] });
		inject('inject start', 'repeat start C', $main_call, $a_tag, $c_tag, $c_source_call);
		check_audio('B+C once', \@peers, ["\xc9", "\xef", undef, undef], { unchanged => [1] });
		inject('inject start', 'start D', $main_call, $a_tag, $d_tag, $d_source_call);
		check_audio('B+C+D', \@peers, ["\xb5", "\xef", undef, undef], { unchanged => [1] });
		inject('inject stop', 'stop C', $main_call, $a_tag, $c_tag, $c_source_call);
		check_audio('B+D remains', \@peers, ["\xbc", "\xef", undef, undef], { unchanged => [1] });
		inject('inject stop', 'stop D', $main_call, $a_tag, $d_tag, $d_source_call);
		check_audio('ordinary after stop', \@peers, ["\xdf", "\xef", undef, undef], { unchanged => [1] });
		inject('inject start', 'restart C', $main_call, $a_tag, $c_tag, $c_source_call);
		check_audio('B+C restarted', \@peers, ["\xc9", "\xef", undef, undef], { unchanged => [1] });
		inject('inject stop', 'stop restarted C', $main_call, $a_tag, $c_tag, $c_source_call);
		inject_error('inject stop', 'already stopped C',
			{ 'call-id' => $main_call, 'to-tag' => $a_tag, 'source-tag' => $c_tag }, 'Failed to stop inject');
		check_audio('ordinary after duplicate stop', \@peers, ["\xdf", "\xef", undef, undef], { unchanged => [1] });
		check_player('all inject stopped', $main_call, $a_tag, $explicit_player);
		if ($options->{player_survives}) {
			local $SIG{PIPE} = 'IGNORE';
			syswrite($sender->{control}, 'B') == 1 or die "pause source B: $!";
			check_audio('player continues without source packets', \@peers, ["\xff", "\xef", undef, undef], { unchanged => [1] });
		}
		1;
	};
	my $error = $@;
	stop_sender($sender);
	die $error unless $ok;
	rtpe_req('delete', 'delete main call', { 'call-id' => $main_call });
}


sub exercise_bidirectional_injection {
	my ($delete_delay, $delete_party) = @_;
	$delete_party //= 'C';
	my @sockets = new_call(map { ['198.51.100.14', $_] } (6020, 6022, 6024, 6026));
	my ($call, $a_tag, $b_tag) = (cid(), ft(), tt());
	my ($c_tag, $d_tag) = ("$a_tag-c", "$a_tag-d");
	my ($port_b) = negotiate('offer', 'A-B offer',
		{ 'call-id' => $call, 'from-tag' => $a_tag }, 6020, 'sendrecv');
	my ($port_a) = negotiate('answer', 'A-B answer',
		{ 'call-id' => $call, 'from-tag' => $a_tag, 'to-tag' => $b_tag }, 6022, 'sendrecv');
	my ($port_c) = negotiate('offer', 'D-C offer',
		{ 'call-id' => $call, 'from-tag' => $d_tag }, 6026, 'sendrecv');
	my ($port_d) = negotiate('answer', 'D-C answer',
		{ 'call-id' => $call, 'from-tag' => $d_tag, 'to-tag' => $c_tag }, 6024, 'sendrecv');
	my @ports = ($port_a, $port_b, $port_c, $port_d);
	my @payloads = ("\xef", "\xdf", "\xcf", "\xff");
	my @peers = map {
		{ socket => $sockets[$_], port => $ports[$_], payload => $payloads[$_],
			sequence => 1000, timestamp => 8000, ssrc => 0x12340000 + $_ }
	} (0 .. 3);
	my $sender = start_sender(\@peers);
	my $ok = eval {
		check_audio('independent pairs', \@peers, ["\xdf", "\xef", "\xff", "\xcf"]);
		inject('inject start', 'A into C', $call, $c_tag, $a_tag, $call);
		inject('inject start', 'B into C', $call, $c_tag, $b_tag, $call);
		check_audio('C receives A+B', \@peers, ["\xdf", "\xef", "\xdb", "\xcf"], { unchanged => [0, 1, 3] });
		inject('inject start', 'C into A', $call, $a_tag, $c_tag, $call);
		check_audio('A-C injection', \@peers, ["\xc9", "\xef", "\xdb", "\xcf"],
			{ unchanged => [1, 2, 3], allowed_components => { 2 => ["\xef", "\xdf"] } });
		inject('inject start', 'C into B', $call, $b_tag, $c_tag, $call);
		check_audio('A-C and B-C injection', \@peers, ["\xc9", "\xcd", "\xdb", "\xcf"],
			{ unchanged => [0, 2, 3], allowed_components => { 0 => ["\xdf", "\xcf"], 2 => ["\xef", "\xdf"] } });
		if (defined $delete_delay) {
			my %tags = (A => $a_tag, B => $b_tag, C => $c_tag, D => $d_tag);
			my @deleted = $delete_party eq 'C' ? qw(C D) : qw(A B);
			my @remaining = $delete_party eq 'C' ? qw(A B) : qw(C D);
			my $restored = $delete_party eq 'C' ? ["\xdf", "\xef", undef, undef] : [undef, undef, "\xff", "\xcf"];
			pause_source($sender, \@peers, $_) for @deleted;
			rtpe_req('delete', "delete $delete_party during bidirectional injection",
				{ 'call-id' => $call, 'from-tag' => $tags{$delete_party}, 'delete-delay' => $delete_delay });
			if ($delete_delay) {
				for my $label (@deleted) {
					my $response = rtpe_req('query', "look up pending deletion of $label",
						{ 'call-id' => $call, 'from-tag' => $tags{$label} });
					ok exists $response->{tags}{$tags{$label}}, "$label remains until deletion expires";
				}
			}
			drain_audio(\@peers, 0.1);
			check_audio('ordinary streams after delete request', \@peers, $restored);
			check_transcoding("$_ after delete request", $call, $tags{$_}, 0) for @remaining;
			if ($delete_delay) {
				drain_audio(\@peers, $delete_delay + 0.5);
				check_audio('ordinary streams after deletion expires', \@peers, $restored,
					{ unchanged => [map { ord($_) - ord('A') } @remaining] });
				check_transcoding("$_ after deletion expires", $call, $tags{$_}, 0) for @remaining;
			}
			for my $label (@deleted) {
				my $response = rtpe_req('query', "look up deleted endpoint $label",
					{ 'call-id' => $call, 'from-tag' => $tags{$label} });
				is_deeply $response->{tags}, {}, "deleted endpoint $label no longer found";
			}
		}
		else {
			inject('inject stop', 'C out of B', $call, $b_tag, $c_tag, $call);
			check_audio('A-C injection remains', \@peers, ["\xc9", "\xef", "\xdb", "\xcf"],
				{ unchanged => [0, 2, 3], allowed_components => { 0 => ["\xdf", "\xcf"], 2 => ["\xef", "\xdf"] } });
			inject('inject stop', 'C out of A', $call, $a_tag, $c_tag, $call);
			check_audio('only C receives A+B', \@peers, ["\xdf", "\xef", "\xdb", "\xcf"],
				{ unchanged => [1, 2, 3], allowed_components => { 2 => ["\xef", "\xdf"] } });
			inject('inject stop', 'A out of C', $call, $c_tag, $a_tag, $call);
			check_audio('only C receives B', \@peers, ["\xdf", "\xef", "\xdf", "\xcf"], { unchanged => [0, 1, 3] });
			inject('inject stop', 'B out of C', $call, $c_tag, $b_tag, $call);
			check_audio('independent pairs restored', \@peers, ["\xdf", "\xef", "\xff", "\xcf"], { unchanged => [0, 1, 3] });
		}
		1;
	};
	my $error = $@;
	stop_sender($sender);
	die $error unless $ok;
	rtpe_req('delete', 'delete call', { 'call-id' => $call });
}


sub playback_file {
	my ($seconds) = @_;
	$seconds //= 10;
	my ($file, $path) = tempfile(SUFFIX => '.wav', TMPDIR => 1, UNLINK => 1);
	my $pcm = pack('s<', 396) x (8000 * $seconds);
	my $wav = 'RIFF' . pack('V', 36 + length($pcm)) . 'WAVEfmt '
		. pack('VvvVVvv', 16, 1, 1, 8000, 16000, 2, 16)
		. 'data' . pack('V', length($pcm)) . $pcm;
	binmode $file;
	print {$file} $wav or die "write playback file: $!";
	close $file or die "close playback file: $!";
	return $path;
}


sub exercise_playback {
	my ($ending) = @_;
	my ($destination, $source_socket) = new_call(
		['198.51.100.14', 6010], ['198.51.100.14', 6012]);
	my @receivers = ({ socket => $destination, label => 'destination' }, { socket => $source_socket, label => 'source' });
	my $created = rtpe_req('create', 'standalone destination', { codec => { offer => ['PCMU'] } });
	my ($call, $tag) = @{$created}{'call-id', 'from-tag'};
	rtpe_req('create answer', 'destination answer', {
		'call-id' => $call, 'from-tag' => $tag, sdp => sdp(6010, 'recvonly'),
	});
	my $source_tag = "$tag-source";
	my ($port) = negotiate('publish', 'only RTP source',
		{ 'call-id' => $call, 'from-tag' => $source_tag }, 6012, 'sendonly');
	my $sender = start_sender([{ socket => $source_socket, port => $port, label => 'source',
		sequence => 1000, timestamp => 8000, ssrc => 0x12345678, payload => "\xcf" }]);
	my %injection = ('call-id' => $call, 'to-tag' => $tag, 'source-tag' => $source_tag);
	my $ok = eval {
		rtpe_req('inject start', 'start sole injection', \%injection);
		check_audio('injected source before playback', \@receivers, ["\xcf", undef], { duration => 1.2 });
		my $play = rtpe_req('play media', 'independent playback', {
			'call-id' => $call, 'from-tag' => $tag, file => playback_file(4),
		});
		is $play->{duration}, 4000, 'playback outlasts inject stop observation';
		check_audio('playback plus injection', \@receivers, ["\xc9", undef], { duration => 1.2 });
		rtpe_req('inject stop', 'stop sole injection', \%injection);
		check_audio('independent playback after inject stop', \@receivers, ["\xdf", undef], { duration => 1.2 });
		if ($ending eq 'stop') {
			rtpe_req('stop media', 'stop independent playback', { 'call-id' => $call, 'from-tag' => $tag });
		}
		drain_audio(\@receivers, $ending eq 'stop' ? 0.3 : 2.0);
		check_audio('player removed after playback ends', \@receivers, [undef, undef]);
		1;
	};
	my $error = $@;
	stop_sender($sender);
	die $error unless $ok;
	rtpe_req('delete', 'delete standalone call', { 'call-id' => $call });
}


sub drain_audio {
	my ($peers, $duration) = @_;
	my $selector = IO::Select->new(map { $_->{socket} } @$peers);
	my $deadline = clock_gettime(CLOCK_MONOTONIC) + $duration;
	while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
		for my $socket ($selector->can_read(0.01)) {
			1 while defined $socket->recv(my $packet, 2048, MSG_DONTWAIT);
		}
	}
}


sub pause_source {
	my ($sender, $peers, $label) = @_;
	syswrite($sender->{control}, $label) == 1 or die "pause source $label: $!";
	drain_audio($peers, 0.1);
}


sub check_transcoding {
	my ($name, $call, $tag, $expected) = @_;
	my $response = rtpe_req('query', $name, { 'call-id' => $call });
	my $flags = $response->{tags}{$tag}{medias}[0]{flags};
	is scalar(grep { $_ eq 'transcoding' } @$flags), $expected, "$name - media transcoding flag";
}


sub exercise_lifecycle {
	my ($transition) = @_;
	my @sockets = new_call(map { ['198.51.100.14', $_] } (6030, 6032, 6034));
	my ($call, $a, $b) = (cid(), ft(), tt());
	my $c = "$a-c";
	my ($port_b) = negotiate('offer', 'A-B offer',
		{ 'call-id' => $call, 'from-tag' => $a }, 6030, 'sendrecv');
	my ($port_a) = negotiate('answer', 'A-B answer',
		{ 'call-id' => $call, 'from-tag' => $a, 'to-tag' => $b }, 6032, 'sendrecv');
	my ($port_c) = negotiate('publish', 'C source',
		{ 'call-id' => $call, 'from-tag' => $c }, 6034, 'sendonly');
	my @ports = ($port_a, $port_b, $port_c);
	my $b_pcm = $transition eq 'playback' ? "\xff" : "\xdf";
	my @payloads = ("\xef", $b_pcm, "\xcf");
	my @peers = map {
		{ socket => $sockets[$_], port => $ports[$_], payload => $payloads[$_],
			sequence => 1000, timestamp => 8000, ssrc => 0x12340000 + $_ }
	} (0 .. 2);
	my $sender = start_sender(\@peers);
	my $ok = eval {
		check_audio('ordinary', \@peers, [$b_pcm, "\xef", undef]);
		check_transcoding('B before injection', $call, $b, 0);
		inject('inject start', 'C into A', $call, $a, $c, $call);
		check_audio('C mixed into A', \@peers,
			[$transition eq 'playback' ? "\xcf" : "\xc9", "\xef", undef], { unchanged => [1] });
		check_transcoding('B during injection', $call, $b, 1);
		check_transcoding('C during injection', $call, $c, 1);
		if ($transition eq 'delete' || $transition eq 'unsubscribe') {
			inject('inject start', 'C into B', $call, $b, $c, $call);
			check_audio('C mixed into both destinations', \@peers, ["\xc9", "\xcd", undef]);
			if ($transition eq 'delete') {
				pause_source($sender, \@peers, 'C');
				rtpe_req('delete', 'delete injecting source',
					{ 'call-id' => $call, 'from-tag' => $c, 'delete-delay' => 0 });
			}
			else {
				rtpe_req('unsubscribe', 'remove only C into A',
					{ 'call-id' => $call, 'from-tag' => $c, 'to-tag' => $a, flags => ['directional'] });
				check_audio('C still mixed into B', \@peers, ["\xdf", "\xcd", undef], { unchanged => [1] });
				rtpe_req('unsubscribe', 'remove C into B',
					{ 'call-id' => $call, 'from-tag' => $c, 'to-tag' => $b, flags => ['directional'] });
			}
			check_audio('ordinary streams restored', \@peers, ["\xdf", "\xef", undef]);
			check_transcoding('A after removal', $call, $a, 0);
			check_transcoding('B after removal', $call, $b, 0);
			if ($transition eq 'unsubscribe') {
				pause_source($sender, \@peers, 'B');
				check_audio('no implicit player after unsubscribe', \@peers, [undef, "\xef", undef]);
			}
		}
		elsif ($transition eq 'playback') {
			pause_source($sender, \@peers, 'C');
			my $play = rtpe_req('play media', 'ten-second playback into A',
				{ 'call-id' => $call, 'from-tag' => $a, file => playback_file() });
			is $play->{duration}, 10000, 'playback outlasts observation';
			check_audio('playback audible before inject stop', \@peers, ["\xdf", "\xef", undef], { duration => 1.2 });
			inject('inject stop', 'C out of A', $call, $a, $c, $call);
			check_audio('active playback survives inject stop', \@peers, ["\xdf", "\xef", undef], { unchanged => [1] });
			rtpe_req('stop media', 'stop playback into A', { 'call-id' => $call, 'from-tag' => $a });
			check_audio('ordinary after playback', \@peers, ["\xff", "\xef", undef], { unchanged => [1] });
		}
		else {
			if ($transition eq 'force') {
				negotiate('offer', 'force player during injection',
					{ 'call-id' => $call, 'from-tag' => $a, 'to-tag' => $b, 'audio-player' => 'force' }, 6030, 'sendrecv');
				negotiate('answer', 'answer updated offer',
					{ 'call-id' => $call, 'from-tag' => $a, 'to-tag' => $b }, 6032, 'sendrecv');
				check_player('explicit policy applied', $call, $a, 1);
				check_audio('mix after updated offer', \@peers, ["\xc9", "\xef", undef]);
			}
			inject('inject stop', 'C out of A', $call, $a, $c, $call);
			check_audio('ordinary after inject stop', \@peers, ["\xdf", "\xef", undef], { unchanged => [1] });
			if ($transition eq 'force') {
				check_player('explicit force survives stop', $call, $a, 1);
				pause_source($sender, \@peers, 'B');
				check_audio('forced player keeps sending silence', \@peers, ["\xff", "\xef", undef]);
			}
			else {
				check_transcoding('B after inject stop', $call, $b, 0);
				check_transcoding('C after inject stop', $call, $c, 0);
			}
		}
		1;
	};
	my $error = $@;
	stop_sender($sender);
	die $error unless $ok;
	rtpe_req('delete', 'delete call', { 'call-id' => $call });
}


sub exercise_t38_cleanup {
	my ($audio, $fax, $source) = new_call(
		['198.51.100.14', 6040], ['198.51.100.14', 6042], ['198.51.100.14', 6044]);
	my ($call, $b, $a) = (cid(), ft(), tt());
	my $c = "$a-c";
	my $offer = rtpe_req('offer', 'decode T.38 into PCMU', {
		'call-id' => $call, 'from-tag' => $b, 'T.38' => ['decode'], sdp => <<SDP,
v=0
o=- 1 1 IN IP4 198.51.100.14
s=inject test
t=0 0
m=image 6042 udptl t38
c=IN IP4 198.51.100.14
a=sendrecv
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:262
a=T38FaxMaxDatagram:300
a=T38FaxUdpEC:t38UDPRedundancy
SDP
	});
	like $offer->{sdp}, qr/m=audio \d+ RTP\/AVP 0/, 'gateway offers PCMU';
	my $answer = rtpe_req('answer', 'PCMU answer to T.38', {
		'call-id' => $call, 'from-tag' => $b, 'to-tag' => $a, sdp => sdp(6040, 'sendrecv'),
	});
	like $answer->{sdp}, qr/m=image \d+ udptl t38/i, 'gateway answers with T.38';
	my ($port) = negotiate('publish', 'C source',
		{ 'call-id' => $call, 'from-tag' => $c }, 6044, 'sendonly');
	my @peers = ({ socket => $audio }, { socket => $fax }, { socket => $source });
	my $sender = start_sender([{ socket => $source, port => $port, label => 'C',
		sequence => 1000, timestamp => 8000, ssrc => 0x12340002, payload => "\xcf" }]);
	my $ok = eval {
		drain_audio(\@peers, 0.3);
		check_audio('idle gateway', \@peers, ["\xff", undef, undef]);
		inject('inject start', 'C into gateway audio', $call, $a, $c, $call);
		check_audio('injected audio at gateway destination', \@peers, ["\xcf", undef, undef]);
		inject('inject stop', 'C out of gateway audio', $call, $a, $c, $call);
		drain_audio(\@peers, 0.3);
		check_audio('idle gateway after inject stop', \@peers, ["\xff", undef, undef]);
		1;
	};
	my $error = $@;
	stop_sender($sender);
	die $error unless $ok;
	rtpe_req('delete', 'delete T.38 call', { 'call-id' => $call, flags => ['fast'], 'delete-delay' => 0 });
}


start_daemon('on-demand', 40);
subtest 'T.38 audio injection cleanup' => \&exercise_t38_cleanup;
subtest 'delete injecting source' => sub { exercise_lifecycle('delete'); };
subtest 'unsubscribe injection' => sub { exercise_lifecycle('unsubscribe'); };
subtest 'active playback survives inject stop' => sub { exercise_lifecycle('playback'); };
subtest 'force applied during injection' => sub { exercise_lifecycle('force'); };
subtest 'media transcoding flags' => sub { exercise_lifecycle('flags'); };
subtest 'bidirectional injection' => \&exercise_bidirectional_injection;
subtest 'delete A during bidirectional injection' => sub { exercise_bidirectional_injection(0, 'A'); };
subtest 'delete B during bidirectional injection' => sub { exercise_bidirectional_injection(0, 'B'); };
subtest 'delete bidirectional injection endpoint' => sub { exercise_bidirectional_injection(0); };
subtest 'delayed delete of bidirectional injection endpoint' => sub { exercise_bidirectional_injection(1); };
subtest 'same call' => sub { exercise_injection({}); };
subtest 'source-call-id' => sub { exercise_injection({ external => 1 }); };
subtest 'SRTP source-call-id' => sub { exercise_injection({ external => 1, srtp => 1 }); };
subtest 'explicit player survives stop' => sub {
	exercise_injection({ settings => { 'audio-player' => 'force' }, explicit_player => 1, player_survives => 1 });
};
NGCP::Rtpengine::AutoTest::shut_rtpe();

start_daemon('always', 40);
subtest 'global always player survives stop' => sub { exercise_injection({ explicit_player => 1, player_survives => 1 }); };
NGCP::Rtpengine::AutoTest::shut_rtpe();

start_daemon('transcoding', 40);
subtest 'transcoding player survives stop' => sub {
	exercise_injection({ settings => { flags => ['force transcoding'] }, player_survives => 1 });
};
NGCP::Rtpengine::AutoTest::shut_rtpe();

start_daemon('play-media', 40);
subtest 'standalone playback stopped after injection' => sub { exercise_playback('stop'); };
subtest 'standalone playback ends after injection' => sub { exercise_playback('eof'); };
NGCP::Rtpengine::AutoTest::shut_rtpe();

start_daemon('on-demand');
subtest 'bidirectional injection with default buffer delay' => \&exercise_bidirectional_injection;
done_testing();
