#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use JSON::PP ();

# These are integration tests against the daemon, not a model of its codec store.
autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
	-n 2223 -f -L 7 -E)) or die;

sub sdp {
	my ($port, @codecs) = @_;
	my $s = "v=0\r\no=- 1 1 IN IP4 198.51.100.1\r\ns=remap\r\nt=0 0\r\n"
		. "m=audio $port RTP/AVP " . join(' ', map { $_->[0] } @codecs)
		. "\r\nc=IN IP4 198.51.100.1\r\n";
	for my $c (@codecs) {
		$s .= "a=rtpmap:$c->[0] $c->[1]\r\n";
		$s .= "a=fmtp:$c->[0] 0-16\r\n" if $c->[1] =~ /^telephone-event\//;
	}
	return $s . "a=sendrecv\r\n";
}

sub send_offer {
	my ($name, $codecs, $options) = @_;
	return rtpe_req('offer', $name, {
		'from-tag' => ft(), sdp => sdp(4000, @$codecs),
		'audio-player' => 'off', %{$options // {}},
	});
}

sub check_codecs {
	my ($name, $sdp, @codecs) = @_;
	my $pts = join(' ', map { $_->[0] } @codecs);
	like($sdp, qr/^m=audio \d+ RTP\/AVP \Q$pts\E\r?$/m, "$name: m-line PTs and order");
	for my $c (@codecs) {
		like($sdp, qr/^a=rtpmap:\Q$c->[0] $c->[1]\E\r?$/m, "$name: rtpmap $c->[0]");
		if ($c->[1] =~ /^telephone-event\//) {
			like($sdp, qr/^a=fmtp:\Q$c->[0]\E 0-16\r?$/m, "$name: fmtp follows event PT");
		}
	}
}

for my $pair ([96, 101], [101, 96], [96, 96], [96, 35], [35, 101]) {
	my ($original, $mapped) = @$pair;
	my $name = "telephone-event $original -> $mapped";
	my ($a, $b) = new_call([qw(198.51.100.1 4000)], [qw(198.51.100.1 4002)]);
	my $offer = send_offer($name, [[0, 'PCMU/8000'], [$original, 'telephone-event/8000']],
		{codec => {'telephone-event-payload' => $mapped}});
	check_codecs("$name offer", $offer->{sdp}, [0, 'PCMU/8000'], [$mapped, 'telephone-event/8000']);
	my ($port_b) = $offer->{sdp} =~ /m=audio (\d+)/;
	my $answer = rtpe_req('answer', $name, {
		'from-tag' => ft(), 'to-tag' => tt(), 'audio-player' => 'off',
		sdp => sdp(4002, [0, 'PCMU/8000'], [$mapped, 'telephone-event/8000']),
	});
	check_codecs("$name answer", $answer->{sdp}, [0, 'PCMU/8000'], [$original, 'telephone-event/8000']);
	my ($port_a) = $answer->{sdp} =~ /m=audio (\d+)/;

	# Existing DTMF forwarding can substitute SSRCs. Do not incorrectly demand
	# byte-for-byte RTP identity: assert PT, marker, sequence, timestamp and payload.
	for my $direction ([$a, $port_a, $b, $port_b, $original, $mapped],
			[$b, $port_b, $a, $port_a, $mapped, $original]) {
		my ($src, $in_port, $dst, $out_port, $in_pt, $out_pt) = @$direction;
		my $seq = 1000;
		my $audio = join('', map { chr($_) } 0..159);
		snd($src, $in_port, rtp(0, $seq++, 10000, 0x12345678, $audio));
		rcv($dst, $out_port, rtpm(0, 1000, 10000, -1, $audio));
		my @events = ([0x80, 7, 160], [0, 7, 320], [0, 135, 480], [0, 135, 480], [0, 135, 480]);
		for my $event (@events) {
			my ($marker, $flags, $duration) = @$event;
			my $payload = pack('CCn', 5, $flags, $duration);
			snd($src, $in_port, rtp($in_pt | $marker, $seq, 10160, 0x12345678, $payload));
			rcv($dst, $out_port, rtpm($out_pt | $marker, $seq, 10160, -1, $payload));
			$seq++;
		}
		snd($src, $in_port, rtp(0, $seq, 10640, 0x12345678, $audio));
		rcv($dst, $out_port, rtpm(0, $seq, 10640, -1, $audio));
	}
}

# Guard cases leave the offer unchanged, rather than taking over another codec's PT.
for my $case (
	['absent option', [[0, 'PCMU/8000'], [96, 'telephone-event/8000']], {}],
	['occupied PT', [[0, 'PCMU/8000'], [101, 'opus/48000/2'], [96, 'telephone-event/8000']],
		{codec => {'telephone-event-payload' => 101}}],
	['no events', [[0, 'PCMU/8000']], {codec => {'telephone-event-payload' => 101}}],
	['multiple event rates', [[0, 'PCMU/8000'], [96, 'telephone-event/8000'], [97, 'telephone-event/16000']],
		{codec => {'telephone-event-payload' => 101}}],
	['asymmetric codecs', [[0, 'PCMU/8000'], [96, 'telephone-event/8000']],
		{codec => {'telephone-event-payload' => 101}, flags => ['allow-asymmetric-codecs']}],
) {
	my ($name, $codecs, $options) = @$case;
	new_call;
	my $resp = send_offer($name, $codecs, $options);
	check_codecs($name, $resp->{sdp}, @$codecs);
}

new_call;
my $resp = send_offer('supplemental order', [[0, 'PCMU/8000'], [96, 'telephone-event/8000'], [13, 'CN/8000']],
	{codec => {'telephone-event-payload' => 101}});
check_codecs('supplemental order', $resp->{sdp}, [0, 'PCMU/8000'], [101, 'telephone-event/8000'], [13, 'CN/8000']);

new_call;
send_offer('event rejected in answer', [[0, 'PCMU/8000'], [96, 'telephone-event/8000']],
	{codec => {'telephone-event-payload' => 101}});
$resp = rtpe_req('answer', 'event rejected in answer', {
	'from-tag' => ft(), 'to-tag' => tt(), 'audio-player' => 'off', sdp => sdp(4002, [0, 'PCMU/8000']),
});
check_codecs('event rejected in answer', $resp->{sdp}, [0, 'PCMU/8000']);
unlike($resp->{sdp}, qr/telephone-event/, 'answer does not reintroduce rejected event codec');

# Re-offers must rebuild from the received SDP, not retain a stale remap.
new_call;
my $established = 0;
for my $stage (['initial remap', 101, 1], ['remove remap', 96, 0], ['reapply remap', 101, 1]) {
	my ($name, $out_pt, $enabled) = @$stage;
	my %options;
	$options{'to-tag'} = tt() if $established;
	$options{codec} = {'telephone-event-payload' => 101} if $enabled;
	my $off = send_offer("same-dialogue $name", [[0, 'PCMU/8000'], [96, 'telephone-event/8000']],
		\%options);
	check_codecs("same-dialogue $name offer", $off->{sdp}, [0, 'PCMU/8000'], [$out_pt, 'telephone-event/8000']);
	my $ans = rtpe_req('answer', "same-dialogue $name", {
		'from-tag' => ft(), 'to-tag' => tt(), 'audio-player' => 'off',
		sdp => sdp(4002, [0, 'PCMU/8000'], [$out_pt, 'telephone-event/8000']),
	});
	check_codecs("same-dialogue $name answer", $ans->{sdp}, [0, 'PCMU/8000'], [96, 'telephone-event/8000']);
	$established = 1;
}

# The former answerer can become offerer without exchanging the legs' PTs.
reverse_tags();
$resp = send_offer('reverse-leg reoffer', [[0, 'PCMU/8000'], [101, 'telephone-event/8000']], {
	'to-tag' => tt(), codec => {'telephone-event-payload' => 96},
});
check_codecs('reverse-leg reoffer', $resp->{sdp}, [0, 'PCMU/8000'], [96, 'telephone-event/8000']);
$resp = rtpe_req('answer', 'reverse-leg reanswer', {
	'from-tag' => ft(), 'to-tag' => tt(), 'audio-player' => 'off',
	sdp => sdp(4002, [0, 'PCMU/8000'], [96, 'telephone-event/8000']),
});
check_codecs('reverse-leg reanswer', $resp->{sdp}, [0, 'PCMU/8000'], [101, 'telephone-event/8000']);

new_call;
send_offer('answer option rejected', [[0, 'PCMU/8000'], [96, 'telephone-event/8000']], {});
$resp = rtpe_raw_req({
	command => 'answer', 'call-id' => cid(), 'from-tag' => ft(), 'to-tag' => tt(),
	sdp => sdp(4002, [0, 'PCMU/8000'], [96, 'telephone-event/8000']),
	codec => {'telephone-event-payload' => 101},
});
like($resp, qr/^error:/, 'valid remap PT is not accepted on an answer');
like($resp, qr/telephone-event-payload is only supported in offer, subscribe-request and create/,
	'answer option error explains offer-only scope');

for my $bad (-1, 0, 8, 64, 95, 128, 'not-an-integer', [], {}) {
	new_call;
	my $resp = rtpe_raw_req({
		command => 'offer', 'call-id' => cid(), 'from-tag' => ft(),
		sdp => sdp(4000, [0, 'PCMU/8000'], [96, 'telephone-event/8000']),
		codec => {'telephone-event-payload' => $bad},
	});
	like($resp, qr/^error:/, 'invalid remap PT rejected');
	like($resp, qr/telephone-event-payload must be an unassigned RTP payload type from 1 to 127, excluding 64 to 95/,
		'invalid remap PT has actionable error');
}

# Reject an offer-only option before delete can mutate an established call.
new_call;
send_offer('delete option rejected', [[0, 'PCMU/8000'], [96, 'telephone-event/8000']], {});
$resp = rtpe_raw_req({
	command => 'delete', 'call-id' => cid(),
	codec => {'telephone-event-payload' => 101},
});
like($resp, qr/^error:/, 'offer-only option rejects delete');
like($resp, qr/telephone-event-payload is only supported in offer, subscribe-request and create/,
	'delete propagates callback error');
$resp = rtpe_raw_req({command => 'query', 'call-id' => cid()});
is($resp->{result}, 'ok', 'rejected delete leaves established call intact');

# Flags-string clients (e.g. Kamailio's rtpengine_offer()) send the PT as a string,
# through the top-level alias. \'101' makes Bencode send a string, not an integer.
for my $case (
	['string in codec dictionary', {codec => {'telephone-event-payload' => \'101'}}],
	['top-level alias', {'codec-telephone-event-payload' => \'101'}],
	['rtpp-flags alias', {'rtpp-flags' => 'codec-telephone-event-payload=101'}],
) {
	my ($name, $options) = @$case;
	new_call;
	my $resp = send_offer($name, [[0, 'PCMU/8000'], [96, 'telephone-event/8000']], $options);
	check_codecs($name, $resp->{sdp}, [0, 'PCMU/8000'], [101, 'telephone-event/8000']);
}

new_call;
send_offer('alias rejected in answer', [[0, 'PCMU/8000'], [96, 'telephone-event/8000']], {});
$resp = rtpe_raw_req({
	command => 'answer', 'call-id' => cid(), 'from-tag' => ft(), 'to-tag' => tt(),
	sdp => sdp(4002, [0, 'PCMU/8000'], [96, 'telephone-event/8000']),
	'codec-telephone-event-payload' => \'101',
});
like($resp, qr/telephone-event-payload is only supported in offer, subscribe-request and create/,
	'top-level alias is offer-only too');

for my $bad ('95', '128', '101abc', 'not-an-integer', '101.5', "101\0abc") {
	new_call;
	my $resp = rtpe_raw_req({
		command => 'offer', 'call-id' => cid(), 'from-tag' => ft(),
		sdp => sdp(4000, [0, 'PCMU/8000'], [96, 'telephone-event/8000']),
		'codec-telephone-event-payload' => \$bad,
	});
	like($resp, qr/telephone-event-payload must be an unassigned RTP payload type from 1 to 127, excluding 64 to 95/,
		"invalid alias value '$bad' rejected");
}

# Errors from flags strings must propagate before the command executes.
for my $command ('offer', 'answer', 'delete') {
	new_call;
	send_offer('rtpp-flags rejection setup', [[0, 'PCMU/8000'], [96, 'telephone-event/8000']], {});
	my $value = $command eq 'offer' ? '101abc' : '101';
	my $resp = rtpe_raw_req({
		command => $command, 'call-id' => cid(), 'from-tag' => ft(), 'to-tag' => tt(),
		sdp => sdp(4002, [0, 'PCMU/8000'], [96, 'telephone-event/8000']),
		'rtpp-flags' => "codec-telephone-event-payload=$value",
	});
	like($resp, qr/^error:/, "$command rejects invalid rtpp-flags option");
	my $reason = $command eq 'offer'
		? 'telephone-event-payload must be an unassigned RTP payload type from 1 to 127, excluding 64 to 95'
		: 'telephone-event-payload is only supported in offer, subscribe-request and create';
	like($resp, qr/\Q$reason\E/, "$command propagates rtpp-flags error");
	$resp = rtpe_raw_req({command => 'query', 'call-id' => cid()});
	is($resp->{result}, 'ok', "$command rejection leaves established call intact");
}

for my $flags ('codec-telephone-event-payload=', 'codec-telephone-event-payload') {
	new_call;
	my $resp = rtpe_raw_req({
		command => 'offer', 'call-id' => cid(), 'from-tag' => ft(),
		sdp => sdp(4000, [0, 'PCMU/8000'], [96, 'telephone-event/8000']),
		'rtpp-flags' => $flags,
	});
	like($resp, qr/telephone-event-payload must be an unassigned RTP payload type from 1 to 127, excluding 64 to 95/,
		'rtpp-flags rejects missing payload value');
}

# Exercise both new command paths through their answers and RTP forwarding.
for my $source_kind ('publish', 'create') {
	my ($a, $b) = new_call([qw(198.51.100.1 4000)], [qw(198.51.100.1 4002)]);
	my $source_pt = $source_kind eq 'create' ? 35 : 96;
	my $source;
	if ($source_kind eq 'create') {
		$source = rtpe_req('create', 'create payload preference', {
			'from-tag' => ft(),
			media => [{type => 'audio', codecs => ['PCMU/8000', 'telephone-event/8000']}],
			codec => {'telephone-event-payload' => 35},
		});
		like($source->{sdp}, qr/^a=rtpmap:35 telephone-event\/8000\r?$/m,
			'create applies payload preference to existing telephone-event');
		rtpe_req('create answer', 'created source answer', {
			'from-tag' => ft(), sdp => sdp(4000, [0, 'PCMU/8000'], [35, 'telephone-event/8000']),
		});
	}
	else {
		$source = rtpe_req('publish', 'subscription source', {
			'from-tag' => ft(), sdp => sdp(4000, [0, 'PCMU/8000'], [96, 'telephone-event/8000']),
		});
	}
	my ($source_port) = $source->{sdp} =~ /m=audio (\d+)/;
	my $subscriber = rtpe_req('subscribe request', "$source_kind subscriber", {
		'from-tag' => ft(), 'to-tag' => tt(), 'audio-player' => 'off',
		codec => {'telephone-event-payload' => 101},
	});
	check_codecs('subscription preference', $subscriber->{sdp}, [0, 'PCMU/8000'], [101, 'telephone-event/8000']);
	my ($subscriber_port) = $subscriber->{sdp} =~ /m=audio (\d+)/;
	rtpe_req('subscribe answer', 'subscription answer', {
		'to-tag' => tt(), sdp => sdp(4002, [0, 'PCMU/8000'], [101, 'telephone-event/8000']),
	});
	my $audio = join('', map { chr($_) } 0..159);
	snd($a, $source_port, rtp(0, 1000, 10000, 0x12345678, $audio));
	rcv($b, $subscriber_port, rtpm(0, 1000, 10000, -1, $audio));
	my $seq = 1001;
	for my $event ([0x80, 7, 160], [0, 7, 320], [0, 135, 480]) {
		my ($marker, $flags, $duration) = @$event;
		my $payload = pack('CCn', 5, $flags, $duration);
		snd($a, $source_port, rtp($source_pt | $marker, $seq, 10160, 0x12345678, $payload));
		rcv($b, $subscriber_port, rtpm(101 | $marker, $seq, 10160, -1, $payload));
		$seq++;
	}
}

for my $case (
	['subscription collision', [[0, 'PCMU/8000'], [101, 'opus/48000/2'], [96, 'telephone-event/8000']], []],
	['subscription asymmetric', [[0, 'PCMU/8000'], [96, 'telephone-event/8000']], ['allow-asymmetric-codecs']],
) {
	my ($name, $codecs, $flags) = @$case;
	new_call;
	rtpe_req('publish', $name, {'from-tag' => ft(), sdp => sdp(4000, @$codecs)});
	my $resp = rtpe_req('subscribe request', $name, {
		'from-tag' => ft(), 'to-tag' => tt(), flags => $flags,
		codec => {'telephone-event-payload' => 101},
	});
	check_codecs($name, $resp->{sdp}, @$codecs);
}

for my $command ('create', 'subscribe request') {
	new_call;
	my $resp = rtpe_raw_req({
		command => $command, 'call-id' => cid(), 'from-tag' => ft(),
		codec => {'telephone-event-payload' => 8},
	});
	like($resp, qr/telephone-event-payload must be an unassigned RTP payload type/,
		"$command rejects fixed payload before executing");
}

# JSON must enforce the same integer/string contract as Bencode.
use_json(1);
for my $options (
	{codec => {'telephone-event-payload' => 101}},
	{codec => {'telephone-event-payload' => '101'}},
	{codec => {'telephone-event-payload' => '0101'}},
	{'codec-telephone-event-payload' => '101'},
) {
	new_call;
	my $resp = send_offer('JSON string payload', [[0, 'PCMU/8000'], [96, 'telephone-event/8000']], $options);
	check_codecs('JSON string payload', $resp->{sdp}, [0, 'PCMU/8000'], [101, 'telephone-event/8000']);
}
for my $bad ('101abc', 101.5, '101.5', [], {}, JSON::PP::true, JSON::PP::false) {
	for my $options (
		{codec => {'telephone-event-payload' => $bad}},
		{'codec-telephone-event-payload' => $bad},
	) {
		new_call;
		my $resp = rtpe_raw_req({
			command => 'offer', 'call-id' => cid(), 'from-tag' => ft(),
			sdp => sdp(4000, [0, 'PCMU/8000'], [96, 'telephone-event/8000']), %$options,
		});
		like($resp, qr/telephone-event-payload must be an unassigned RTP payload type from 1 to 127, excluding 64 to 95/,
			'JSON invalid value rejected');
	}
}
use_json(0);

done_testing();
