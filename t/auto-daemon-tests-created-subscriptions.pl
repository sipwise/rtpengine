#!/usr/bin/perl

# Retained SDP ownership for created and subscribed endpoints.

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use Time::HiRes qw(sleep);
use IO::Select;

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -n 2223 -f -L 7 -E)) or die;

# Generate independently owned request bodies so later commands reuse the parser buffers.
sub endpoint_sdp {
	my ($port, $name) = @_;
	return "v=0\r\no=- 123456 7 IN IP4 198.51.100.10\r\ns=$name\r\nt=0 0\r\n" .
		"c=IN IP4 198.51.100.10\r\nm=audio $port RTP/AVP 0\r\n" .
		"a=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n";
}

# Churn unrelated SDP requests in the same call without changing the source endpoint.
sub churn_requests {
	for my $n (1 .. 32) {
		rtpe_req('publish', 'request buffer churn', {
			'from-tag' => 'churn',
			sdp => endpoint_sdp(5010, "unrelated-$n") . "a=x-padding:" . ('x' x (1000 + $n)) . "\r\n",
		});
	}
}

for my $kind ('created', 'subscribed') {
	my ($source, $listener) = new_call([qw(198.51.100.10 5000)], [qw(198.51.100.10 5002)]);
	my $response;
	if ($kind eq 'created') {
		$response = rtpe_req('create', 'created source', {
			'from-tag' => ft(),
			media => [{type => 'audio', codecs => ['PCMU/8000']}],
		});
		rtpe_req('create answer', 'created source answer', {
			'from-tag' => ft(), sdp => endpoint_sdp(5000, 'retained-session'),
		});
	}
	else {
		rtpe_req('publish', 'subscription parent', {
			'from-tag' => 'parent', sdp => endpoint_sdp(5004, 'parent-session'),
		});
		$response = rtpe_req('subscribe request', 'subscribed source', {
			'from-tag' => 'parent', 'to-tag' => ft(),
		});
		rtpe_req('subscribe answer', 'subscribed source answer', {
			'to-tag' => ft(), sdp => endpoint_sdp(5000, 'retained-session'),
		});
	}
	my ($input_port) = $response->{sdp} =~ /m=audio (\d+)/;
	ok($input_port, "$kind source has a media port");
	churn_requests();
	my $offer = rtpe_req('subscribe request', "$kind WebRTC listener", {
		'from-tag' => ft(), 'to-tag' => 'webrtc-listener', flags => ['WebRTC', 'block DTMF'],
		codec => {mask => ['all'], transcode => ['opus']},
	});
	like($offer->{sdp}, qr/^m=audio \d+ UDP\/TLS\/RTP\/SAVPF 96\r?$/m, "$kind retains audio type and Opus payload");
	like($offer->{sdp}, qr/^a=rtpmap:96 opus\/48000\/2\r?$/m, "$kind retains requested Opus codec");
	if ($kind eq 'created') {
		like($offer->{sdp}, qr/^o=- 123456 \d+ IN IP4 \S+\r?$/m, 'created answer retains a valid origin');
		like($offer->{sdp}, qr/^s=retained-session\r?$/m, 'created answer retains session name');
		my $plain = rtpe_req('subscribe request', 'created decoded audio listener', {
			'from-tag' => ft(), 'to-tag' => tt(),
			codec => {mask => ['all'], transcode => ['L16/16000/1']},
		});
		my ($payload_type) = $plain->{sdp} =~ /a=rtpmap:(\d+) L16\/16000/;
		ok(defined $payload_type, 'decoded audio listener negotiates L16');
		$payload_type //= 96;
		rtpe_req('subscribe answer', 'created decoded audio answer', {
			'to-tag' => tt(),
			flags => ['allow transcoding'],
			sdp => "v=0\r\no=- 8 1 IN IP4 198.51.100.10\r\ns=listener\r\nt=0 0\r\n" .
				"c=IN IP4 198.51.100.10\r\nm=audio 5002 RTP/AVP $payload_type\r\n" .
				"a=rtpmap:$payload_type L16/16000/1\r\na=recvonly\r\n",
		});
		my $select = IO::Select->new($listener);
		my $audible = 0;
		for my $seq (1 .. 20) {
			snd($source, $input_port, rtp(0, $seq, $seq * 160, 0x5678, "\x40" x 160));
			sleep(0.02);
			while ($select->can_read(0)) {
				my $packet;
				$listener->recv($packet, 65535);
				next if length($packet) < 12 || (ord(substr($packet, 1, 1)) & 0x7f) != $payload_type;
				$audible++ if grep { abs($_) > 500 } unpack('s>*', substr($packet, 12));
			}
		}
		ok($audible >= 5, 'created source delivers decoded non-silent audio after request churn');
	}
	rtpe_req('delete', "$kind cleanup", {});
}
done_testing();
