#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use MIME::Base64 qw(encode_base64);

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -n 2223 -f -L 7 -E)) or die;

new_call;
my $response = rtpe_req('create', 'SDES disabled', {
	'from-tag' => ft(),
	'transport-protocol' => 'UDP/TLS/RTP/SAVP',
	SDES => ['off'],
});
unlike($response->{sdp}, qr/^a=crypto:/m, 'SDES disabled: no crypto attributes');
like($response->{sdp}, qr/^a=fingerprint:/m, 'SDES disabled: DTLS still offered');
rtpe_req('delete', 'SDES disabled', {});

my @suites = qw(AEAD_AES_128_GCM AES_256_CM_HMAC_SHA1_80 AES_CM_128_HMAC_SHA1_80);
my %key_lengths = (AEAD_AES_128_GCM => 28, AES_256_CM_HMAC_SHA1_80 => 46,
	AES_CM_128_HMAC_SHA1_80 => 30);

for my $suite (@suites) {
	my ($secure, $plain) = new_call([qw(198.51.100.10 5000)], [qw(198.51.100.10 5002)]);
	my ($secure_tag, $plain_tag) = (ft(), tt());
	my $offer = rtpe_req('create', "$suite offer", {
		'from-tag' => $secure_tag,
		'transport-protocol' => 'RTP/SAVP',
		DTLS => 'off',
		SDES => [map { "only-$_" } @suites],
		codec => { offer => ['PCMU'] },
	});
	unlike($offer->{sdp}, qr/^a=(?:fingerprint|setup|tls-id):/m, "$suite: DTLS disabled");
	# Select each suite from the same offer, including suites other than its first preference.
	my ($crypto_tag, $out_key) = $offer->{sdp} =~ /^a=crypto:(\d+) \Q$suite\E inline:(\S+)/m;
	ok(defined($crypto_tag), "$suite is offered");
	my ($secure_port) = $offer->{sdp} =~ /^m=audio (\d+)/m;
	my $in_key = encode_base64('x' x $key_lengths{$suite}, '');
	rtpe_req('create answer', "$suite answer", {
		'from-tag' => $secure_tag,
		sdp => <<SDP,
v=0
o=- 1 1 IN IP4 198.51.100.10
s=secure
t=0 0
c=IN IP4 198.51.100.10
m=audio 5000 RTP/SAVP 0
a=rtpmap:0 PCMU/8000
a=crypto:$crypto_tag $suite inline:$in_key
a=sendrecv
SDP
	});
	my $query = rtpe_req('query', "$suite initialized media", {});
	my $media = $query->{tags}{$secure_tag}{medias}[0];
	ok(!grep($_ eq 'DTLS-SRTP', @{$media->{flags}}), "$suite: DTLS remains disabled");
	is(scalar(@{$media->{streams}}), 2, "$suite: RTP and RTCP streams exist");
	for my $stream (@{$media->{streams}}) {
		is($stream->{'crypto suite'}, $suite, "$suite: output crypto context uses selected suite");
	}

	# The Perl SRTP helper supports AES-CM. GCM is covered by the context assertions above.
	if (my $cs = $NGCP::Rtpclient::SRTP::crypto_suites{$suite}) {
		my $plain_offer = rtpe_req('create', "$suite plain peer", {
			'from-tag' => $plain_tag,
			DTLS => 'off', SDES => ['off'],
			codec => { offer => ['PCMU'] },
		});
		my ($plain_port) = $plain_offer->{sdp} =~ /^m=audio (\d+)/m;
		rtpe_req('create answer', "$suite plain answer", {
			'from-tag' => $plain_tag,
			sdp => <<SDP,
v=0
o=- 2 1 IN IP4 198.51.100.10
s=plain
t=0 0
c=IN IP4 198.51.100.10
m=audio 5002 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
SDP
		});
		rtpe_req('connect', "$suite bidirectional media", {
			'from-tag' => $secure_tag,
			'to-tag' => $plain_tag,
			flags => ['directional', 'bidirectional'],
		});
		my $send_ctx = { cs => $cs, key => $in_key };
		my $receive_ctx = { cs => $cs, key => $out_key };
		srtp_snd($secure, $secure_port, rtp(0, 1000, 3000, 0x1234, "\x11" x 160), $send_ctx);
		rcv($plain, $plain_port, rtpm(0, 1000, 3000, -1, "\x11" x 160));
		snd($plain, $plain_port, rtp(0, 2000, 4000, 0x5678, "\x22" x 160));
		srtp_rcv($secure, $secure_port, rtpm(0, 2000, 4000, -1, "\x22" x 160), $receive_ctx);
	}
	rtpe_req('delete', "$suite cleanup", {});
}

done_testing();
