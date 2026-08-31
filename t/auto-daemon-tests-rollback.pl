#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use NGCP::Rtpclient::ICE;
use NGCP::Rtpclient::DTLS;
use IO::Multiplex;
use Socket qw(MSG_DONTWAIT);
use Test::More;

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
		-n 2223 -c 12345 -f -L 7 -E -u 2222)) or die;

sub sdp {
	my ($address, $port, $payload, $direction, $extra_media) = @_;
	my $codec = $payload == 8 ? 'PCMA' : 'PCMU';
	my $ret = "v=0\r\no=- 1 1 IN IP4 $address\r\ns=rollback\r\n"
		. "c=IN IP4 $address\r\nt=0 0\r\nm=audio $port RTP/AVP $payload\r\n"
		. "a=rtpmap:$payload $codec/8000\r\na=$direction\r\n";
	$ret .= "m=video " . ($port + 2) . " RTP/AVP 96\r\n"
		. "a=rtpmap:96 VP8/90000\r\na=$direction\r\n" if $extra_media;
	return $ret;
}

sub rollback {
	my ($via_branch) = @_;
	my %req = ('call-id' => cid(), 'from-tag' => ft(), 'to-tag' => tt());
	$req{'via-branch'} = $via_branch if defined $via_branch;
	return rtpe_req('rollback', 'rollback state', \%req);
}

sub negotiated_tags {
	my ($state) = @_;
	# __fill_stream() refreshes ps->last_packet_us on each offer. Query exposes
	# that value, truncated to seconds, as both "last packet" and "last user
	# packet". It is liveness state rather than negotiated media state.
	# Whole-tag comparisons are safe only while no media has flowed: once packets
	# arrive, the per-media SSRC lists also contain traffic-derived statistics.
	# Such tests must compare only the negotiated fields they intend to restore.
	for my $tag (values %{$state->{tags}}) {
		for my $media (@{$tag->{medias}}) {
			for my $stream (@{$media->{streams}}) {
				delete $stream->{'last packet'};
				delete $stream->{'last user packet'};
			}
		}
	}
	return $state->{tags};
}

sub secure_sdp {
	my ($address, $port, $ufrag, $pwd, $key, $direction) = @_;
	return "v=0\r\no=- 2 2 IN IP4 $address\r\ns=rollback-secure\r\n"
		. "c=IN IP4 $address\r\nt=0 0\r\nm=audio $port RTP/SAVP 0\r\n"
		. "a=rtpmap:0 PCMU/8000\r\na=$direction\r\n"
		. "a=ice-ufrag:$ufrag\r\na=ice-pwd:$pwd\r\n"
		. "a=candidate:1 1 UDP 2130706431 $address $port typ host\r\n"
		. "a=candidate:1 2 UDP 2130706430 $address " . ($port + 1) . " typ host\r\n"
		. "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:$key\r\n";
}

sub dtls_sdp {
	my ($address, $port, $fingerprint, $tls_id, $setup) = @_;
	return "v=0\r\no=- 3 3 IN IP4 $address\r\ns=rollback-dtls\r\n"
		. "c=IN IP4 $address\r\nt=0 0\r\nm=audio $port UDP/TLS/RTP/SAVP 0\r\n"
		. "a=rtpmap:0 PCMU/8000\r\na=setup:$setup\r\n"
		. "a=fingerprint:sha-256 $fingerprint\r\na=tls-id:$tls_id\r\n";
}

sub secure_parameters {
	my ($sdp) = @_;
	my @parameters = $sdp =~ /^(a=(?:ice-ufrag|ice-pwd):.*|a=crypto:1 .*)$/mg;
	return \@parameters;
}

my ($rollback_dtls, $rollback_dtls_mux, $rollback_dtls_connected,
	@rollback_dtls_components);
my $rollback_dtls_output = sub {
	my ($component, $data) = @_;
	my ($socket, $port) = @{$rollback_dtls_components[$component]};
	snd($socket, $port, $data);
};

sub mux_input {
	my ($self, $mux, $fh, $input) = @_;
	my $peer = $mux->udp_peer($fh);
	$rollback_dtls->input($fh, $input, $peer);
	for my $component (@$rollback_dtls) {
		return unless $component->{_connected};
	}
	return if $rollback_dtls_connected;
	$rollback_dtls_connected = 1;
	pass('DTLS re-handshake succeeds with restored configuration');
	$mux->endloop();
}

sub consecutive_offer_rollback {
	my ($label) = @_;
	new_call;
	rtpe_req('offer', "$label initial offer", {
		'from-tag' => ft(), flags => ['track-state'],
		sdp => sdp('198.51.100.60', 10000, 0, 'sendrecv'),
	});
	rtpe_req('answer', "$label initial answer", {
		'from-tag' => ft(), 'to-tag' => tt(),
		sdp => sdp('198.51.100.61', 11000, 0, 'sendrecv'),
	});
	my $committed_state = rtpe_req('query', "$label committed state", {});

	my $first = rtpe_req('offer', "$label first pending offer", {
		'from-tag' => ft(), 'to-tag' => tt(),
		sdp => sdp('198.51.100.62', 10020, 8, 'sendonly'),
	});
	my $second = rtpe_req('offer', "$label second pending offer", {
		'from-tag' => ft(), 'to-tag' => tt(),
		sdp => sdp('198.51.100.63', 10030, 8, 'recvonly', 1),
	});
	my $rolled_back = rollback();
	is($rolled_back->{'rolled-back'}, 1, "$label rollback consumes the original snapshot");
	my $restored_state = rtpe_req('query', "$label restored state", {});
	is_deeply(negotiated_tags($restored_state), negotiated_tags($committed_state),
		"$label rollback restores the originally committed state");
}

new_call;
my $resp = rtpe_req('offer', 'tracked initial offer', {
	'from-tag' => ft(), flags => ['track-state'], supports => ['rollback'],
	sdp => sdp('198.51.100.10', 4000, 0, 'sendrecv'),
});
is_deeply($resp->{supported}, ['rollback'], 'rollback capability advertised');

$resp = rtpe_req('answer', 'tracked initial answer', {
	'from-tag' => ft(), 'to-tag' => tt(),
	sdp => sdp('198.51.100.20', 5000, 0, 'sendrecv'),
});
my $committed = rtpe_req('query', 'query committed state', {});

$resp = rtpe_req('offer', 'failed renegotiation', {
	'from-tag' => ft(), 'to-tag' => tt(),
	sdp => sdp('198.51.100.11', 4010, 8, 'sendonly', 1),
});
$resp = rollback();
is($resp->{'rolled-back'}, 1, 'pending checkpoint rolls back');
my $restored = rtpe_req('query', 'query restored state', {});
is_deeply(negotiated_tags($restored), negotiated_tags($committed),
	'query media state restored');
$resp = rollback();
is($resp->{'rolled-back'}, 0, 'repeated rollback is a no-op');

rtpe_req('offer', 'completed renegotiation offer', {
	'from-tag' => ft(), 'to-tag' => tt(),
	sdp => sdp('198.51.100.12', 4020, 8, 'sendrecv'),
});
$resp = rtpe_req('answer', 'completed renegotiation answer', {
	'from-tag' => ft(), 'to-tag' => tt(),
	sdp => sdp('198.51.100.22', 5020, 8, 'sendrecv'),
});
$resp = rollback(2);
is($resp->{'rolled-back'}, 0, 'completed exchange cannot be rolled back');

consecutive_offer_rollback('consecutive offers');

my ($subscription_a, $subscription_b, $subscription_sink) = new_call(
	[qw(198.51.100.80 12000)],
	[qw(198.51.100.80 12010)],
	[qw(198.51.100.80 12020)],
);
my $subscription_offer = rtpe_req('offer', 'subscription rollback initial offer', {
	'from-tag' => ft(), flags => ['track-state'],
	sdp => sdp('198.51.100.80', 12000, 0, 'sendrecv'),
});
my ($subscription_port_a) = $subscription_offer->{sdp} =~ /^m=audio (\d+)/m;
my $subscription_answer = rtpe_req('answer', 'subscription rollback initial answer', {
	'from-tag' => ft(), 'to-tag' => tt(),
	sdp => sdp('198.51.100.80', 12010, 0, 'sendrecv'),
});
my ($subscription_port_b) = $subscription_answer->{sdp} =~ /^m=audio (\d+)/m;
my $subscription = rtpe_req('subscribe request', 'subscription before rollback', {
	'from-tag' => ft(),
});
my ($subscription_port_sink) = $subscription->{sdp} =~ /^m=audio (\d+)/m;
ok($subscription_port_a && $subscription_port_b && $subscription_port_sink,
	'subscription relay ports captured');
rtpe_req('subscribe answer', 'subscription before rollback answer', {
	'from-tag' => $subscription->{'from-tag'},
	'to-tag' => $subscription->{'to-tag'},
	sdp => sdp('198.51.100.80', 12020, 0, 'recvonly'),
});
snd($subscription_a, $subscription_port_b,
	rtp(0, 5000, 8000, 0x7890, "\x55" x 160));
rcv($subscription_b, $subscription_port_a,
	rtpm(0, 5000, 8000, 0x7890, "\x55" x 160));
rcv($subscription_sink, $subscription_port_sink,
	rtpm(0, 5000, 8000, 0x7890, "\x55" x 160));
my $subscription_committed = rtpe_req('query', 'subscription committed state', {});
my $subscription_pending = rtpe_req('offer', 'subscription rejected renegotiation', {
	'from-tag' => ft(), 'to-tag' => tt(),
	sdp => sdp('198.51.100.81', 12030, 8, 'sendonly'),
});
my $subscription_rollback = rollback();
is($subscription_rollback->{'rolled-back'}, 1,
	'subscription call rolls back rejected renegotiation');
my $subscription_restored = rtpe_req('query', 'subscription restored state', {});
# Do not compare the complete query: restoring the committed remote endpoint is
# itself an endpoint change and therefore triggers call_stream_crypto_reset(),
# which intentionally resets the SSRC's ext_seq along with the crypto context.
for my $tag (keys %{$subscription_committed->{tags}}) {
	is_deeply($subscription_restored->{tags}{$tag}{subscriptions},
		$subscription_committed->{tags}{$tag}{subscriptions},
		"rollback preserves subscriptions for $tag");
	is_deeply($subscription_restored->{tags}{$tag}{subscribers},
		$subscription_committed->{tags}{$tag}{subscribers},
		"rollback preserves subscribers for $tag");
}
is_deeply($subscription_restored->{tags}{ft()}{medias}[0]{streams}[0]{endpoint},
	$subscription_committed->{tags}{ft()}{medias}[0]{streams}[0]{endpoint},
	'active subscription resolves to the restored source endpoint');
snd($subscription_a, $subscription_port_b,
	rtp(0, 5001, 8160, 0x7890, "\x66" x 160));
rcv($subscription_b, $subscription_port_a,
	rtpm(0, 5001, 8160, 0x7890, "\x66" x 160));
rcv($subscription_sink, $subscription_port_sink,
	rtpm(0, 5001, 8160, 0x7890, "\x66" x 160));

new_call;
rtpe_req('offer', 'untracked offer', {
	'from-tag' => ft(), sdp => sdp('198.51.100.30', 6000, 0, 'sendrecv'),
});
rtpe_req('answer', 'untracked answer', {
	'from-tag' => ft(), 'to-tag' => tt(),
	sdp => sdp('198.51.100.40', 7000, 0, 'sendrecv'),
});
$resp = rollback();
is($resp->{'rolled-back'}, 0, 'untracked call has no checkpoint');

my ($secure_sock) = new_call([qw(198.51.100.50 8000)]);
my $secure_offer = secure_sdp('198.51.100.50', 8000, 'oldUfrag',
	'oldPassword0123456789012', 'MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw', 'sendrecv');
$resp = rtpe_req('offer', 'tracked ICE and SDES offer', {
	'from-tag' => ft(), 'via-branch' => 'rollback-branch',
	flags => ['track-state'], sdp => $secure_offer,
});
my $secure_parameters = secure_parameters($resp->{sdp});
rtpe_req('answer', 'tracked ICE and SDES answer', {
	'from-tag' => ft(), 'to-tag' => tt(),
	sdp => secure_sdp('198.51.100.51', 9000, 'answerUfrag',
		'answerPassword0123456789', 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo5ODc2', 'sendrecv'),
});
rtpe_req('offer', 'ICE restart and SDES rekey', {
	'from-tag' => ft(), 'to-tag' => tt(), 'via-branch' => 'rollback-branch',
	sdp => secure_sdp('198.51.100.52', 8010, 'newUfrag',
		'newPassword0123456789012', 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIz', 'sendonly'),
});
my $branch_error = rtpe_raw_req({command => 'rollback', 'call-id' => cid(),
	'from-tag' => ft(), 'to-tag' => tt(), 'via-branch' => 'wrong-branch'});
like($branch_error, qr/Unknown dialogue/, 'incorrect via-branch does not select the dialogue');
$resp = rollback(2, 'rollback-branch');
is($resp->{'rolled-back'}, 1, 'ICE restart and SDES rekey roll back');
$resp = rtpe_req('offer', 'replay pre-restart ICE and SDES offer', {
	'from-tag' => ft(), 'to-tag' => tt(), 'via-branch' => 'rollback-branch', sdp => $secure_offer,
});
is_deeply(secure_parameters($resp->{sdp}), $secure_parameters,
	'local ICE credentials and SDES key are restored');
my ($secure_port) = $resp->{sdp} =~ /^m=audio (\d+)/m;
my ($local_ufrag) = $resp->{sdp} =~ /^a=ice-ufrag:(\S+)/m;
my ($local_pwd) = $resp->{sdp} =~ /^a=ice-pwd:(\S+)/m;
my @restored_check = rcv($secure_sock, -1,
	qr/^\x00\x01\x00.\x21\x12\xa4\x42(............)/s);
snd($secure_sock, $secure_port, NGCP::Rtpclient::ICE::stun_succ(
	$secure_port, $restored_check[2], 'oldPassword0123456789012'));
while (1) {
	my $discard = '';
	last unless defined $secure_sock->recv($discard, 65535, MSG_DONTWAIT);
}
my ($stun_packet) = NGCP::Rtpclient::ICE::stun_req(0, 65527, 1,
	'oldUfrag', $local_ufrag, $local_pwd);
snd($secure_sock, $secure_port, $stun_packet);
rcv($secure_sock, -1, qr/^\x01\x01\x00.\x21\x12\xa4\x42/s);
pass('restored ICE credentials authenticate a connectivity check');
rollback(2, 'rollback-branch');

my ($dtls_sock) = new_call([qw(198.51.100.55 9500)]);
$rollback_dtls_mux = IO::Multiplex->new();
$rollback_dtls_mux->set_callback_object(__PACKAGE__);
$rollback_dtls = NGCP::Rtpclient::DTLS::Group->new($rollback_dtls_mux,
	$rollback_dtls_output, [[$dtls_sock]]);
my $original_fingerprint = $rollback_dtls->[0]->fingerprint();
my $original_dtls_offer = dtls_sdp('198.51.100.55', 9500, $original_fingerprint,
	'rollback-original', 'passive');
rtpe_req('offer', 'tracked DTLS offer', {
	'from-tag' => ft(), flags => ['track-state'], SDES => 'off',
	sdp => $original_dtls_offer,
});
my $dtls_answer = rtpe_req('answer', 'tracked DTLS answer', {
	'from-tag' => ft(), 'to-tag' => tt(), SDES => 'off',
	sdp => dtls_sdp('198.51.100.56', 9510, join(':', ('BB') x 32),
		'rollback-answer', 'active'),
});
my ($restored_dtls_port) = $dtls_answer->{sdp} =~ /^m=audio (\d+)/m;
ok($restored_dtls_port, 'committed DTLS relay port captured');
rtpe_req('offer', 'DTLS fingerprint and role change later rejected', {
	'from-tag' => ft(), 'to-tag' => tt(), SDES => 'off',
	sdp => dtls_sdp('198.51.100.55', 9500, join(':', ('AA') x 32),
		'rollback-rejected', 'active'),
});
my $dtls_rollback = rollback(2);
is($dtls_rollback->{'rolled-back'}, 1, 'DTLS configuration rolls back');
$rollback_dtls_mux->add($dtls_sock);
@rollback_dtls_components = ([$dtls_sock, $restored_dtls_port]);
$rollback_dtls->accept();
$rollback_dtls_mux->loop();
rtpe_req('delete', 'delete DTLS rollback call', {
	'from-tag' => ft(), 'to-tag' => tt(),
});

new_call;
my $fork_from = ft();
my $fork_a = 'fork-a-' . tt();
my $fork_b = 'fork-b-' . tt();
rtpe_req('offer', 'fork A initial offer', {
	'from-tag' => $fork_from, 'via-branch' => 'fork-a', flags => ['track-state'],
	sdp => sdp('198.51.100.60', 10000, 0, 'sendrecv'),
});
rtpe_req('answer', 'fork A initial answer', {
	'from-tag' => $fork_from, 'to-tag' => $fork_a, 'via-branch' => 'fork-a',
	sdp => sdp('198.51.100.61', 10010, 0, 'sendrecv'),
});
rtpe_req('offer', 'fork B initial offer', {
	'from-tag' => $fork_from, 'via-branch' => 'fork-b', flags => ['track-state'],
	sdp => sdp('198.51.100.62', 10020, 0, 'sendrecv'),
});
rtpe_req('answer', 'fork B initial answer', {
	'from-tag' => $fork_from, 'to-tag' => $fork_b, 'via-branch' => 'fork-b',
	sdp => sdp('198.51.100.63', 10030, 0, 'sendrecv'),
});
my $fork_a_offer = rtpe_req('offer', 'fork A rejected renegotiation', {
	'from-tag' => $fork_from, 'to-tag' => $fork_a, 'via-branch' => 'fork-a',
	sdp => sdp('198.51.100.64', 10040, 8, 'sendonly'),
});
my $fork_b_offer = rtpe_req('offer', 'fork B rejected renegotiation', {
	'from-tag' => $fork_from, 'to-tag' => $fork_b, 'via-branch' => 'fork-b',
	sdp => sdp('198.51.100.65', 10050, 8, 'recvonly'),
});
my $fork_error = rtpe_raw_req({command => 'rollback', 'call-id' => cid(),
	'from-tag' => $fork_from, 'to-tag' => $fork_b, 'via-branch' => 'fork-a'});
like($fork_error, qr/Unknown dialogue/, 'branch and to-tag must identify the same fork');
my $fork_a_rollback = rtpe_req('rollback', 'rollback fork A', {
	'from-tag' => $fork_from, 'to-tag' => $fork_a, 'via-branch' => 'fork-a',
});
is($fork_a_rollback->{'rolled-back'}, 1, 'fork A rolls back independently');
my $fork_a_repeat = rtpe_req('rollback', 'repeat rollback fork A', {
	'from-tag' => $fork_from, 'to-tag' => $fork_a, 'via-branch' => 'fork-a',
});
is($fork_a_repeat->{'rolled-back'}, 0, 'fork A checkpoint was consumed');
my $fork_committed = rtpe_req('query', 'fork state before second rollback', {});
my $fork_b_rollback = rtpe_req('rollback', 'rollback fork B', {
	'from-tag' => $fork_from, 'to-tag' => $fork_b, 'via-branch' => 'fork-b',
});
is($fork_b_rollback->{'rolled-back'}, 1, 'fork B checkpoint remains pending');
# The caller monologue is shared between branches. Rolling back the second one
# must not reinstate what rolling back the first one undid.
my $fork_after = rtpe_req('query', 'fork state after both rollbacks', {});
is_deeply($fork_after->{tags}{$fork_from}{medias},
	$fork_committed->{tags}{$fork_from}{medias},
	'rolling back the second fork leaves the caller alone');

new_call;
rtpe_req('offer', 'stress initial offer', {
	'from-tag' => ft(), flags => ['track-state'],
	sdp => sdp('198.51.100.70', 11000, 0, 'sendrecv'),
});
rtpe_req('answer', 'stress initial answer', {
	'from-tag' => ft(), 'to-tag' => tt(),
	sdp => sdp('198.51.100.71', 11010, 0, 'sendrecv'),
});
for my $iteration (1 .. 10) {
	rtpe_req('offer', "stress offer $iteration", {
		'from-tag' => ft(), 'to-tag' => tt(),
		sdp => sdp('198.51.100.72', 11020 + $iteration * 2,
			$iteration % 2 ? 8 : 0, $iteration % 2 ? 'sendonly' : 'recvonly'),
	});
	my $rolled_back = rollback();
	is($rolled_back->{'rolled-back'}, 1, "stress rollback $iteration consumes checkpoint");
}
my $pending_delete = rtpe_req('offer', 'leave checkpoint pending for delete', {
	'from-tag' => ft(), 'to-tag' => tt(),
	sdp => sdp('198.51.100.73', 11100, 8, 'sendonly'),
});
rtpe_req('delete', 'delete call after repeated rollbacks', {
	'from-tag' => ft(), 'to-tag' => tt(),
});

my $error = rtpe_raw_req({command => 'rollback', 'call-id' => 'unknown-call',
	'from-tag' => 'from', 'to-tag' => 'to'});
like($error, qr/Unknown call-id/, 'unknown call is an error');
$error = rtpe_raw_req({command => 'rollback', 'call-id' => cid(),
	'from-tag' => 'unknown-tag', 'to-tag' => tt()});
like($error, qr/Unknown dialogue/, 'unknown dialogue is an error');

# --- a merged call must not claim to have rolled back ---
#
# call_merge() renumbers every unique id, and a snapshot is keyed on them, so a
# checkpoint taken before the merge no longer describes anything. It is dropped,
# and rollback says so rather than reporting a success that restored nothing.
new_call;
my $mg_cid = cid();
my $mg_ft = ft();
my $mg_tt = tt();
rtpe_req('offer', 'merge: tracked offer', {
	'from-tag' => $mg_ft, flags => ['track-state'],
	sdp => sdp('198.51.100.120', 17000, 0, 'sendrecv'),
});
rtpe_req('answer', 'merge: answer', {
	'from-tag' => $mg_ft, 'to-tag' => $mg_tt,
	sdp => sdp('198.51.100.121', 17010, 0, 'sendrecv'),
});
rtpe_req('offer', 'merge: rejected offer', {
	'from-tag' => $mg_ft, 'to-tag' => $mg_tt,
	sdp => sdp('198.51.100.122', 17020, 8, 'sendonly'),
});

new_call;
rtpe_req('offer', 'merge: other call offer', {
	'from-tag' => ft(), sdp => sdp('198.51.100.123', 17030, 0, 'sendrecv'),
});
rtpe_req('answer', 'merge: other call answer', {
	'from-tag' => ft(), 'to-tag' => tt(),
	sdp => sdp('198.51.100.124', 17040, 0, 'sendrecv'),
});

# the first call listed survives, so the tracked one is the side being renumbered
rtpe_req('mesh', 'merge the two calls', {
	flags => [],
	calls => [cid(), $mg_cid],
	tags => [
		{ from => $mg_ft, to => [$mg_tt] },
		{ from => $mg_tt, to => [$mg_ft] },
	],
});
my $mg_resp = rtpe_raw_req({command => 'rollback', 'call-id' => $mg_cid,
	'from-tag' => $mg_ft, 'to-tag' => $mg_tt});
ok(ref($mg_resp) ne 'HASH' || !$mg_resp->{'rolled-back'},
	'a merged call does not report a rollback it did not perform');

# --- both sides of a dialogue are checkpointed together ---
#
# A monologue is shared between forked branches, so one side can already hold a
# checkpoint while the other has never been tracked. Both are taken together, or
# a rollback restores half a dialogue and still reports success.
new_call;
my $sym_from = ft();
my $sym_a = 'sym-a-' . tt();
my $sym_b = 'sym-b-' . tt();
rtpe_req('offer', 'symmetry: branch A tracked offer', {
	'from-tag' => $sym_from, 'via-branch' => 'sym-a', flags => ['track-state'],
	sdp => sdp('198.51.100.130', 18000, 0, 'sendrecv'),
});
rtpe_req('answer', 'symmetry: branch A answer', {
	'from-tag' => $sym_from, 'to-tag' => $sym_a, 'via-branch' => 'sym-a',
	sdp => sdp('198.51.100.131', 18010, 0, 'sendrecv'),
});
# branch B never asks for tracking, but shares the caller monologue with A
rtpe_req('offer', 'symmetry: branch B untracked offer', {
	'from-tag' => $sym_from, 'via-branch' => 'sym-b',
	sdp => sdp('198.51.100.132', 18020, 0, 'sendrecv'),
});
rtpe_req('answer', 'symmetry: branch B answer', {
	'from-tag' => $sym_from, 'to-tag' => $sym_b, 'via-branch' => 'sym-b',
	sdp => sdp('198.51.100.133', 18030, 0, 'sendrecv'),
});
my $sym_committed = rtpe_req('query', 'symmetry: committed state', {});
rtpe_req('offer', 'symmetry: branch B rejected offer', {
	'from-tag' => $sym_from, 'to-tag' => $sym_b, 'via-branch' => 'sym-b',
	sdp => sdp('198.51.100.134', 18040, 8, 'sendonly'),
});
my $sym_rollback = rtpe_req('rollback', 'symmetry: rollback branch B', {
	'from-tag' => $sym_from, 'to-tag' => $sym_b, 'via-branch' => 'sym-b',
});
my $sym_restored = rtpe_req('query', 'symmetry: restored state', {});
is_deeply($sym_restored->{tags}{$sym_b}{medias},
	$sym_committed->{tags}{$sym_b}{medias},
	'the far side is restored, not just the shared caller');

done_testing;
