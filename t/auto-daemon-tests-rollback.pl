#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use NGCP::Rtpclient::ICE;
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
	my ($generation, $via_branch) = @_;
	my %req = ('call-id' => cid(), 'from-tag' => ft(), 'to-tag' => tt());
	$req{generation} = $generation if defined $generation;
	$req{'via-branch'} = $via_branch if defined $via_branch;
	return rtpe_req('rollback', 'rollback state', \%req);
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

sub secure_parameters {
	my ($sdp) = @_;
	my @parameters = $sdp =~ /^(a=(?:ice-ufrag|ice-pwd):.*|a=crypto:1 .*)$/mg;
	return \@parameters;
}

sub consecutive_offer_rollback {
	my ($use_generation, $label) = @_;
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
	is($first->{generation}, 2, "$label first offer opens generation 2");
	my $second = rtpe_req('offer', "$label second pending offer", {
		'from-tag' => ft(), 'to-tag' => tt(),
		sdp => sdp('198.51.100.63', 10030, 8, 'recvonly', 1),
	});
	is($second->{generation}, $first->{generation},
		"$label second offer preserves the pending generation");

	my $rolled_back = rollback($use_generation ? $first->{generation} : undef);
	is($rolled_back->{'rolled-back'}, 1, "$label rollback consumes the original snapshot");
	my $restored_state = rtpe_req('query', "$label restored state", {});
	is_deeply($restored_state->{tags}, $committed_state->{tags},
		"$label rollback restores the originally committed state");
}

new_call;
my $resp = rtpe_req('offer', 'tracked initial offer', {
	'from-tag' => ft(), flags => ['track-state'], supports => ['rollback'],
	sdp => sdp('198.51.100.10', 4000, 0, 'sendrecv'),
});
is($resp->{generation}, 1, 'initial offer opens generation 1');
is_deeply($resp->{supported}, ['rollback'], 'rollback capability advertised');

$resp = rtpe_req('answer', 'tracked initial answer', {
	'from-tag' => ft(), 'to-tag' => tt(),
	sdp => sdp('198.51.100.20', 5000, 0, 'sendrecv'),
});
is($resp->{generation}, 1, 'initial answer commits generation 1');
my $committed = rtpe_req('query', 'query committed state', {});

$resp = rtpe_req('offer', 'failed renegotiation', {
	'from-tag' => ft(), 'to-tag' => tt(),
	sdp => sdp('198.51.100.11', 4010, 8, 'sendonly', 1),
});
is($resp->{generation}, 2, 'renegotiation opens generation 2');
$resp = rollback(99);
is($resp->{'rolled-back'}, 0, 'generation mismatch is a no-op');
is($resp->{generation}, 1, 'generation mismatch returns the committed generation');
$resp = rollback(2);
is($resp->{'rolled-back'}, 1, 'matching generation rolls back');
is($resp->{generation}, 1, 'rollback returns committed generation');
my $restored = rtpe_req('query', 'query restored state', {});
is_deeply($restored->{tags}, $committed->{tags}, 'query media state restored');
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
is($resp->{generation}, 2, 'completed renegotiation commits generation 2');
$resp = rollback(2);
is($resp->{'rolled-back'}, 0, 'completed exchange cannot be rolled back');

consecutive_offer_rollback(0, 'consecutive offers without generation');
consecutive_offer_rollback(1, 'consecutive offers with first generation');

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
is($fork_a_offer->{generation}, 2, 'fork A has its own pending generation');
is($fork_b_offer->{generation}, 2, 'fork B has its own pending generation');
my $fork_error = rtpe_raw_req({command => 'rollback', 'call-id' => cid(),
	'from-tag' => $fork_from, 'to-tag' => $fork_b, 'via-branch' => 'fork-a'});
like($fork_error, qr/Unknown dialogue/, 'branch and to-tag must identify the same fork');
my $fork_a_rollback = rtpe_req('rollback', 'rollback fork A', {
	'from-tag' => $fork_from, 'to-tag' => $fork_a, 'via-branch' => 'fork-a', generation => 2,
});
is($fork_a_rollback->{'rolled-back'}, 1, 'fork A rolls back independently');
my $fork_a_repeat = rtpe_req('rollback', 'repeat rollback fork A', {
	'from-tag' => $fork_from, 'to-tag' => $fork_a, 'via-branch' => 'fork-a', generation => 2,
});
is($fork_a_repeat->{'rolled-back'}, 0, 'fork A checkpoint was consumed');
my $fork_b_rollback = rtpe_req('rollback', 'rollback fork B', {
	'from-tag' => $fork_from, 'to-tag' => $fork_b, 'via-branch' => 'fork-b', generation => 2,
});
is($fork_b_rollback->{'rolled-back'}, 1, 'fork B checkpoint remains pending');

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
	my $generation = rtpe_req('offer', "stress offer $iteration", {
		'from-tag' => ft(), 'to-tag' => tt(),
		sdp => sdp('198.51.100.72', 11020 + $iteration * 2,
			$iteration % 2 ? 8 : 0, $iteration % 2 ? 'sendonly' : 'recvonly'),
	});
	my $rolled_back = rollback($generation->{generation});
	is($rolled_back->{'rolled-back'}, 1, "stress rollback $iteration consumes checkpoint");
}
rtpe_req('delete', 'delete call after repeated rollbacks', {
	'from-tag' => ft(), 'to-tag' => tt(),
});

my $error = rtpe_raw_req({command => 'rollback', 'call-id' => 'unknown-call',
	'from-tag' => 'from', 'to-tag' => 'to'});
like($error, qr/Unknown call-id/, 'unknown call is an error');
$error = rtpe_raw_req({command => 'rollback', 'call-id' => cid(),
	'from-tag' => 'unknown-tag', 'to-tag' => tt()});
like($error, qr/Unknown dialogue/, 'unknown dialogue is an error');

done_testing;
