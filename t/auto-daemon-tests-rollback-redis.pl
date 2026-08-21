#!/usr/bin/perl

use strict;
use warnings;
use Bencode;
use JSON;
use NGCP::Rtpengine::AutoTest;
use Socket qw(AF_INET SOCK_STREAM sockaddr_in inet_aton);
use Test::More;

my $redis_format = $ENV{RTPE_REDIS_FORMAT} // 'json';

# Fake Redis listener. Keep the last SET payload in this process and return it
# to the next daemon instance through KEYS/GET, modelling a takeover without an
# external redis-server dependency.
my $redis_listener;
socket($redis_listener, AF_INET, SOCK_STREAM, 0) or die;
bind($redis_listener, sockaddr_in(6379, inet_aton('203.0.113.42'))) or die;
listen($redis_listener, 10) or die;

my ($redis_fd, $saved_call_id, $saved_record);
my $launches = 0;

sub redis_read_exact {
	my ($fd, $len) = @_;
	my $buf = '';
	while (length($buf) < $len) {
		my $part;
		recv($fd, $part, $len - length($buf), 0) or die;
		$buf .= $part;
	}
	return $buf;
}

sub redis_read_line {
	my ($fd) = @_;
	my $buf = '';
	while ($buf !~ /\r\n\z/) {
		$buf .= redis_read_exact($fd, 1);
	}
	$buf =~ s/\r\n\z//;
	return $buf;
}

sub redis_command {
	my ($fd) = @_;
	my $intro = redis_read_line($fd);
	$intro =~ /^\*(\d+)\z/ or die "invalid Redis array: $intro";
	my @args;
	for (1 .. $1) {
		my $bulk = redis_read_line($fd);
		$bulk =~ /^\$(\d+)\z/ or die "invalid Redis bulk string: $bulk";
		push @args, redis_read_exact($fd, $1);
		redis_read_exact($fd, 2) eq "\r\n" or die "invalid Redis bulk terminator";
	}
	return @args;
}

sub redis_reply_simple {
	my ($fd, $reply) = @_;
	send($fd, "+$reply\r\n", 0) or die;
}

sub redis_reply_bulk {
	my ($fd, $value) = @_;
	send($fd, '$' . length($value) . "\r\n$value\r\n", 0) or die;
}

sub redis_preamble {
	my ($name) = @_;
	my $fd;
	accept($fd, $redis_listener) or die;

	is_deeply([redis_command($fd)], ['PING'], "$name PING");
	redis_reply_simple($fd, 'PONG');
	is_deeply([redis_command($fd)], ['SELECT', '15'], "$name SELECT");
	redis_reply_simple($fd, 'OK');
	is_deeply([redis_command($fd)], ['INFO'], "$name INFO");
	redis_reply_bulk($fd, "role:master\r\n");
	is_deeply([redis_command($fd)], ['TYPE', 'calls'], "$name TYPE");
	redis_reply_simple($fd, 'none');

	return $fd;
}

$NGCP::Rtpengine::AutoTest::launch_cb = sub {
	$launches++;
	$redis_fd = redis_preamble("launch $launches");

	is_deeply([redis_command($redis_fd)], ['PING'], "launch $launches restore PING");
	redis_reply_simple($redis_fd, 'PONG');
	is_deeply([redis_command($redis_fd)], ['KEYS', '*'], "launch $launches restore KEYS");

	if (!defined $saved_record) {
		send($redis_fd, "*0\r\n", 0) or die;
		return;
	}

	send($redis_fd, "*1\r\n\$" . length($saved_call_id)
		. "\r\n$saved_call_id\r\n", 0) or die;

	my $restore_fd = redis_preamble("launch $launches restore worker");
	is_deeply([redis_command($restore_fd)], ['GET', $saved_call_id],
		"launch $launches restore GET");
	redis_reply_bulk($restore_fd, $saved_record);
};

my ($expected_generation, $expected_pending_generation, $expected_pending);

sub decode_record {
	my ($record) = @_;
	return $redis_format eq 'json' ? decode_json($record) : Bencode::bdecode($record, 1);
}

sub encode_record {
	my ($record) = @_;
	return encode_json($record) if $redis_format eq 'json';
	my $as_strings;
	$as_strings = sub {
		my ($value) = @_;
		return { map { $_ => $as_strings->($value->{$_}) } keys %$value }
			if ref($value) eq 'HASH';
		return [ map { $as_strings->($_) } @$value ] if ref($value) eq 'ARRAY';
		my $copy = $value;
		return \$copy;
	};
	return Bencode::bencode($as_strings->($record));
}

sub checkpoint_with_invalid_generation_type {
	my ($record) = @_;
	my $decoded = decode_record($record);
	my $checkpoint_data = $decoded->{json}{'checkpoint-data'};
	$checkpoint_data =~ s/%([0-9a-fA-F]{2})/chr(hex($1))/ge
		if $redis_format eq 'json';
	my $checkpoint = decode_json($checkpoint_data);
	$checkpoint->{checkpoints}[0]{generation} = 'banana';
	$checkpoint_data = encode_json($checkpoint);
	$checkpoint_data =~ s/([^A-Za-z0-9_.~-])/sprintf('%%%02X', ord($1))/ge
		if $redis_format eq 'json';
	$decoded->{json}{'checkpoint-data'} = $checkpoint_data;
	return encode_record($decoded);
}

sub inspect_checkpoint {
	my ($record) = @_;
	my $decoded = decode_record($record);
	my $checkpoint_data = $decoded->{json}{'checkpoint-data'};
	ok(defined $checkpoint_data, "$redis_format record contains checkpoint-data");
	$checkpoint_data =~ s/%([0-9a-fA-F]{2})/chr(hex($1))/ge
		if $redis_format eq 'json';

	my $checkpoint = decode_json($checkpoint_data);
	is($checkpoint->{version}, 1, "$redis_format checkpoint payload version");
	is(scalar @{$checkpoint->{checkpoints}}, 1,
		"$redis_format record contains one dialogue checkpoint");
	my $dialogue = $checkpoint->{checkpoints}[0];
	is($dialogue->{generation}, $expected_generation,
		"$redis_format committed generation serialized");
	is($dialogue->{'pending-generation'}, $expected_pending_generation,
		"$redis_format pending generation serialized");
	is($dialogue->{pending} ? 1 : 0, $expected_pending,
		"$redis_format pending state serialized");
}

sub expect_redis_update {
	my ($generation, $pending_generation, $pending) = @_;
	($expected_generation, $expected_pending_generation, $expected_pending)
		= ($generation, $pending_generation, $pending);

	$NGCP::Rtpengine::req_cb = sub {
		is_deeply([redis_command($redis_fd)], ['PING'], "$redis_format update PING");
		redis_reply_simple($redis_fd, 'PONG');

		my @set = redis_command($redis_fd);
		is($set[0], 'SET', "$redis_format update uses SET");
		is($set[3], 'EX', "$redis_format update carries expiry");
		like($set[4], qr/^\d+\z/, "$redis_format update expiry is numeric");
		($saved_call_id, $saved_record) = @set[1, 2];
		inspect_checkpoint($saved_record);
		redis_reply_simple($redis_fd, 'OK');
	};
}

sub expect_redis_update_without_checkpoint {
	$NGCP::Rtpengine::req_cb = sub {
		is_deeply([redis_command($redis_fd)], ['PING'],
			"$redis_format invalid-checkpoint update PING");
		redis_reply_simple($redis_fd, 'PONG');
		my @set = redis_command($redis_fd);
		is($set[0], 'SET', "$redis_format invalid-checkpoint update uses SET");
		is($set[3], 'EX', "$redis_format invalid-checkpoint update carries expiry");
		my $decoded = decode_record($set[2]);
		ok(!exists $decoded->{json}{'checkpoint-data'},
			"$redis_format invalid checkpoint is omitted from the restored call record");
		redis_reply_simple($redis_fd, 'OK');
	};
}

sub redis_rtpe_req {
	my ($generation, $pending_generation, $pending, @request) = @_;
	expect_redis_update($generation, $pending_generation, $pending);
	my $response = rtpe_req(@request);
	$NGCP::Rtpengine::req_cb = undef;
	return $response;
}

sub sdp {
	my ($address, $port, $ufrag, $pwd, $key, $direction) = @_;
	return "v=0\r\no=- 2 2 IN IP4 $address\r\ns=rollback-redis-secure\r\n"
		. "c=IN IP4 $address\r\nt=0 0\r\nm=audio $port RTP/SAVP 0\r\n"
		. "a=rtpmap:0 PCMU/8000\r\na=$direction\r\n"
		. "a=ice-ufrag:$ufrag\r\na=ice-pwd:$pwd\r\n"
		. "a=candidate:1 1 UDP 2130706431 $address $port typ host\r\n"
		. "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:$key\r\n";
}

sub secure_parameters {
	my ($body) = @_;
	my @parameters = $body =~ /^(a=(?:ice-ufrag|ice-pwd):.*|a=crypto:1 .*)$/mg;
	return \@parameters;
}

my @daemon_args = (qw(--config-file=none -t -1 -i foo/203.0.113.1
	-n 2233 -c 12346 -f -L 7 -E --redis-num-threads=1),
	"--redis=203.0.113.42:6379/15", "--redis-format=$redis_format");
$NGCP::Rtpengine::AutoTest::port = 2233;
autotest_start(@daemon_args) or die;

new_call;
my ($call_id, $from_tag, $to_tag) = (cid(), ft(), tt());
my $via_branch = 'rollback-redis-branch';
my $response = redis_rtpe_req(0, 1, 1, 'offer', 'tracked Redis offer', {
	'from-tag' => $from_tag, 'via-branch' => $via_branch, flags => ['track-state'],
	sdp => sdp('198.51.100.80', 12000, 'oldRedisUfrag',
		'oldRedisPassword012345678', 'MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw', 'sendrecv'),
});
my $secure_parameters = secure_parameters($response->{sdp});
is($response->{generation}, 1, 'initial Redis generation opened');

redis_rtpe_req(1, 0, 0, 'answer', 'tracked Redis answer', {
	'from-tag' => $from_tag, 'to-tag' => $to_tag, 'via-branch' => $via_branch,
	sdp => sdp('198.51.100.81', 12010, 'answerRedisUfrag',
		'answerRedisPassword012345', 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo5ODc2', 'sendrecv'),
});
$response = redis_rtpe_req(1, 2, 1, 'offer', 'offer later rejected by the far end', {
	'from-tag' => $from_tag, 'to-tag' => $to_tag, 'via-branch' => $via_branch,
	sdp => sdp('198.51.100.82', 12020, 'newRedisUfrag',
		'newRedisPassword012345678', 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIz', 'sendonly'),
});
is($response->{generation}, 2, 'pending Redis generation stored');
my $pending_record = $saved_record;

NGCP::Rtpengine::AutoTest::shut_rtpe();
$NGCP::Rtpengine::req_cb = undef;
autotest_start(@daemon_args) or die;

$response = redis_rtpe_req(1, 0, 0, 'rollback', 'rollback after Redis takeover', {
	'call-id' => $call_id, 'from-tag' => $from_tag, 'to-tag' => $to_tag,
	'via-branch' => $via_branch, generation => 2,
});
is($response->{'rolled-back'}, 1, 'pending checkpoint survives Redis takeover');
is($response->{generation}, 1, 'committed generation survives Redis takeover');

my $query = rtpe_req('query', 'query rolled-back Redis call', {'call-id' => $call_id});
ok($query->{tags}{$from_tag}{medias}[0]{streams}[0]{'local port'},
	'selected media socket survives takeover rollback');
is($query->{tags}{$from_tag}{medias}[0]{streams}[0]{endpoint}{address}, '198.51.100.80',
	'remote media endpoint survives takeover rollback');

$response = redis_rtpe_req(1, 2, 1, 'offer', 'verify restored Redis media state', {
	'call-id' => $call_id, 'from-tag' => $from_tag, 'to-tag' => $to_tag,
	'via-branch' => $via_branch,
	sdp => sdp('198.51.100.80', 12000, 'oldRedisUfrag',
		'oldRedisPassword012345678', 'MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw', 'sendrecv'),
});
is($response->{generation}, 2, 'tracking remains enabled after takeover rollback');
is_deeply(secure_parameters($response->{sdp}), $secure_parameters,
	'ICE credentials and committed SDES key survive takeover rollback');

redis_rtpe_req(2, 0, 0, 'answer', 'commit exchange after takeover rollback', {
	'call-id' => $call_id, 'from-tag' => $from_tag, 'to-tag' => $to_tag,
	'via-branch' => $via_branch,
	sdp => sdp('198.51.100.81', 12010, 'answerRedisUfrag',
		'answerRedisPassword012345', 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo5ODc2', 'sendrecv'),
});

NGCP::Rtpengine::AutoTest::shut_rtpe();
$NGCP::Rtpengine::req_cb = undef;
autotest_start(@daemon_args) or die;
$response = redis_rtpe_req(2, 0, 0, 'rollback', 'rollback after committed state crosses Redis', {
	'call-id' => $call_id, 'from-tag' => $from_tag, 'to-tag' => $to_tag,
	'via-branch' => $via_branch, generation => 3,
});
is($response->{'rolled-back'}, 0, 'committed checkpoint remains consumed in Redis');
is($response->{generation}, 2, 'new committed generation persists in Redis');

NGCP::Rtpengine::AutoTest::shut_rtpe();
$NGCP::Rtpengine::req_cb = undef;
$saved_record = checkpoint_with_invalid_generation_type($pending_record);
autotest_start(@daemon_args) or die;
$query = rtpe_req('query', 'query call restored without invalid checkpoint', {
	'call-id' => $call_id,
});
ok($query->{tags}{$from_tag}, 'invalid checkpoint data does not discard the restored call');
expect_redis_update_without_checkpoint();
$response = rtpe_req('rollback', 'invalid checkpoint degrades to no rollback state', {
	'call-id' => $call_id, 'from-tag' => $from_tag, 'to-tag' => $to_tag,
	'via-branch' => $via_branch, generation => 2,
});
$NGCP::Rtpengine::req_cb = undef;
is($response->{'rolled-back'}, 0, 'type-invalid checkpoint is discarded atomically');

NGCP::Rtpengine::AutoTest::shut_rtpe();
done_testing;
