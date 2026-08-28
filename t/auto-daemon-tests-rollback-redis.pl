#!/usr/bin/perl

use strict;
use warnings;
use Bencode;
use JSON;
use NGCP::Rtpengine::AutoTest;
use File::Temp ();
use IO::Select;
use POSIX ();
use Socket qw(AF_INET SOCK_STREAM sockaddr_in inet_aton);
use Test::More;

my $redis_format = $ENV{RTPE_REDIS_FORMAT} // 'json';

# Fake Redis server, run in a forked child.
#
# The daemon writes to Redis from the poller thread as well as after a signalling
# request, so a test servicing it only between requests eventually leaves a write
# unanswered, which blocks the daemon in redis_consume(). A separate process
# always answers; the parent reads what was stored through the files below.
#
#   $state/seq       number of SETs the child has serviced
#   $state/last      value of the most recent SET
#   $state/override  if present, served in place of the next GET, then removed

my $redis_listener;
socket($redis_listener, AF_INET, SOCK_STREAM, 0) or die;
bind($redis_listener, sockaddr_in(6379, inet_aton('203.0.113.42'))) or die;
listen($redis_listener, 10) or die;

my $state = File::Temp::tempdir("rollback-redis-XXXXXX", TMPDIR => 1, CLEANUP => 1);
write_file("$state/seq", "0");

sub write_file {
	my ($path, $content) = @_;
	open(my $fh, '>', "$path.tmp") or die "$path: $!";
	binmode($fh);
	print $fh $content;
	close($fh) or die;
	rename("$path.tmp", $path) or die "$path: $!";
}

sub read_file {
	my ($path) = @_;
	open(my $fh, '<', $path) or return undef;
	binmode($fh);
	local $/;
	my $content = <$fh>;
	close($fh);
	return $content;
}

sub server_read_exact {
	my ($fd, $len) = @_;
	my $buf = '';
	while (length($buf) < $len) {
		my $part;
		defined(recv($fd, $part, $len - length($buf), 0)) or return undef;
		length($part) or return undef;
		$buf .= $part;
	}
	return $buf;
}

sub server_read_line {
	my ($fd) = @_;
	my $buf = '';
	while ($buf !~ /\r\n\z/) {
		my $byte = server_read_exact($fd, 1);
		defined($byte) or return undef;
		$buf .= $byte;
	}
	$buf =~ s/\r\n\z//;
	return $buf;
}

sub server_read_command {
	my ($fd) = @_;
	my $intro = server_read_line($fd);
	defined($intro) && $intro =~ /^\*(\d+)\z/ or return undef;
	my @args;
	for (1 .. $1) {
		my $bulk = server_read_line($fd);
		defined($bulk) && $bulk =~ /^\$(\d+)\z/ or return undef;
		my $arg = server_read_exact($fd, $1);
		defined($arg) or return undef;
		server_read_exact($fd, 2);
		push @args, $arg;
	}
	return \@args;
}

# Answer every command the daemon can send, so it is never left waiting.
sub redis_server {
	my %store;
	my $sets = 0;
	my $select = IO::Select->new($redis_listener);

	while (1) {
		for my $fh ($select->can_read(1)) {
			if ($fh == $redis_listener) {
				my $client;
				accept($client, $redis_listener) or next;
				$select->add($client);
				next;
			}
			my $command = server_read_command($fh);
			if (!$command) {
				$select->remove($fh);
				close($fh);
				next;
			}
			my $verb = uc($command->[0]);
			if ($verb eq 'PING') {
				send($fh, "+PONG\r\n", 0);
			}
			elsif ($verb eq 'INFO') {
				my $info = "role:master\r\n";
				send($fh, '$' . length($info) . "\r\n$info\r\n", 0);
			}
			elsif ($verb eq 'TYPE') {
				send($fh, "+none\r\n", 0);
			}
			elsif ($verb eq 'KEYS') {
				my @keys = keys %store;
				my $reply = '*' . scalar(@keys) . "\r\n";
				$reply .= '$' . length($_) . "\r\n$_\r\n" for @keys;
				send($fh, $reply, 0);
			}
			elsif ($verb eq 'GET') {
				my $value = read_file("$state/override");
				if (defined $value) {
					unlink("$state/override");
				}
				else {
					$value = $store{$command->[1]};
				}
				if (defined $value) {
					send($fh, '$' . length($value) . "\r\n$value\r\n", 0);
				}
				else {
					send($fh, "\$-1\r\n", 0);
				}
			}
			elsif ($verb eq 'SET') {
				$store{$command->[1]} = $command->[2];
				write_file("$state/last", $command->[2]);
				write_file("$state/seq", ++$sets);
				send($fh, "+OK\r\n", 0);
			}
			elsif ($verb eq 'DEL') {
				delete $store{$command->[1]};
				send($fh, ":1\r\n", 0);
			}
			else {
				send($fh, "+OK\r\n", 0);
			}
		}
	}
}

my $redis_pid = fork();
defined($redis_pid) or die "cannot fork Redis server";
if (!$redis_pid) {
	$SIG{TERM} = sub { POSIX::_exit(0) };
	redis_server();
	POSIX::_exit(0);
}
# The listener stays open here: under the preload's fake network, closing it in
# the parent removes the socket the child is accepting on.
END { kill('TERM', $redis_pid) if $redis_pid }

sub redis_sets_seen {
	return int(read_file("$state/seq") // 0);
}

# The daemon writes to Redis before it answers, so the record is normally there
# already; poll briefly to cover the child not having flushed it yet.
sub redis_record_after {
	my ($before) = @_;
	for (1 .. 500) {
		return read_file("$state/last") if redis_sets_seen() > $before;
		select(undef, undef, undef, 0.01);
	}
	die 'no Redis update seen after the daemon answered';
}

sub serve_next_get {
	my ($record) = @_;
	write_file("$state/override", $record);
}

my ($expected_pending, $last_record);

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

# Record values are escaped by the encoder; JSON records carry them percent
# encoded, native (bencode) records do not.
sub field {
	my ($value) = @_;
	return undef if !defined $value;
	$value =~ s/%([0-9a-fA-F]{2})/chr(hex($1))/ge if $redis_format eq 'json';
	return $value;
}

# A field that is not a number must disable rollback for the call without
# discarding the call itself.
sub checkpoint_with_invalid_field_type {
	my ($record) = @_;
	my $decoded = decode_record($record);
	$decoded->{'checkpoint-0'}{pending} = 'banana';
	return encode_record($decoded);
}

sub inspect_checkpoint {
	my ($record) = @_;
	my $decoded = decode_record($record);
	my $checkpoint = $decoded->{'checkpoint-0'};
	ok(defined $checkpoint, "$redis_format record contains a checkpoint");
	is(field($decoded->{json}{num_checkpoints}), 1,
		"$redis_format record contains one dialogue checkpoint");
	is(field($checkpoint->{pending}) ? 1 : 0, $expected_pending,
		"$redis_format pending state serialized");
	# The snapshot is a nested call record, so it is checked for presence rather
	# than shape: what it must contain is asserted by restoring from it.
	ok(!$expected_pending || length(field($checkpoint->{snapshot}) // ''),
		"$redis_format pending checkpoint carries a snapshot");
	# A snapshot never leaves the daemon, so it is bencode whatever the record is.
	ok(!$expected_pending || (field($checkpoint->{snapshot}) // '') =~ /^d/,
		"$redis_format snapshot is bencode");
}

# What rollback restored, judged against the record rather than against `query`.
#
# query exposes only a subset of a media's state, so a rollback can stop restoring
# the rest with every existing assertion still green -- which happened. The record
# carries all of it: the committed state must serialise the same before and after.
sub durable_state {
	my ($record) = @_;
	return durable_fields(decode_record($record));
}

# A snapshot is a call record too, so it is filtered the same way. It is always
# bencode, whatever the record around it is.
sub checkpoint_snapshot {
	my ($record) = @_;
	my $checkpoint = decode_record($record)->{'checkpoint-0'} or return undef;
	my $snapshot = field($checkpoint->{snapshot}) or return undef;
	return durable_fields(Bencode::bdecode($snapshot, 1));
}

sub durable_fields {
	my ($decoded) = @_;
	my %out;
	for my $key (keys %$decoded) {
		# Checkpoint entries describe the pending exchange, not the committed
		# state, and are expected to differ.
		next if $key =~ /^checkpoint/;
		# Sockets and endpoint maps are a per-call pool. A rejected offer can add
		# to it, and rollback repoints the media rather than freeing what was
		# allocated, exactly as the feature has always behaved. What must match is
		# the dialogue's own state, not the size of the pool behind it.
		next if $key =~ /^(?:sfd|map|map_sfds|maps)-\d+$/;
		if ($key eq 'json') {
			my %call = %{$decoded->{$key}};
			# Wall-clock and bookkeeping that moves on its own.
			delete @call{qw(created created_us created_ts last_signal deleted
				ml_deleted last_redis_update num_checkpoints num_sfds num_maps)};
			$out{$key} = \%call;
			next;
		}
		$out{$key} = $decoded->{$key};
	}
	return \%out;
}

sub redis_rtpe_req {
	my ($pending, @request) = @_;
	my $before = redis_sets_seen();
	my $response = rtpe_req(@request);
	$last_record = redis_record_after($before);
	$expected_pending = $pending;
	inspect_checkpoint($last_record);
	return $response;
}

sub assert_record_without_checkpoint {
	my ($record) = @_;
	my $decoded = decode_record($record);
	is(field($decoded->{json}{num_checkpoints}) // 0, 0,
		"$redis_format invalid checkpoint is omitted from the restored call record");
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

# Plain RTP, and the same media upgraded to DTLS-SRTP. Used to check that a
# rollback removes state the rejected offer introduced, rather than only
# overwriting state that existed in both.
sub plain_sdp {
	my ($address, $port) = @_;
	return "v=0\r\no=- 4 4 IN IP4 $address\r\ns=rollback-upgrade\r\n"
		. "c=IN IP4 $address\r\nt=0 0\r\nm=audio $port RTP/AVP 0\r\n"
		. "a=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n";
}

sub dtls_upgrade_sdp {
	my ($address, $port) = @_;
	return "v=0\r\no=- 4 5 IN IP4 $address\r\ns=rollback-upgrade\r\n"
		. "c=IN IP4 $address\r\nt=0 0\r\nm=audio $port UDP/TLS/RTP/SAVP 0\r\n"
		. "a=rtpmap:0 PCMU/8000\r\na=sendrecv\r\na=setup:actpass\r\n"
		. "a=fingerprint:sha-256 " . join(':', ('AB') x 32) . "\r\n"
		. "a=tls-id:upgradetlsid0123456789abcdef\r\n"
		# ICE too, so the rollback has candidates to remove as well as DTLS state.
		. "a=ice-ufrag:upgradeUfrag\r\na=ice-pwd:upgradePassword01234567\r\n"
		. "a=candidate:1 1 UDP 2130706431 $address $port typ host\r\n";
}

sub secure_parameters {
	my ($body) = @_;
	my @parameters = $body =~ /^(a=(?:ice-ufrag|ice-pwd):.*|a=crypto:1 .*)$/mg;
	return \@parameters;
}

# A second interface so a rejected offer can move the media somewhere else.
my @daemon_args = (qw(--config-file=none -t -1 -i foo/203.0.113.1 -i bar/203.0.113.2
	-n 2233 -c 12346 -f -L 7 -E --redis-num-threads=1),
	"--redis=203.0.113.42:6379/15", "--redis-format=$redis_format");
$NGCP::Rtpengine::AutoTest::port = 2233;
autotest_start(@daemon_args) or die;

new_call;
my ($call_id, $from_tag, $to_tag) = (cid(), ft(), tt());
my $via_branch = 'rollback-redis-branch';
my $response = redis_rtpe_req(1, 'offer', 'tracked Redis offer', {
	'from-tag' => $from_tag, 'via-branch' => $via_branch, flags => ['track-state'],
	sdp => sdp('198.51.100.80', 12000, 'oldRedisUfrag',
		'oldRedisPassword012345678', 'MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw', 'sendrecv'),
});
my $secure_parameters = secure_parameters($response->{sdp});

redis_rtpe_req(0, 'answer', 'tracked Redis answer', {
	'from-tag' => $from_tag, 'to-tag' => $to_tag, 'via-branch' => $via_branch,
	sdp => sdp('198.51.100.81', 12010, 'answerRedisUfrag',
		'answerRedisPassword012345', 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo5ODc2', 'sendrecv'),
});
$response = redis_rtpe_req(1, 'offer', 'offer later rejected by the far end', {
	'from-tag' => $from_tag, 'to-tag' => $to_tag, 'via-branch' => $via_branch,
	sdp => sdp('198.51.100.82', 12020, 'newRedisUfrag',
		'newRedisPassword012345678', 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIz', 'sendonly'),
});
my $pending_record = $last_record;

NGCP::Rtpengine::AutoTest::shut_rtpe();
autotest_start(@daemon_args) or die;

$response = redis_rtpe_req(0, 'rollback', 'rollback after Redis takeover', {
	'call-id' => $call_id, 'from-tag' => $from_tag, 'to-tag' => $to_tag,
	'via-branch' => $via_branch,
});
is($response->{'rolled-back'}, 1, 'pending checkpoint survives Redis takeover');

my $query = rtpe_req('query', 'query rolled-back Redis call', {'call-id' => $call_id});
ok($query->{tags}{$from_tag}{medias}[0]{streams}[0]{'local port'},
	'selected media socket survives takeover rollback');
is($query->{tags}{$from_tag}{medias}[0]{streams}[0]{endpoint}{address}, '198.51.100.80',
	'remote media endpoint survives takeover rollback');

$response = redis_rtpe_req(1, 'offer', 'verify restored Redis media state', {
	'call-id' => $call_id, 'from-tag' => $from_tag, 'to-tag' => $to_tag,
	'via-branch' => $via_branch,
	sdp => sdp('198.51.100.80', 12000, 'oldRedisUfrag',
		'oldRedisPassword012345678', 'MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw', 'sendrecv'),
});
is_deeply(secure_parameters($response->{sdp}), $secure_parameters,
	'ICE credentials and committed SDES key survive takeover rollback');

redis_rtpe_req(0, 'answer', 'commit exchange after takeover rollback', {
	'call-id' => $call_id, 'from-tag' => $from_tag, 'to-tag' => $to_tag,
	'via-branch' => $via_branch,
	sdp => sdp('198.51.100.81', 12010, 'answerRedisUfrag',
		'answerRedisPassword012345', 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo5ODc2', 'sendrecv'),
});

NGCP::Rtpengine::AutoTest::shut_rtpe();
autotest_start(@daemon_args) or die;
$response = redis_rtpe_req(0, 'rollback', 'rollback after committed state crosses Redis', {
	'call-id' => $call_id, 'from-tag' => $from_tag, 'to-tag' => $to_tag,
	'via-branch' => $via_branch,
});
is($response->{'rolled-back'}, 0, 'committed checkpoint remains consumed in Redis');

NGCP::Rtpengine::AutoTest::shut_rtpe();
serve_next_get(checkpoint_with_invalid_field_type($pending_record));
autotest_start(@daemon_args) or die;
$query = rtpe_req('query', 'query call restored without invalid checkpoint', {
	'call-id' => $call_id,
});
ok($query->{tags}{$from_tag}, 'invalid checkpoint data does not discard the restored call');
my $before_invalid = redis_sets_seen();
$response = rtpe_req('rollback', 'invalid checkpoint degrades to no rollback state', {
	'call-id' => $call_id, 'from-tag' => $from_tag, 'to-tag' => $to_tag,
	'via-branch' => $via_branch,
});
assert_record_without_checkpoint(redis_record_after($before_invalid));
is($response->{'rolled-back'}, 0, 'type-invalid checkpoint is discarded atomically');

# --- rollback restores the whole committed state, not just what query shows ---
new_call;
my ($cov_call, $cov_from, $cov_to) = (cid(), ft(), tt());
redis_rtpe_req(1, 'offer', 'coverage offer', {
	'from-tag' => $cov_from, flags => ['track-state'], direction => [qw(foo foo)],
	sdp => sdp('198.51.100.90', 14000, 'covUfrag', 'covPassword0123456789',
		'MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw', 'sendrecv'),
});
redis_rtpe_req(0, 'answer', 'coverage answer', {
	'from-tag' => $cov_from, 'to-tag' => $cov_to,
	sdp => sdp('198.51.100.91', 14010, 'covAnsUfrag', 'covAnsPassword012345',
		'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo5ODc2', 'sendrecv'),
});
my $committed_record = $last_record;

# A rejected offer that moves the media to the other interface.
redis_rtpe_req(1, 'offer', 'coverage rejected offer', {
	'from-tag' => $cov_from, 'to-tag' => $cov_to, direction => [qw(bar bar)],
	sdp => sdp('198.51.100.92', 14020, 'covNewUfrag', 'covNewPassword012345',
		'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIz', 'sendonly'),
});
isnt(durable_state($last_record), durable_state($committed_record),
	'the rejected offer really changed the stored state');

my $before_roll = redis_sets_seen();
my $cov_rollback = rtpe_req('rollback', 'coverage rollback', {
	'call-id' => $cov_call, 'from-tag' => $cov_from, 'to-tag' => $cov_to,
});
is($cov_rollback->{'rolled-back'}, 1, 'coverage rollback applied');
is_deeply(durable_state(redis_record_after($before_roll)),
	durable_state($committed_record),
	'rollback restores the committed state in full');

# --- a rollback must remove state the rejected offer introduced ---
#
# Fields the encoder writes only when set -- tls_id, the DTLS fingerprint, the
# preferred hash function, the endpoint map -- are absent from a snapshot taken
# before they existed. Restoring has to treat that absence as "clear this", not
# as "leave it alone", or an upgrade to DTLS survives its own rollback.
new_call;
my ($up_call, $up_from, $up_to) = (cid(), ft(), tt());
redis_rtpe_req(1, 'offer', 'upgrade: plain offer', {
	'from-tag' => $up_from, flags => ['track-state'],
	sdp => plain_sdp('198.51.100.95', 15000),
});
redis_rtpe_req(0, 'answer', 'upgrade: plain answer', {
	'from-tag' => $up_from, 'to-tag' => $up_to,
	sdp => plain_sdp('198.51.100.96', 15010),
});
my $plain_record = $last_record;

redis_rtpe_req(1, 'offer', 'upgrade: rejected DTLS offer', {
	'from-tag' => $up_from, 'to-tag' => $up_to,
	sdp => dtls_upgrade_sdp('198.51.100.97', 15020),
});
my $upgraded = decode_record($last_record);
ok(defined field($upgraded->{'media-0'}{hash_func}),
	'the rejected offer really introduced DTLS state');

my $before_up = redis_sets_seen();
my $up_rollback = rtpe_req('rollback', 'upgrade: rollback', {
	'call-id' => $up_call, 'from-tag' => $up_from, 'to-tag' => $up_to,
});
is($up_rollback->{'rolled-back'}, 1, 'upgrade rollback applied');
is_deeply(durable_state(redis_record_after($before_up)),
	durable_state($plain_record),
	'rollback removes DTLS state the rejected offer introduced');

# --- the snapshot-only state has to survive a rollback too ---
#
# ICE credentials and candidates, endpoint learning, offered codecs, tls_id, the
# preferred hash function and the endpoint map are written into snapshots only,
# so a record comparison cannot see them: a rollback could stop restoring any of
# them with every assertion above still green. Comparing the snapshot taken
# before the rejected offer against one taken after the rollback covers all of
# them at once, because a snapshot is taken before its offer is applied and so
# describes the state the rollback was supposed to reproduce.
new_call;
my ($rt_call, $rt_from, $rt_to) = (cid(), ft(), tt());
redis_rtpe_req(1, 'offer', 'round trip: offer', {
	'from-tag' => $rt_from, flags => ['track-state'],
	sdp => sdp('198.51.100.98', 15030, 'roundTripUfrag', 'roundTripPassword0123456',
		'Ai0RVBUpx3FYuJEyv1oOTQVHrfXEIQGRxWLXQBvR', 'sendrecv'),
});
redis_rtpe_req(0, 'answer', 'round trip: answer', {
	'from-tag' => $rt_from, 'to-tag' => $rt_to,
	sdp => sdp('198.51.100.99', 15040, 'roundTripAnswer', 'roundTripAnswerPwd012345',
		'HHf1TXWnpZlfXHBw5Q3xTNTIhFvbEHIYnmSMDGqR', 'sendrecv'),
});

redis_rtpe_req(1, 'offer', 'round trip: rejected offer', {
	'from-tag' => $rt_from, 'to-tag' => $rt_to,
	sdp => sdp('198.51.100.100', 15050, 'roundTripReject', 'roundTripRejectPwd01234',
		'GHi1TXWnpZlfXHBw5Q3xTNTIhFvbEHIYnmSMDGqQ', 'sendrecv'),
});
my $snapshot_before = checkpoint_snapshot($last_record);
ok($snapshot_before, 'round trip: committed snapshot captured');

my $rt_rollback = rtpe_req('rollback', 'round trip: rollback', {
	'call-id' => $rt_call, 'from-tag' => $rt_from, 'to-tag' => $rt_to,
});
is($rt_rollback->{'rolled-back'}, 1, 'round trip: rollback applied');

# The snapshot for this offer is taken before it is applied, so it describes the
# state the rollback restored.
redis_rtpe_req(1, 'offer', 'round trip: offer after rollback', {
	'from-tag' => $rt_from, 'to-tag' => $rt_to,
	sdp => sdp('198.51.100.101', 15060, 'roundTripAfter', 'roundTripAfterPwd012345',
		'JKl1TXWnpZlfXHBw5Q3xTNTIhFvbEHIYnmSMDGqP', 'sendrecv'),
});
my $snapshot_after = checkpoint_snapshot($last_record);
ok($snapshot_after, 'round trip: post-rollback snapshot captured');

is_deeply($snapshot_after, $snapshot_before,
	'rollback restores the snapshot-only state as well');

NGCP::Rtpengine::AutoTest::shut_rtpe();
done_testing;
