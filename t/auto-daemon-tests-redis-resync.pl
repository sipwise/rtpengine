#!/usr/bin/perl

# --redis-resync-on-master-change: when the master's replication ID changes
# at a reconnect (a new master), every own call is written again, and the
# recent DELs are made again; a reconnect to the same master does nothing.

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use NGCP::Rtpengine::FakeRedis;
use Test::More;
use Time::HiRes qw(sleep);


my $listener = redis_listen('203.0.113.42');
my $fd;
my $replid = 'a' x 40;

my $sdp = <<SDP;
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# a missing reply fails the test with the daemon's last log lines
$SIG{ALRM} = sub { die "timeout\n" };

# nothing arrives on the Redis connection for this long
sub quiet {
	my ($secs, $n) = @_;
	ok(!readable($fd, $secs), $n);
}
# the next command (after the PING of the connection check), answered, as
# "CMD key"
sub next_cmd {
	my $n = shift;
	ok(readable($fd, 3), "$n comes") or die "nothing on the Redis connection: $n\n";
	redis_expect($fd, ['PING'], "+PONG\r\n", "$n PING");
	my $c = redis_read($fd);
	redis_send($fd, $c->[0] eq 'DEL' ? ":1\r\n" : "+OK\r\n");
	return "$c->[0] $c->[1]";
}
# a new call, written at once
sub stored_call {
	my $n = shift;
	new_call;
	my $id = cid();
	$NGCP::Rtpengine::req_cb = sub { is(next_cmd($n), "SET $id", "$n stored") };
	offer("call $n", { }, $sdp);
	return $id;
}
sub delete_call {
	my ($id, $n) = @_;
	$NGCP::Rtpengine::req_cb = sub { is(next_cmd("$n del"), "DEL $id", "$n deleted") };
	rtpe_req('delete', "delete $n", { 'delete delay' => 0 });
}
# the statistics match the "queued" lines of the log
sub resync_stats {
	my ($n) = @_;
	my @q = rtpe_log() =~ /resync after a master change: (\d+) own calls and (\d+) deletions queued/g;
	my ($calls, $dels) = (0, 0);
	while (@q) {
		$calls += shift(@q);
		$dels += shift(@q);
	}
	is(redis_stat('redisresyncs'), $n, "$n resyncs counted");
	is(redis_stat('redisresynccalls'), $calls, 'calls queued: as logged');
	is(redis_stat('redisresyncdeletes'), $dels, 'deletions queued: as logged');
}
# the connection drops; the next call's write reconnects, to a master with
# this replication ID
sub reconnect_call {
	my ($id, $n) = @_;
	redis_close($fd);
	$replid = $id;
	new_call;
	my $cid = cid();
	$NGCP::Rtpengine::req_cb = sub {
		$fd = redis_conn($listener, $n, replid => $replid);
		redis_expect_set($fd, $cid, "+OK\r\n", $n, no_ping => 1);
	};
	offer($n, { }, $sdp);
	undef($NGCP::Rtpengine::req_cb);
	return $cid;
}
# the resync's writes, in any order, until nothing comes for 0.5 s; the call
# whose write made the reconnect is in it only if that write was done first
sub resync {
	my ($n, $own) = @_;
	my %got;
	my $i = 0;
	while (readable($fd, 0.5)) {
		$i++;
		$got{next_cmd("$n $i")} = 1;
	}
	delete($got{"SET $own"});
	return \%got;
}

# refused at startup: the write connection accepts any role (on a replica,
# INFO gives the master's replication ID, so no change would be seen). The
# address has no listener, and the run is bounded, so that if the refusal is
# lost, rtpengine fails to connect (another message) instead of hanging.
{
	my $out = `timeout -k 1 10 $ENV{RTPE_BIN} --config-file=none -i 203.0.113.1 -n 2223 -f -E --redis-cmd-timeout=1000 --redis=auth\@203.0.113.99:6379/2 --redis-write=auth\@203.0.113.99:6379/2 --redis-resync-on-master-change 2>&1`;
	isnt($?, 0, 'write connection with any role: refused');
	like($out, qr/--redis-resync-on-master-change needs a write connection that requires the master role/,
		'refusal explained');
}

$NGCP::Rtpengine::AutoTest::launch_cb = sub {
	$fd = redis_conn($listener, 'startup', replid => $replid);
	redis_expect($fd, ['PING'], "+PONG\r\n", 'startup PING');
	redis_expect($fd, ['KEYS', '*'], "*0\r\n", 'startup KEYS');
};

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E
			--redis=auth@203.0.113.42:6379/2
			--redis-resync-on-master-change --redis-cmd-timeout=1000))
		or die;


# a call that asked not to be stored: never written, not even by a resync

new_call;
undef($NGCP::Rtpengine::req_cb);
offer('call N, not stored', { flags => ['no-redis-update'] }, $sdp);
quiet(0.5, 'N not stored');

# two calls, one of them deleted

my $a_id = stored_call('A');
my $b_id = stored_call('B');
delete_call($b_id, 'B');


# the connection drops, and the reconnect finds the same master (same
# replication ID): nothing more than the write itself

my $c_id = reconnect_call('a' x 40, 'C after a reconnect to the same master');
quiet(0.5, 'same master: no resync');


# the reconnect finds a new master: the own calls (A, C; D is being written
# by the write that reconnected) are written again, and B's DEL is made again

my $d_id = reconnect_call('b' x 40, 'D on the new master');
is_deeply(resync('resync', $d_id), { "SET $a_id" => 1, "SET $c_id" => 1, "DEL $b_id" => 1 },
	'resync: every own call written, the recent DEL made again');
like(rtpe_log(), qr/new replication ID \(b{40}, was a{40}\)/, 'master change logged');
like(rtpe_log(), qr/resync after a master change: [23] own calls and 1 deletions queued/, 'resync queued');
like(rtpe_log(), qr/resync after a master change done in \d+ ms/, 'resync done');
resync_stats(1);


# CLI "standby": the existing calls are foreign now. At the next master
# change, only the recent DEL (B) is made again (H is written by its own write).

my $resp = rtpe_req('cli', 'standby', { body => 'standby' });
like($resp->{response}, qr/all calls set to 'foreign/, 'all calls foreign');
my $h_id = reconnect_call('c' x 40, 'H on the third master');
is_deeply(resync('second resync', $h_id), { "DEL $b_id" => 1 },
	'second resync: foreign calls left out');
like(rtpe_log(), qr/resync after a master change: [01] own calls and 1 deletions queued/, 'second resync queued');
resync_stats(2);


# --redis-resync-delete-window and --redis-resync-delete-max

NGCP::Rtpengine::AutoTest::shut_rtpe();
redis_close($fd);
$replid = 'd' x 40;
autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E
			--redis=auth@203.0.113.42:6379/2
			--redis-resync-on-master-change --redis-cmd-timeout=1000
			--redis-resync-delete-window=2000 --redis-resync-delete-max=2))
		or die;

# P and Q, deleted more than 2 s before the master change, are not deleted
# again; U is

my $p_id = stored_call('P');
delete_call($p_id, 'P');
my $q_id = stored_call('Q');
delete_call($q_id, 'Q');
sleep(2.2);
my $u_id = stored_call('U');
delete_call($u_id, 'U');
my $r_id = reconnect_call('e' x 40, 'R on a new master');
is_deeply(resync('third resync', $r_id), { "DEL $u_id" => 1 },
	'third resync: only the deletion within the window');
like(rtpe_log(), qr/[01] own calls and 1 deletions queued$/m,
	'third resync: P and Q left the window, none dropped for the size');

# of U, V, W and X, only the last two deletions are remembered (R is still
# a call)

my $v_id = stored_call('V');
delete_call($v_id, 'V');
my $w_id = stored_call('W');
delete_call($w_id, 'W');
my $x_id = stored_call('X');
delete_call($x_id, 'X');
my $y_id = reconnect_call('f' x 40, 'Y on a new master');
is_deeply(resync('fourth resync', $y_id), { "SET $r_id" => 1, "DEL $w_id" => 1, "DEL $x_id" => 1 },
	'fourth resync: R, and only the last two deletions');
like(rtpe_log(), qr/[12] own calls and 2 deletions queued \(some older deletions were dropped: too many\)/,
	'dropped deletions logged');

# no deletion for 2.2 s: W and X are still remembered, but older than the
# window at the next master change, so they are not made again

sleep(2.2);
my $z_id = reconnect_call('0' x 40, 'Z on a new master');
is_deeply(resync('fifth resync', $z_id), { "SET $r_id" => 1, "SET $y_id" => 1 },
	'fifth resync: the calls, no deletion older than the window');
resync_stats(3);


done_testing();
