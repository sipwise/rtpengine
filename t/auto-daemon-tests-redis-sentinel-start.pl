#!/usr/bin/perl

# Redis Sentinel, started with no Sentinel reachable (--no-redis-required),
# and polled rarely (--redis-sentinel-interval=60000), so that every query
# seen here was triggered by rtpengine itself: by an operation with no master
# known, by a NOREPLICAS refusal, by a READONLY refusal, or by a reconnect
# that finds a replica. The Sentinel password comes from the environment.

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use NGCP::Rtpengine::FakeRedis;
use Test::More;
use Time::HiRes qw(sleep);


my %l = map { $_ => redis_listen("203.0.113.$_") } (42, 44);

sentinels_start('spw2', '203.0.113.43' => 'down');

# a missing reply fails the test with the daemon's last log lines
$SIG{ALRM} = sub { die "timeout\n" };
# a role probe can give up before it is answered
$SIG{PIPE} = 'IGNORE';

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

# the queries since the last call
my $queries_seen = 0;
sub new_queries {
	my $n = sentinel_queries('203.0.113.43');
	my $ret = $n - $queries_seen;
	$queries_seen = $n;
	return $ret;
}
sub wait_query {
	my $n = shift;
	for (1 .. 60) {
		return pass($n) if new_queries();
		sleep(0.05);
	}
	fail($n);
}
# a write refused with $err
sub refused_write {
	my ($fd, $err, $n) = @_;
	new_call;
	$NGCP::Rtpengine::req_cb = sub { redis_expect_set($fd, cid(), "-$err\r\n", $n) };
	offer($n, { }, $sdp);
}


$ENV{RTPENGINE_REDIS_SENTINEL_AUTH_PW} = 'spw2';

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E
			--redis=auth@sentinel/2
			--redis-sentinel=203.0.113.43:26379
			--redis-sentinel-master=mymaster
			--redis-sentinel-interval=60000
			--no-redis-required
		))
		or die;

like(rtpe_log(), qr/Starting with no master of 'mymaster' known from Redis Sentinel/,
	'started without a master');
like(rtpe_log(), qr/Redis Sentinel is used without --redis-cmd-timeout/,
	'no command timeout: warned, not changed');
ok(!readable($l{42}, 0), 'no data connection at startup');


# no master known: the update is skipped, nothing is connected

new_call;
$NGCP::Rtpengine::req_cb = sub {
	ok(!readable($l{42}, 0.3), 'no master known: no connection');
};
offer('write with no master known', { }, $sdp);
like(rtpe_log(), qr/No master of 'mymaster' known from Redis Sentinel yet/, 'skipped write logged');


# the Sentinel comes up: the next skipped update wakes the thread, which
# finds the master long before its next poll

sentinels_set('203.0.113.43' => '203.0.113.42 6379 1');
new_queries();
new_call;
undef($NGCP::Rtpengine::req_cb);
offer('write that wakes the Sentinel thread', { }, $sdp);
wait_query('woken by a write with no master known');
like(sentinel_log(), qr/^203\.0\.113\.43:26379 AUTH spw2$/m, 'Sentinel password from the environment');
wait_probe($l{42}, 'first master');
wait_log(qr/master of 'mymaster' is now 203\.0\.113\.42:6379 \(config epoch 1\)/, 'master published');

my $fd;
new_call;
$NGCP::Rtpengine::req_cb = sub {
	$fd = redis_conn($l{42}, 'first connection');
	redis_expect_set($fd, cid(), "+OK\r\n", 'first write', no_ping => 1);
};
offer('first write', { }, $sdp);


# NOREPLICAS: the connection is kept, and the Sentinels are asked at once;
# they name .44, where the next write goes

sentinels_set('203.0.113.43' => '203.0.113.44 6379 2');
new_queries();
refused_write($fd, 'NOREPLICAS Not enough good replicas to write.', 'NOREPLICAS write');
wait_query('woken by NOREPLICAS');
wait_probe($l{44}, 'after NOREPLICAS');
wait_log(qr/master of 'mymaster' is now 203\.0\.113\.44:6379 \(config epoch 2\)/, '.44 published');

new_call;
$NGCP::Rtpengine::req_cb = sub {
	redis_closed($fd, 'connection to .42 closed');
	$fd = redis_conn($l{44}, 'after NOREPLICAS');
	redis_expect_set($fd, cid(), "+OK\r\n", 'write on .44', no_ping => 1);
};
offer('write on .44', { }, $sdp);
unlike(rtpe_log(), qr/RE-Establishing connection for Redis server 203\.0\.113\.44/,
	'the move is logged once');

# NOREPLICAS again, within the poll interval: the connection is kept, and
# the Sentinels are not asked again (a master also says this for as long as
# it lacks replicas: at most one query per interval)

new_queries();
refused_write($fd, 'NOREPLICAS Not enough good replicas to write.', 'NOREPLICAS again');
sleep(0.5);
is(new_queries(), 0, 'NOREPLICAS again: no new query within the interval');


# READONLY: the master role is implied in Sentinel mode, so the connection
# is dropped at once, and the Sentinels are asked

new_queries();
new_call;
$NGCP::Rtpengine::req_cb = sub {
	redis_expect_set($fd, cid(), "-READONLY You can't write against a read only replica.\r\n", 'READONLY');
	redis_closed($fd, 'READONLY: connection dropped');
};
offer('READONLY write', { }, $sdp);
wait_query('woken by READONLY');

# The Sentinel still names .44 (same address and epoch: no probe). The
# reconnect finds a replica, gives up after one INFO, asks the Sentinels
# again, and makes no new attempt within the next second.

sleep(0.3);
new_queries();
new_call;
$NGCP::Rtpengine::req_cb = sub {
	$fd = redis_conn($l{44}, 'replica', role => 'slave', refused => 1);
	redis_closed($fd, 'replica: connection closed after one INFO');
};
offer('write while .44 is a replica', { }, $sdp);
wait_query('woken by the role mismatch');
ok(!readable($l{44}, 0.3), 'no probe for an unchanged answer, no reconnect within the pause');

new_call;
$NGCP::Rtpengine::req_cb = sub {
	ok(!readable($l{44}, 0.2), 'no reconnect within the pacing interval');
};
offer('write within the pacing interval', { }, $sdp);

sleep(1);
new_call;
$NGCP::Rtpengine::req_cb = sub {
	$fd = redis_conn($l{44}, 'master again');
	redis_expect_set($fd, cid(), "+OK\r\n", 'master again', no_ping => 1);
};
offer('write after the pacing interval', { }, $sdp);


undef($NGCP::Rtpengine::req_cb);

done_testing();
