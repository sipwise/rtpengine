#!/usr/bin/perl

# --redis-require-master: the write connection (--redis-write) requires the
# master role, and a role error (READONLY, MASTERDOWN) on it drops the
# connection, so that the reconnect checks the role again. The fake Redis
# plays a master that is demoted to a replica, then promoted again.

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use NGCP::Rtpengine::FakeRedis;
use Test::More;


my $listener = redis_listen('203.0.113.42');
my ($write_fd, $read_fd);

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


$NGCP::Rtpengine::AutoTest::launch_cb = sub {
	# the write connection first, then the read connection, which restores
	$write_fd = redis_conn($listener, 'startup write');
	$read_fd = redis_conn($listener, 'startup read');
	redis_expect($read_fd, ['PING'], "+PONG\r\n", 'startup PING');
	redis_expect($read_fd, ['KEYS', '*'], "*0\r\n", 'startup KEYS');
};

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E
			--redis=auth@203.0.113.42:6379/2 --redis-write=auth@203.0.113.42:6379/2
			--redis-require-master --redis-cmd-timeout=1000))
		or die;


# a write that succeeds, then a refusal that is not about the role, which
# keeps the connection

new_call;
$NGCP::Rtpengine::req_cb = sub { redis_expect_set($write_fd, cid(), "+OK\r\n", 'ok') };
offer('accepted write', { }, $sdp);

new_call;
$NGCP::Rtpengine::req_cb = sub {
	redis_expect_set($write_fd, cid(), "-NOREPLICAS Not enough good replicas to write.\r\n", 'NOREPLICAS');
};
offer('NOREPLICAS write', { }, $sdp);
is(redis_write_errors(), 1, 'NOREPLICAS counted');

new_call;
$NGCP::Rtpengine::req_cb = sub {
	ok(!readable($listener, 0.2), 'no reconnect after NOREPLICAS');
	redis_expect_set($write_fd, cid(), "+OK\r\n", 'after NOREPLICAS');
};
offer('write after NOREPLICAS', { }, $sdp);


# READONLY: the server has become a replica. The write is counted, and the
# connection is dropped at once.

new_call;
$NGCP::Rtpengine::req_cb = sub {
	redis_expect_set($write_fd, cid(), "-READONLY You can't write against a read only replica.\r\n",
		'READONLY');
	redis_closed($write_fd, 'READONLY: connection dropped');
};
offer('READONLY write', { }, $sdp);
is(redis_write_errors(), 2, 'READONLY counted');
like(rtpe_log(), qr/Redis 203\.0\.113\.42:6379 is not a master: dropping the connection/,
	'drop logged');

# The next write reconnects, finds a replica, and gives up after one INFO;
# no new attempt follows within the next second, and the one after it finds
# the master again.

new_call;
$NGCP::Rtpengine::req_cb = sub {
	$write_fd = redis_conn($listener, 'replica', role => 'slave', refused => 1);
	redis_closed($write_fd, 'replica: connection closed after one INFO');
};
offer('write while the node is a replica', { }, $sdp);

new_call;
$NGCP::Rtpengine::req_cb = sub {
	ok(!readable($listener, 0.3), 'no reconnect within the pacing interval')
		or die "reconnect attempted within the pacing interval\n";
};
offer('write within the pacing interval', { }, $sdp);

sleep(1);

new_call;
$NGCP::Rtpengine::req_cb = sub {
	$write_fd = redis_conn($listener, 'master again');
	redis_expect_set($write_fd, cid(), "+OK\r\n", 'master again', no_ping => 1);
};
offer('write after the pacing interval', { }, $sdp);


# MASTERDOWN drops the connection too; here the reconnect finds a master

new_call;
$NGCP::Rtpengine::req_cb = sub {
	redis_expect_set($write_fd, cid(),
		"-MASTERDOWN Link with MASTER is down and replica-serve-stale-data is set to 'no'.\r\n",
		'MASTERDOWN');
	redis_closed($write_fd, 'MASTERDOWN: connection dropped');
};
offer('MASTERDOWN write', { }, $sdp);
is(redis_write_errors(), 3, 'MASTERDOWN counted');

new_call;
$NGCP::Rtpengine::req_cb = sub {
	$write_fd = redis_conn($listener, 'after MASTERDOWN');
	redis_expect_set($write_fd, cid(), "+OK\r\n", 'after MASTERDOWN', no_ping => 1);
};
offer('write after MASTERDOWN', { }, $sdp);


# the read connection was never touched, and without Sentinel options
# nothing of Sentinel is set up
ok(!readable($read_fd, 0), 'nothing on the read connection');
unlike(rtpe_log(), qr/Sentinel/, 'no Sentinel');


undef($NGCP::Rtpengine::req_cb);

done_testing();
