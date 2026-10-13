#!/usr/bin/perl

# Error replies to Redis writes, and reconnects to a node with the wrong
# role. The fake Redis plays a node that refuses writes (as a demoted master
# or a master without enough replicas does) or that answers as a replica on
# reconnect.

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use NGCP::Rtpengine::FakeRedis;
use Test::More;


my $listener = redis_listen('203.0.113.42');
my $fd;

# a missing reply fails the test with the daemon's last log lines
$SIG{ALRM} = sub { die "timeout\n" };

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
	$fd = redis_conn($listener, 'startup');
	redis_expect($fd, ['PING'], "+PONG\r\n", 'startup PING');
	redis_expect($fd, ['KEYS', '*'], "*0\r\n", 'startup KEYS');
};

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E --redis=auth@203.0.113.42:6379/2
			--redis-cmd-timeout=1000))
		or die;


# a write that succeeds

new_call;
$NGCP::Rtpengine::req_cb = sub { redis_expect_set($fd, cid(), "+OK\r\n", 'ok') };
offer('accepted write', { }, $sdp);
is(redis_write_errors(), 0, 'no write error');


# writes refused by the server are counted, and the connection is kept:
# reconnecting to the same address cannot help

my $count = 0;
for my $err ("READONLY You can't write against a read only replica.",
		"NOREPLICAS Not enough good replicas to write.",
		"LOADING Redis is loading the dataset in memory")
{
	my ($code) = $err =~ /^(\w+)/;

	new_call;
	$NGCP::Rtpengine::req_cb = sub { redis_expect_set($fd, cid(), "-$err\r\n", $code) };
	offer("$code write", { }, $sdp);
	$count++;
	is(redis_write_errors(), $count, "$code counted");
	like(rtpe_log(), qr/ERR: .*Redis 203\.0\.113\.42:6379 refused a write: \Q$err\E \(1 refused since the last report\)/,
		'first refused write logged at once') if $code eq 'READONLY';

	# the next write goes through the same connection
	new_call;
	$NGCP::Rtpengine::req_cb = sub {
		ok(!readable($listener, 0.2), "no reconnect after $code");
		redis_expect_set($fd, cid(), "+OK\r\n", "after $code");
	};
	offer("write after $code", { }, $sdp);
	is(redis_write_errors(), $count, "nothing more counted after $code");
}


# a refused DEL is counted too

$NGCP::Rtpengine::req_cb = sub {
	redis_expect_del($fd, cid(), "-READONLY You can't write against a read only replica.\r\n", 'refused');
};
rtpe_req('delete', 'refused delete', { 'delete delay' => 0 });
$count++;
is(redis_write_errors(), $count, 'refused DEL counted');


# no reply within --redis-cmd-timeout: the connection is dropped at once
# (not at the next PING), the next write reconnects, and nothing is counted
# as a refused write

new_call;
$NGCP::Rtpengine::req_cb = sub { redis_expect_set($fd, cid(), undef, 'no reply') };
offer('write without reply', { }, $sdp);
redis_closed($fd, 'connection closed at once after the timeout', 0.5);
is(redis_write_errors(), $count, 'I/O error not counted as a refused write');

new_call;
$NGCP::Rtpengine::req_cb = sub {
	$fd = redis_conn($listener, 'after no reply');
	redis_expect_set($fd, cid(), "+OK\r\n", 'after no reply', no_ping => 1);
};
offer('write after no reply', { }, $sdp);


undef($NGCP::Rtpengine::req_cb);

done_testing();
