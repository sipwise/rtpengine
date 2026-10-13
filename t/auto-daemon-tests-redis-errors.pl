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
use Time::HiRes qw(time sleep);


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


# The server closes the connection (as Sentinel does when it demotes a
# master) and the reconnect finds a replica, while the master role is
# required (--redis without --redis-write): one INFO, and no sleep or second
# INFO under the lock. The INFO reply has nothing after the role line, which
# must not be read past its end (an ASan build aborts without strncmp()).

redis_close($fd);

new_call;
$NGCP::Rtpengine::req_cb = sub {
	$fd = redis_conn($listener, 'replica', role => 'slave', short => 1, refused => 1);
	redis_closed($fd, 'replica: connection closed after one INFO');
	# no ng reply if rtpengine died: fail instead of waiting forever
	alarm(5);
};
offer('write while the node is a replica', { }, $sdp);
alarm(0);

# within the next second, no new connection is attempted; after it, the next
# write reconnects, and the node is master again

new_call;
$NGCP::Rtpengine::req_cb = sub {
	ok(!readable($listener, 0.3), 'no reconnect within the pacing interval')
		or die "reconnect attempted within the pacing interval\n";
};
offer('write within the pacing interval', { }, $sdp);

sleep(1);

new_call;
$NGCP::Rtpengine::req_cb = sub {
	$fd = redis_conn($listener, 'master again');
	redis_expect_set($fd, cid(), "+OK\r\n", 'master again', no_ping => 1);
};
offer('write after the pacing interval', { }, $sdp);


# The server goes away (the connection is refused): that failure is quick,
# so it is not paced, and the first write after the server is back goes
# through: the reconnect must come before the ng reply.

redis_close($fd);
close($listener);

new_call;
undef($NGCP::Rtpengine::req_cb);
my $log_pos = length(rtpe_log());
offer('write while the server is down', { }, $sdp);
# (under the test preload library, a refused connection shows as "No such
# file or directory")
like(substr(rtpe_log(), $log_pos), qr/Lost connection to Redis '203\.0\.113\.42'\n(?:.*\n)*?.*Failed to connect to Redis 203\.0\.113\.42:6379, error: /,
	'connection refused');

$listener = redis_listen('203.0.113.42');

new_call;
$NGCP::Rtpengine::req_cb = sub {
	ok(readable($listener, 2), 'reconnect on the first write after a refused connection')
		or die "no reconnect after a refused connection\n";
	$fd = redis_conn($listener, 'server back');
	redis_expect_set($fd, cid(), "+OK\r\n", 'server back', no_ping => 1);
};
offer('write when the server is back', { }, $sdp);


# Non-default pacing: with --redis-reconnect-slow=0 even a refused
# connection is followed by the pause, and --redis-reconnect-pause=2500
# makes it last longer than the default second.

undef($NGCP::Rtpengine::req_cb);
NGCP::Rtpengine::AutoTest::shut_rtpe();
redis_close($fd);
autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E --redis=auth@203.0.113.42:6379/2
			--redis-cmd-timeout=1000
			--redis-reconnect-pause=2500 --redis-reconnect-slow=0))
		or die;

redis_close($fd);
close($listener);

new_call;
offer('write while the server is down, paced', { }, $sdp);
my $t0 = time();	# the pause began during that request
$listener = redis_listen('203.0.113.42');

new_call;
$NGCP::Rtpengine::req_cb = sub {
	ok(!readable($listener, 0.3), 'refused connection followed by the pause');
};
offer('write after a refused connection', { }, $sdp);

sleep(1.2 - (time() - $t0));
new_call;
$NGCP::Rtpengine::req_cb = sub {
	ok(!readable($listener, 0.2), 'still paused after one second');
};
offer('write after one second', { }, $sdp);

sleep(2.7 - (time() - $t0));
new_call;
$NGCP::Rtpengine::req_cb = sub {
	$fd = redis_conn($listener, 'after the pause');
	redis_expect_set($fd, cid(), "+OK\r\n", 'after the pause', no_ping => 1);
};
offer('write after the pause', { }, $sdp);


# --redis-reconnect-pause=0: no pause, even after a failure counted as slow

undef($NGCP::Rtpengine::req_cb);
NGCP::Rtpengine::AutoTest::shut_rtpe();
redis_close($fd);
autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E --redis=auth@203.0.113.42:6379/2
			--redis-cmd-timeout=1000
			--redis-reconnect-pause=0 --redis-reconnect-slow=0))
		or die;

redis_close($fd);
close($listener);
new_call;
offer('write while the server is down, no pause', { }, $sdp);
$listener = redis_listen('203.0.113.42');

new_call;
$NGCP::Rtpengine::req_cb = sub {
	ok(readable($listener, 2), 'no pause: the next write reconnects')
		or die "no reconnect with --redis-reconnect-pause=0\n";
	$fd = redis_conn($listener, 'no pause');
	redis_expect_set($fd, cid(), "+OK\r\n", 'no pause', no_ping => 1);
};
offer('write right after a failure', { }, $sdp);


undef($NGCP::Rtpengine::req_cb);

done_testing();
