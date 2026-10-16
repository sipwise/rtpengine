#!/usr/bin/perl

# Redis Sentinel and keyspace notifications: the subscription follows the
# master named by the Sentinels, and is made again on each new master.

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use NGCP::Rtpengine::FakeRedis;
use Test::More;


my %l = map { $_ => redis_listen("203.0.113.$_") } (42, 44);

sentinels_start('spw', '203.0.113.43' => '203.0.113.42 6379 1', '203.0.113.45' => '203.0.113.42 6379 1');

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

my $psubscribed = "*3\r\n\$10\r\npsubscribe\r\n\$16\r\n__keyspace\@3__:*\r\n:1\r\n";

# the subscription's connection: AUTH, then psubscribe
sub subscription {
	my ($l, $n) = @_;
	my $fd = redis_accept($l);
	redis_expect($fd, ['AUTH', 'auth'], "+OK\r\n", "$n AUTH");
	redis_expect($fd, ['psubscribe', '__keyspace@3__:*'], $psubscribed, "$n psubscribe");
	return $fd;
}


my ($main_fd, $notify_fd, $sub_fd);

$NGCP::Rtpengine::AutoTest::launch_cb = sub {
	# discovery (Sentinels, then a role probe on .42), then the main and
	# notification connections
	$main_fd = redis_conn($l{42}, 'startup main');
	$notify_fd = redis_conn($l{42}, 'startup notify');

	# two connections from two threads: the subscription, and the restore
	# thread's copy of the notification connection
	my @fds = map { redis_accept($l{42}) } (0, 1);
	# the notification thread checks its connection before subscribing
	redis_expect($notify_fd, ['PING'], "+PONG\r\n", 'startup notify PING');
	for my $fd (@fds) {
		redis_expect($fd, ['AUTH', 'auth'], "+OK\r\n", 'startup AUTH');
		my $c = redis_read($fd);
		if ($c->[0] eq 'psubscribe') {
			$sub_fd = $fd;
			is(join(' ', @$c), 'psubscribe __keyspace@3__:*', 'startup psubscribe');
			redis_send($fd, $psubscribed);
			next;
		}
		is(join(' ', @$c), 'SELECT 2', 'restore copy SELECT');
		redis_send($fd, "+OK\r\n");
		redis_expect($fd, ['INFO'], info_reply('master'), 'restore copy INFO');
		redis_expect($fd, ['TYPE', 'calls'], "+none\r\n", 'restore copy TYPE');
		redis_expect($fd, ['PING'], "+PONG\r\n", 'restore copy PING');
		redis_expect($fd, ['SELECT', '3'], "+OK\r\n", 'restore copy SELECT 3');
		redis_expect($fd, ['KEYS', '*'], "*0\r\n", 'restore copy KEYS');
		redis_expect($fd, ['SELECT', '2'], "+OK\r\n", 'restore copy SELECT back');
	}
	# own calls
	redis_expect($main_fd, ['PING'], "+PONG\r\n", 'restore PING');
	redis_expect($main_fd, ['KEYS', '*'], "*0\r\n", 'restore KEYS');
};

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E
			--redis=auth@sentinel/2
			--redis-sentinel-master=mymaster --redis-cmd-timeout=1000
			--subscribe-keyspace=3
			--redis-num-threads=1),
		'--redis-sentinel=spw@203.0.113.43:26379,203.0.113.45:26379')
		or die;

is_deeply(\@probes, [['203.0.113.42', 'auth', 'master']], 'one role probe at startup');

new_call;
$NGCP::Rtpengine::req_cb = sub { redis_expect_set($main_fd, cid(), "+OK\r\n", 'first write') };
offer('first write on .42', { }, $sdp);


# The server closes the subscription, the master is unchanged: the event
# loop must end (nothing, the timer included, may keep it running), and the
# notification thread checks its connection and subscribes again.

redis_close($sub_fd);
redis_expect($notify_fd, ['PING'], "+PONG\r\n", 'subscription closed: connection checked');
$sub_fd = subscription($l{42}, 'subscription closed: again on .42');


# Failover, then back: each time, the old subscription and its sync
# connection are closed, both are made again on the new master, and the next
# write goes there, with nothing sent to the old master first.

for my $step ([44, 2, 'failover'], [42, 3, 'failback']) {
	my ($to, $epoch, $n) = @$step;
	sentinels_set('203.0.113.43' => "203.0.113.$to 6379 $epoch", '203.0.113.45' => "203.0.113.$to 6379 $epoch");
	wait_probe($l{$to}, $n);
	wait_log(qr/master of 'mymaster' is now 203\.0\.113\.$to:6379 \(config epoch $epoch\)/, "$n: published");

	redis_closed($sub_fd, "$n: old subscription closed");
	redis_closed($notify_fd, "$n: old notification connection closed");
	$notify_fd = redis_conn($l{$to}, "$n: notify");
	$sub_fd = subscription($l{$to}, "$n: subscription");

	new_call;
	$NGCP::Rtpengine::req_cb = sub {
		redis_closed($main_fd, "$n: main connection closed without a write");
		$main_fd = redis_conn($l{$to}, "$n: main");
		redis_expect_set($main_fd, cid(), "+OK\r\n", "$n: write", no_ping => 1);
	};
	offer("first write after the $n", { }, $sdp);
}
like(rtpe_log(), qr/the master of 'mymaster' has changed: subscribing again/, 'subscriber change logged');

# no stray connection: everything above was scripted
ok(!readable($l{$_}, 0.5), "nothing more on .$_") for (42, 44);


undef($NGCP::Rtpengine::req_cb);

done_testing();
