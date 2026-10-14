#!/usr/bin/perl

# Redis Sentinel: --redis=PW@sentinel/DB takes the master's address from the
# Sentinels. Two fake Sentinels (203.0.113.43 and .45) name the master; two
# fake data nodes (203.0.113.42 and .44) are scripted here.

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use NGCP::Rtpengine::FakeRedis;
use Test::More;
use Time::HiRes qw(sleep time);


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

sub published {
	my $re = shift;
	return scalar(() = rtpe_log() =~ /master of 'mymaster' is now $re/g);
}
# wait until this Sentinel has been asked $n more times
sub queried {
	my ($ip, $n) = @_;
	my $q = sentinel_queries($ip);
	for (1 .. 100) {
		return 1 if sentinel_queries($ip) >= $q + $n;
		sleep(0.05);
	}
	return 0;
}
sub write_on {
	my ($fd, $n) = @_;
	new_call;
	$NGCP::Rtpengine::req_cb = sub { redis_expect_set($$fd, cid(), "+OK\r\n", $n) };
	offer($n, { }, $sdp);
}
# the next write moves to the new master, with nothing sent to the old one
sub write_moves {
	my ($fd, $to, $n) = @_;
	new_call;
	$NGCP::Rtpengine::req_cb = sub {
		redis_closed($$fd, "$n: old connection closed without a write");
		$$fd = redis_conn($l{$to}, "$n: on .$to");
		redis_expect_set($$fd, cid(), "+OK\r\n", $n, no_ping => 1);
	};
	offer($n, { }, $sdp);
}


my $main_fd;

$NGCP::Rtpengine::AutoTest::launch_cb = sub {
	# discovery (Sentinels, then a role probe on .42), then the connection
	$main_fd = redis_conn($l{42}, 'startup');
	redis_expect($main_fd, ['PING'], "+PONG\r\n", 'restore PING');
	redis_expect($main_fd, ['KEYS', '*'], "*0\r\n", 'restore KEYS');
};

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E
			--redis=auth@sentinel/2
			--redis-sentinel-master=mymaster --redis-sentinel-interval=500
			--redis-cmd-timeout=1000),
		'--redis-sentinel=spw@203.0.113.43:26379,203.0.113.45:26379')
		or die;


# startup: both Sentinels asked, with their password; the master they name
# checked with ROLE and the data password before it was used

for my $s ('203.0.113.43', '203.0.113.45') {
	like(sentinel_log(), qr/^\Q$s\E:26379 AUTH spw\n\Q$s\E:26379 SENTINEL MASTER mymaster\n\Q$s\E:26379 SENTINEL GET-MASTER-ADDR-BY-NAME mymaster$/m,
		"Sentinel $s asked at startup");
}
is_deeply(\@probes, [['203.0.113.42', 'auth', 'master']], 'one role probe at startup, with the data password');
is(published(qr/203\.0\.113\.42:6379 \(config epoch 1\)/), 1, 'master published');
like(rtpe_log(), qr/Using Redis Sentinel for the master of 'mymaster'/, 'Sentinel mode');
write_on(\$main_fd, 'first write on .42');


# Failover to .44. The Sentinel running it (.45) has raised the epoch and
# names the promoted replica in GET-MASTER-ADDR-BY-NAME, while the "ip" of
# its SENTINEL MASTER is still the old master; the other Sentinel (.43) has
# not heard of it yet. The new master is taken at once, once.

sentinels_set('203.0.113.43' => '203.0.113.42 6379 1', '203.0.113.45' => '203.0.113.44 6379 2 203.0.113.42');
wait_probe($l{44}, 'failover, leader alone at the new epoch');
wait_log(qr/master of 'mymaster' is now 203\.0\.113\.44:6379 \(config epoch 2\)/, 'new master published');
sentinels_set('203.0.113.43' => '203.0.113.44 6379 2', '203.0.113.45' => '203.0.113.44 6379 2');
ok(queried('203.0.113.43', 2), 'Sentinels asked again');
ok(!readable($l{44}, 0), 'failover: no second probe');
is(published(qr/203\.0\.113\.44/), 1, 'failover: published once');

write_moves(\$main_fd, 44, 'first write after the failover');
like(rtpe_log(), qr/following the master of 'mymaster' from 203\.0\.113\.42:6379 to 203\.0\.113\.44:6379/,
	'move logged');
write_on(\$main_fd, 'next write on .44');


# a Sentinel that missed the failover names .42 with the old epoch: not used
# while the other one names the new master

sentinels_set('203.0.113.43' => '203.0.113.42 6379 1', '203.0.113.45' => '203.0.113.44 6379 2');
ok(queried('203.0.113.43', 2), 'stale Sentinel asked');
ok(!readable($l{42}, 0), 'stale Sentinel: no probe and no connection to .42');
unlike(rtpe_log(), qr/epochs went back/, 'stale Sentinel, the other one up to date: no error');


# Every Sentinel that answers names an older epoch: never followed, an error
# is logged once, and the master in use is kept. First the stale Sentinel
# alone, then (after a normal state) a Sentinel set redeployed without its
# state, whose epochs start again.

my $epoch_back = qr/every Sentinel that answers names 203\.0\.113\.42:6379 as master of 'mymaster' at config epoch 1, older than 2 \(203\.0\.113\.44:6379, in use\): not followed\. If the Sentinels were redeployed without their state, their epochs went back, and rtpengine must be restarted/;
sentinels_set('203.0.113.43' => '203.0.113.42 6379 1', '203.0.113.45' => 'down');
wait_log($epoch_back, 'older epoch from every Sentinel that answers: error');
ok(queried('203.0.113.43', 2), 'asked again');
is(scalar(() = rtpe_log() =~ /$epoch_back/g), 1, 'logged once');

sentinels_set('203.0.113.43' => '203.0.113.44 6379 2', '203.0.113.45' => '203.0.113.44 6379 2');
ok(queried('203.0.113.43', 2), 'back to the epoch in use');
sentinels_set('203.0.113.43' => '203.0.113.42 6379 1', '203.0.113.45' => '203.0.113.42 6379 1');
ok(queried('203.0.113.43', 2), 'redeployed Sentinels asked');
is(scalar(() = rtpe_log() =~ /$epoch_back/g), 2, 'logged again after the normal state');
ok(!readable($l{42}, 0), 'older epoch: no probe and no connection to .42');
is(published(qr/203\.0\.113\.42:6379 \(config epoch 1\)/), 1, 'older epoch: .42 not published again');
write_on(\$main_fd, 'write on the master in use');


# a Sentinel names a node at a newer epoch, but it is a replica: not used,
# and asked again soon (before the next poll); then the Sentinels agree on
# .44 at that epoch (same address: no probe)

$role{'203.0.113.42'} = 'slave';
sentinels_set('203.0.113.43' => '203.0.113.42 6379 3', '203.0.113.45' => 'down');
wait_probe($l{42}, 'replica candidate');
my $t = time();
wait_probe($l{42}, 'replica candidate again');
ok(time() - $t < 0.45, 'replica candidate asked again before the next poll');
sentinels_set('203.0.113.43' => '203.0.113.44 6379 3', '203.0.113.45' => '203.0.113.44 6379 3');
serve_probes(1, $l{42});
ok(!readable($l{44}, 0), 'same address at a newer epoch: no probe');
is(scalar(() = rtpe_log() =~ /names 203\.0\.113\.42:6379 as master of 'mymaster' \(config epoch 3\), but it is a slave: not used/g),
	1, 'replica candidate refused, logged once');
is(published(qr/203\.0\.113\.42:6379 \(config epoch 3\)/), 0, 'replica never published');
write_on(\$main_fd, 'write after a replica candidate');


# no Sentinel answers: the last master is kept, logged once

sentinels_set('203.0.113.43' => 'down', '203.0.113.45' => 'down');
wait_log(qr/no Sentinel answered for 'mymaster'; keeping 203\.0\.113\.44:6379/, 'no Sentinel answering: logged');
sleep(1.2);
is(scalar(() = rtpe_log() =~ /no Sentinel answered/g), 1, 'logged once');
write_on(\$main_fd, 'write without Sentinels');

sentinels_set('203.0.113.43' => '203.0.113.44 6379 3', '203.0.113.45' => '203.0.113.44 6379 3');
wait_log(qr/Redis Sentinel 203\.0\.113\.43:26379 answers again/, 'Sentinel back');


# a second failover, back to .42, seen first from its leader (.45), then
# from both: one move, at once, no flip back

$role{'203.0.113.42'} = 'master';
sentinels_set('203.0.113.43' => '203.0.113.44 6379 3', '203.0.113.45' => '203.0.113.42 6379 4 203.0.113.44');
wait_probe($l{42}, 'second failover');
wait_log(qr/master of 'mymaster' is now 203\.0\.113\.42:6379 \(config epoch 4\)/, 'new master at once');
sentinels_set('203.0.113.43' => '203.0.113.42 6379 4', '203.0.113.45' => '203.0.113.42 6379 4');
ok(queried('203.0.113.43', 2), 'Sentinels asked again');
is(published(qr/203\.0\.113\.44:6379 \(config epoch 4\)/), 0, 'no flip back to the old master');
ok(!readable($l{44}, 0), 'no probe of the old master');
write_moves(\$main_fd, 42, 'first write on the new master');


# throughout: the Sentinels only got their own password and their two
# queries, and every role probe used the data password

is(scalar(grep { !/^(applied \d+|\S+ (AUTH spw|SENTINEL MASTER mymaster|SENTINEL GET-MASTER-ADDR-BY-NAME mymaster))$/ } split(/\n/, sentinel_log())), 0,
	'Sentinels get nothing else');
is(scalar(grep { $_->[1] ne 'auth' } @probes), 0, 'role probes only use the data password');


undef($NGCP::Rtpengine::req_cb);

done_testing();
