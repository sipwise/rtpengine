#!/usr/bin/perl

# A call that is destroyed while a writer holds it is not written back, and
# is deleted if the writer got there first. The writer here is the "kill
# calls" timer, which rewrites an SRTP call that was never stored (X, offered
# with no-redis-update); the fake Redis holds back one reply to place X's
# deletion at the right moment.

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use NGCP::Rtpengine::FakeRedis;
use Test::More;
use Time::HiRes qw(sleep);


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
my $x_sdp = (split(/-{10,}\n/, $sdp))[0];

# X: an SRTP call that is never written by its own requests
sub offer_x {
	my $id = shift;
	my $r = rtpe_req_async({ command => 'offer', 'call-id' => $id, 'from-tag' => 'x', sdp => $x_sdp,
			'transport-protocol' => 'RTP/SAVP', flags => ['no-redis-update'] })->();
	is($r->{result}, 'ok', "$id offered, not stored");
}


$NGCP::Rtpengine::AutoTest::launch_cb = sub {
	$fd = redis_conn($listener, 'startup');
	redis_expect($fd, ['PING'], "+PONG\r\n", 'startup PING');
	redis_expect($fd, ['KEYS', '*'], "*0\r\n", 'startup KEYS');
};

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E --redis=auth@203.0.113.42:6379/2
			--redis-cmd-timeout=3000))
		or die;


# 1. The timer waits for the lock (held by another call's write) while X is
# deleted: X must not be written afterwards. (A write would come before the
# deletion's reply: the deletion waits for the timer's pass, on the call
# iterator's lock.)

my $x1 = 'destroyed-1-' . rand();
my $del;
new_call;
$NGCP::Rtpengine::req_cb = sub {
	redis_expect_set($fd, cid(), undef, 'held write');
	offer_x($x1);
	sleep(1.5);	# the timer runs every second: it now waits for the lock
	$del = rtpe_req_async({ command => 'delete', 'call-id' => $x1, 'delete delay' => 0 });
	sleep(0.3);
	redis_send($fd, "+OK\r\n");
};
offer('write held while X is deleted', { }, $sdp);
undef($NGCP::Rtpengine::req_cb);

my $w = readable($fd, 1.5);
ok(!$w, 'destroyed call not written back');
if ($w) {
	redis_expect($fd, ['PING'], "+PONG\r\n", 'unexpected write PING');
	my $c = redis_read($fd);
	diag("written: $c->[0] $c->[1]");
	redis_send($fd, "+OK\r\n");
}
is($del->()->{result}, 'ok', 'X deleted');


# 2. The timer has the lock and checks the connection (its PING is held) when
# X is deleted: the deletion must wait, and delete the key the timer writes.

my $x2 = 'destroyed-2-' . rand();
offer_x($x2);
redis_expect($fd, ['PING'], undef, 'timer PING (reply held)');
$del = rtpe_req_async({ command => 'delete', 'call-id' => $x2, 'delete delay' => 0 });
sleep(0.3);
redis_send($fd, "+PONG\r\n");
redis_expect_set($fd, $x2, "+OK\r\n", 'timer write of X', no_ping => 1);
redis_expect_del($fd, $x2, ":1\r\n", 'then its deletion')
	if ok(readable($fd, 1.5), 'the deletion follows the write');
is($del->()->{result}, 'ok', 'X deleted');


done_testing();
