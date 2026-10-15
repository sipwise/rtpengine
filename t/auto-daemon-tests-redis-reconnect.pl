#!/usr/bin/perl

# A reconnect attempt is made without the connection's lock: while one
# thread waits for a server that accepts the connection but does not answer
# (here, its AUTH), another request's Redis operation waits for it only
# --redis-reconnect-slow (300 ms here), then is skipped, instead of waiting
# for the lock until the attempt times out (--redis-cmd-timeout, 2 s). An
# attempt that ends sooner lets the waiting operation through, a call
# deleted meanwhile is not written, and a deletion that waited does not
# remove the key of a new call with the same ID.

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use NGCP::Rtpengine::FakeRedis;
use Test::More;
use Time::HiRes qw(time sleep);
use Bencode;


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
my $offer_sdp = (split(/-{10,}\n/, $sdp))[0];

# a third ng client (the test's offer() and rtpe_req_async() use the other
# two), for a request made while two others wait
my $c3;
sub req3 {
	my ($req) = @_;
	$c3 //= NGCP::Rtpengine->new('127.0.0.1', 2223);
	my $cookie = rand() . ' ';
	$c3->{socket}->send($cookie . Bencode::bencode($req), 0) or die $!;
	return sub {
		my $ret;
		local $SIG{ALRM} = sub { die "no reply to the '$req->{command}' request\n" };
		alarm(5);
		$c3->{socket}->recv($ret, 65535) or die $!;
		alarm(0);
		$ret =~ s/^\Q$cookie\E//s or die $ret;
		return Bencode::bdecode($ret, 1);
	};
}

# answer whatever comes until nothing for 0.5 s: { "CMD key" => 1 }
sub drain {
	my %got;
	while (readable($fd, 0.5)) {
		my $c = redis_read($fd);
		last unless $c;
		redis_send($fd, $c->[0] eq 'PING' ? "+PONG\r\n" : $c->[0] eq 'DEL' ? ":1\r\n" : "+OK\r\n");
		$got{"$c->[0] " . ($c->[1] // '')} = 1;
	}
	return \%got;
}


$NGCP::Rtpengine::AutoTest::launch_cb = sub {
	$fd = redis_conn($listener, 'startup');
	redis_expect($fd, ['PING'], "+PONG\r\n", 'startup PING');
	redis_expect($fd, ['KEYS', '*'], "*0\r\n", 'startup KEYS');
};

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E --redis=auth@203.0.113.42:6379/2
			--redis-cmd-timeout=2000 --redis-reconnect-slow=300))
		or die;


new_call;
$NGCP::Rtpengine::req_cb = sub { redis_expect_set($fd, cid(), "+OK\r\n", 'first write') };
offer('first write', { }, $sdp);


# The server closes the connection. A's write reconnects; the new
# connection's AUTH is held. Meanwhile B is offered on another socket.

redis_close($fd);
new_call;
my $a_id = cid();
$NGCP::Rtpengine::req_cb = sub {
	$fd = redis_accept($listener, 2);
	redis_expect($fd, ['AUTH', 'auth'], undef, 'reconnect AUTH (reply held)');
	my $t = time();
	my $b = rtpe_req_async({ command => 'offer', 'call-id' => "b-$a_id", 'from-tag' => 'b',
			sdp => $offer_sdp })->();
	my $dt = time() - $t;
	is($b->{result}, 'ok', 'B answered');
	ok($dt < 1, sprintf('B not held by the reconnect (%.3f s)', $dt));
	redis_send($fd, "+OK\r\n");
	redis_expect($fd, ['SELECT', '2'], "+OK\r\n", 'reconnect SELECT');
	redis_expect($fd, ['INFO'], info_reply('master'), 'reconnect INFO');
	redis_expect($fd, ['TYPE', 'calls'], "+none\r\n", 'reconnect TYPE');
	redis_expect_set($fd, $a_id, "+OK\r\n", 'A written after the reconnect', no_ping => 1);
	ok(!readable($fd, 0.3), "B's write skipped");
};
offer('A reconnects', { }, $sdp);


# The same, but the server answers 50 ms after B's request: B's write waits
# for the attempt and is made after A's.

redis_close($fd);
new_call;
my $c_id = cid();
$NGCP::Rtpengine::req_cb = sub {
	$fd = redis_accept($listener, 2);
	redis_expect($fd, ['AUTH', 'auth'], undef, 'second reconnect AUTH (reply held)');
	my $d = rtpe_req_async({ command => 'offer', 'call-id' => "d-$c_id", 'from-tag' => 'd',
			sdp => $offer_sdp });
	sleep(0.05);
	redis_send($fd, "+OK\r\n");
	my $t = time();
	redis_expect($fd, ['SELECT', '2'], "+OK\r\n", 'second reconnect SELECT');
	redis_expect($fd, ['INFO'], info_reply('master'), 'second reconnect INFO');
	redis_expect($fd, ['TYPE', 'calls'], "+none\r\n", 'second reconnect TYPE');
	redis_expect_set($fd, $c_id, "+OK\r\n", 'C written after the reconnect', no_ping => 1);
	redis_expect_set($fd, "d-$c_id", "+OK\r\n", 'D written after C');
	is($d->()->{result}, 'ok', 'D answered');
	my $dt = time() - $t;
	ok($dt < 0.15, sprintf('D woken by the end of the attempt (%.3f s)', $dt));
};
offer('C reconnects', { }, $sdp);


# B2's write waits for E's attempt, and B2 (never stored) is deleted during
# the wait: after E's write, only B2's PING.

redis_close($fd);
new_call;
my $e_id = cid();
$NGCP::Rtpengine::req_cb = sub {
	$fd = redis_accept($listener, 2);
	redis_expect($fd, ['AUTH', 'auth'], undef, 'fourth reconnect AUTH (reply held)');
	my $b2 = rtpe_req_async({ command => 'offer', 'call-id' => "b2-$e_id", 'from-tag' => 'b2',
			sdp => $offer_sdp });
	sleep(0.05);
	is(req3({ command => 'delete', 'call-id' => "b2-$e_id", 'delete delay' => 0 })->()->{result}, 'ok',
		'B2 deleted while its write waits');
	redis_send($fd, "+OK\r\n");
	redis_expect($fd, ['SELECT', '2'], "+OK\r\n", 'fourth reconnect SELECT');
	redis_expect($fd, ['INFO'], info_reply('master'), 'fourth reconnect INFO');
	redis_expect($fd, ['TYPE', 'calls'], "+none\r\n", 'fourth reconnect TYPE');
	redis_expect_set($fd, $e_id, "+OK\r\n", 'E written after the reconnect', no_ping => 1);
	is_deeply(drain(), { 'PING ' => 1 }, 'B2 not written after its deletion');
	is($b2->()->{result}, 'ok', 'B2 answered');
};
offer('E reconnects', { }, $sdp);


# Z is stored. Its deletion, then a new call with Z's ID, both wait for F's
# attempt: whatever order they get the lock in, the key is the new call's,
# and the old call's DEL is not made.

new_call;
my $z_id = cid();
$NGCP::Rtpengine::req_cb = sub { redis_expect_set($fd, $z_id, "+OK\r\n", 'Z stored') };
offer('Z', { }, $sdp);
redis_close($fd);
new_call;
my $f_id = cid();
$NGCP::Rtpengine::req_cb = sub {
	$fd = redis_accept($listener, 2);
	redis_expect($fd, ['AUTH', 'auth'], undef, 'fifth reconnect AUTH (reply held)');
	my $del = rtpe_req_async({ command => 'delete', 'call-id' => $z_id, 'delete delay' => 0 });
	sleep(0.05);
	my $z2 = req3({ command => 'offer', 'call-id' => $z_id, 'from-tag' => 'z2', sdp => $offer_sdp });
	sleep(0.05);
	redis_send($fd, "+OK\r\n");
	redis_expect($fd, ['SELECT', '2'], "+OK\r\n", 'fifth reconnect SELECT');
	redis_expect($fd, ['INFO'], info_reply('master'), 'fifth reconnect INFO');
	redis_expect($fd, ['TYPE', 'calls'], "+none\r\n", 'fifth reconnect TYPE');
	redis_expect_set($fd, $f_id, "+OK\r\n", 'F written after the reconnect', no_ping => 1);
	my $got = drain();
	ok($got->{"SET $z_id"}, 'the new Z written');
	ok(!$got->{"DEL $z_id"}, 'the old Z not deleted over it');
	is($del->()->{result}, 'ok', 'old Z deleted');
	is($z2->()->{result}, 'ok', 'new Z offered');
};
offer('F reconnects', { }, $sdp);


# X is deleted while its own write reconnects (it was never stored, so the
# deletion has nothing to do): the write must not follow the deletion.

redis_close($fd);
new_call;
my $x_id = cid();
$NGCP::Rtpengine::req_cb = sub {
	$fd = redis_accept($listener, 2);
	redis_expect($fd, ['AUTH', 'auth'], undef, 'third reconnect AUTH (reply held)');
	my $del = rtpe_req_async({ command => 'delete', 'call-id' => $x_id, 'delete delay' => 0 });
	is($del->()->{result}, 'ok', 'X deleted during its reconnect');
	redis_send($fd, "+OK\r\n");
	redis_expect($fd, ['SELECT', '2'], "+OK\r\n", 'third reconnect SELECT');
	redis_expect($fd, ['INFO'], info_reply('master'), 'third reconnect INFO');
	redis_expect($fd, ['TYPE', 'calls'], "+none\r\n", 'third reconnect TYPE');
	ok(!readable($fd, 0.5), 'X not written after its deletion');
};
offer('X reconnects', { }, $sdp);


# the connection is in use again

new_call;
$NGCP::Rtpengine::req_cb = sub { redis_expect_set($fd, cid(), "+OK\r\n", 'next write') };
offer('next write', { }, $sdp);
like(rtpe_log(), qr/RE-Established connection to Redis 203\.0\.113\.42:6379/, 'reconnect logged');


undef($NGCP::Rtpengine::req_cb);

done_testing();
