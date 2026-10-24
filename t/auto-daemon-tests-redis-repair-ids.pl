#!/usr/bin/perl

# --redis-repair-writes and call IDs: a call deleted while its writes are
# refused or skipped, and a new call that takes its ID. The DEL of the old
# key is repaired unless the new call owns the key, which it takes over if
# it was never written.

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use NGCP::Rtpengine::FakeRedis;
use Test::More;
use Time::HiRes qw(time sleep);
use NGCP::Rtpengine;
use Bencode;


my $listener = redis_listen('203.0.113.42');
my $fd;

# a missing reply fails the test with the daemon's last log lines
local $SIG{ALRM} = sub { die "timeout\n" };

my $noreplicas = "-NOREPLICAS Not enough good replicas to write.\r\n";

# nothing arrives on the Redis connection for this long
sub quiet {
	my ($secs, $n) = @_;
	ok(!readable($fd, $secs), $n);
}
# something arrives within this long
sub soon {
	my ($secs, $n) = @_;
	ok(readable($fd, $secs), $n) or die "nothing on the Redis connection: $n\n";
}
sub req {
	my ($cb, $req, @args) = @_;
	$NGCP::Rtpengine::req_cb = $cb;
	$req->(@args);
	undef($NGCP::Rtpengine::req_cb);
}

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


$NGCP::Rtpengine::AutoTest::launch_cb = sub {
	$fd = redis_conn($listener, 'startup');
	redis_expect($fd, ['PING'], "+PONG\r\n", 'startup PING');
	redis_expect($fd, ['KEYS', '*'], "*0\r\n", 'startup KEYS');
};

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E
			--redis=auth@203.0.113.42:6379/2
			--redis-repair-writes --redis-cmd-timeout=1000))
		or die;


# a call whose SET was refused is deleted while the server still refuses
# (during the back-off after K's refused repair): what is repaired is the
# DEL of its key, not the SET of the deleted call

new_call;
my $k_id = cid();
req(sub { redis_expect_set($fd, $k_id, $noreplicas, 'K refused') }, \&offer, 'K refused', { }, $sdp);
soon(2, 'repair attempt of K');
redis_expect_set($fd, $k_id, $noreplicas, 'repair attempt of K, refused');
new_call;
my $h_id = cid();
req(sub { redis_expect_set($fd, $h_id, $noreplicas, 'H refused') }, \&offer, 'H refused', { }, $sdp);
req(sub { redis_expect_del($fd, $h_id, $noreplicas, 'H DEL refused') }, \&rtpe_req, 'delete',
	'delete H, refused', { 'delete delay' => 0 });
my %got;
soon(2, 'repairs after the back-off');
while (readable($fd, 0.5)) {
	my $cmd = redis_read($fd) or last;
	redis_send($fd, $cmd->[0] eq 'PING' ? "+PONG\r\n" : $cmd->[0] eq 'DEL' ? ":1\r\n" : "+OK\r\n");
	$got{"$cmd->[0] $cmd->[1]"} = 1 if $cmd->[0] ne 'PING';
}
is_deeply(\%got, { "SET $k_id" => 1, "DEL $h_id" => 1 }, 'K written, and the DEL of H repaired');


# During the back-off after L's refused repair: P is stored, and its
# deletion waits for X's attempt (AUTH held); meanwhile a new call takes P's
# ID, and its write, which waits only 100 ms, is skipped. The old P's DEL
# leaves the key to the new P, and the new P's repair is kept.

new_call;
my $l_id = cid();
req(sub { redis_expect_set($fd, $l_id, $noreplicas, 'L refused') }, \&offer, 'L refused', { }, $sdp);
soon(2, 'repair attempt of L');
redis_expect_set($fd, $l_id, $noreplicas, 'repair attempt of L, refused');
new_call;
my $p_id = cid();
req(sub { redis_expect_set($fd, $p_id, "+OK\r\n", 'P stored') }, \&offer, 'P', { }, $sdp);
redis_close($fd);
new_call;
my $x_id = cid();
req(sub {
	$fd = redis_accept($listener, 3);
	redis_expect($fd, ['AUTH', 'auth'], undef, 'X reconnect AUTH (reply held)');
	my $del = rtpe_req_async({ command => 'delete', 'call-id' => $p_id, 'delete delay' => 0 });
	sleep(0.05);
	# on a third socket, without the request callback
	my $c3 = NGCP::Rtpengine->new('127.0.0.1', 2223);
	$c3->{socket}->send('p2 ' . Bencode::bencode({ command => 'offer', 'call-id' => $p_id,
			'from-tag' => 'p2', sdp => $offer_sdp }), 0) or die $!;
	my $ret;
	$c3->{socket}->recv($ret, 65535);
	like($ret, qr/result.*ok/, 'new P offered, its write skipped');
	redis_send($fd, "+OK\r\n");
	redis_expect($fd, ['SELECT', '2'], "+OK\r\n", 'X reconnect SELECT');
	redis_expect($fd, ['INFO'], info_reply('master'), 'X reconnect INFO');
	redis_expect($fd, ['TYPE', 'calls'], "+none\r\n", 'X reconnect TYPE');
	redis_expect_set($fd, $x_id, "+OK\r\n", 'X written after the reconnect', no_ping => 1);
	my %seen;
	my $end = time() + 3;
	while (time() < $end && readable($fd, $end - time())) {
		my $cmd = redis_read($fd) or last;
		redis_send($fd, $cmd->[0] eq 'PING' ? "+PONG\r\n" : $cmd->[0] eq 'DEL' ? ":1\r\n" : "+OK\r\n");
		$seen{"$cmd->[0] $cmd->[1]"} = 1 if $cmd->[0] ne 'PING';
		last if $seen{"SET $p_id"} && $seen{"SET $l_id"};
	}
	ok(!$seen{"DEL $p_id"}, 'the old P not deleted: the ID is taken');
	ok($seen{"SET $p_id"}, 'the new P written by the repair');
	ok($seen{"SET $l_id"}, 'L written by the repair');
	is($del->()->{result}, 'ok', 'old P deletion answered');
}, \&offer, 'X reconnects', { }, $sdp);


# A long outage: A's DEL is refused; then, while the connection is paused
# (the server came back as a replica), a new call B takes A's ID and is
# deleted before anything of it is stored. Once the server is a master
# again, the repair deletes A's key and writes nothing of B.

new_call;
my $ab_id = cid();
req(sub { redis_expect_set($fd, $ab_id, "+OK\r\n", 'A stored') }, \&offer, 'A', { }, $sdp);
req(sub { redis_expect_del($fd, $ab_id, $noreplicas, 'A DEL refused') }, \&rtpe_req, 'delete',
	'delete A, refused', { 'delete delay' => 0 });
soon(2, 'A DEL repair attempt');
redis_expect_del($fd, $ab_id, $noreplicas, 'A DEL repair attempt, refused');
redis_close($fd);
req(sub {
	$fd = redis_conn($listener, 'replica, B', role => 'slave', refused => 1);
	redis_closed($fd, 'replica, B: connection closed');
}, \&offer, 'B with the ID of A, while the node is a replica', { }, $sdp);
rtpe_req('delete', 'delete B, never stored', { 'delete delay' => 0 });
ok(readable($listener, 4), 'repair reconnects') or die;
$fd = redis_conn($listener, 'master again, A and B');
redis_expect_del($fd, $ab_id, ":1\r\n", "A's key deleted", no_ping => 1);
quiet(1.2, 'nothing of B written');


# The same, with the pass's attempt of B's entry falling in the pause: B's
# write is skipped again and B is marked afresh before it is deleted, never
# stored. Once the server is a master again, the repair deletes A's key.

new_call;
my $ac_id = cid();
req(sub { redis_expect_set($fd, $ac_id, "+OK\r\n", 'A2 stored') }, \&offer, 'A2', { }, $sdp);
req(sub { redis_expect_del($fd, $ac_id, $noreplicas, 'A2 DEL refused') }, \&rtpe_req, 'delete',
	'delete A2, refused', { 'delete delay' => 0 });
soon(2, 'A2 DEL repair attempt');
redis_expect_del($fd, $ac_id, $noreplicas, 'A2 DEL repair attempt, refused');
redis_close($fd);
req(sub {
	$fd = redis_conn($listener, 'replica, B2', role => 'slave', refused => 1);
	redis_closed($fd, 'replica, B2: connection closed');
}, \&offer, 'B2 with the ID of A2, while the node is a replica', { }, $sdp);
sleep(1.3);	# the pass's attempt of B2's entry falls in the pause
rtpe_req('delete', 'delete B2, never stored', { 'delete delay' => 0 });
ok(readable($listener, 4), 'repair reconnects for A2') or die "nothing to repair: A2's DEL lost\n";
$fd = redis_conn($listener, 'master again, A2 and B2');
redis_expect_del($fd, $ac_id, ":1\r\n", "A2's key deleted", no_ping => 1);
quiet(1.2, 'nothing of B2 written');
# K, the DEL of H, L, the new P, the DEL of A and the DEL of A2
is(redis_stat('redisrepairedwrites'), 6, 'repaired writes counted');


done_testing();
