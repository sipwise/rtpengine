#!/usr/bin/perl

# --redis-repair-writes: an own call's write that was not stored (refused by
# the server, or skipped while the connection was down) is written again by
# a background pass, once writes succeed; a refused DEL is retried as a DEL,
# unless the call-id is in use again.

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


# a refused write is written again, once, by the repair pass

new_call;
my $a_id = cid();
req(sub { redis_expect_set($fd, $a_id, $noreplicas, 'refused') }, \&offer, 'refused write', { }, $sdp);
soon(2, 'repair comes');
redis_expect_set($fd, $a_id, "+OK\r\n", 'repair');
quiet(0.5, 'repaired once, nothing more');
like(rtpe_log(), qr/Redis: 1 writes repaired, 0 still pending/, 'repair logged');
is(redis_stat('redisrepairedwrites'), 1, 'repair counted');


# while the server still refuses, one attempt a second

new_call;
my $b_id = cid();
req(sub { redis_expect_set($fd, $b_id, $noreplicas, 'refused again') }, \&offer, 'write refused twice', { }, $sdp);
soon(2, 'first repair comes');
redis_expect_set($fd, $b_id, $noreplicas, 'first repair, refused');
my $t = time();
quiet(0.7, 'no new attempt within the back-off');
soon(2, 'second repair comes');
ok(time() - $t >= 0.9, 'second repair after about a second');
redis_expect_set($fd, $b_id, "+OK\r\n", 'second repair');
quiet(0.5, 'nothing more');
is(redis_stat('redisrepairedwrites'), 2, 'only the stored repair counted');


# a newer write of the same call that is stored clears the repair

new_call;
my $c_id = cid();
req(sub { redis_expect_set($fd, $c_id, $noreplicas, 'refused offer') }, \&offer, 'refused offer', { }, $sdp);
soon(2, 'repair attempt');
redis_expect_set($fd, $c_id, $noreplicas, 'repair attempt, refused');
# within the back-off, the call's own next write is stored
req(sub { redis_expect_set($fd, $c_id, "+OK\r\n", 'answer stored') }, \&answer, 'answer stored', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 4000 RTP/AVP 0 8
c=IN IP4 198.51.100.3
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
quiet(1.2, 'stored by a newer write: no repair');


# a refused DEL is retried as a DEL

new_call;
my $d_id = cid();
req(sub { redis_expect_set($fd, $d_id, "+OK\r\n", 'call to delete') }, \&offer, 'call to delete', { }, $sdp);
req(sub { redis_expect_del($fd, $d_id, $noreplicas, 'refused') }, \&rtpe_req, 'delete', 'refused delete',
	{ 'delete delay' => 0 });
soon(2, 'DEL repair comes');
redis_expect_del($fd, $d_id, ":1\r\n", 'repair');
quiet(0.5, 'nothing more after the DEL');


# a refused DEL, then a new call with the same ID whose write is refused
# too: the repair writes the new call (SET), it never deletes its key

req(sub { redis_expect_set($fd, $d_id, "+OK\r\n", 'same ID again') }, \&offer, 'call to delete, again', { }, $sdp);
req(sub { redis_expect_del($fd, $d_id, $noreplicas, 'refused again') }, \&rtpe_req, 'delete',
	'refused delete again', { 'delete delay' => 0 });
soon(2, 'DEL repair attempt');
redis_expect_del($fd, $d_id, $noreplicas, 'repair attempt, refused');
req(sub { redis_expect_set($fd, $d_id, $noreplicas, 'new call, same ID, refused') }, \&offer,
	'new call with the same ID', { }, $sdp);
soon(2, 'repair of the new call');
redis_expect_set($fd, $d_id, "+OK\r\n", 'the key is in use again: SET, not DEL');
quiet(0.5, 'nothing more');


# writes skipped while the connection is paused (the server came back as a
# replica) are written once it is a master again

redis_close($fd);
new_call;
my $f_id = cid();
req(sub {
	$fd = redis_conn($listener, 'replica', role => 'slave', refused => 1);
	redis_closed($fd, 'replica: connection closed');
}, \&offer, 'write while the node is a replica', { }, $sdp);
ok(readable($listener, 3), 'repair reconnects') or die;
$fd = redis_conn($listener, 'master again');
redis_expect_set($fd, $f_id, "+OK\r\n", 'skipped write repaired', no_ping => 1);
quiet(0.5, 'nothing more');


# a call whose only write was skipped, deleted before the repair: nothing to
# repair, not even a DEL (no SET of it was ever sent)

redis_close($fd);
new_call;
req(sub {
	$fd = redis_conn($listener, 'replica, S', role => 'slave', refused => 1);
	redis_closed($fd, 'replica, S: connection closed');
}, \&offer, 'S while the node is a replica', { }, $sdp);
rtpe_req('delete', 'delete S, never stored', { 'delete delay' => 0 });
ok(!readable($listener, 2.5), 'never-stored call deleted: no repair, no DEL');


# A call that was never stored is deleted while the repair pass reconnects
# to write it (its AUTH is held). The reconnect does not hold the lock, so
# the deletion finds "never stored" at once; back under the lock, the
# repair finds the call gone and writes nothing.

redis_close($fd);
new_call;
my $r_id = cid();
req(sub {
	$fd = redis_conn($listener, 'replica again', role => 'slave', refused => 1);
	redis_closed($fd, 'replica again: connection closed');
}, \&offer, 'R while the node is a replica', { }, $sdp);
$fd = redis_accept($listener, 3);
redis_expect($fd, ['AUTH', 'auth'], undef, 'repair AUTH (reply held)');
rtpe_req('delete', 'delete R while the repair reconnects', { 'delete delay' => 0 });
redis_send($fd, "+OK\r\n");
redis_expect($fd, ['SELECT', '2'], "+OK\r\n", 'repair SELECT');
redis_expect($fd, ['INFO'], info_reply('master'), 'repair INFO');
redis_expect($fd, ['TYPE', 'calls'], "+none\r\n", 'repair TYPE');
quiet(0.5, 'R neither written nor deleted');


# A refused DEL of Z is retried by the repair pass, whose reconnect is held
# at its AUTH; meanwhile a new call takes Z's ID (its write waits, then is
# skipped). Back under the lock, the repair leaves Z's key to the new call:
# no DEL, then the new call's skipped write is repaired.

new_call;
my $z_id = cid();
req(sub { redis_expect_set($fd, $z_id, "+OK\r\n", 'Z stored') }, \&offer, 'Z', { }, $sdp);
req(sub { redis_expect_del($fd, $z_id, $noreplicas, 'Z DEL refused') }, \&rtpe_req, 'delete',
	'delete Z, refused', { 'delete delay' => 0 });
soon(2, 'Z DEL repair attempt');
redis_expect_del($fd, $z_id, $noreplicas, 'Z DEL repair attempt, refused');
redis_close($fd);
$fd = redis_accept($listener, 3);
redis_expect($fd, ['AUTH', 'auth'], undef, 'repair AUTH (reply held)');
req(undef, \&offer, 'new Z while the repair reconnects', { }, $sdp);
redis_send($fd, "+OK\r\n");
redis_expect($fd, ['SELECT', '2'], "+OK\r\n", 'repair SELECT');
redis_expect($fd, ['INFO'], info_reply('master'), 'repair INFO');
redis_expect($fd, ['TYPE', 'calls'], "+none\r\n", 'repair TYPE');
soon(2, 'repair of the new Z');
redis_expect_set($fd, $z_id, "+OK\r\n", 'the new Z written, the key not deleted');
quiet(0.5, 'nothing more after Z');


# a call that becomes foreign (CLI "standby") is not repaired

new_call;
my $g_id = cid();
req(sub { redis_expect_set($fd, $g_id, $noreplicas, 'G refused') }, \&offer, 'G refused', { }, $sdp);
soon(2, 'repair attempt of G');
redis_expect_set($fd, $g_id, $noreplicas, 'repair attempt of G, refused');
my $resp = rtpe_req('cli', 'standby', { body => 'standby' });
like($resp->{response}, qr/all calls set to 'foreign/, 'all calls foreign');
quiet(1.3, 'foreign call: no repair');
# a, b, the DEL of d, the SET of d's new call, f and the new Z
is(redis_stat('redisrepairedwrites'), 6, 'repaired writes counted');


done_testing();
