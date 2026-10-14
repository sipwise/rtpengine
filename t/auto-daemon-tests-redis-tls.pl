#!/usr/bin/perl

# TLS to Redis: the certificate must come from the CA and match the address
# (or --redis-tls-server-name), a client certificate is sent, a handshake
# that gets no answer is given up, and the keyspace subscription and the
# Redis Sentinel connections speak TLS too. Certificates are made here with
# the openssl tool.

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use NGCP::Rtpengine::FakeRedis;
use Test::More;
use File::Temp;
use IO::Socket::SSL;
use Time::HiRes qw(time sleep);


# the refusals at startup; a build without TLS support has no TLS option,
# and nothing else can be tested
sub refused_start {
	my ($opts, $re, $n) = @_;
	my $out = `timeout -k 1 10 $ENV{RTPE_BIN} --config-file=none -i 203.0.113.1 -n 2223 -f -E --redis=auth\@203.0.113.99:6379/2 $opts 2>&1`;
	isnt($?, 0, "$n: refused");
	like($out, $re, "$n: explained");
	return $out;
}

if (refused_start('--redis-certfile=x', qr/./, 'TLS option') =~ /Unknown option --redis-certfile/) {
	pass('no TLS options in a build without TLS support');
	done_testing();
	exit(0);
}
refused_start('--redis-certfile=x', qr/Redis TLS needs --redis-cafile or --redis-capath/,
	'client certificate without a CA');
refused_start('--redis-cafile=/dev/null --redis-certfile=x',
	qr/--redis-certfile and --redis-keyfile must be given together/, 'certificate without a key');
refused_start('--redis-cafile=/nonexistent', qr/cannot load the CA file or path/, 'unreadable CA file');


my $d = File::Temp->newdir();
tls_ca($d, $_) for qw(ca ca2);
tls_cert($d, 'ca', 'srv', 'IP:203.0.113.42');
tls_cert($d, 'ca2', 'srv-ca2', 'IP:203.0.113.42');
tls_cert($d, 'ca', 'srv-ip', 'IP:203.0.113.99');
tls_cert($d, 'ca', 'rtpengine');
tls_cert($d, 'ca', 'name', 'DNS:redis.sub.test');
tls_cert($d, 'ca', 'name-other', 'DNS:other.sub.test');
tls_cert($d, 'ca', 'name-wild', 'DNS:*.sub.test');
tls_cert($d, 'ca', 'name-partial', 'DNS:re*.sub.test');
tls_cert($d, 'ca', 'redis.sub.test');	# the name in the CN only
tls_cert($d, 'ca', 'sentinel', 'IP:203.0.113.43');

sub cert {
	my ($name, %opt) = @_;
	redis_tls(SSL_cert_file => "$d/$name.pem", SSL_key_file => "$d/$name.key", %opt);
}
# the first server requires a client certificate from the CA
my %client_cert = (SSL_verify_mode => SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
	SSL_ca_file => "$d/ca.pem");

my $l = redis_listen('203.0.113.42');

# a missing reply fails the test with the daemon's last log lines
local $SIG{ALRM} = sub { die "timeout\n" };
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

# the server closes the connection; at the next write, rtpengine connects
# again and refuses the certificate, and logs it once more
sub refused_cert {
	my ($fd, $re, $n) = @_;
	my $before = () = rtpe_log() =~ /$re/g;
	redis_close($fd);
	new_call;
	$NGCP::Rtpengine::req_cb = sub { redis_tls_refused($l, "$n: handshake not completed") };
	offer($n, { }, $sdp);
	for (1 .. 100) {
		my $now = () = rtpe_log() =~ /$re/g;
		return pass("$n: logged") if $now > $before;
		sleep(0.05);
	}
	fail("$n: logged");
}


# verification of the address, client certificate

my $fd;
cert('srv', %client_cert);
$NGCP::Rtpengine::AutoTest::launch_cb = sub {
	$fd = redis_conn($l, 'startup');
	is($fd->peer_certificate('cn'), 'rtpengine', 'client certificate sent');
	ok(!defined($fd->get_servername()), 'no SNI for an IP address');
	redis_expect($fd, ['PING'], "+PONG\r\n", 'startup PING');
	redis_expect($fd, ['KEYS', '*'], "*0\r\n", 'startup KEYS');
};

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E
			--redis=auth@203.0.113.42:6379/2),
		"--redis-cafile=$d/ca.pem", "--redis-certfile=$d/rtpengine.pem",
		"--redis-keyfile=$d/rtpengine.key")
		or die;

new_call;
$NGCP::Rtpengine::req_cb = sub { redis_expect_set($fd, cid(), "+OK\r\n", 'write over TLS') };
offer('write over TLS', { }, $sdp);

cert('srv-ca2', %client_cert);
refused_cert($fd, qr/Failed to connect to Redis 203\.0\.113\.42:6379, error: TLS: certificate of 203\.0\.113\.42 not accepted: unable to get local issuer certificate/,
	'certificate from another CA');

cert('srv-ip', %client_cert);
refused_cert($fd, qr/error: TLS: certificate of 203\.0\.113\.42 not accepted: IP address mismatch/,
	'certificate for another address');

# no command timeout: the connect timeout (1 s) bounds the handshake
my $frozen;
new_call;
$NGCP::Rtpengine::req_cb = sub {
	readable($l, 5) or die;
	accept($frozen, $l) or die;
};
my $start = time();
alarm(5);
offer('handshake with no answer', { }, $sdp);
alarm(0);
my $took = time() - $start;
ok($took >= 0.9 && $took < 2.5, 'handshake with no answer given up after the connect timeout')
	or diag("took $took s");
wait_log(qr/error: TLS: handshake with 203\.0\.113\.42 timed out/, 'handshake timeout logged');
close($frozen);

# after a slow failure, one second without attempts
sleep(1.1);
cert('srv', %client_cert);
new_call;
$NGCP::Rtpengine::req_cb = sub {
	$fd = redis_conn($l, 'reconnect');
	redis_expect_set($fd, cid(), "+OK\r\n", 'write after reconnecting', no_ping => 1);
};
offer('reconnected over TLS', { }, $sdp);

# the connect timeout bounded only the handshake: with no command timeout, a
# slow reply is waited for, on the same connection
new_call;
$NGCP::Rtpengine::req_cb = sub {
	redis_expect($fd, ['PING'], undef, 'slow reply: PING');
	sleep(1.5);
	redis_send($fd, "+PONG\r\n");
	redis_expect_set($fd, cid(), "+OK\r\n", 'slow reply: write', no_ping => 1);
};
offer('slow reply after a TLS reconnect', { }, $sdp);
ok(!readable($l, 0), 'slow reply: no new connection');

NGCP::Rtpengine::AutoTest::shut_rtpe();
undef($NGCP::Rtpengine::req_cb);


# --redis-tls-server-name, and the keyspace subscription

cert('name');
my ($notify_fd, $sub_fd);
my $psubscribed = "*3\r\n\$10\r\npsubscribe\r\n\$16\r\n__keyspace\@3__:*\r\n:1\r\n";

sub subscription {
	my ($n) = @_;
	my $s = redis_accept($l);
	is($s->get_servername(), 'redis.sub.test', "$n: SNI");
	redis_expect($s, ['AUTH', 'auth'], "+OK\r\n", "$n AUTH");
	redis_expect($s, ['psubscribe', '__keyspace@3__:*'], $psubscribed, "$n psubscribe");
	return $s;
}

$NGCP::Rtpengine::AutoTest::launch_cb = sub {
	$fd = redis_conn($l, 'name: startup main');
	is($fd->get_servername(), 'redis.sub.test', 'name: SNI');
	$notify_fd = redis_conn($l, 'name: startup notify');

	# two connections from two threads: the subscription, and the restore
	# thread's copy of the notification connection. The subscription's
	# handshake starts once its thread has checked the notification
	# connection.
	my @fds = map { redis_accept($l, 5, 1) } (0, 1);
	redis_expect($notify_fd, ['PING'], "+PONG\r\n", 'name: startup notify PING');
	for my $s (@fds) {
		redis_handshake($s);
		redis_expect($s, ['AUTH', 'auth'], "+OK\r\n", 'name: startup AUTH');
		my $c = redis_read($s);
		if ($c->[0] eq 'psubscribe') {
			$sub_fd = $s;
			is(join(' ', @$c), 'psubscribe __keyspace@3__:*', 'name: startup psubscribe');
			is($s->get_servername(), 'redis.sub.test', 'name: subscription SNI');
			redis_send($s, $psubscribed);
			next;
		}
		is(join(' ', @$c), 'SELECT 2', 'name: restore copy SELECT');
		redis_send($s, "+OK\r\n");
		redis_expect($s, ['INFO'], info_reply('master'), 'name: restore copy INFO');
		redis_expect($s, ['TYPE', 'calls'], "+none\r\n", 'name: restore copy TYPE');
		redis_expect($s, ['PING'], "+PONG\r\n", 'name: restore copy PING');
		redis_expect($s, ['SELECT', '3'], "+OK\r\n", 'name: restore copy SELECT 3');
		redis_expect($s, ['KEYS', '*'], "*0\r\n", 'name: restore copy KEYS');
		redis_expect($s, ['SELECT', '2'], "+OK\r\n", 'name: restore copy SELECT back');
	}
	redis_expect($fd, ['PING'], "+PONG\r\n", 'name: restore PING');
	redis_expect($fd, ['KEYS', '*'], "*0\r\n", 'name: restore KEYS');
};

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E
			--redis=auth@203.0.113.42:6379/2
			--subscribe-keyspace=3 --redis-num-threads=1
			--redis-tls-server-name=redis.sub.test
			--redis-cmd-timeout=5000),
		"--redis-cafile=$d/ca.pem")
		or die;

new_call;
$NGCP::Rtpengine::req_cb = sub { redis_expect_set($fd, cid(), "+OK\r\n", 'name: write') };
offer('name: write over TLS', { }, $sdp);

cert('name-other');
refused_cert($fd, qr/error: TLS: certificate of redis\.sub\.test not accepted: hostname mismatch/,
	'name: certificate for another name');

cert('name-partial');
my $name_refused = qr/error: TLS: certificate of redis\.sub\.test not accepted: hostname mismatch/;
refused_cert($fd, $name_refused, 'name: partial wildcard');

cert('redis.sub.test');
refused_cert($fd, $name_refused, 'name: name in the CN only');

cert('name-wild');
new_call;
$NGCP::Rtpengine::req_cb = sub {
	$fd = redis_conn($l, 'name: wildcard');
	redis_expect_set($fd, cid(), "+OK\r\n", 'name: wildcard: write', no_ping => 1);
};
offer('name: wildcard accepted', { }, $sdp);
cert('name-other');

# the subscription is made again, over TLS, with the same verification
redis_close($sub_fd);
redis_expect($notify_fd, ['PING'], "+PONG\r\n", 'name: subscription closed: connection checked');
redis_tls_refused($l, 'name: subscription with a certificate for another name: refused');
wait_log(qr/redis_notify_async_context_disconnect: TLS: certificate of redis\.sub\.test not accepted: hostname mismatch/,
	'name: subscription refusal logged with the reason');
cert('name');
redis_expect($notify_fd, ['PING'], "+PONG\r\n", 'name: subscription refused: connection checked');
$sub_fd = subscription('name: subscription again');


NGCP::Rtpengine::AutoTest::shut_rtpe();
undef($NGCP::Rtpengine::req_cb);


# Redis Sentinel: the queries and the role probes speak TLS. The Sentinels
# are checked against their addresses, the data nodes (the role probe
# included) against --redis-tls-server-name.

my $l44 = redis_listen('203.0.113.44');
cert('name');
my $sentinel_tls = "$d/sentinel.pem $d/sentinel.key";
sentinels_start('spw', tls => $sentinel_tls, '203.0.113.43' => '203.0.113.42 6379 1');

$NGCP::Rtpengine::AutoTest::launch_cb = sub {
	$fd = redis_conn($l, 'sentinel: startup');
	redis_expect($fd, ['PING'], "+PONG\r\n", 'sentinel: startup PING');
	redis_expect($fd, ['KEYS', '*'], "*0\r\n", 'sentinel: startup KEYS');
};

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E
			--redis=auth@sentinel/2
			--redis-sentinel-master=mymaster --redis-sentinel-interval=200
			--redis-cmd-timeout=1000 --redis-tls-server-name=redis.sub.test),
		'--redis-sentinel=spw@203.0.113.43:26379', "--redis-cafile=$d/ca.pem")
		or die;

like(sentinel_log(), qr/^203\.0\.113\.43:26379 AUTH spw$/m, 'sentinel: queried over TLS');
is_deeply(\@probes, [['203.0.113.42', 'auth', 'master']], 'sentinel: role probe over TLS');

# a Sentinel whose certificate is for another address is not asked
sentinels_set(tls => "$d/srv-ip.pem $d/srv-ip.key", '203.0.113.43' => '203.0.113.42 6379 1');
wait_log(qr/Redis Sentinel: cannot connect to 203\.0\.113\.43:26379: TLS: certificate of 203\.0\.113\.43 not accepted: IP address mismatch/,
	'sentinel: certificate for another address refused');
like(sentinel_log(), qr/^203\.0\.113\.43:26379 TLS refused$/m, 'sentinel: handshake not completed');

# a master whose certificate is for another name is not followed
cert('name-other');
sentinels_set(tls => $sentinel_tls, '203.0.113.43' => '203.0.113.44 6379 2');
redis_tls_refused($l44, 'sentinel: role probe of a master with the wrong certificate');
wait_log(qr/Redis Sentinel: cannot connect to 203\.0\.113\.44:6379: TLS: certificate of redis\.sub\.test not accepted: hostname mismatch/,
	'sentinel: role probe refused the certificate');
new_call;
$NGCP::Rtpengine::req_cb = sub { redis_expect_set($fd, cid(), "+OK\r\n", 'sentinel: write') };
offer('sentinel: still on the master in use', { }, $sdp);
unlike(rtpe_log(), qr/master of 'mymaster' is now 203\.0\.113\.44/, 'sentinel: not followed');


done_testing();
