package NGCP::Rtpengine::FakeRedis;

# Fake Redis servers for the daemon tests: listeners on test addresses (made
# local by tests-preload.so), and helpers that read the commands that
# rtpengine sends (RESP arrays of bulk strings) and answer them.

use strict;
use warnings;
use Socket qw(AF_INET SOCK_STREAM sockaddr_in inet_aton);
use Test::More;
use Time::HiRes qw(time sleep);
use NGCP::Rtpengine::AutoTest;
use Exporter 'import';

our @EXPORT = qw(redis_listen redis_accept redis_conn redis_read redis_send redis_expect
	redis_expect_set redis_expect_del redis_close redis_closed readable info_reply
	redis_write_errors wait_log);

my %rbuf;	# what was read from each socket and not parsed yet


sub redis_listen {
	my ($ip, $port) = @_;
	my $l;
	socket($l, AF_INET, SOCK_STREAM, 0) or die;
	bind($l, sockaddr_in($port // 6379, inet_aton($ip))) or die "bind $ip: $!";
	listen($l, 10) or die;
	return $l;
}

# is there something to accept on a listener, or to read on a socket?
sub readable {
	my ($fh, $timeout) = @_;
	return 1 if length($rbuf{fileno($fh)} // '');
	my $rin = '';
	vec($rin, fileno($fh), 1) = 1;
	return select(my $rout = $rin, undef, undef, $timeout) > 0;
}

# one complete command from the buffer, or undef
sub parse_cmd {
	my $b = shift;
	return unless $$b =~ /^\*(\d+)\r\n/;
	my $n = $1;
	my $pos = length("*$n\r\n");
	my @args;
	for (1 .. $n) {
		return unless substr($$b, $pos) =~ /^\$(\d+)\r\n/;
		my $len = $1;
		my $hl = length("\$$len\r\n");
		return if length($$b) < $pos + $hl + $len + 2;
		push(@args, substr($$b, $pos + $hl, $len));
		$pos += $hl + $len + 2;
	}
	substr($$b, 0, $pos) = '';
	return \@args;
}

# the next command, as an array ref; undef if the connection was closed
sub redis_read {
	my ($fd, $timeout) = @_;
	my $b = \$rbuf{fileno($fd)};
	$$b //= '';
	my $end = time() + ($timeout // 3);
	while (1) {
		my $c = parse_cmd($b);
		return $c if $c;
		my $left = $end - time();
		die "timeout waiting for a Redis command\n" if $left <= 0 || !readable($fd, $left);
		my $data;
		if (!sysread($fd, $data, 65536)) {
			delete($rbuf{fileno($fd)});
			return;
		}
		$$b .= $data;
	}
}

sub redis_send {
	my ($fd, $s) = @_;
	send($fd, $s, 0) // die "send to fake Redis: $!";
}

# the next command must be @$exp; it is answered with $reply, unless undef
sub redis_expect {
	my ($fd, $exp, $reply, $n) = @_;
	my $c = redis_read($fd);
	is(join(' ', @{$c // ['(closed)']}), join(' ', @$exp), $n);
	redis_send($fd, $reply) if defined($reply);
	return $c;
}

sub redis_close {
	my $fd = shift;
	delete($rbuf{fileno($fd)});
	close($fd);
}

# rtpengine closed the connection, with nothing sent before
sub redis_closed {
	my ($fd, $n, $timeout) = @_;
	my $c = eval { redis_read($fd, $timeout) };
	ok(!$@ && !defined($c), $n) or diag($@ || "got: $c->[0]");
	redis_close($fd);
}

sub bulk {
	my $s = shift;
	return "\$" . length($s) . "\r\n$s\r\n";
}

# the reply to INFO: more than the role line, as a real reply has, unless
# "short"; with "replid", the replication IDs too
sub info_reply {
	my ($role, %opt) = @_;
	return bulk("role:$role\r\n") if $opt{short};
	my $i = "# Replication\r\nrole:$role\r\nconnected_slaves:0\r\n";
	$i .= "master_replid:$opt{replid}\r\nmaster_replid2:" . ('0' x 40) . "\r\n" if $opt{replid};
	return bulk($i . "master_repl_offset:0\r\n");
}

sub redis_accept {
	my ($l, $timeout) = @_;
	readable($l, $timeout // 5) or die "no connection to the fake Redis\n";
	my $fd;
	accept($fd, $l) or die;
	$rbuf{fileno($fd)} = '';
	return $fd;
}

# A new data connection: AUTH, SELECT, INFO answered with the role (default
# "master"), then TYPE unless "refused" (the role is not the one wanted).
# Options: auth, db, role, short, replid, refused.
sub redis_conn {
	my ($l, $n, %opt) = @_;
	my $fd = redis_accept($l);
	redis_expect($fd, ['AUTH', $opt{auth} // 'auth'], "+OK\r\n", "$n AUTH");
	redis_expect($fd, ['SELECT', $opt{db} // 2], "+OK\r\n", "$n SELECT");
	redis_expect($fd, ['INFO'], info_reply($opt{role} // 'master', %opt), "$n INFO");
	redis_expect($fd, ['TYPE', 'calls'], "+none\r\n", "$n TYPE") unless $opt{refused};
	return $fd;
}

# The SET of call $id, after the PING of the connection check unless
# "no_ping", answered with $reply (not at all if undef).
sub redis_expect_set {
	my ($fd, $id, $reply, $n, %opt) = @_;
	redis_expect($fd, ['PING'], "+PONG\r\n", "$n PING") unless $opt{no_ping};
	my $c = redis_read($fd);
	ok($c && @$c == 5 && $c->[0] eq 'SET' && $c->[1] eq $id && $c->[3] eq 'EX', "$n SET")
		or diag('got: ' . join(' ', @{$c // ['(closed)']}[0 .. 1]));
	redis_send($fd, $reply) if defined($reply);
}

sub redis_expect_del {
	my ($fd, $id, $reply, $n, %opt) = @_;
	redis_expect($fd, ['PING'], "+PONG\r\n", "$n PING") unless $opt{no_ping};
	redis_expect($fd, ['DEL', $id], $reply, "$n DEL");
}

sub redis_write_errors {
	local $NGCP::Rtpengine::req_cb;
	my $resp = rtpe_req('statistics', 'statistics', { });
	return $resp->{statistics}{totalstatistics}{rediswriteerrors};
}

sub wait_log {
	my ($re, $n, $timeout) = @_;
	my $end = time() + ($timeout // 5);
	while (time() < $end) {
		return pass($n) if rtpe_log() =~ $re;
		sleep(0.05);
	}
	fail($n);
	die "not in the log: $re\n";
}

1;
