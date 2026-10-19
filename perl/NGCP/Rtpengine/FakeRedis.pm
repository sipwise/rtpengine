package NGCP::Rtpengine::FakeRedis;

# Fake Redis servers for the daemon tests: listeners on test addresses (made
# local by tests-preload.so), and helpers that read the commands that
# rtpengine sends (RESP arrays of bulk strings) and answer them.

use strict;
use warnings;
use Socket qw(AF_INET SOCK_STREAM sockaddr_in inet_aton);
use File::Temp;
use Test::More;
use Time::HiRes qw(time sleep);
use IO::Select;
use POSIX ();
use NGCP::Rtpengine::AutoTest;
use Exporter 'import';

our @EXPORT = qw(redis_listen redis_accept redis_conn redis_read redis_send redis_expect
	redis_expect_set redis_expect_del redis_close redis_closed readable info_reply
	redis_write_errors wait_log
	redis_serve redis_sets_seen redis_record_after redis_serve_next_get);

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

# A fake Redis that answers every command, run in a forked child, for tests
# that cannot answer rtpengine's writes in step: the daemon also writes from
# the poller thread, and a write left unanswered blocks it. It keeps the SETs
# in a hash, answers GET and KEYS from it, and leaves files for the parent in
# a temporary directory:
#   seq       number of SETs answered
#   last      value of the most recent SET
#   override  if present, served in place of the next GET, then removed
# The listener stays open in the parent: under the preload's fake network,
# closing it there removes the socket the child accepts on.

my ($serve_dir, $serve_pid);

sub serve_write {
	my ($path, $content) = @_;
	open(my $fh, '>', "$path.tmp") or die "$path: $!";
	binmode($fh);
	print $fh $content;
	close($fh) or die;
	rename("$path.tmp", $path) or die "$path: $!";
}

sub serve_read {
	my ($path) = @_;
	open(my $fh, '<', $path) or return;
	binmode($fh);
	local $/ = undef;
	my $content = <$fh>;
	close($fh);
	return $content;
}

sub serve_cmd {
	my ($fh, $store, $sets, $c) = @_;
	my $verb = uc($c->[0]);
	if ($verb eq 'PING') {
		redis_send($fh, "+PONG\r\n");
	}
	elsif ($verb eq 'INFO') {
		redis_send($fh, info_reply('master', short => 1));
	}
	elsif ($verb eq 'TYPE') {
		redis_send($fh, "+none\r\n");
	}
	elsif ($verb eq 'KEYS') {
		my @keys = keys %$store;
		redis_send($fh, '*' . scalar(@keys) . "\r\n" . join('', map { bulk($_) } @keys));
	}
	elsif ($verb eq 'GET') {
		my $value = serve_read("$serve_dir/override");
		if (defined $value) {
			unlink("$serve_dir/override");
		}
		else {
			$value = $store->{$c->[1]};
		}
		redis_send($fh, defined($value) ? bulk($value) : "\$-1\r\n");
	}
	elsif ($verb eq 'SET') {
		$store->{$c->[1]} = $c->[2];
		serve_write("$serve_dir/last", $c->[2]);
		serve_write("$serve_dir/seq", ++$$sets);
		redis_send($fh, "+OK\r\n");
	}
	elsif ($verb eq 'DEL') {
		delete $store->{$c->[1]};
		redis_send($fh, ":1\r\n");
	}
	else {
		redis_send($fh, "+OK\r\n");
	}
}

sub redis_serve {
	my ($l) = @_;
	$serve_dir = File::Temp::tempdir("fake-redis-XXXXXX", TMPDIR => 1, CLEANUP => 1);
	serve_write("$serve_dir/seq", "0");
	$serve_pid = fork();
	defined($serve_pid) or die "cannot fork the fake Redis";
	return if $serve_pid;

	# the child leaves only through _exit(): a normal exit would run
	# File::Temp's cleanup and remove the directory under the parent
	$SIG{TERM} = sub { POSIX::_exit(0) }; ## no critic (Variables::RequireLocalizedPunctuationVars)
	eval { serve_loop($l) };
	print STDERR "fake Redis: $@" if $@;
	POSIX::_exit($@ ? 1 : 0);
}

sub serve_loop {
	my ($l) = @_;
	my %store;
	my $sets = 0;
	my $select = IO::Select->new($l);
	while (1) {
		for my $fh ($select->can_read(1)) {
			if ($fh == $l) {
				my $client;
				accept($client, $l) or next;
				$rbuf{fileno($client)} = '';
				$select->add($client);
				next;
			}
			# every complete command read, then wait for more
			while (1) {
				my $c = redis_read($fh, 60);
				if (!$c) {
					$select->remove($fh);
					redis_close($fh);
					last;
				}
				serve_cmd($fh, \%store, \$sets, $c);
				last unless length($rbuf{fileno($fh)});
			}
		}
	}
}
END { kill('TERM', $serve_pid) if $serve_pid }

sub redis_sets_seen {
	return int(serve_read("$serve_dir/seq") // 0);
}

# The daemon writes to Redis before it answers, so the record is normally there
# already; poll briefly to cover the child not having flushed it yet.
sub redis_record_after {
	my ($before) = @_;
	for (1 .. 500) {
		return serve_read("$serve_dir/last") if redis_sets_seen() > $before;
		sleep(0.01);
	}
	die 'no Redis update seen after the daemon answered';
}

sub redis_serve_next_get {
	my ($record) = @_;
	serve_write("$serve_dir/override", $record);
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
