package NGCP::Rtpengine::FakeRedis;

# Fake Redis servers for the daemon tests: listeners on test addresses (made
# local by tests-preload.so), and helpers that read the commands that
# rtpengine sends (RESP arrays of bulk strings) and answer them. Fake Redis
# Sentinels run in a child process (sentinels_start()), so that they answer
# while the test script handles the data nodes. With redis_tls(), the fake
# servers speak TLS (IO::Socket::SSL, loaded only then).

use strict;
use warnings;
use Socket qw(AF_INET SOCK_STREAM sockaddr_in inet_aton);
use Scalar::Util qw(blessed);
use File::Temp;
use IO::Handle;
use Test::More;
use Time::HiRes qw(time sleep);
use IO::Select;
use POSIX ();
use NGCP::Rtpengine::AutoTest;
use Exporter 'import';

our @EXPORT = qw(redis_listen redis_accept redis_conn redis_read redis_send redis_expect
	redis_expect_set redis_expect_del redis_close redis_closed readable info_reply
	redis_write_errors redis_stat wait_log redis_tls redis_tls_refused redis_handshake tls_ca tls_cert
	redis_serve redis_sets_seen redis_record_after redis_serve_next_get
	%role @probes wait_probe serve_probes
	sentinels_start sentinels_set sentinel_log sentinel_queries);

my %rbuf;	# what was read from each socket and not parsed yet
my %node;	# IP of each listener, by fileno
my $tls;	# IO::Socket::SSL server options, if TLS

# Role probes of the Sentinel thread (AUTH, then ROLE) on the data nodes are
# answered from %role (by IP, "master" by default), and recorded in @probes
# as [IP, password, role answered].
our %role;
our @probes;


sub redis_listen {
	my ($ip, $port) = @_;
	my $l;
	socket($l, AF_INET, SOCK_STREAM, 0) or die;
	bind($l, sockaddr_in($port // 6379, inet_aton($ip))) or die "bind $ip: $!";
	listen($l, 10) or die;
	$node{fileno($l)} = $ip;
	return $l;
}

# is there something to accept on a listener, or to read on a socket?
sub readable {
	my ($fh, $timeout) = @_;
	return 1 if length($rbuf{fileno($fh)} // '');
	return 1 if blessed($fh) && $fh->isa('IO::Socket::SSL') && $fh->pending;
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
	syswrite($fd, $s) // die "send to fake Redis: $!";
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

# with "later", the TLS handshake is left to redis_handshake()
sub redis_accept {
	my ($l, $timeout, $later) = @_;
	readable($l, $timeout // 5) or die "no connection to the fake Redis\n";
	my $fd;
	accept($fd, $l) or die;
	redis_handshake($fd) unless $later;
	$rbuf{fileno($fd)} = '';
	return $fd;
}

sub redis_handshake {
	my $fd = shift;
	return unless $tls;
	IO::Socket::SSL->start_SSL($fd, %$tls)
		or die "TLS handshake with rtpengine failed: $IO::Socket::SSL::SSL_ERROR\n";
}

# The servers speak TLS with these IO::Socket::SSL options (certificate,
# key, client verification...), or plain TCP if none.
sub redis_tls {
	my %opt = @_;
	require IO::Socket::SSL;
	$tls = %opt ? { SSL_server => 1, Timeout => 3, %opt } : undef;
}

# rtpengine connects and gives up during the handshake
sub redis_tls_refused {
	my ($l, $n) = @_;
	readable($l, 5) or die "no connection to the fake Redis\n";
	accept(my $fd, $l) or die;
	ok(!IO::Socket::SSL->start_SSL($fd, %$tls), $n);
	close($fd);
}

# Test certificates (EC P-256, valid for a day), made with the openssl tool
# in $dir: a CA, and a certificate signed by it for subjectAltName $san.
sub tls_ca {
	my ($dir, $name) = @_;
	system(qw(openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1
		-subj), "/CN=$name", '-keyout', "$dir/$name.key", '-out', "$dir/$name.pem") == 0 or die;
}

my $cert_serial = 0;
sub tls_cert {
	my ($dir, $ca, $name, $san) = @_;
	system(qw(openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes
		-subj), "/CN=$name", '-keyout', "$dir/$name.key", '-out', "$dir/$name.csr") == 0 or die;
	open(my $fh, '>', "$dir/$name.ext") or die;
	print $fh "subjectAltName=$san\n" if $san;
	close($fh);
	system(qw(openssl x509 -req -days 1 -set_serial), ++$cert_serial, '-in', "$dir/$name.csr",
		'-CA', "$dir/$ca.pem", '-CAkey', "$dir/$ca.key", '-extfile', "$dir/$name.ext",
		'-out', "$dir/$name.pem") == 0 or die;
}

sub role_reply {
	my $role = shift;
	return "*3\r\n\$6\r\nmaster\r\n:0\r\n*0\r\n" if $role eq 'master';
	return "*5\r\n\$5\r\nslave\r\n\$12\r\n203.0.113.44\r\n:6379\r\n\$9\r\nconnected\r\n:0\r\n";
}

# after the AUTH of a probe: answer its ROLE
sub probe_answer {
	my ($fd, $ip, $auth) = @_;
	my $r = $role{$ip} // 'master';
	redis_send($fd, role_reply($r));
	push(@probes, [$ip, $auth, $r]);
	redis_close($fd);
}

# A new data connection: AUTH, SELECT, INFO answered with the role (default
# "master"), then TYPE unless "refused" (the role is not the one wanted).
# Options: auth, db, role, short, replid, refused. Probes that come first
# are answered.
sub redis_conn {
	my ($l, $n, %opt) = @_;
	my ($fd, $auth, $c);
	while (1) {
		$fd = redis_accept($l);
		$auth = redis_read($fd);
		# (a probe can give up before it is answered)
		redis_send($fd, "+OK\r\n") if $auth;
		$c = $auth && redis_read($fd);
		last if $c && $c->[0] ne 'ROLE';
		$c ? probe_answer($fd, $node{fileno($l)}, $auth->[1]) : redis_close($fd);
	}
	is(join(' ', @$auth), 'AUTH ' . ($opt{auth} // 'auth'), "$n AUTH");
	is(join(' ', @$c), 'SELECT ' . ($opt{db} // 2), "$n SELECT");
	redis_send($fd, "+OK\r\n");
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
	return redis_stat('rediswriteerrors');
}

# a counter of the "statistics" command's totals
sub redis_stat {
	my ($name) = @_;
	local $NGCP::Rtpengine::req_cb;
	my $resp = rtpe_req('statistics', 'statistics', { });
	return $resp->{statistics}{totalstatistics}{$name};
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



# wait for a role probe on this listener
sub wait_probe {
	my ($l, $n, $timeout) = @_;
	my $fd = redis_accept($l, $timeout);
	my $c = redis_expect($fd, ['AUTH', 'auth'], "+OK\r\n", "$n: probe AUTH with the data password");
	redis_expect($fd, ['ROLE'], undef, "$n: probe ROLE");
	probe_answer($fd, $node{fileno($l)}, $c->[1]);
}

# for a while, answer every probe on these listeners, whatever arrives
sub serve_probes {
	my ($secs, @l) = @_;
	my $end = time() + $secs;
	while ((my $left = $end - time()) > 0) {
		my $rin = '';
		vec($rin, fileno($_), 1) = 1 for @l;
		next unless select(my $rout = $rin, undef, undef, $left) > 0;
		for my $l (grep { vec($rout, fileno($_), 1) } @l) {
			my $fd = redis_accept($l);
			my $a = eval { redis_read($fd, 1) };
			redis_send($fd, "+OK\r\n") if $a;
			my $c = $a && eval { redis_read($fd, 1) };
			$c && $c->[0] eq 'ROLE' ? probe_answer($fd, $node{fileno($l)}, $a->[1]) : redis_close($fd);
		}
	}
}


# Fake Sentinels. The child re-reads a state file every 50 ms and logs every
# command it gets ("IP:PORT COMMAND ARG..."), plus "applied N" for each new
# state. Each Sentinel (IP, port 26379) is either "down" (not listening) or
# "MASTER_IP MASTER_PORT EPOCH [MONITORED_IP]": it names this master
# (GET-MASTER-ADDR-BY-NAME) at this config epoch (SENTINEL MASTER), whose
# "ip" is MONITORED_IP if given: a Sentinel running a failover reports the
# promoted replica in the former and still the old master in the latter.

my ($sentinel_pid, $sentinel_state, $sentinel_log, $sentinel_password);
my $serial = 0;

sub sentinel_log {
	open(my $fh, '<', "$sentinel_log") or die;
	local $/;
	return <$fh> // '';
}

# how many times this Sentinel was asked for the master
sub sentinel_queries {
	my $ip = shift;
	my @l = sentinel_log() =~ /^\Q$ip\E:26379 SENTINEL MASTER mymaster$/mg;
	return scalar(@l);
}

# set what the Sentinels answer (IP => state), and wait until it is applied
sub sentinels_set {
	my %st = @_;
	$serial++;
	open(my $fh, '>', "$sentinel_state.new") or die;
	print $fh "serial $serial\npassword $sentinel_password\n";
	print $fh "$_:26379 $st{$_}\n" for sort(keys(%st));
	close($fh);
	rename("$sentinel_state.new", "$sentinel_state") or die;
	return unless $sentinel_pid;
	for (1 .. 100) {
		return if sentinel_log() =~ /^applied $serial$/m;
		sleep(0.05);
	}
	die "fake Sentinels did not apply state $serial\n";
}

sub sentinels_start {
	($sentinel_password, my %st) = @_;
	$sentinel_state = File::Temp->new(TEMPLATE => 'rtpe-sentinel-state.XXXXXXXXXX', TMPDIR => 1);
	$sentinel_log = File::Temp->new(TEMPLATE => 'rtpe-sentinel-log.XXXXXXXXXX', TMPDIR => 1);
	sentinels_set(%st);
	$sentinel_pid = fork() // die;
	if (!$sentinel_pid) {
		exec($^X, (map { "-I$_" } grep { !ref($_) } @INC), '-MNGCP::Rtpengine::FakeRedis',
			'-e', 'NGCP::Rtpengine::FakeRedis::sentinel_main(@ARGV)',
			"$sentinel_state", "$sentinel_log") or die;
	}
	sentinels_set(%st);
}

END {
	if ($sentinel_pid) {
		kill('TERM', $sentinel_pid);
		waitpid($sentinel_pid, 0);
	}
}

# the child
sub sentinel_main {
	my ($statefile, $logfile) = @_;
	open(my $log, '>>', $logfile) or die;
	$log->autoflush(1);
	my $done = 0;
	$SIG{TERM} = sub { $done = 1 };
	$SIG{PIPE} = 'IGNORE';
	my (%sentinels, %clients, $password);
	my $applied = -1;

	my $read_state = sub {
		open(my $fh, '<', $statefile) or return;
		my ($ser, %want);
		while (my $l = <$fh>) {
			my @f = split(' ', $l);
			if ($f[0] eq 'serial') { $ser = $f[1] }
			elsif ($f[0] eq 'password') { $password = $f[1] }
			else { $want{$f[0]} = [ @f[1 .. $#f] ] }
		}
		close($fh);
		for my $s (keys(%want)) {
			my $st = $sentinels{$s} //= { };
			$st->{state} = $want{$s};
			if ($want{$s}[0] eq 'down') {
				close(delete($st->{listener})) if $st->{listener};
			}
			elsif (!$st->{listener}) {
				my ($ip, $port) = split(/:/, $s);
				$st->{listener} = redis_listen($ip, $port);
			}
		}
		# a Sentinel that goes down closes its clients too
		for my $fn (keys(%clients)) {
			next if $sentinels{$clients{$fn}{sentinel}}{listener};
			close($clients{$fn}{fh});
			delete($clients{$fn});
		}
		if (defined($ser) && $ser != $applied) {
			$applied = $ser;
			print $log "applied $ser\n";
		}
	};

	my $reply = sub {
		my ($c, $args) = @_;
		my $st = $sentinels{$c->{sentinel}}{state};
		print $log "$c->{sentinel} @$args\n";
		my $cmd = uc($args->[0]) . ' ' . uc($args->[1] // '');
		if ($cmd =~ /^AUTH /) {
			return "-WRONGPASS invalid username-password pair\r\n" if $args->[-1] ne $password;
			$c->{authed} = 1;
			return "+OK\r\n";
		}
		return "-NOAUTH Authentication required.\r\n" unless $c->{authed};
		return "-ERR No such master with that name\r\n" if ($args->[2] // '') ne 'mymaster';
		my ($ip, $port, $epoch, $monitored) = @$st;
		return "*2\r\n" . bulk($ip) . bulk($port) if $cmd eq 'SENTINEL GET-MASTER-ADDR-BY-NAME';
		my @kv = (name => 'mymaster', ip => $monitored // $ip, port => $port, flags => 'master',
			'num-slaves' => 2, 'num-other-sentinels' => 2, quorum => 2, 'config-epoch' => $epoch);
		return '*' . scalar(@kv) . "\r\n" . join('', map { bulk($_) } @kv) if $cmd eq 'SENTINEL MASTER';
		return "-ERR unknown command\r\n";
	};

	$read_state->();
	while (!$done) {
		my $rin = '';
		my %l = map { fileno($_->{listener}) => $_ } grep { $_->{listener} } values(%sentinels);
		vec($rin, $_, 1) = 1 for (keys(%l), keys(%clients));
		if (select(my $rout = $rin, undef, undef, 0.05) > 0) {
			for my $fn (grep { vec($rout, $_, 1) } keys(%l)) {
				my ($s) = grep { $sentinels{$_} == $l{$fn} } keys(%sentinels);
				accept(my $fh, $l{$fn}{listener}) or next;
				$clients{fileno($fh)} = { fh => $fh, buf => '', sentinel => $s };
			}
			for my $fn (grep { vec($rout, $_, 1) } keys(%clients)) {
				my $c = $clients{$fn};
				my $data;
				if (!sysread($c->{fh}, $data, 65536)) {
					close($c->{fh});
					delete($clients{$fn});
					next;
				}
				$c->{buf} .= $data;
				while (my $args = parse_cmd(\$c->{buf})) {
					syswrite($c->{fh}, $reply->($c, $args));
				}
			}
		}
		$read_state->();
	}
	exit(0);
}

1;
