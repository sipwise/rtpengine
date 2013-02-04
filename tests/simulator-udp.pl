#!/usr/bin/perl

use strict;
use warnings;
use Socket;
use UUID;
use BSD::Resource;
use Getopt::Long;
use Socket6;

my ($NUM, $RUNTIME) = (1000, 30);
my ($NODEL, $IP, $IPV6, $KEEPGOING, $REINVITES, $BRANCHES);
GetOptions(
		'no-delete'	=> \$NODEL,
		'num-calls=i'	=> \$NUM,
		'local-ip=s'	=> \$IP,
		'local-ipv6=s'	=> \$IPV6,
		'runtime=i'	=> \$RUNTIME,
		'keep-going'	=> \$KEEPGOING,		# don't stop sending rtp if a packet doesn't go through
		'reinvites'	=> \$REINVITES,
		'branches'	=> \$BRANCHES,
) or die;

($IP || $IPV6) or die("at least one of --local-ip or --local-ipv6 must be given");

$SIG{ALRM} = sub { print "alarm!\n"; };
setrlimit(RLIMIT_NOFILE, 8000, 8000);

my @chrs = ('a' .. 'z', 'A' .. 'Z', '0' .. '9');
sub rand_str {
	my ($len) = @_;
	return join('', (map {$chrs[rand(@chrs)]} (1 .. $len)));
}

my $fd;
sub msg {
	my ($l) = @_;
	my $cookie = $$ . '_' . rand_str(10);
	my $r;
	while (1) {
		send($fd, "$cookie $l", 0) or die $!;
		my $err = '';
		alarm(1);
		recv($fd, $r, 0xffff, 0) or $err = "$!";
		alarm(0);
		$err =~ /interrupt/i and next;
		$err and die $err;
		last;
	}
	$r =~ s/^\Q$cookie\E +//s or die $r;
	$r =~ s/[\r\n]+$//s;
	return $r;
}

socket($fd, AF_INET, SOCK_DGRAM, 0) or die $!;
connect($fd, sockaddr_in(2222, inet_aton("127.0.0.1"))) or die $!;

msg('V') eq '20040107' or die;

my (@calls, %branches);

sub do_rtp {
	print("sending rtp\n");
	for my $c (@calls) {
		$c or next;
		my ($fds,$outputs,$protos) = @$c[0,4,6];
		for my $i ([0,1],[1,0]) {
			my ($a, $b) = @$i;
			my $pr = $$protos[$a];
			my $payload = rand_str(100);
			send($$fds[$a], $payload, 0, $$pr{sockaddr}($$outputs[$b][0],
				inet_pton($$pr{family}, $$outputs[$b][1]))) or die $!;
			my $x;
			my $err = '';
			alarm(1);
			recv($$fds[$b], $x, 0xffff, 0) or $err = "$!";
			alarm(0);
			$err && $err !~ /interrupt/i and die $err;
			if (($x || '') ne $payload) {
				warn("no rtp reply received, ports $$outputs[$b][0] and $$outputs[$a][0]");
				$KEEPGOING or undef($c);
			}
		}
	}
}

my %proto_defs = (
	ipv4 => {
		code		=> 'I',
		family		=> AF_INET,
		reply		=> '4',
		address		=> $IP,
		sockaddr	=> \&sockaddr_in,
	},
	ipv6 => {
		code		=> 'E',
		family		=> AF_INET6,
		reply		=> '6',
		address		=> $IPV6,
		sockaddr	=> \&sockaddr_in6,
	},
);
my @protos_avail;
$IP and push(@protos_avail, $proto_defs{ipv4});
$IPV6 and push(@protos_avail, $proto_defs{ipv6});
my @sides = qw(A B);

sub callid {
	my $i = rand_str(50);
	$BRANCHES or return $i;
	rand() < .5 and return $i;
	if (rand() < .5) {
		my @k = keys(%branches);
		@k and $i = $k[rand(@k)];
	}
	my $b = rand_str(20);
	push(@{$branches{$i}}, $b);
	return "$i;$b";
}

sub update_lookup {
	my ($c, $i) = @_;
	my $j = $i ^ 1;

	my $callid = $$c[5] || ($$c[5] = callid());

	my $protos = $$c[6] || ($$c[6] = []);
	my $fds = $$c[0] || ($$c[0] = []);
	for my $x (0,1) {
		$$protos[$x] and next;
		$$protos[$x] = $protos_avail[rand(@protos_avail)];
		undef($$fds[$x]);
	}
	my ($pr, $pr_o) = @$protos[$i, $j];
	my @prefixes = qw(US LS);
	$prefixes[0] .= join('', (map {$_->{code}} @$protos));

	my $ports = $$c[1] || ($$c[1] = []);
	my $ips = $$c[2] || ($$c[2] = []);
	if (!$$fds[$i]) {
		socket($$fds[$i], $$pr{family}, SOCK_DGRAM, 0) or die $!;
		while (1) {
			my $port = rand(0x7000) << 1 + 1024;
			bind($$fds[$i], $$pr{sockaddr}($port,
				inet_pton($$pr{family}, $$pr{address}))) and last;
		}
		my $addr = getsockname($$fds[$i]);
		my $ip;
		($$ports[$i], $ip) = $$pr{sockaddr}($addr);
		$$ips[$i] = inet_ntop($$pr{family}, $ip);
	}

	my $tags = $$c[3] || ($$c[3] = []);
	$$tags[$i] or $$tags[$i] = rand_str(15);

	my $tagstr = ($i == 1 ? "$$tags[0];1 " : '') . "$$tags[$i];1";
	my $o = msg("$prefixes[$i] $callid $$ips[$i] $$ports[$i] $tagstr");
	$o =~ /^(\d+) ([\d.a-f:]+) ([46])[\r\n]*$/is or die $o;
	$1 == 0 and die "mediaproxy ran out of ports";
	$3 ne $$pr_o{reply} and die "incorrect address family reply code";
	$$c[4][$i] = [$1,$2];
}

for my $iter (1 .. $NUM) {
	($iter % 10 == 0) and print("$iter\n"), do_rtp();

	my $c = [];
	update_lookup($c, 0);
	update_lookup($c, 1);
	push(@calls, $c);
}

my $end = time() + $RUNTIME;
while (time() < $end) {
	sleep(1);
	do_rtp();

	@calls = sort {rand() < .5} grep(defined, @calls);

	if ($REINVITES) {
		my $c = $calls[rand(@calls)];
		print("simulating re-invite on $$c[5]");
		for my $i (0,1) {
			if (rand() < .5) {
				print(", side $sides[$i]: new port");
				undef($$c[0][$i]);
			}
			else {
				print(", side $sides[$i]: same port");
			}
		}
		print("\n");
		update_lookup($c, 0);
		update_lookup($c, 1);
	}
}

if (!$NODEL) {
	print("deleting\n");
	for my $c (@calls) {
		$c or next;
		my ($tags, $callid) = @$c[3,5];
		$BRANCHES && rand() < .3 and $callid =~ s/;.*//;
		msg("D $callid $$tags[0] $$tags[1]");
	}
}
print("done\n");
