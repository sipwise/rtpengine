#!/usr/bin/perl

use strict;
use warnings;
use Socket;
use UUID;
use BSD::Resource;

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
connect($fd, sockaddr_in(12222, inet_aton("127.0.0.1"))) or die $!;

msg('V') eq '20040107' or die;

my @calls;
for my $iter (1 .. 1000) {
	($iter % 10 == 0) and print("$iter\n");

	my $callid = rand_str(50);

	my @prefixes = qw(USII LS);
	my (@fds,@ports,@ips,@tags,@outputs);
	for my $i (0,1) {
		socket($fds[$i], AF_INET, SOCK_DGRAM, 0) or die $!;
		bind($fds[$i], sockaddr_in(0, INADDR_ANY)) or die $!;
		my $addr = getsockname($fds[$i]);
		($ports[$i]) = sockaddr_in($addr);
		$ips[$i] = '127.0.0.1';
		$tags[$i] = rand_str(15);
		my $o = msg("$prefixes[$i] $callid $ips[$i] $ports[$i] $tags[$i];1");
		$o =~ /^(\d+) ([\d.]+) 4[\r\n]*$/s or die $o;
		$outputs[$i] = [$1,$2];
	}

	push(@calls, [\(@fds,@ports,@ips,@tags,@outputs)]);

	for my $c (@calls) {
		my ($fds,$outputs) = @$c[0,4];
		for my $i ([0,1],[1,0]) {
			my ($a, $b) = @$i;
			send($$fds[$a], 'rtp', 0, sockaddr_in($$outputs[$b][0], inet_aton($$outputs[$b][1]))) or die $!;
			my $x;
			my $err = '';
			alarm(1);
			recv($$fds[$b], $x, 0xffff, 0) or $err = "$!";
			alarm(0);
			$err && $err !~ /interrupt/i and die $err;
			$x eq 'rtp' or die $x;
		}
	}
}
