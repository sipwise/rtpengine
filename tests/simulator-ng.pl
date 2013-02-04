#!/usr/bin/perl

use strict;
use warnings;
use Socket;
use UUID;
use BSD::Resource;
use Getopt::Long;
use Socket6;
use Bencode qw( bencode bdecode );

my ($NUM, $RUNTIME, $STREAMS) = (1000, 30, 1);
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
		'max-streams=i'	=> \$STREAMS,
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
	my ($d) = @_;
	my $l = bencode($d);
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
	return $r ? bdecode($r, 1) : undef;
}

socket($fd, AF_INET, SOCK_DGRAM, 0) or die $!;
connect($fd, sockaddr_in(2223, inet_aton("127.0.0.1"))) or die $!;

msg({command => 'ping'})->{result} eq 'pong' or die;

my (@calls, %branches);

sub do_rtp {
	print("sending rtp\n");
	for my $c (@calls) {
		$c or next;
		my ($fds,$outputs,$protos) = @$c[0,4,6];
		for my $j (0 .. $#{$$fds[0]}) {
			for my $i ([0,1],[1,0]) {
				my ($a, $b) = @$i;
				my $pr = $$protos[$a];
				my $payload = rand_str(100);
				send($$fds[$a][$j], $payload, 0, $$pr{sockaddr}($$outputs[$b][$j][0],
					inet_pton($$pr{family}, $$outputs[$b][$j][1]))) or die $!;
				my $x;
				my $err = '';
				alarm(1);
				recv($$fds[$b][$j], $x, 0xffff, 0) or $err = "$!";
				alarm(0);
				$err && $err !~ /interrupt/i and die $err;
				if (($x || '') ne $payload) {
					warn("no rtp reply received, ports $$outputs[$b][$j][0] and $$outputs[$a][$j][0]");
					$KEEPGOING or undef($c);
				}
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
		family_str	=> 'IP4',
		direction	=> 'internal',
	},
	ipv6 => {
		code		=> 'E',
		family		=> AF_INET6,
		reply		=> '6',
		address		=> $IPV6,
		sockaddr	=> \&sockaddr_in6,
		family_str	=> 'IP6',
		direction	=> 'external',
	},
);
my @protos_avail;
$IP and push(@protos_avail, $proto_defs{ipv4});
$IPV6 and push(@protos_avail, $proto_defs{ipv6});
my @sides = qw(A B);

sub callid {
	my $i = rand_str(50);
	$BRANCHES or return [$i];
	rand() < .5 and return [$i];
	if (rand() < .5) {
		my @k = keys(%branches);
		@k and $i = $k[rand(@k)];
	}
	my $b = rand_str(20);
	push(@{$branches{$i}}, $b);
	return [$i, $b];
}

sub update_lookup {
	my ($c, $i) = @_;
	my $j = $i ^ 1;

	my $c_v = $$c[5] || ($$c[5] = callid());
	my ($callid, $viabranch) = @$c_v;

	my $protos = $$c[6] || ($$c[6] = []);
	my $fds_a = $$c[0] || ($$c[0] = []);
	for my $x (0,1) {
		$$protos[$x] and next;
		$$protos[$x] = $protos_avail[rand(@protos_avail)];
		undef($$fds_a[$x]);
	}
	my ($pr, $pr_o) = @$protos[$i, $j];
	my @commands = qw(offer answer);

	my $ports_a = $$c[1] || ($$c[1] = []);
	my $ports_t = $$ports_a[$i] || ($$ports_a[$i] = []);
	my $ips_a = $$c[2] || ($$c[2] = []);
	my $ips_t = $$ips_a[$i] || ($$ips_a[$i] = []);
	my $fds_t = $$fds_a[$i] || ($$fds_a[$i] = []);
	my $fds_o = $$fds_a[$j];
	my $num_streams = int(rand($STREAMS));
	($fds_o && @$fds_o) and $num_streams = $#$fds_o;
	for my $j (0 .. $num_streams) {
		if (!$$fds_t[$j]) {
			socket($$fds_t[$j], $$pr{family}, SOCK_DGRAM, 0) or die $!;
			while (1) {
				my $port = rand(0x7000) << 1 + 1024;
				bind($$fds_t[$j], $$pr{sockaddr}($port,
					inet_pton($$pr{family}, $$pr{address}))) and last;
			}
			my $addr = getsockname($$fds_t[$j]);
			my $ip;
			($$ports_t[$j], $ip) = $$pr{sockaddr}($addr);
			$$ips_t[$j] = inet_ntop($$pr{family}, $ip);
		}
	}

	my $tags = $$c[3] || ($$c[3] = []);
	$$tags[$i] or $$tags[$i] = rand_str(15);

	my $sdp = <<"!";
v=0
o=blah 123 123 IN $$pr{family_str} $$ips_t[0]
s=session
c=IN $$pr{family_str} $$ips_t[0]
t=0 0
!
	for my $p (@$ports_t) {
		$sdp .= <<"!";
m=audio $p RTP/AVP 8
a=rtpmap:8 PCMA/8000
!
	}

	my $dict = {sdp => $sdp, command => $commands[$i], 'call-id' => $callid,
		'from-tag' => $$tags[0],
		flags => [ qw( trust-address ) ],
		replace => [ qw( origin session-connection ) ],
		direction => [ $$pr{direction}, $$pr_o{direction} ],
		'received-from' => [ qw(IP4 127.0.0.1) ],
	};
	$viabranch and $dict->{'via-branch'} = $viabranch;
	$i == 1 and $dict->{'to-tag'} = $$tags[1];

	my $o = msg($dict);
	$$o{result} eq 'ok' or die;
	my ($rp_af, $rp_add) = $$o{sdp} =~ /c=IN IP([46]) (\S+)/s or die;
	my @rp_ports = $$o{sdp} =~ /m=audio (\d+)/gs or die;
	$rp_af ne $$pr_o{reply} and die "incorrect address family reply code";
	my $rpl_a = $$c[4] || ($$c[4] = []);
	my $rpl_t = $$rpl_a[$i] || ($$rpl_a[$i] = []);
	for my $rpl (@rp_ports) {
		$rpl == 0 and die "mediaproxy ran out of ports";
		push(@$rpl_t, [$rpl,$rp_add]);
	}
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
		print("simulating re-invite on $$c[5][0]");
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
		my ($tags, $c_v) = @$c[3,5];
		my ($callid, $viabranch) = @$c_v;
		my $dict = { command => 'delete', 'call-id' => $callid, 'from-tag' => $$tags[0],
			'to-tag' => $$tags[1],
		};
		$BRANCHES && rand() < .7 and $$dict{'via-branch'} = $viabranch;
		msg($dict);
	}
}
print("done\n");
