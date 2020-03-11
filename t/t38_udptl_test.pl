#!/usr/bin/perl

use strict;
use warnings;
use IPC::Open3;
use IO::Socket;
use IO::Socket::IP;

my $laddr = shift or die;
my $lport = shift or die;
my $raddr = shift or die;
my $rport = shift or die;

my $sock = IO::Socket::IP->new(Type => &SOCK_DGRAM, Proto => 'udp',
		LocalHost => $laddr, LocalPort => $lport,
		PeerHost => $raddr, PeerPort => $rport,
	)
		or die;

my $devnull;
die unless open($devnull, '>', '/dev/null');

my ($src, $sink);
my $pid = open3($sink, $src, ">&".fileno($devnull), @ARGV) or die;

my $lseq = 0;
my $rseq = 0;
my $srcbuf = '';

local $| = 1;

while (1) {
	my $rin = '';
	vec($rin, fileno($src), 1) = 1;
	while (select(my $rout = $rin, undef, undef, 0.01) == 1) {
		my $ret = sysread($src, my $buf, 1);
		last unless $ret;
		$srcbuf .= $buf;
		my ($seq_out, $len, $pkt) = unpack('SSa*', $srcbuf);
		next unless defined($pkt);
		next if length($pkt) < $len;

		substr($srcbuf, 0, $len + 4) = '';
		substr($pkt, $len) = '';

		my $udptl = pack('nCa*Ca*Ca*', $seq_out, length($pkt), $pkt, 0x00,
			'', 0, '');

		print('!');
		last unless $sock->syswrite($udptl);
	}

	$rin = '';
	vec($rin, fileno($sock), 1) = 1;
	while (select(my $rout = $rin, undef, undef, 0.01) == 1) {
		my $ret = $sock->sysread(my $buf, 0xffff);
		my ($seq, $len, $pkt) = unpack('nCa*', $buf);
		my $t38 = substr($pkt, 0, $len);

		print('.');
		last unless syswrite($sink, pack('SSa*', $seq, length($t38), $t38));
	}
}
