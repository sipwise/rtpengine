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

my ($src, $sink);
my $pid = open3($sink, $src, '>&STDERR', @ARGV) or die;

my ($playsrc, $playsink);
open($playsrc, '|-', qw(play -q -c 1 -e a-law -r 8000 -t raw -)) or die;
open($playsink, '|-', qw(play -q -c 1 -e a-law -r 8000 -t raw -)) or die;

my $lseq = rand(65536);
my $lssrc = rand(65536);
my $lts = rand(2*32);
my $lpt = 8; # PCMA
my $lmark = 0x80;
my $rseq = -1;
my $rts = -1;

while (1) {
	my $buf;

	last unless sysread($src, $buf = '', 160);
	syswrite($playsrc, $buf);

	my $rtp = pack('CCnNN a*', 0x80, $lpt | $lmark, $lseq, $lts, $lssrc, $buf);
	last unless $sock->syswrite($rtp) or last;
	$lseq++;
	$lts += 160;
	$lmark = 0x00;

	last unless $sock->sysread($buf = '', 0xffff);

	my ($ver, $rpt, $seq, $ts, $rssrc, $payload) = unpack('CCnNN a*', $buf);
	die unless length($payload) == 160;
	die unless ($rpt & 0x7f) == $lpt;
	die unless ($rseq == -1 || (($rseq + 1) & 0xffff) == $seq);
	die unless ($rts == -1 || (($rts + 160) & 0xffffffff) == $ts);
	syswrite($playsink, $payload);
	$rseq = $seq;
	$rts = $ts;

	last unless syswrite($sink, $payload);
}
