#!/usr/bin/perl

use strict;
use warnings;
use Socket;
use Socket6;

my %cmds = (noop => 1, add => 2, delete => 3, update => 4);
$| = 1;

open(F, "> /proc/mediaproxy/0/control") or die;
{
	my $x = select(F);
	$| = 1;
	select($x);
}

sub mp_address {
	my ($fam, $addr, $port) = @_;

	if ($fam eq 'inet') {
		return pack('i a4 a12 S S', 2, inet_aton($addr), '', $port, 0);
	}
	if ($fam eq 'inet6') {
		return pack('i a16 S S', 10, inet_pton(AF_INET6, $addr), $port, 0);
	}
	if ($fam eq '') {
		return pack('i a16 S S', 0, '', 0, 0);
	}

	die;
}
sub mediaproxy_message {
	my ($cmd, $target_port,
		$src_addr_family, $src_addr_addr, $src_addr_port,
		$dst_addr_family, $dst_addr_addr, $dst_addr_port,
		$mirror_addr_family, $mirror_addr_addr, $mirror_addr_port,
		$tos) = @_;

	my $ret = '';

	$ret .= pack('I SS', $cmds{$cmd}, $target_port, 0);
	$ret .= mp_address($src_addr_family, $src_addr_addr, $src_addr_port);
	$ret .= mp_address($dst_addr_family, $dst_addr_addr, $dst_addr_port);
	$ret .= mp_address($mirror_addr_family, $mirror_addr_addr, $mirror_addr_port);
	$ret .= pack('C CS', $tos, 0, 0);
}

my $sleep = 5;
#my @src = qw(inet 10.15.20.61);
#my @dst = qw(inet 10.15.20.58);
my @src = qw(inet6 2a00:4600:1:0:a00:27ff:feb0:f7fe);
my @dst = qw(inet6 2a00:4600:1:0:6884:adff:fe98:6ac5);
my @nul = ('', '', '');

print("add 9876 -> 1234/6543\n");
syswrite(F, mediaproxy_message('add', 9876, @src, 1234, @dst, 6543, @nul, 184));
sleep($sleep);

print("add fail\n");
syswrite(F, mediaproxy_message('add', 9876, @src, 1234, @dst, 6543, @dst, 6789, 184));
sleep($sleep);

print("update 9876 -> 1234/6543 & 6789\n");
syswrite(F, mediaproxy_message('update', 9876, @src, 1234, @dst, 6543, @dst, 6789, 184));
sleep($sleep);

print("update 9876 -> 2345/7890 & 4321\n");
syswrite(F, mediaproxy_message('update', 9876, @src, 2345, @dst, 7890, @dst, 4321, 184));
sleep($sleep);

print("add fail\n");
syswrite(F, mediaproxy_message('add', 9876, @src, 1234, @dst, 6543, @dst, 6789, 184));
sleep($sleep);

print("update 9876 -> 1234/6543\n");
syswrite(F, mediaproxy_message('update', 9876, @src, 1234, @dst, 6543, @nul, 184));
sleep($sleep);

print("delete\n");
syswrite(F, mediaproxy_message('delete', 9876, @nul, @nul, @nul, 0));
sleep($sleep);

print("delete fail\n");
syswrite(F, mediaproxy_message('delete', 9876, @nul, @nul, @nul, 0));
sleep($sleep);

print("update fail\n");
syswrite(F, mediaproxy_message('update', 9876, @src, 1234, @dst, 6543, @nul, 184));
sleep($sleep);

close(F);
