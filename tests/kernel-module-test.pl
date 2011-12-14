#!/usr/bin/perl

use strict;
use warnings;
use Socket;
use Socket6;

my %cmds = (noop => 1, add => 2, delete => 3, update => 4);
$| = 1;

open(F, "> /proc/mediaproxy/1/control");
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

my @src = qw(inet 192.168.231.132);
my @dst = qw(inet 192.168.231.1);
my @nul = ('', '', '');

print("add 9876 -> 1234/6543\n");
syswrite(F, mediaproxy_message('add', 9876, @src, 1234, @dst, 6543, @nul, 184));
sleep(30);

print("add fail\n");
syswrite(F, mediaproxy_message('add', 9876, @src, 1234, @dst, 6543, @dst, 6789, 184));
sleep(30);

print("update 9876 -> 1234/6543 & 6789\n");
syswrite(F, mediaproxy_message('update', 9876, @src, 1234, @dst, 6543, @dst, 6789, 184));
sleep(30);

print("update 9876 -> 2345/7890 & 4321\n");
syswrite(F, mediaproxy_message('update', 9876, @src, 2345, @dst, 7890, @dst, 4321, 184));
sleep(30);

print("add fail\n");
syswrite(F, mediaproxy_message('add', 9876, @src, 1234, @dst, 6543, @dst, 6789, 184));
sleep(30);

print("update 9876 -> 1234/6543\n");
syswrite(F, mediaproxy_message('update', 9876, @src, 1234, @dst, 6543, @nul, 184));
sleep(30);

print("delete\n");
syswrite(F, mediaproxy_message('delete', 9876, @nul, @nul, @nul, 0));
sleep(30);

print("delete fail\n");
syswrite(F, mediaproxy_message('delete', 9876, @nul, @nul, @nul, 0));
sleep(30);

print("update fail\n");
syswrite(F, mediaproxy_message('update', 9876, @src, 1234, @dst, 6543, @nul, 184));
sleep(30);

close(F);
