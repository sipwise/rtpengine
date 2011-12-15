#!/usr/bin/perl

use strict;
use warnings;
use Socket;
use Socket6;

my $t = $ARGV[0] || "0";

my $format = 'SS ia16SS ia16SS ia16SS CCCC   LLLLLL';
my $len = length(pack($format, (0) x 100));

open(X, "<", "/proc/mediaproxy/$t/blist") or die;
my $buf;
while (sysread(X, $buf, $len)) {
	my @b = unpack($format, $buf);
	for (2,6,10) {
		if ($b[$_] == AF_INET) {
			$b[$_ + 1] = inet_ntoa($b[$_ + 1]);
		}
		elsif ($b[$_] == AF_INET6) {
			$b[$_ + 1] = inet_ntop(AF_INET6, $b[$_ + 1]);
		}
		elsif ($b[$_] == 0) {
			$b[$_ + 1] = '---';
		}
	}
	for (18, 20, 22) {
		$b[$_] += $b[$_ + 1] * 2**32;
	}
	printf("%5u %15s:%-5u -> %15s:%-5u (-> %15s:%-5u) [%u] [%llu %llu %llu]\n", @b[0,3,4,7,8,11,12,14,18,20,22]);
}
