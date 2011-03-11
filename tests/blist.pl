#!/usr/bin/perl

use strict;
use warnings;
use Socket;

my $t = $ARGV[0] || "0";

open(X, "<", "/proc/mediaproxy/$t/blist") or die;
my $buf;
while (sysread(X, $buf, 48)) {
	my @b = unpack("Sa2 a4a4 SS a4 Sa2   LLLLLL", $buf);
	for (2,3,6) {
		$b[$_] = inet_ntoa($b[$_]);
	}
	for (9,11,13) {
		$b[$_] += $b[$_ + 1] * 2**32;
	}
	printf("%5u %15s:%-5u -> %15s:%-5u (-> %15s:%-5u) [%llu %llu %llu]\n", @b[0,2,4,3,5,6,7,9,11,13]);
}
