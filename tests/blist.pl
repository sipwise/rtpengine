#!/usr/bin/perl

use strict;
use warnings;
use Socket;
use Socket6;

my $t = $ARGV[0] || "0";

my $format = 'SS ia16SS ia16SS ia16SS CCCC   LLLLLL';
my $len = length(pack($format, (0) x 100));

open(my $fh, "<", "/proc/rtpengine/$t/blist") or die;
my $buf;
while (sysread($fh, $buf, $len)) {
	my @buf = unpack($format, $buf);
	for (2,6,10) {
		if ($buf[$_] == AF_INET) {
			$buf[$_ + 1] = inet_ntoa($buf[$_ + 1]);
		}
		elsif ($buf[$_] == AF_INET6) {
			$buf[$_ + 1] = inet_ntop(AF_INET6, $buf[$_ + 1]);
		}
		elsif ($buf[$_] == 0) {
			$buf[$_ + 1] = '---';
		}
	}
	for (18, 20, 22) {
		$buf[$_] += $buf[$_ + 1] * 2**32;
	}
	printf("%5u %15s:%-5u -> %15s:%-5u (-> %15s:%-5u) [%u] [%llu %llu %llu]\n", @buf[0,3,4,7,8,11,12,14,18,20,22]);
}
close($fh);
