#!/usr/bin/perl

use strict;
use warnings;
use Socket;

$| = 1;

open(F, "> /proc/mediaproxy/1/control");
{
	my $x = select(F);
	$| = 1;
	select($x);
}
#print F (pack("I SS LLSS LS S", 0, 0, -1, 0, 0, 0, 0, 0, 0, -1));
#sleep(10);

print("add 9876 -> 1234/6543\n");
syswrite(F, pack("I SS a4a4 SS a4 S S", 1, 9876, -1, inet_aton("192.168.231.132"), inet_aton("192.168.231.1"), 1234, 6543, "", 0, -1));
sleep(30);

print("add fail\n");
syswrite(F, pack("I SS a4a4 SS a4 S S", 1, 9876, -1, inet_aton("192.168.231.132"), inet_aton("192.168.231.1"), 1234, 6543, inet_aton("192.168.231.1"), 6789, -1));
sleep(30);

print("update 9876 -> 1234/6543 & 6789\n");
syswrite(F, pack("I SS a4a4 SS a4 S S", 3, 9876, -1, inet_aton("192.168.231.132"), inet_aton("192.168.231.1"), 1234, 6543, inet_aton("192.168.231.1"), 6789, -1));
sleep(30);

print("update 9876 -> 2345/7890 & 4321\n");
syswrite(F, pack("I SS a4a4 SS a4 S S", 3, 9876, -1, inet_aton("192.168.231.132"), inet_aton("192.168.231.1"), 2345, 7890, inet_aton("192.168.231.1"), 4321, -1));
sleep(30);

print("add fail\n");
syswrite(F, pack("I SS a4a4 SS a4 S S", 1, 9876, -1, inet_aton("192.168.231.132"), inet_aton("192.168.231.1"), 1234, 6543, inet_aton("192.168.231.1"), 6789, -1));
sleep(30);

print("update 9876 -> 1234/6543\n");
syswrite(F, pack("I SS a4a4 SS a4 S S", 3, 9876, -1, inet_aton("192.168.231.132"), inet_aton("192.168.231.1"), 1234, 6543, "", 0, -1));
sleep(30);

print("delete\n");
syswrite(F, pack("I SS a4a4 SS a4 S S", 2, 9876, -1, "", "", 0, 0, "", 0, -1));
sleep(30);

print("delete fail\n");
syswrite(F, pack("I SS a4a4 SS a4 S S", 2, 9876, -1, "", "", 0, 0, "", 0, -1));
sleep(30);

print("update fail\n");
syswrite(F, pack("I SS a4a4 SS a4 S S", 3, 9876, -1, inet_aton("192.168.231.132"), inet_aton("192.168.231.1"), 1234, 6543, "", 0, -1));
sleep(30);

close(F);
