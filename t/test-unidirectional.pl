#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use IO::Socket;

my $r = NGCP::Rtpengine::Test->new(host => '192.168.1.128');
my ($a, $b) = $r->client_pair(
	{sockdomain => &Socket::AF_INET},
	{sockdomain => &Socket::AF_INET}
);

$r->timer_once(3, sub { $b->answer($a, ICE => 'remove', flags => ['unidirectional']); });
$r->timer_once(10, sub { $r->stop(); });

$a->offer($b, ICE => 'remove', flags => ['unidirectional']);
$b->start_rtp();

$r->run();

$a->teardown();
