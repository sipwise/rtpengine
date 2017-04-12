#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use IO::Socket;

my $r = NGCP::Rtpengine::Test->new();
my ($a, $b) = $r->client_pair(
	{
		sockdomain => &Socket::AF_INET,
		packetloss => 5,
	},
	{
		sockdomain => &Socket::AF_INET,
		packetloss => 10,
	}
);

$r->timer_once(1, sub {
		$b->answer($a, ICE => 'remove');
		$a->start_rtp();
		$a->start_rtcp();
	});
$r->timer_once(60, sub { $r->stop(); });

$a->offer($b, ICE => 'remove');
$b->start_rtp();
$b->start_rtcp();

$r->run();

$a->teardown(dump => 1);
