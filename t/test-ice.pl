#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;

my $r = NGCP::Rtpengine::Test->new();
my $a = $r->client(ice => 1);
my $b = $r->client(sockdomain => &Socket::AF_INET);

$r->timer_once(3, sub { $b->answer($a) });
$r->timer_once(5, sub { $a->start_rtp(); $b->start_rtp(); });

$a->offer($b, ICE => 'remove', 'address-family' => 'IP4');

$r->run();
