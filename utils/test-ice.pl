#!/usr/bin/perl

use strict;
use warnings;
use Rtpengine;

my $r = Rtpengine::Test->new();
my $a = $r->client(ice => 1);
my $b = $r->client();

$r->timer_once(3, sub { $b->answer($a) });

$a->offer($b, ICE => 'remove');

$r->run();
