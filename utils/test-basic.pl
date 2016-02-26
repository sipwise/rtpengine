#!/usr/bin/perl

use strict;
use warnings;
use Rtpengine;

my $r = Rtpengine::Test->new();
my $a = $r->client();
my $b = $r->client();

$r->timer_once(3, sub { $b->answer($a) });

$a->offer($b);

$r->run();
