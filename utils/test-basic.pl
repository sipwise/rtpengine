#!/usr/bin/perl

use strict;
use warnings;
use Rtpengine::Test;

my $r = Rtpengine::Test->new();
my $a = $r->client();
my $b = $r->client();

$r->timer_once(3, sub { $b->answer($a, ICE => 'remove') });

$a->offer($b, ICE => 'remove');

$r->run();
