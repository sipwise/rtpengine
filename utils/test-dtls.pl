#!/usr/bin/perl

use strict;
use warnings;
use Rtpengine;

my $r = Rtpengine::Test->new();
my $a = $r->client(dtls => 1);
my $b = $r->client();

$r->timer_once(3, sub { $b->answer($a) });

$a->offer($b, 'transport-protocol' => 'RTP/AVP');

$r->run();
