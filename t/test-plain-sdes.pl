#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use IO::Socket;

my $r = NGCP::Rtpengine::Test->new();
my ($a, $b) = $r->client_pair(
	{},
	{sdes => 1}
);

@{$b->{sdes}->{suites}} >= 7 or die; # all that we support

$r->timer_once(10, sub { $r->stop(); });

$a->offer($b, ICE => 'remove', 'transport-protocol' => 'RTP/SAVP');

@{$b->{sdes}->{remote_suites}} >= 7 or die; # all that we support
$b->{sdes}->trim();
@{$b->{sdes}->{remote_suites}} == 1 or die; # just 1 for answer
@{$b->{sdes}->{suites}} == 1 or die; # just 1 for answer

$b->answer($a, ICE => 'remove');

@{$b->{sdes}->{remote_suites}} == 1 or die; # just 1 answer
@{$b->{sdes}->{suites}} == 1 or die; # just 1 after negotiation

$a->start_rtp();
$a->start_rtcp();
$b->start_rtp();
$b->start_rtcp();

$r->run();

$a->teardown();
