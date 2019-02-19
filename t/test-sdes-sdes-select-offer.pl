#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use IO::Socket;

my $r = NGCP::Rtpengine::Test->new();
my ($a, $b) = $r->client_pair(
	{sdes => 1, sdes_args => {suites => [qw(
		AES_256_CM_HMAC_SHA1_80 AES_256_CM_HMAC_SHA1_32
		AES_CM_128_HMAC_SHA1_80 AES_CM_128_HMAC_SHA1_32
	)]}},
	{sdes => 1}
);

@{$a->{sdes}->{suites}} == 4 or die; # the ones we selected
@{$b->{sdes}->{suites}} >= 7 or die; # all that we support

$r->timer_once(10, sub { $r->stop(); });

$a->offer($b, ICE => 'remove');

@{$a->{sdes}->{suites}} == 4 or die; # the ones we selected

@{$b->{sdes}->{remote_suites}} >= 7 or die; # all that we support (our selected + added by rtpengine)
$b->{sdes}->trim();
@{$b->{sdes}->{remote_suites}} == 1 or die; # just 1 for answer
@{$b->{sdes}->{suites}} == 1 or die; # just 1 for answer

$b->answer($a, ICE => 'remove');

@{$a->{sdes}->{remote_suites}} == 1 or die; # just 1 answer
@{$a->{sdes}->{suites}} == 1 or die; # just 1 after negotiation

@{$b->{sdes}->{remote_suites}} == 1 or die; # just 1 answer
@{$b->{sdes}->{suites}} == 1 or die; # just 1 after negotiation

$a->start_rtp();
$a->start_rtcp();
$b->start_rtp();
$b->start_rtcp();

$r->run();

$a->teardown();
