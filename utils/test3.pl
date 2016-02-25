#!/usr/bin/perl

use strict;
use warnings;
use Rtpengine;
use Time::HiRes qw(time);

my ($r, $a, $b);

my $offer = time();
my $answer = $offer + 3;

my $answer_done = 0;
my $cb = sub {
	my ($now) = @_;
	if ($now >= $answer && !$answer_done) {
		$b->answer($a);
		$answer_done = 1;
	}
};

$r = Rtpengine::Test->new($cb);
$a = $r->client();
$b = $r->client();

$a->offer($b);
$r->run();
