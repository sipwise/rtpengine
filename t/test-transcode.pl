#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use IO::Socket;

my $r = NGCP::Rtpengine::Test->new();
my ($a, $b) = $r->client_pair(
	{sockdomain => &Socket::AF_INET, codecs => [qw(PCMU)], no_data_check => 1},
	{sockdomain => &Socket::AF_INET, codecs => [qw(G722)], no_data_check => 1}
);

$r->timer_once(3, sub {
		$b->answer($a, ICE => 'remove', label => "callee");
		$a->remote_codecs() eq 'PCMU/8000/1' or die;
		$a->send_codecs() eq 'PCMU/8000/1' or die;
		$a->start_rtp();
		$a->start_rtcp();
	});
$r->timer_once(10, sub { $r->stop(); });

$a->offer($b, ICE => 'remove', label => "caller", codec => { transcode => ['G722']}, flags => [qw(record-call)]);
$b->remote_codecs() eq 'PCMU/8000/1,G722/8000/1' or die;
$b->send_codecs() eq 'G722/8000/1' or die;
$b->start_rtp();
$b->start_rtcp();

$r->run();

$a->teardown(dump => 1);
