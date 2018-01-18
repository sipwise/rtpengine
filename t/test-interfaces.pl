#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use IO::Socket;

my $iterations = 10;
my @interfaces = qw(int ext);
my @domains = (&Socket::AF_INET);

my $r = NGCP::Rtpengine::Test->new(media_port => 50000);

for my $a_domain (@domains) {
	for my $b_domain (@domains) {
		if (!@interfaces) {
			for (1 .. $iterations) {
				run_test([], $a_domain, $b_domain);
			}
		}
		else {
			for my $a_interface (@interfaces) {
				for my $b_interface (@interfaces) {
					for (1 .. $iterations) {
						run_test([$a_interface, $b_interface], $a_domain, $b_domain);
					}
				}
			}
		}
	}
}

sub run_test {
	my ($directions, $a_domain, $b_domain) = @_;
	print("Testing directions @{$directions} between $a_domain and $b_domain\n");

	my ($a, $b) = $r->client_pair(
		{sockdomain => $a_domain},
		{sockdomain => $b_domain}
	);

	print("Offering with address:  " . $a->{sockets}->[0]->[0]->sockhost . "\n");
	my %dir_arg = ();
	$dir_arg{direction} = $directions if @{$directions};
	$a->offer($b, ICE => 'remove', label => "caller", %dir_arg);
	print("Offer out with address: " . $b->{remote_media}->connection->{address} . "\n");

	print("Answering with address:  " . $b->{sockets}->[0]->[0]->sockhost . "\n");
	$b->answer($a, ICE => 'remove', label => "callee");
	print("Answer out with address: " . $a->{remote_media}->connection->{address} . "\n");

	$a->teardown();

	print("\n");
}
