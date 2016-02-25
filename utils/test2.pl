#!/usr/bin/perl

use strict;
use warnings;
use DTLS;
use RTP;
use SDP;
use Rtpengine;
use IO::Socket::IP;
use IO::Multiplex;
use Time::HiRes qw(time);
use List::Util;

my $mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);

# create local sockets for A and B sides

my @A_interfaces = qw(
	192.168.1.90
	10.10.8.18
	2001:470:1d:76c:feaa:14ff:fe97:be6b
	fdd5:725c:61d7:0:feaa:14ff:fe97:be6b
	2a02:1b8:7:1:803d:beff:fe69:fefd
);
my @B_interfaces = @A_interfaces;

@A_interfaces = List::Util::shuffle @A_interfaces;
@B_interfaces = List::Util::shuffle @B_interfaces;

my $sport = 2000;

my (@A_sockets, @B_sockets, @A_rtp, @A_rtcp, @B_rtp, @B_rtcp, @A_component_peers, @B_component_peers);

for my $a (@A_interfaces) {
	my $rtp = IO::Socket::IP->new(Type => SOCK_DGRAM, Proto => 'udp',
		LocalHost => $a, LocalPort => $sport++) or die($a);
	my $rtcp = IO::Socket::IP->new(Type => SOCK_DGRAM, Proto => 'udp',
		LocalHost => $a, LocalPort => $sport++) or die($a);
	print("local interface side A: " . $rtp->sockhost() . '/' . $rtp->sockport() . '/'
		. $rtcp->sockport() . "\n");
	push(@A_sockets, [$rtp, $rtcp]);
	push(@A_rtp, $rtp);
	push(@A_rtcp, $rtcp);
	$mux->add($rtp);
	$mux->add($rtcp);
	$mux->set_timeout($rtp, 0.01);
}

print("-\n");

for my $a (@B_interfaces) {
	my $rtp = IO::Socket::IP->new(Type => SOCK_DGRAM, Proto => 'udp',
		LocalHost => $a, LocalPort => $sport++) or die($a);
	my $rtcp = IO::Socket::IP->new(Type => SOCK_DGRAM, Proto => 'udp',
		LocalHost => $a, LocalPort => $sport++) or die($a);
	print("local interface side B: " . $rtp->sockhost() . '/' . $rtp->sockport() . '/'
		. $rtcp->sockport() . "\n");
	push(@B_sockets, [$rtp, $rtcp]);
	push(@B_rtp, $rtp);
	push(@B_rtcp, $rtcp);
	$mux->add($rtp);
	$mux->add($rtcp);
	$mux->set_timeout($rtp, 0.01);
}

# create outgoing SDP for side A

my $A_main = $A_sockets[0]; # for o= and m= line details
my $A_local_sdp = SDP->new($A_main->[0]); # no global connection given

# rtp and rtcp, everything else default
my $A_local_media = $A_local_sdp->add_media(SDP::Media->new($A_main->[0], $A_main->[1], 'RTP/SAVPF'));

# create side A DTLS clients

my $A_send_func = sub {
	my ($component, $s) = @_;
	$A_main->[$component]->send($s, 0, $A_component_peers[$component]);
};
my $A_dtls = DTLS::Group->new($mux, $A_send_func, [ \@A_rtp, \@A_rtcp ]);
$A_local_media->add_attrs($A_dtls->encode());
$A_dtls->accept();

# send side A SDP to rtpengine

my $A_local_sdp_body = $A_local_sdp->encode();
# XXX validate SDP

my $rtpengine = Rtpengine->new('localhost', 2223);

my $callid = rand();
my $fromtag = rand();
my $totag = rand();

print("doing rtpengine offer\n");
my $offer_sent = time();
my $A_offer = { command => 'offer', ICE => 'remove', 'call-id' => $callid, 'from-tag' => $fromtag,
	sdp => $A_local_sdp_body };

my $B_offer = $rtpengine->req($A_offer);
my $offer_done = time();

# decode incoming SDP for side B

my $B_remote_sdp_body = $B_offer->{sdp};
my $B_remote_sdp = SDP->decode($B_remote_sdp_body);
# XXX validate SDP
@{$B_remote_sdp->{medias}} == 1 or die;
my $B_remote_media = $B_remote_sdp->{medias}->[0];

# run the machine and simulate delayed answer

my $do_answer = time() + 3;

$mux->loop();



sub mux_input {
	my ($self, $mux, $fh, $input) = @_;
	my $peer = $mux->udp_peer($fh);
	#
	# keep track of peer addresses
	peer_addr_check($fh, $peer, \@A_rtp, \@A_component_peers, 0);
	peer_addr_check($fh, $peer, \@A_rtcp, \@A_component_peers, 1);

	$A_dtls->input($fh, $input, $peer);
}

sub mux_timeout {
	my ($self, $mux, $fh) = @_;

	if ($do_answer && time() >= $do_answer) {
		do_answer();
	}

	$mux->set_timeout($fh, 0.01);
}

sub do_answer {
	$do_answer = 0;

	# create answer from B to A

	my $B_main = $B_sockets[0]; # for o= and m= line details
	my $B_local_sdp = SDP->new($B_main->[0]); # no global connection given

	# rtp and rtcp, everything else default
	my $B_local_media = $B_local_sdp->add_media(SDP::Media->new($B_main->[0], $B_main->[1]));

	# send side A SDP to rtpengine
	my $B_local_sdp_body = $B_local_sdp->encode();
	# XXX validate SDP

	my $B_answer = { command => 'answer', ICE => 'remove', 'call-id' => $callid, 'from-tag' => $fromtag,
		'to-tag' => $totag, sdp => $B_local_sdp_body };

	print("doing rtpengine answer\n");
	my $A_answer = $rtpengine->req($B_answer);

	# decode incoming SDP for side A

	my $A_remote_sdp_body = $A_answer->{sdp};
	my $A_remote_sdp = SDP->decode($A_remote_sdp_body);
	# XXX validate SDP
	@{$A_remote_sdp->{medias}} == 1 or die;
	my $A_remote_media = $A_remote_sdp->{medias}->[0];

	# return to IO handler loop
}

sub peer_addr_check {
	my ($fh, $peer, $sockets, $dest_list, $idx) = @_;
	if (List::Util::any {$fh == $_} @$sockets) {
		$dest_list->[$idx] = $peer;
	}
}
