#!/usr/bin/perl

use strict;
use warnings;
use DTLS;
use ICE;
use RTP;
use SDP;
use Rtpengine;
use IO::Socket::IP;
use IO::Multiplex;
use Time::HiRes qw(time);

my $mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);

# create local sockets for A and B sides

my @A_interfaces = qw(
	192.168.1.90
	10.10.8.18
	2001:470:1d:76c:feaa:14ff:fe97:be6b
	fdd5:725c:61d7:0:feaa:14ff:fe97:be6b
	2a02:1b8:7:1:9847:efff:fe2e:f17d
);
my @B_interfaces = @A_interfaces;

@A_interfaces = sort {rand() <=> rand()} @A_interfaces;
@B_interfaces = sort {rand() <=> rand()} @B_interfaces;

my $sport = 2000;

my (@A_sockets, @B_sockets);

for my $a (@A_interfaces) {
	my $rtp = IO::Socket::IP->new(Type => SOCK_DGRAM, Proto => 'udp',
		LocalHost => $a, LocalPort => $sport++) or die($a);
	my $rtcp = IO::Socket::IP->new(Type => SOCK_DGRAM, Proto => 'udp',
		LocalHost => $a, LocalPort => $sport++) or die($a);
	print("local interface side A: " . $rtp->sockhost() . '/' . $rtp->sockport() . '/'
		. $rtcp->sockport() . "\n");
	push(@A_sockets, [$rtp, $rtcp]);
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
	$mux->add($rtp);
	$mux->add($rtcp);
	$mux->set_timeout($rtp, 0.01);
}

# create outgoing SDP for side A

my $A_main = $A_sockets[0]; # for o= and m= line details
my $A_local_sdp = SDP->new($A_main->[0]); # no global connection given

# rtp and rtcp, everything else default
my $A_local_media = $A_local_sdp->add_media(SDP::Media->new($A_main->[0], $A_main->[1]));

# create side A ICE agent

my $A_ice = ICE->new(2, 1); # 2 components, controlling
my $pref = 65535;
for my $s (@A_sockets) {
	$A_ice->add_candidate($pref--, 'host', @$s); # 2 components
}

$A_local_media->add_attrs($A_ice->encode());

# send side A SDP to rtpengine

my $A_local_sdp_body = $A_local_sdp->encode();
# XXX validate SDP

my $rtpengine = Rtpengine->new('localhost', 2223);

my $callid = rand();
my $fromtag = rand();
my $totag = rand();

print("doing rtpengine offer\n");
my $offer_sent = time();
my $A_offer = { command => 'offer', ICE => 'force', 'call-id' => $callid, 'from-tag' => $fromtag,
	sdp => $A_local_sdp_body };

my $B_offer = $rtpengine->req($A_offer);
my $offer_done = time();

# decode incoming SDP for side B

my $B_remote_sdp_body = $B_offer->{sdp};
my $B_remote_sdp = SDP->decode($B_remote_sdp_body);
# XXX validate SDP
@{$B_remote_sdp->{medias}} == 1 or die;
my $B_remote_media = $B_remote_sdp->{medias}->[0];

# create side B ICE agent

my $B_ice = ICE->new(2, 0); # 2 components, controlled
$pref = 65535;
for my $s (@B_sockets) {
	$B_ice->add_candidate($pref--, 'host', @$s); # 2 components
}

# add remote ICE infos for side B

$B_ice->decode($B_remote_media->decode_ice());

# run the machine and simulate delayed answer

my $do_answer = time() + 3;

$mux->loop();



sub mux_input {
	my ($self, $mux, $fh, $input) = @_;
	my $peer = $mux->udp_peer($fh);
	$A_ice->input($fh, $input, $peer);
	$B_ice->input($fh, $input, $peer);
}

sub mux_timeout {
	my ($self, $mux, $fh) = @_;

	$A_ice->timer();
	$B_ice->timer();

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

	$B_local_media->add_attrs($B_ice->encode());

	# send side A SDP to rtpengine
	my $B_local_sdp_body = $B_local_sdp->encode();
	# XXX validate SDP

	my $B_answer = { command => 'answer', ICE => 'force', 'call-id' => $callid, 'from-tag' => $fromtag,
		'to-tag' => $totag, sdp => $B_local_sdp_body };

	print("doing rtpengine answer\n");
	my $A_answer = $rtpengine->req($B_answer);

	# decode incoming SDP for side A

	my $A_remote_sdp_body = $A_answer->{sdp};
	my $A_remote_sdp = SDP->decode($A_remote_sdp_body);
	# XXX validate SDP
	@{$A_remote_sdp->{medias}} == 1 or die;
	my $A_remote_media = $A_remote_sdp->{medias}->[0];

	# add remote ICE infos for side B

	$A_ice->decode($A_remote_media->decode_ice());

	# return to IO handler loop
}
