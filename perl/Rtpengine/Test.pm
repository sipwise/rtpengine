package Rtpengine::Test;

use strict;
use warnings;
use Socket;
use Socket6;
use IO::Socket;
use IO::Socket::IP;
use Bencode;
use Data::Dumper;
use Net::Interface;
use List::Util;
use IO::Multiplex;
use Time::HiRes qw(time);
use SDP;
use ICE;
use DTLS;
use RTP;
use Rtpengine;

sub new {
	my ($class) = @_;

	my $self = {};
	bless $self, $class;

	# detect local interfaces

	my @intfs = Net::Interface->interfaces();

	my @v4 = map {$_->address(&IO::Socket::AF_INET)} @intfs;
	@v4 = map {Socket6::inet_ntop(&IO::Socket::AF_INET, $_)} @v4;
	@v4 = grep {$_ !~ /^127\./} @v4;
	@v4 or die("no IPv4 addresses found");

	my @v6 = map {$_->address(&IO::Socket::AF_INET6)} @intfs;
	@v6 = map {Socket6::inet_ntop(&IO::Socket::AF_INET6, $_)} @v6;
	@v6 = grep {$_ !~ /^::|^fe80:/} @v6;
	@v4 or die("no IPv6 addresses found");

	$self->{v4_addresses} = \@v4;
	$self->{v6_addresses} = \@v6;
	$self->{all_addresses} = [ @v4, @v6 ];

	# supporting objects

	$self->{mux} = IO::Multiplex->new();
	$self->{mux}->set_callback_object($self);

	$self->{media_port} = 2000;
	$self->{timers} = [];
	$self->{clients} = [];

	$self->{control} = Rtpengine->new('localhost', 2223);
	$self->{callid} = rand();

	return $self;
};

sub client {
	my ($self, %args) = @_;
	my $cl = Rtpengine::Test::Client->_new($self, %args);
	push(@{$self->{clients}}, $cl);
	return $cl;
}

sub run {
	my ($self) = @_;
	$self->{mux}->loop();
}

sub stop {
	my ($self) = @_;
	$self->{mux}->endloop();
}

sub timer_once {
	my ($self, $delay, $sub) = @_;
	push(@{$self->{timers}}, { sub => $sub, when => time() + $delay });
	@{$self->{timers}} = sort {$a->{when} <=> $b->{when}} @{$self->{timers}};
}

sub mux_input {
	my ($self, $mux, $fh, $input) = @_;

	my $peer = $mux->udp_peer($fh);

	for my $cl (@{$self->{clients}}) {
		$$input eq '' and last;
		$cl->_input($fh, $input, $peer);
	}
}

sub mux_timeout {
	my ($self, $mux, $fh) = @_;

	$mux->set_timeout($fh, 0.01);

	my $now = time();
	while (@{$self->{timers}} && $self->{timers}->[0]->{when} <= $now) {
		my $t = shift(@{$self->{timers}});
		$t->{sub}->();
	}

	for my $cl (@{$self->{clients}}) {
		$cl->_timer();
	}
}


package Rtpengine::Test::Client;

sub _new {
	my ($class, $parent, %args) = @_;

	my $self = {};
	bless $self, $class;

	$self->{parent} = $parent;
	$self->{tag} = rand();

	# create media sockets
	my @addresses = @{$parent->{all_addresses}};
	@addresses = List::Util::shuffle @addresses;
	my (@sockets, @rtp, @rtcp);
	# XXX support rtcp-mux and rtcp-less media

	for my $address (@addresses) {
		my $rtp = IO::Socket::IP->new(Type => &Socket::SOCK_DGRAM, Proto => 'udp',
			LocalHost => $address, LocalPort => $parent->{media_port}++) or die($address);
		my $rtcp = IO::Socket::IP->new(Type => &Socket::SOCK_DGRAM, Proto => 'udp',
			LocalHost => $address, LocalPort => $parent->{media_port}++) or die($address);
		push(@sockets, [$rtp, $rtcp]);
		push(@rtp, $rtp);
		push(@rtcp, $rtcp);
		$parent->{mux}->add($rtp);
		$parent->{mux}->add($rtcp);
		$parent->{mux}->set_timeout($rtp, 0.01); # XXX overkill, only need this on one
	}

	$self->{sockets} = \@sockets;
	$self->{rtp_sockets} = \@rtp;
	$self->{rtcp_sockets} = \@rtcp;

	$self->{main_sockets} = $sockets[0]; # for m= and o=
	$self->{local_sdp} = SDP->new($self->{main_sockets}->[0]); # no global c=
	$self->{component_peers} = []; # keep track of peer source addresses

	# default protocol
	my $proto = 'RTP/AVP';
	$args{dtls} and $proto = 'UDP/TLS/RTP/SAVP';
	$args{protocol} and $proto = $args{protocol};

	$self->{local_media} = $self->{local_sdp}->add_media(SDP::Media->new(
		$self->{main_sockets}->[0], $self->{main_sockets}->[1], $proto)); # main rtp and rtcp
	# XXX support multiple medias

	if ($args{dtls}) {
		$self->{dtls} = DTLS::Group->new($parent->{mux}, $self, [ \@rtp, \@rtcp ]);
		$self->{local_media}->add_attrs($self->{dtls}->encode());
		$self->{dtls}->accept(); # XXX support other modes
	}
	if ($args{ice}) {
		$self->{ice} = ICE->new(2, 1); # 2 components, controlling XXX
		my $pref = 65535;
		for my $s (@sockets) {
			$self->{ice}->add_candidate($pref--, 'host', @$s); # 2 components
		}
		$self->{local_media}->add_attrs($self->{ice}->encode());
	}

	return $self;
}

sub dtls_send {
	my ($self, $component, $s) = @_;
	$self->{main_sockets}->[$component]->send($s, 0, $self->{component_peers}->[$component]);
}

sub _default_req_args {
	my ($self, $cmd, %args) = @_;

	my $req = { command => $cmd, 'call-id' => $self->{parent}->{callid} };

	for my $cp (qw(sdp from-tag to-tag ICE transport-protocol)) {
		$args{$cp} and $req->{$cp} = $args{$cp};
	}

	return $req;
}

sub offer {
	my ($self, $other, %args) = @_;

	my $sdp_body = $self->{local_sdp}->encode();
	# XXX validate SDP

	my $req = $self->_default_req_args('offer', 'from-tag' => $self->{tag}, sdp => $sdp_body, %args);

	my $out = $self->{parent}->{control}->req($req);

	$other->_offered($out);
}

sub _offered {
	my ($self, $req) = @_;

	my $sdp_body = $req->{sdp} or die;
	$self->{remote_sdp} = SDP->decode($sdp_body);
	# XXX validate SDP
	@{$self->{remote_sdp}->{medias}} == 1 or die;
	$self->{remote_media} = $self->{remote_sdp}->{medias}->[0];
	$self->{ice} and $self->{ice}->decode($self->{remote_media}->decode_ice());
}

sub answer {
	my ($self, $other, %args) = @_;

	my $sdp_body = $self->{local_sdp}->encode();
	# XXX validate SDP

	my $req = $self->_default_req_args('answer', 'from-tag' => $other->{tag}, 'to-tag' => $self->{tag},
		sdp => $sdp_body, %args);

	my $out = $self->{parent}->{control}->req($req);

	$other->_answered($out);
}

sub _answered {
	my ($self, $req) = @_;

	my $sdp_body = $req->{sdp} or die;
	$self->{remote_sdp} = SDP->decode($sdp_body);
	# XXX validate SDP
	@{$self->{remote_sdp}->{medias}} == 1 or die;
	$self->{remote_media} = $self->{remote_sdp}->{medias}->[0];
	$self->{ice} and $self->{ice}->decode($self->{remote_media}->decode_ice());
}

sub delete {
	my ($self, %args) = @_;

	my $req = $self->_default_req_args('delete', 'from-tag' => $self->{tag}, %args);

	my $out = $self->{parent}->{control}->req($req);
}

sub _input {
	my ($self, $fh, $input, $peer) = @_;

	_peer_addr_check($fh, $peer, $self->{rtp_sockets}, $self->{component_peers}, 0);
	_peer_addr_check($fh, $peer, $self->{rtcp_sockets}, $self->{component_peers}, 1);

	$self->{dtls} and $self->{dtls}->input($fh, $input, $peer);
	$self->{ice} and $self->{ice}->input($fh, $input, $peer);

	$$input eq '' and return;

	# must be RTP input
	$$input = '';
}

sub _timer {
	my ($self) = @_;
	$self->{ice} and $self->{ice}->timer();
	$self->{rtp} and $self->{rtp}->timer();
}

sub _peer_addr_check {
	my ($fh, $peer, $sockets, $dest_list, $idx) = @_;
	if (List::Util::any {$fh == $_} @$sockets) {
		$dest_list->[$idx] = $peer;
	}
}

sub start_rtp {
	my ($self) = @_;
	$self->{rtp} and die;
	my $dest = $self->{remote_media}->endpoint();
	$self->{rtp} = RTP->new($self->{rtp_sockets}->[0], $dest) or die;
}

1;
