package Rtpengine;

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

sub new {
	my ($class, $addr, $port) = @_;

	my $self = {};
	bless $self, $class;

	if (ref($addr)) {
		$self->{socket} = $addr;
	}
	else {
		$self->{socket} = IO::Socket::IP->new(Type => &Socket::SOCK_DGRAM, Proto => 'udp',
				PeerHost => $addr, PeerPort => $port);
	}

	return $self;
}

sub req {
	my ($self, $packet) = @_;

	my $cookie = rand() . ' ';
	my $p = $cookie . Bencode::bencode($packet);
	$self->{socket}->send($p, 0) or die $!;
	my $ret;
	$self->{socket}->recv($ret, 65535) or die $!;
	$ret =~ s/^\Q$cookie\E//s or die $ret;
	my $resp = Bencode::bdecode($ret, 1);

	$resp->{result} or die Dumper $resp;

	if ($resp->{result} eq 'error') {
		die "Error reason: \"$resp->{'error-reason'}\"";
	}

	return $resp;
}

sub offer {
	my ($self, $packet) = @_;
	return $self->req( { %$packet, command => 'offer' } );
}
sub answer {
	my ($self, $packet) = @_;
	return $self->req( { %$packet, command => 'answer' } );
}

package Rtpengine::Test;

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

	$self->{rtpe} = Rtpengine->new('localhost', 2223);
	$self->{callid} = rand();

	return $self;
};

sub client {
	my ($self, %args) = @_;
	return Rtpengine::Test::Client->_new($self, %args);
}

sub run {
	my ($self) = @_;

	$self->{mux}->loop();
}

sub timer_once {
	my ($self, $delay, $sub) = @_;
	push(@{$self->{timers}}, { sub => $sub, when => time() + $delay });
	@{$self->{timers}} = sort {$a->{when} <=> $b->{when}} @{$self->{timers}};
}

sub mux_input {
	my ($self, $mux, $fh, $input) = @_;

	my $peer = $mux->udp_peer($fh);
}

sub mux_timeout {
	my ($self, $mux, $fh) = @_;

	$mux->set_timeout($fh, 0.01);

	my $now = time();
	while (@{$self->{timers}} && $self->{timers}->[0]->{when} <= $now) {
		my $t = shift(@{$self->{timers}});
		$t->{sub}->();
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

	$self->{local_media} = $self->{local_sdp}->add_media(SDP::Media->new(
		$self->{main_sockets}->[0], $self->{main_sockets}->[1], 'RTP/AVP')); # main rtp and rtcp

	return $self;
}

sub offer {
	my ($self, $other) = @_;

	my $sdp_body = $self->{local_sdp}->encode();
	# XXX validate SDP

	my $req = { command => 'offer', ICE => 'remove', 'call-id' => $self->{parent}->{callid},
		'from-tag' => $self->{tag}, sdp => $sdp_body };

	my $out = $self->{parent}->{rtpe}->req($req);

	$other->offered($out);
}

sub offered {
	my ($self, $req) = @_;

	my $sdp_body = $req->{sdp} or die;
	$self->{remote_sdp} = SDP->decode($sdp_body);
	# XXX validate SDP
	@{$self->{remote_sdp}->{medias}} == 1 or die;
	$self->{remote_media} = $self->{remote_sdp}->{medias}->[0];
}

sub answer {
	my ($self, $other) = @_;

	my $sdp_body = $self->{local_sdp}->encode();
	# XXX validate SDP

	my $req = { command => 'answer', ICE => 'remove', 'call-id' => $self->{parent}->{callid},
		'from-tag' => $other->{tag}, 'to-tag' => $self->{tag}, sdp => $sdp_body };

	my $out = $self->{parent}->{rtpe}->req($req);

	$other->answered($out);
}

sub answered {
	my ($self, $req) = @_;

	my $sdp_body = $req->{sdp} or die;
	$self->{remote_sdp} = SDP->decode($sdp_body);
	# XXX validate SDP
	@{$self->{remote_sdp}->{medias}} == 1 or die;
	$self->{remote_media} = $self->{remote_sdp}->{medias}->[0];
}

1;
