package NGCP::Rtpengine;

use strict;
use warnings;
use Socket;
use Socket6;
use IO::Socket;
use IO::Socket::IP;
use Bencode;
use Data::Dumper;
use JSON;

sub new {
	my ($class, $addr, $port) = @_;

	my $self = {};
	bless $self, $class;

	if (ref($addr)) {
		$self->{socket} = $addr;
	}
	else {
		$self->{socket} = IO::Socket::IP->new(Type => &SOCK_DGRAM, Proto => 'udp',
				PeerHost => $addr, PeerPort => $port);
	}

	return $self;
}

sub req {
	my ($self, $packet) = @_;

	my $cookie = rand() . ' ';
	my $p = $cookie . ($self->{json} ? encode_json($packet) : Bencode::bencode($packet));
	$self->{socket}->send($p, 0) or die $!;
	my $ret;
	$self->{socket}->recv($ret, 65535) or die $!;
	$ret =~ s/^\Q$cookie\E//s or die $ret;
	my $resp = $self->{json} ? decode_json($ret) : Bencode::bdecode($ret, 1);

	$resp->{result} or die Dumper $resp;

	if ($resp->{result} eq 'error') {
		die "Error reason: \"$resp->{'error-reason'}\"";
	}

	return $resp;
}

sub offer {
	my ($self, $packet) = @_;
	return $self->req( { command => 'offer', %$packet } );
}
sub answer {
	my ($self, $packet) = @_;
	return $self->req( { command => 'answer', %$packet } );
}

1;
