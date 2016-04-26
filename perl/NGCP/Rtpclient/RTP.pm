package NGCP::Rtpclient::RTP;

use strict;
use warnings;
use Time::HiRes qw(time);
use Math::BigInt;

sub new {
	my ($class, $cb_obj) = @_;

	my $self = {};
	bless $self, $class;

	$self->{cb_obj} = $cb_obj;

	$self->{ssrc} = int(rand(2**32));
	$self->{next_send} = time();
	$self->{ptime} = 20;
	$self->{clockrate} = 8000;
	$self->{timestamp} = Math::BigInt->new(int(rand(2**32)));
	$self->{seq} = rand(2**16);
	$self->{payload} = 100;

	return $self;
}

sub timer {
	my ($self) = @_;

	time() < $self->{next_send} and return;

	my $hdr = pack("CCnNN", 0x80, 0x00, $self->{seq}, $self->{timestamp}->bstr(), $self->{ssrc});
	my $payload = chr(rand(256)) x $self->{payload}; # XXX adapt to codec

	$self->{cb_obj}->rtp_send($hdr . $payload);

	$self->{seq}++;
	$self->{seq} > 0xffff and $self->{seq} -= 0x10000;

	$self->{next_send} = $self->{next_send} + $self->{ptime} / 1000;

	$self->{timestamp} += $self->{clockrate} / (1.0 / ($self->{ptime} / 1000)); # XXX might be fractional
	$self->{timestamp} > 0xffffffff and $self->{timestamp} -= Math::BigInt->new('0x100000000');
}

1;
