package NGCP::Rtpclient::RTCP;

use strict;
use warnings;
use Time::HiRes qw(time);
use Math::BigFloat;

sub new {
	my ($class, $cb_obj, $rtp_obj) = @_;

	$rtp_obj or return;

	my $self = {};
	bless $self, $class;

	$self->{cb_obj} = $cb_obj;
	$self->{rtp_obj} = $rtp_obj;

	$self->{interval} = 2; # seconds
	$self->{next_send} = time() + $self->{interval};

	return $self;
}

sub timer {
	my ($self) = @_;

	time() < $self->{next_send} and return;

	my $pack = $self->_sr();

	$self->{cb_obj}->rtcp_send($pack);

	$self->{next_send} = $self->{next_send} + $self->{interval};
}

sub input {
	my ($self, $packet) = @_;

	my ($vprc, $pt, $len, $rest) = unpack('CCn a*', $packet);
	($vprc & 0xe0) == 0x80 or die;
	my $rc = ($vprc & 0x1f);
	$rc > 1 and die;
	$len++;
	$len <<= 2;
	$len == length($packet) or die;

	if ($pt == 200) {
		my ($ssrc, @sr) = unpack('NNNNNN', $rest);
		$self->{last_sr}->{$ssrc} = { received_time => time(), packet => \@sr };
	}
}

sub _sr {
	my ($self) = @_;

	# receiver reports
	my $rrs = '';
	my $num_rrs = 0;
	my $others = $self->{rtp_obj}->{other_ssrcs};
	my @other_ssrcs = keys(%$others);
	scalar(@other_ssrcs) <= 1 or die;
	if (my $oss = $other_ssrcs[0]) {
		my $ss = $others->{$oss};
		my ($lsr, $dlsr) = (0,0);
		my $last_sr = $self->{last_sr}->{$ss->{ssrc}};
		if ($last_sr) {
			# ntp timestamp fraction
			$lsr = ($last_sr->{packet}->[0] << 16) | ($last_sr->{packet}->[1] >> 16);
			$dlsr = (time() - $last_sr->{received_time}) * 65536;
		}
		# packets lost number
		my $lost = $ss->{packets_lost} & 0x7ff;
		my $lost_frac = $ss->{lost_last} / ($ss->{received_last} + $ss->{lost_last});
		$lost_frac *= 256;
		$lost_frac = int($lost_frac);
		$lost_frac < 0 and $lost_frac = 0;
		$lost_frac > 255 and $lost_frac = 255;
		$lost = $lost | ($lost_frac << 24);

		$rrs .= pack('NNNNNN', $ss->{ssrc}, $lost, $ss->{seq}, $ss->{jitter}, $lsr, $dlsr);
		$num_rrs++;

		$ss->{received_last} = 0;
		$ss->{lost_last} = 0;
	}

	# actual sr
	my $now = Math::BigFloat->new(time());
	$now->badd(2208988800);
	my @parts = $now->dparts();
	my $ints = $parts[0];
	my $frac = $parts[1];
	$frac->bmul(Math::BigFloat->new('0x100000000'));
	my $pl = pack("NNNNN", $ints, $frac,
		$self->{rtp_obj}->{timestamp}->bstr(),
		$self->{rtp_obj}->{packet_count}, $self->{rtp_obj}->{octet_count});

	$pl .= $rrs;

	my $pack = $self->_header(200, $num_rrs, length($pl)) . $pl;
	return $pack;
}

sub _header {
	my ($self, $type, $rc, $length) = @_;
	return pack("CCnN", 0x80 | $rc, $type, (($length + 8) >> 2) - 1, $self->{rtp_obj}->{ssrc});
}

1;
