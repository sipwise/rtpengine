package NGCP::Rtpclient::RTP;

use strict;
use warnings;
use Time::HiRes qw(time);
use Math::BigInt;
use Math::BigFloat;

sub new {
	my ($class, $cb_obj, %args) = @_;

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
	$self->{packet_count} = 0;
	$self->{octet_count} = 0;
	$self->{other_ssrcs} = {};
	$self->{args} = \%args;

	return $self;
}

sub timer {
	my ($self) = @_;

	time() < $self->{next_send} and return;

	my $hdr = pack("CCnNN", 0x80, 0x00, $self->{seq}, $self->{timestamp}->bstr(), $self->{ssrc});
	my $payload = chr(rand(256)) x $self->{payload}; # XXX adapt to codec

	my $lost = 0;
	if (($self->{args}->{packetloss} // 0) > 0) {
		my $r = rand(100);
		($r < $self->{args}->{packetloss}) and $lost = 1;
	}

	$lost or $self->{cb_obj}->rtp_send($hdr . $payload);

	$self->{seq}++;
	$self->{seq} > 0xffff and $self->{seq} -= 0x10000;

	$self->{next_send} = $self->{next_send} + $self->{ptime} / 1000;

	$self->{timestamp} += $self->{clockrate} / (1.0 / ($self->{ptime} / 1000)); # XXX might be fractional
	$self->{timestamp} > 0xffffffff and $self->{timestamp} -= Math::BigInt->new('0x100000000');

	$self->{packet_count}++;
	$self->{octet_count} += length($payload);
}

sub input {
	my ($self, $packet) = @_;

	my $now = time();

	my ($vpxcc, $pt, $seq, $ts, $ssrc, $payload) = unpack("CCnNN a*", $packet);
	$vpxcc == 0x80 or die;
	$pt == 0 or die;

	my $remote = ($self->{other_ssrcs}->{$ssrc} //= {
			ssrc => $ssrc,
			packets_received => 0,
			packets_lost => 0,
			octets_received => 0,
			roc => 0,
			seq => $seq, # highest seen
			jitter => 0,
			queue_seq => $seq, # next expected seq -- to detect lost packets
			queue => {},
			lost_last => 0, # since last SR/RR
			received_last => 0, # since last SR/RR
			dupes => 0,
		});

	$remote->{packets_received}++;
	$remote->{received_last}++;
	$remote->{octets_received} += length($payload);

	# normalize seq using roc
	my $extseq = ($remote->{roc} << 16) | $seq;
	my $diff = $extseq - $remote->{seq};
	if ($diff < -0x8000) {
		$extseq += 0x10000;
	}
	elsif ($diff >= 0x8000) {
		$extseq -= 0x10000;
	}

	# update seq/roc if necessary -- highest seq seen
	if ($extseq > $remote->{seq}) {
		$remote->{seq} = $extseq;
		$remote->{roc} = $extseq >> 16;
	}

	# check dupes and packet loss
	if ($extseq == $remote->{queue_seq}) {
		# in sequence and expected
		$remote->{queue_seq}++;
		# see if we can pull packets out of the queue
		while (exists($remote->{queue}->{$remote->{queue_seq}})) {
			delete($remote->{queue}->{$remote->{queue_seq}});
			$remote->{queue_seq}++;
		}
	}
	elsif ($extseq < $remote->{queue_seq}) {
		$remote->{dupes}++;
	}
	else {
		# ahead of sequence -- queue it up if not a dupe
		if (exists($remote->{queue}->{$extseq})) {
			$remote->{dupes}++;
		}
		else {
			$remote->{queue}->{$extseq} = $packet;
			# see if our "jitter buffer" is full and account for packet loss
			my @seqs = keys(%{$remote->{queue}});
			if (@seqs >= 20) {
				@seqs = sort {$a <=> $b} (@seqs);
				# seek up to the lowest seq in buffer and count each missing
				# seq as a lost packet
				my $min = $seqs[0];
				$remote->{lost_last} += $min - $remote->{queue_seq};
				$remote->{packets_lost} += $min - $remote->{queue_seq};
				# now unqueue what we have as much as we can
				$remote->{queue_seq} = $min;
				while (my $qseq = shift(@seqs)) {
					$qseq != $remote->{queue_seq} and last;
					delete($remote->{queue}->{$qseq});
					$remote->{queue_seq}++;
				}
			}
		}

	}
	
	# calc jitter
	if ($remote->{last_ts} && $remote->{last_seq}) {
		my $lt = Math::BigFloat->new($remote->{last_ts});
		$lt->bsub(Math::BigFloat->new($now));
		$lt->bmul($self->{clockrate});
		my $diff = $lt->bstr() - ($remote->{last_seq} - $extseq);
		$remote->{jitter} = $remote->{jitter} + (abs($diff) - $remote->{jitter}) / 16;
	}
	$remote->{last_ts} = $now;
	$remote->{last_seq} = $extseq;
}

1;
