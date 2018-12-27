package NGCP::Rtpclient::SDES;

use strict;
use warnings;
use NGCP::Rtpclient::SRTP;
use MIME::Base64;

sub new {
	my ($class, %args) = @_;

	my $self = {};
	bless $self, $class;

	# our list of crypto suites

	if (!$args{suites} || !@{$args{suites}}) {
		$self->{suites} = [@NGCP::Rtpclient::SRTP::crypto_suites];
	}
	else {
		$self->{suites} = [];
		for my $s (@{$args{suites}}) {
			my $o = $NGCP::Rtpclient::SRTP::crypto_suites{$s};
			$o or die;
			push(@{$self->{suites}}, $o);
		}
	}

	# duplicate content and generate random keys

	my $id = 1;
	for my $s (@{$self->{suites}}) {
		$s = {%$s};
		$s->{id} = $id++;
		$s->{master_key} = join('', map {chr(rand(256))} (1 .. $s->{key_length}));
		$s->{master_salt} = join('', map {chr(rand(256))} (1 .. $s->{salt_length}));
	}

	return $self
}

sub encode {
	my ($self) = @_;
	my @ret;
	for my $s (@{$self->{suites}}) {
		push(@ret, "a=crypto:$s->{id} $s->{str} inline:" .
			encode_base64($s->{master_key} . $s->{master_salt}, ''));
	}
	return @ret;
}

sub decode {
	my ($self, $sdp_media) = @_;
	$self->{remote_suites} = [];
	my $suites = $sdp_media->get_attrs('crypto');
	for my $line (@{$suites}) {
		my ($id, $s, $b64) = $line =~ /^(\S+) (\S+) inline:(\S+)$/ or next;
		$s = $NGCP::Rtpclient::SRTP::crypto_suites{$s};
		$s or next; # crypto suite not supported by perl mod
		$s = {%$s};
		$s->{id} = $id;
		($s->{master_key}, $s->{master_salt}) = NGCP::Rtpclient::SRTP::decode_inline_base64($b64, $s);
		push(@{$self->{remote_suites}}, $s);
	}
	return;
}

# construct ->suites to match suites from ->remote_suites after an offer
sub offered {
	my ($self) = @_;
	my @out;
	for my $r (@{$self->{remote_suites}}) {
		for my $s (@{$self->{suites}}) {
			if ($r->{str} eq $s->{str}) {
				my $dup = {%$s};
				$dup->{remote} = $r;
				$dup->{id} = $r->{id};
				push(@out, $dup);
			}
		}
	}
	@{$self->{suites}} = @out;
	$self->{suite} = $out[0];
	return;
}

# prunes ->suites to contain only matching suites from ->remote_suites after an answer
sub answered {
	my ($self) = @_;
	my @out;
	for my $s (@{$self->{suites}}) {
		for my $r (@{$self->{remote_suites}}) {
			if ($r->{id} eq $s->{id} && $r->{str} eq $s->{str}) {
				$s->{remote} = $r;
				push(@out, $s);
			}
		}
	}
	@{$self->{suites}} = @out;
	$self->{suite} = $out[0];
	return;
}

# after an offer, trims the list of suites to just the one shared/supported one
sub trim {
	my ($self) = @_;
	splice(@{$self->{suites}}, 1);
	splice(@{$self->{remote_suites}}, 1);
}

1;
