package NGCP::Rtpclient::SDP;

use strict;
use warnings;
use IO::Socket;
use Time::HiRes qw(gettimeofday);
use Socket;
use Socket6;

sub new {
	my ($class, $origin, $connection) = @_;

	my $self = {};
	bless $self, $class;

	$self->{version} = 1;
	$self->{medias} = [];
	$self->{origin} = $origin;
	$self->{connection} = $connection;

	return $self;
}

sub decode {
	my ($class, $body) = @_;

	my $self = {};
	bless $self, $class;

	my $medias = $self->{medias} = [];

	my @lines = split(/\r\n/, $body);

	my ($media, $attr_store);

	for my $line (@lines) {
		$attr_store = $media ? $media : $self;

		if ($line =~ /^[ost]=/) {
			# ignore
			next;
		}
		if ($line =~ /^m=(\S+) (\d+) (\S+) (\d+(?: \d+)*)$/s) {
			$media = $self->add_media(NGCP::Rtpclient::SDP::Media->new_remote($1, $2, $3, $4));
			next;
		}
		if ($line =~ /^c=(.*)$/) {
			$attr_store->{connection} = decode_address($1);
			next;
		}
		if ($line =~ /^a=(([\w-]+)(?::(.*))?)$/) {
			my $full = $1;
			my $name = $2;
			my $cont = $3;

			push(@{$attr_store->{attributes_list}}, $full);
			push(@{$attr_store->{attributes_hash}->{$name}}, $cont);
		}
	}

	for my $m (@$medias) {
		$m->decode();
	}

	return $self;
}

sub add_media {
	my ($self, $media) = @_;

	push(@{$self->{medias}}, $media);
	$media->{parent} = $self;

	return $media;
}

sub encode {
	my ($self) = @_;

	my ($secs, $msecs) = gettimeofday();

	my @out;

	push(@out, 'v=0');
	push(@out, 'o=- ' . ($secs ^ $msecs) . ' ' . ($self->{version}++) . ' ' . encode_address($self->{origin}));
	push(@out, 's=tester');
	$self->{connection} and push(@out, 'c=' . encode_address($self->{connection}));
	push(@out, 't=0 0');

	for my $m (@{$self->{medias}}) {
		push(@out, $m->encode($self->{connection}));
	}

	return join("\r\n", @out) . "\r\n";
}

sub encode_address {
	my ($sock) = @_;

	my $domain = $sock->sockdomain();
	my $addr = $sock->sockhost();

	$domain == &AF_INET and return "IN IP4 $addr";
	$domain == &AF_INET6 and return "IN IP6 $addr";
	die "$domain $addr";
}

sub decode_address {
	my ($s) = @_;
	if ($s =~ /^IN IP4 (\d+\.\d+\.\d+\.\d+)$/s) {
		return { address => $1, family => &AF_INET };
	}
	if ($s =~ /^IN IP6 ([0-9a-fA-F:]+)$/s) {
		return { address => $1, family => &AF_INET6 };
	}
	die $s;
}


package NGCP::Rtpclient::SDP::Media;

use Socket;
use Socket6;
use IO::Socket;

sub new {
	my ($class, $rtp, $rtcp, $protocol, $type) = @_;

	my $self = {};
	bless $self, $class;

	$self->{rtp} = $rtp; # main transport
	$self->{rtcp} = $rtcp; # optional
	$self->{protocol} = $protocol // 'RTP/AVP';
	$self->{type} = $type // 'audio';
	$self->{payload_types} = [0];

	$self->{additional_attributes} = [];

	return $self;
};

sub new_remote {
	my ($class, $protocol, $port, $type, $payload_types) = @_;

	my $self = {};
	bless $self, $class;

	$self->{protocol} = $protocol;
	$self->{port} = $port;
	$self->{type} = $type;
	$self->{payload_types} = [split(/ /, $payload_types)];

	return $self;
};

sub add_attrs {
	my ($self, @list) = @_;
	push(@{$self->{additional_attributes}}, @list);
}

sub encode {
	my ($self, $parent_connection) = @_;

	my $pconn = $parent_connection ? NGCP::Rtpclient::SDP::encode_address($parent_connection) : '';
	my @out;

	push(@out, "m=$self->{type} " . $self->{rtp}->sockport() . ' ' . $self->{protocol} . ' '
		. join(' ', @{$self->{payload_types}}));

	my $rtpconn = NGCP::Rtpclient::SDP::encode_address($self->{rtp});
	$rtpconn eq $pconn or push(@out, "c=$rtpconn");

	push(@out, 'a=sendrecv');

	if ($self->{rtcp}) {
		my $rtcpconn = NGCP::Rtpclient::SDP::encode_address($self->{rtcp});
		push(@out, 'a=rtcp:' . $self->{rtcp}->sockport()
			. ($rtcpconn eq $rtpconn ? '' : (' ' . NGCP::Rtpclient::SDP::encode_address($self->{rtcp}))));
	}

	push(@out, @{$self->{additional_attributes}});

	return @out;
}

sub decode {
	my ($self) = @_;

	my $attrs = $self->{attributes_hash};

	if ($attrs->{rtcp}) {
		my $a = $attrs->{rtcp}->[0];
		$a =~ /^(\d+)(?: (IN .*))?$/ or die $a;
		$self->{rtcp_port} = $1;
		$2 and $self->{rtcp_connection} = decode_address($2);
	}
}

sub connection {
	my ($self) = @_;
	$self->{connection} and return $self->{connection};
	return $self->{parent}->{connection};
}

sub rtcp_port {
	my ($self) = @_;
	$self->{rtcp_port} and return $self->{rtcp_port};
	return $self->{port} + 1;
}

sub rtcp_connection {
	my ($self) = @_;
	$self->{rtcp_connection} and return $self->{rtcp_connection};
	return $self->connection();
}

sub decode_ice {
	my ($self) = @_;
	my $ret = {};
	$ret->{ufrag} = $self->{attributes_hash}->{'ice-ufrag'}->[0];
	$ret->{pwd} = $self->{attributes_hash}->{'ice-pwd'}->[0];
	$ret->{candidates} = $self->{attributes_hash}->{'candidate'};
	return $ret;
}

sub endpoint {
	my ($self) = @_;
	my $conn = $self->connection();
	my $port = $self->{port};
	$conn->{family} == &AF_INET and return pack_sockaddr_in($port, inet_aton($conn->{address}));
	$conn->{family} == &AF_INET6 and return pack_sockaddr_in6($port, inet_pton(&AF_INET6, $conn->{address}));
	die;
}

sub rtcp_endpoint {
	my ($self) = @_;
	my $conn = $self->rtcp_connection();
	my $port = $self->rtcp_port();
	$conn->{family} == &AF_INET and return pack_sockaddr_in($port, inet_aton($conn->{address}));
	$conn->{family} == &AF_INET6 and return pack_sockaddr_in6($port, inet_pton(&AF_INET6, $conn->{address}));
	die;
}

1;
