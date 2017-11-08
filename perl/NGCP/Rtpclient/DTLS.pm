package NGCP::Rtpclient::DTLS;

use strict;
use warnings;
use NGCP::Rtpclient::SRTP;
use File::Temp;
use Crypt::OpenSSL::RSA;
use IO::Socket::INET;
use IPC::Open3;
use IO::Multiplex;
use Time::HiRes qw(sleep time);

sub new {
	my ($class, $mux, $local_sockets, $output_func, $tag, $cert) = @_;

	my $self = {};
	bless $self, $class;

	$self->{_output_func} = $output_func;
	$self->{_mux} = $mux;
	$self->{_tag} = $tag;
	$self->{_local_sockets} = $local_sockets;

	if ($cert) {
		$self->set_cert($cert);
	}
	else {
		$self->new_cert();
	}

	return $self;
}

sub new_cert {
	my ($self) = @_;

	my $rsa_key = Crypt::OpenSSL::RSA->generate_key(1024);
	my $priv_key = $rsa_key->get_private_key_string();
	my $key_file = File::Temp->new();
	print $key_file $priv_key;
	close($key_file);

	my $cert_file = File::Temp->new();
	system(qw(openssl req -key), $key_file->filename(), '-out', $cert_file->filename(),
		qw(-new -x509 -days 30 -subj /CN=tester -batch));
	my $cert;
	read($cert_file, $cert, 10000);
	close($cert_file);

	my $cert_key_file = File::Temp->new();
	print $cert_key_file $cert;
	print $cert_key_file $priv_key;
	close($cert_key_file);

	$self->set_cert($cert_key_file);
	return $cert_key_file;
}

sub get_cert {
	my ($self) = @_;
	return $self->{_cert_key_file};
}

sub set_cert {
	my ($self, $file) = @_;
	$self->{_cert_key_file} = $file;
}

# XXX unify these two
sub connect { ## no critic: Subroutines::ProhibitBuiltinHomonyms
	my ($self) = @_;

	$self->{_connected} and return;

	$self->_kill_openssl_child();

	my $near = $self->{_near};

	$near or ($near = $self->{_near} = IO::Socket::INET->new(Type => SOCK_DGRAM, LocalAddr => 'localhost',
		Proto => 'udp'));

	my $near_port = $near->sockport();

	my ($openssl_in, $openssl_out);
	$self->{_openssl_pid} = open3($openssl_in, $openssl_out, undef,
		qw(openssl s_client -connect),
		"localhost:$near_port",
		'-cert', $self->{_cert_key_file}->filename(), qw(-dtls1 -use_srtp
		SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32 -keymatexport EXTRACTOR-dtls_srtp
		-keymatexportlen 60));
	$self->{_openssl_out} = $openssl_out;
	$self->{_openssl_in} = $openssl_in;
	$self->{_openssl_buf} = '';

	$self->{_mux}->add($near);
	$self->{_mux}->add($openssl_out);
}
sub accept { ## no critic: Subroutines::ProhibitBuiltinHomonyms
	my ($self) = @_;

	$self->{_connected} and return;

	$self->_kill_openssl_child();

	my ($near_port, $near_peer);
	my $near = $self->{_near};
	if ($near) {
		$near_port = $near->peerport();
		$near_peer = $near->peeraddr();
	}
	else {
		my $tmp = IO::Socket::INET->new(Type => SOCK_DGRAM, LocalAddr => 'localhost', Proto => 'udp');
		$near_port = $tmp->sockport();
		undef($tmp);

		$near = $self->{_near} = IO::Socket::INET->new(Type => SOCK_DGRAM, LocalAddr => 'localhost',
			Proto => 'udp');
		$near_peer = pack_sockaddr_in($near_port, inet_aton("localhost"));
		# $near gets connected below
	}

	my ($openssl_in, $openssl_out);
	$self->{_openssl_pid} = open3($openssl_in, $openssl_out, undef,
		qw(openssl s_server -accept),
		$near_port,
		'-cert', $self->{_cert_key_file}->filename(), qw(-dtls1 -use_srtp
		SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32 -keymatexport EXTRACTOR-dtls_srtp
		-keymatexportlen 60));
	# XXX dtls 1.2 ?

	sleep(0.2); # given openssl a short while to start up

	$self->_near_peer($near_peer);

	$self->{_openssl_out} = $openssl_out;
	$self->{_openssl_in} = $openssl_in;
	$self->{_openssl_buf} = '';

	$self->{_mux}->add($near);
	$self->{_mux}->add($openssl_out);
}

sub _kill_openssl_child {
	my ($self) = @_;

	if ($self->{_openssl_pid}) {
		kill(9, $self->{_openssl_pid});
		waitpid($self->{_openssl_pid}, 0);
	}
	delete($self->{_openssl_pid});
	delete($self->{_openssl_in});
	delete($self->{_openssl_out});
}

sub DESTROY {
	my ($self) = @_;

	$self->_kill_openssl_child();
}

sub _openssl_input {
	my ($self, $fh, $s_r, $peer) = @_;

	if ($self->{_openssl_done}) {
		$$s_r = '';
		return;
	}

	$self->{_openssl_buf} .= $$s_r;
	$$s_r = '';

	if ($self->{_openssl_buf} =~ /Server certificate\n(-----BEGIN CERTIFICATE-----\n.*?\n-----END CERTIFICATE-----\n).*SRTP Extension negotiated, profile=(\S+).*Keying material: ([0-9a-fA-F]{120})/s) {
		$self->{_peer_cert} = $1;
		$self->{_profile} = $2;
		$self->{_keys} = pack('H*', $3);
		$self->{_connected} = 1;
		$self->{_openssl_done} = 1;
	}
	if ($self->{_openssl_buf} =~ /\nDONE\n/s) {
		$self->{_openssl_done} = 1;
	}
}

sub _near_peer {
	my ($self, $peer) = @_;

	$self->{_near_peer} and return;

	$self->{_near_peer} = $peer;
	CORE::connect($self->{_near}, $self->{_near_peer});
}

sub _near_input {
	my ($self, $fh, $s_r, $peer) = @_;

	my $func = $self->{_output_func};
	if (ref($func) eq 'CODE') {
		$func->($self->{_tag}, $$s_r);
	}
	else {
		# object
		$func->dtls_send($self->{_tag}, $$s_r);
	}

	$self->_near_peer($peer);

	$$s_r = '';
}

sub input {
	my ($self, $fh, $s_r, $peer) = @_;

	$$s_r eq '' and return;

	if ($fh == $self->{_openssl_out}) { # openssl's stdout
		return $self->_openssl_input($fh, $s_r, $peer);
	}
	elsif ($fh == $self->{_near}) { # UDP input from openssl - forward to peer
		return $self->_near_input($fh, $s_r, $peer);
	}

	# UDP input from peer - demux and forward to openssl
	is_dtls($$s_r) or return;
	$self->{_near_peer} or return; # nowhere to forward it to
	grep {$fh == $_} @{$self->{_local_sockets}} or return; # not one of ours

	send($self->{_near}, $$s_r, 0);
	$$s_r = '';
}

sub peer_cert {
	my ($self) = @_;
	$self->{_peer_cert_file} and return $self->{_peer_cert_file};
	$self->{_peer_cert} or return;

	my $cert_file = File::Temp->new();
	print $cert_file $self->{_peer_cert};
	close($cert_file);

	return ($self->{_peer_cert_file} = $cert_file);
}

sub cert_fingerprint {
	my ($cert_file) = @_;
	my $fd;
	open($fd, '-|', qw(openssl x509 -in), $cert_file->filename(), qw(-fingerprint -noout));
	my $fp = <$fd>;
	close($fd);
	$fp =~ /SHA1 Fingerprint=([0-9a-f:]+)/i or return;
	return $1;
}

sub fingerprint {
	my ($self) = @_;
	return cert_fingerprint($self->{_cert_key_file});
}

sub get_keys {
	my ($self) = @_;

	$self->{_keys} =~ /^(.{16})(.{16})(.{14})(.{14})$/s or return;
	return ($self->{_profile}, $1, $2, $3, $4);
}

sub is_dtls {
	my ($s) = @_;
	length($s) < 1 and return 0;
	my $c = ord(substr($s, 0, 1));
	$c < 20 and return 0;
	$c > 63 and return 0;
	return 1;
}

sub encode {
	my ($self) = @_;
	my @ret;
	push(@ret, 'a=setup:actpass');
	push(@ret, 'a=fingerprint:sha-1 ' . $self->fingerprint());
	return @ret;
}

package NGCP::Rtpclient::DTLS::Group;

sub new {
	my ($class, $mux, $output_func, $socket_components, $cert) = @_;

	my $self = [];
	bless $self, $class;

	my $max_component = $#{$socket_components};

	for my $idx (0 .. $max_component) {
		my $local_sockets = $socket_components->[$idx];
		my $cl = NGCP::Rtpclient::DTLS->new($mux, $local_sockets, $output_func, $idx, $cert);
		push(@$self, $cl);
		$cert = $cl->get_cert();
	}

	return $self;
}

sub encode {
	my ($self, @rest) = @_;
	return $self->[0]->encode(@rest);
}
sub connect { ## no critic: Subroutines::ProhibitBuiltinHomonyms
	my ($self, @rest) = @_;
	for my $cl (@$self) {
		$cl->accept(@rest);
	}
}
sub accept { ## no critic: Subroutines::ProhibitBuiltinHomonyms
	my ($self, @rest) = @_;
	for my $cl (@$self) {
		$cl->accept(@rest);
	}
}
sub input {
	my ($self, @rest) = @_;
	for my $cl (@$self) {
		$cl->input(@rest);
	}
}

1;
