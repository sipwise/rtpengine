package DTLS;

use strict;
use warnings;
use SRTP;
use File::Temp;
use Crypt::OpenSSL::RSA;
use IO::Socket::INET;
use IPC::Open3;
use IO::Multiplex;

sub new {
	my ($class) = @_;

	my $self = {};
	bless $self, $class;

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

sub check_cert {
	my ($self, $file) = @_;
	$self->{_cert_key_file} and return;
	$self->new_cert();
}

sub connect {
	my ($self, $local, $dest) = @_;
	$self->check_cert();

	$self->{_connected} and return 1;

	$self->_kill_openssl_child();

	my $near = $self->{_near};
	my $far = $self->{_far};

	if (!$far) {
		if (ref($local)) {
			$far = $local;
		}
		else {
			$far = IO::Socket::INET->new(Type => SOCK_DGRAM, PeerAddr => $dest,
					LocalAddr => $local, Proto => 'udp');
		}
		$self->{_far} = $far;
	}

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

	my $mux = IO::Multiplex->new();
	$mux->add($near);
	$mux->add($far);
	$mux->add($openssl_out);

	$mux->set_callback_object($self);
	$mux->loop;

	$self->{_connected} or return 0;
	return 1;
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

sub mux_input {
	my ($self, $mux, $fh, $input) = @_;

	if ($fh == $self->{_openssl_out}) {
		$self->{_openssl_buf} .= $$input;
	}
	elsif ($fh == $self->{_near}) {
		send($self->{_far}, $$input, 0);
		if (!$self->{_near_peer}) {
			$self->{_near_peer} = $mux->udp_peer($fh);
			CORE::connect($self->{_near}, $self->{_near_peer});
		}
	}
	if ($fh == $self->{_far}) {
		if (is_dtls($$input) && $self->{_near_peer}) {
			send($self->{_near}, $$input, 0);
		}
	}

	$$input = '';

	if ($self->{_openssl_buf} =~ /Server certificate\n(-----BEGIN CERTIFICATE-----\n.*?\n-----END CERTIFICATE-----\n).*SRTP Extension negotiated, profile=(\S+).*Keying material: ([0-9a-fA-F]{120})/s) {
		$self->{_peer_cert} = $1;
		$self->{_profile} = $2;
		$self->{_keys} = pack('H*', $3);
		$self->{_connected} = 1;
		$mux->endloop();
	}
	if ($self->{_openssl_buf} =~ /\nDONE\n/s) {
		$mux->endloop();
	}
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

sub mux_eof {
	my ($self, $mux, $fh) = @_;

	if ($fh == $self->{_openssl_out}) {
		$mux->endloop();
	}
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

1;
