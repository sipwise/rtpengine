package NGCP::Rtpclient::SRTP;

use strict;
use warnings;
use Crypt::Rijndael;
use Digest::SHA qw(hmac_sha1);
use MIME::Base64;

our $SRTP_DEBUG = 0;

our @crypto_suites = (
	{
		str		=> 'AES_CM_128_HMAC_SHA1_80',
		dtls_name	=> 'SRTP_AES128_CM_SHA1_80',
		auth_tag	=> 10,
		enc_func	=> \&aes_cm,
		iv_rtp		=> \&aes_cm_iv_rtp,
		iv_rtcp		=> \&aes_cm_iv_rtcp,
		key_length	=> 16,
		salt_length	=> 14,
	},
	{
		str		=> 'AES_CM_128_HMAC_SHA1_32',
		dtls_name	=> 'SRTP_AES128_CM_SHA1_32',
		auth_tag	=> 4,
		enc_func	=> \&aes_cm,
		iv_rtp		=> \&aes_cm_iv_rtp,
		iv_rtcp		=> \&aes_cm_iv_rtcp,
		key_length	=> 16,
		salt_length	=> 14,
	},
	{
		str		=> 'F8_128_HMAC_SHA1_80',
		auth_tag	=> 10,
		enc_func	=> \&aes_f8,
		iv_rtp		=> \&aes_f8_iv_rtp,
		iv_rtcp		=> \&aes_f8_iv_rtcp,
		key_length	=> 16,
		salt_length	=> 14,
	},
	{
		str		=> 'AES_192_CM_HMAC_SHA1_80',
		#dtls_name	=> 'SRTP_AES128_CM_SHA1_80',
		auth_tag	=> 10,
		enc_func	=> \&aes_cm,
		iv_rtp		=> \&aes_cm_iv_rtp,
		iv_rtcp		=> \&aes_cm_iv_rtcp,
		key_length	=> 24,
		salt_length	=> 14,
	},
	{
		str		=> 'AES_256_CM_HMAC_SHA1_80',
		#dtls_name	=> 'SRTP_AES128_CM_SHA1_80',
		auth_tag	=> 10,
		enc_func	=> \&aes_cm,
		iv_rtp		=> \&aes_cm_iv_rtp,
		iv_rtcp		=> \&aes_cm_iv_rtcp,
		key_length	=> 32,
		salt_length	=> 14,
	},
	{
		str		=> 'AES_192_CM_HMAC_SHA1_32',
		#dtls_name	=> 'SRTP_AES128_CM_SHA1_80',
		auth_tag	=> 4,
		enc_func	=> \&aes_cm,
		iv_rtp		=> \&aes_cm_iv_rtp,
		iv_rtcp		=> \&aes_cm_iv_rtcp,
		key_length	=> 24,
		salt_length	=> 14,
	},
	{
		str		=> 'AES_256_CM_HMAC_SHA1_32',
		#dtls_name	=> 'SRTP_AES128_CM_SHA1_80',
		auth_tag	=> 4,
		enc_func	=> \&aes_cm,
		iv_rtp		=> \&aes_cm_iv_rtp,
		iv_rtcp		=> \&aes_cm_iv_rtcp,
		key_length	=> 32,
		salt_length	=> 14,
	},
);
our %crypto_suites = map {$$_{str} => $_} @crypto_suites;

sub aes_cm {
	my ($data, $key, $iv) = @_;

	my $c = Crypt::Rijndael->new($key) or die;
	length($iv) == 16 or die;
	my @iv = unpack("C16", $iv);
	my $out = '';

	while ($data ne '') {
		$iv = pack("C16", @iv);
		my $key_segment = $c->encrypt($iv);
		length($key_segment) == 16 or die;
		my @ks = unpack("C16", $key_segment);
		my @ds = unpack("C16", $data);

		for my $i (0 .. $#ds) {
			my $ss = $ds[$i];
			my $kk = $ks[$i];
			$out .= chr($ss ^ $kk);
		}

		substr($data, 0, 16, '');
		$data eq '' and last;

		for my $i (reverse(0 .. 15)) {
			$iv[$i]++;
			if ($iv[$i] == 256) {
				$iv[$i] = 0;
			}
			else {
				last;
			}
		}
	}

	return $out;
}

sub aes_f8 {
	my ($data, $key, $iv, $salt) = @_;

	my $m = $salt . "\x55\x55";
	my $c = Crypt::Rijndael->new(xor_128($key, $m)) or die;
	my $ivx = $c->encrypt($iv);
	undef($c);

	$c = Crypt::Rijndael->new($key) or die;
	my $p_s = "\0" x 16;
	my $j = 0;
	my $out = '';

	while ($data ne '') {
		my $jx = ("\0" x 12) . pack("N", $j);
		my $key_segment = $c->encrypt(xor_128($ivx, $jx, $p_s));
			length($key_segment) == 16 or die;
		my @ks = unpack("C16", $key_segment);
		my @ds = unpack("C16", $data);

		for my $i (0 .. $#ds) {
			my $ss = $ds[$i];
			my $kk = $ks[$i];
			$out .= chr($ss ^ $kk);
		}

		substr($data, 0, 16, '');
		$data eq '' and last;

		$p_s = $key_segment;
		$j++;
	}

	return $out;
}

sub prf_n {
	my ($n, $key, $x) = @_;
	my $d = "\0" x ($n / 8);
	my $ks = aes_cm($d, $key, $x . "\0\0");
	return substr($ks, 0, $n / 8);
}

sub xor_n {
	my ($n, @l) = @_;
	$n /= 8;
	my @o = (0) x $n;
	for my $e (@l) {
		my @e = unpack("C$n", $e);
		if (@e < $n) {
			unshift(@e, ((0) x ($n - @e)));
		}
		for my $i (0 .. $#o) {
			$o[$i] ^= $e[$i];
		}
	}
	return pack("C$n", @o);
}

sub xor_112 {
	return xor_n(112, @_);
}
sub xor_128 {
	return xor_n(128, @_);
}

sub gen_rtp_session_keys {
	my ($master_key, $master_salt) = @_;

	# this assumes session key length identical to master key length
	my $session_key = prf_n(length($master_key) * 8, $master_key, xor_112($master_salt, "\0\0\0\0\0\0\0"));
	my $auth_key = prf_n(160, $master_key, xor_112($master_salt, "\1\0\0\0\0\0\0"));
	my $session_salt = prf_n(112, $master_key, xor_112($master_salt, "\2\0\0\0\0\0\0"));
	if ($SRTP_DEBUG) {
		print("RTP keys generated for master key " . unpack("H8", $master_key) . "... and salt " .
			unpack("H8", $master_salt) . "... are: " .
			unpack("H8", $session_key) . "..., " .
			unpack("H*", $auth_key) . ", " .
			unpack("H8", $session_salt) . "...\n");
	}

	return ($session_key, $auth_key, $session_salt);
}

sub gen_rtcp_session_keys {
	my ($master_key, $master_salt) = @_;

	# this assumes session key length identical to master key length
	my $session_key = prf_n(length($master_key) * 8, $master_key, xor_112($master_salt, "\3\0\0\0\0\0\0"));
	my $auth_key = prf_n(160, $master_key, xor_112($master_salt, "\4\0\0\0\0\0\0"));
	my $session_salt = prf_n(112, $master_key, xor_112($master_salt, "\5\0\0\0\0\0\0"));
	if ($SRTP_DEBUG) {
		print("RTCP keys generated for master key " . unpack("H8", $master_key) . "... and salt " .
			unpack("H8", $master_salt) . "... are: " .
			unpack("H8", $session_key) . "..., " .
			unpack("H*", $auth_key) . ", " .
			unpack("H8", $session_salt) . "...\n");
	}

	return ($session_key, $auth_key, $session_salt);
}

sub aes_cm_iv_rtp {
	my ($r, $ssalt, $roc) = @_;

	my ($hdr, $seq, $ts, $ssrc) = unpack('a2na4a4', $r);
	my $iv = xor_128($ssalt . "\0\0",
		$ssrc . "\0\0\0\0\0\0\0\0", pack("Nnn", $roc, $seq, 0));
	return $iv;
}

sub aes_cm_iv_rtcp {
	my ($r, $ssalt, $idx) = @_;

	$idx ||= 0;
	my ($hdr, $ssrc) = unpack('a4a4', $r);
	my $iv = xor_128($ssalt . "\0\0",
		$ssrc . "\0\0\0\0\0\0\0\0", pack("Nn", $idx, 0));
	return $iv;
}

sub aes_f8_iv_rtp {
	my ($r, $ssalt, $roc) = @_;

	my ($hdr, $fields) = unpack('a1a11', $r);
	my $iv = pack('Ca*N', 0, $fields, $roc);
	return $iv;
}

sub aes_f8_iv_rtcp {
	my ($r, $ssalt, $idx) = @_;

	my ($fields) = unpack('a8', $r);
	my $iv = pack('a*Na*', "\0\0\0\0", (($idx || 0) | 0x80000000), $fields);
	return $iv;
}

sub decode_inline_base64 {
	my ($b64, $cs) = @_;
	# append possibly missing trailing ==
	$b64 .= '=' x (4 - (length($b64) % 4)) if ((length($b64) % 4) != 0);
	my $ks = decode_base64($b64);
	length($ks) == ($cs->{key_length} + $cs->{salt_length}) or die;
	my @ret = unpack("a$cs->{key_length}a$cs->{salt_length}", $ks);
	return @ret;
}

sub encrypt_rtp {
	my ($suite, $skey, $ssalt, $sauth, $roc, $mki, $mki_len, $unenc_srtp, $unauth_srtp, $packet) = @_;

	my ($hdr, $seq, $h2, $to_enc) = unpack('a2na8a*', $packet);
	$roc = $roc || 0;
	$seq == 0 and $roc++;

	my $iv = $$suite{iv_rtp}->($packet, $ssalt, $roc);
	my $enc = $unenc_srtp ? $to_enc : $$suite{enc_func}->($to_enc, $skey,
		$iv, $ssalt);
	my $pkt = pack('a*na*a*', $hdr, $seq, $h2, $enc);

	my $hmac = hmac_sha1($pkt . pack("N", $roc), $sauth);
#	print("HMAC for packet " . unpack("H*", $pkt) . " ROC $roc is " . unpack("H*", $hmac) . "\n");

	append_mki(\$pkt, $mki_len, $mki);

	#$pkt .= pack("N", 1); # mki
	$pkt .= substr($hmac, 0, $unauth_srtp ? 0 : $$suite{auth_tag});

	return ($pkt, $roc);
}

sub decrypt_rtp {
	my ($suite, $skey, $ssalt, $sauth, $roc, $packet) = @_;

	# XXX MKI, session parameters

	my $plen = length($packet);
	my $auth_tag = substr($packet, $plen - $$suite{auth_tag}, $$suite{auth_tag});
	$packet = substr($packet, 0, $plen - $$suite{auth_tag});

	my ($hdr, $seq, $h2, $to_enc) = unpack('a2na8a*', $packet);
	$roc = $roc || 0;
	$seq == 0 and $roc++;

	my $iv = $$suite{iv_rtp}->($packet, $ssalt, $roc);
	my $enc = $$suite{enc_func}->($to_enc, $skey,
		$iv, $ssalt);
	my $pkt = pack('a*na*a*', $hdr, $seq, $h2, $enc);

	my $hmac = hmac_sha1($packet . pack("N", $roc), $sauth);
#	print("HMAC for packet " . unpack("H*", $pkt) . " ROC $roc is " . unpack("H*", $hmac) . "\n");

	#$pkt .= pack("N", 1); # mki

	return ($pkt, $roc, $auth_tag, $hmac);
}

sub encrypt_rtcp {
	my ($suite, $skey, $ssalt, $sauth, $idx, $mki, $mki_len, $unenc_srtcp, $packet) = @_;

	my $iv = $suite->{iv_rtcp}->($packet, $ssalt, $idx);
	my ($hdr, $to_enc) = unpack('a8a*', $packet);
	my $enc = $unenc_srtcp ? $to_enc :
		$suite->{enc_func}->($to_enc, $skey,
		$iv, $ssalt);
	my $pkt = $hdr . $enc;
	$pkt .= pack("N", (($idx || 0) | ($unenc_srtcp ? 0 : 0x80000000)));

	my $hmac = hmac_sha1($pkt, $sauth);

	append_mki(\$pkt, $mki_len, $mki);

	#$pkt .= pack("N", 1); # mki
	$pkt .= substr($hmac, 0, 10);

	$idx++;

	return ($pkt, $idx);
}

sub decrypt_rtcp {
	my ($suite, $skey, $ssalt, $sauth, $packet) = @_;

	# XXX MKI, session parameters

	my $plen = length($packet);
	my $auth_tag = substr($packet, $plen - 10, 10);
	my $idx_raw = substr($packet, $plen - 4 - 10, 4);
	my ($idx) = unpack('N', $idx_raw);
	$idx &= 0x7fffffff;
	my $auth_packet = substr($packet, 0, $plen - 10);
	$packet = substr($packet, 0, $plen - 10 - 4);

	my $iv = $suite->{iv_rtcp}->($packet, $ssalt, $idx);
	my ($hdr, $to_enc) = unpack('a8a*', $packet);
	my $enc = $suite->{enc_func}->($to_enc, $skey,
		$iv, $ssalt);
	my $pkt = $hdr . $enc;

	my $hmac = hmac_sha1($auth_packet, $sauth);

	return ($pkt, $idx, $auth_tag, $hmac);
}

sub append_mki {
	my ($pack_r, $mki_len, $mki) = @_;

	$mki_len or return;

	$mki = pack('N', $mki);
	while (length($mki) < $mki_len) {
		$mki = "\x00" . $mki;
	}
	if (length($mki) > $mki_len) {
		$mki = substr($mki, -$mki_len);
	}
	$$pack_r .= $mki;
}

package NGCP::Rtpclient::SRTP::Context;

sub new {
	my ($class, $suite) = @_;

	my $self = {};
	bless $self, $class;

	$self->{suite} = $suite; # includes all parameters
	my $remote = $self->{remote} = $suite->{remote}; # shortcut

	$self->{roc} = 0;
	$self->{remote_roc} = 0;

	@$self{qw(session_key auth_key session_salt)}
		= NGCP::Rtpclient::SRTP::gen_rtp_session_keys($suite->{master_key}, $suite->{master_salt});
	@$self{qw(rtcp_session_key rtcp_auth_key rtcp_session_salt)}
		= NGCP::Rtpclient::SRTP::gen_rtcp_session_keys($suite->{master_key}, $suite->{master_salt});
	@$self{qw(remote_session_key remote_auth_key remote_session_salt)}
		= NGCP::Rtpclient::SRTP::gen_rtp_session_keys($remote->{master_key}, $remote->{master_salt});
	@$self{qw(remote_rtcp_session_key remote_rtcp_auth_key remote_rtcp_session_salt)}
		= NGCP::Rtpclient::SRTP::gen_rtcp_session_keys($remote->{master_key}, $remote->{master_salt});

	return $self;
};

sub encrypt {
	my ($self, $component, $pack) = @_;

	if ($component == 0) {
		# XXX MKI, SRTP/SDES session options
		my ($p, $roc) = NGCP::Rtpclient::SRTP::encrypt_rtp(@$self{qw(suite session_key session_salt
			auth_key roc)}, '', 0,
			0, 0, $pack);
		$self->{roc} = $roc;
		return $p;
	}
	else {
		# RTCP
		my ($p, $idx) = NGCP::Rtpclient::SRTP::encrypt_rtcp(@$self{qw(suite rtcp_session_key
			rtcp_session_salt
			rtcp_auth_key rtcp_index)}, '', 0,
			0, $pack);
		$self->{rtcp_index} = $idx;
		return $p;
	}
}

sub decrypt {
	my ($self, $component, $pack) = @_;

	if ($component == 0) {
		# XXX MKI, SRTP/SDES session options
		my ($p, $roc) = NGCP::Rtpclient::SRTP::decrypt_rtp(@$self{qw(remote remote_session_key
			remote_session_salt
			remote_auth_key remote_roc)}, $pack);
		$self->{remote_roc} = $roc;
		# XXX verify hmac/auth
		return $p;
	}
	else {
		# RTCP
		my ($p, $idx) = NGCP::Rtpclient::SRTP::decrypt_rtcp(@$self{qw(remote remote_rtcp_session_key
			remote_rtcp_session_salt
			remote_rtcp_auth_key)}, $pack);
		$self->{remote_rtcp_index} = $idx;
		# XXX verify hmac/auth
		return $p;
	}
}

1;
