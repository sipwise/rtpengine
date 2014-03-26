#!/usr/bin/perl

use strict;
use warnings;
use Socket;
use UUID;
use BSD::Resource;
use Getopt::Long;
use Socket6;
use Bencode qw( bencode bdecode );
use Time::HiRes;
use Crypt::Rijndael;
use Digest::SHA qw(hmac_sha1);
use MIME::Base64;
use Data::Dumper;

my ($NUM, $RUNTIME, $STREAMS, $PAYLOAD, $INTERVAL, $RTCP_INTERVAL, $STATS_INTERVAL)
	= (1000, 30, 1, 160, 20, 5, 5);
my ($NODEL, $IP, $IPV6, $KEEPGOING, $REINVITES, $PROTOS, $DEST, $SUITES, $NOENC, $RTCPMUX, $BUNDLE, $LAZY);
GetOptions(
		'no-delete'	=> \$NODEL,
		'num-calls=i'	=> \$NUM,
		'local-ip=s'	=> \$IP,
		'local-ipv6=s'	=> \$IPV6,
		'runtime=i'	=> \$RUNTIME,
		'keep-going'	=> \$KEEPGOING,		# don't stop sending rtp if a packet doesn't go through
		'reinvites'	=> \$REINVITES,
		'max-streams=i'	=> \$STREAMS,
		'protocols=s'	=> \$PROTOS,		# "RTP/AVP,RTP/SAVP"
		'destination=s'	=> \$DEST,
		'payload-size=i'=> \$PAYLOAD,
		'rtp-interval=i'=> \$INTERVAL,		# in ms
		'rtcp-interval=i'=>\$RTCP_INTERVAL,	# in seconds
		'stats-interval=i'=>\$STATS_INTERVAL,
		'suites=s'	=> \$SUITES,
		'no-encrypt'	=> \$NOENC,
		'rtcp-mux'	=> \$RTCPMUX,
		'bundle'	=> \$BUNDLE,
		'lazy-params'	=> \$LAZY,
) or die;

($IP || $IPV6) or die("at least one of --local-ip or --local-ipv6 must be given");

$SIG{ALRM} = sub { print "alarm!\n"; };
setrlimit(RLIMIT_NOFILE, 8000, 8000);

$PROTOS and $PROTOS = [split(/\s*[,;:]+\s*/, $PROTOS)];
$PROTOS && @$PROTOS == 1 and $$PROTOS[1] = $$PROTOS[0];
$DEST and $DEST = [split(/:/, $DEST)];
$$DEST[0] or $$DEST[0] = '127.0.0.1';
$$DEST[1] or $$DEST[1] = 2223;
$SUITES and $SUITES = [split(/\s*[,;:]+\s*/, $SUITES)];

my @chrs = ('a' .. 'z', 'A' .. 'Z', '0' .. '9');
sub rand_str {
	my ($len) = @_;
	return join('', (map {$chrs[rand(@chrs)]} (1 .. $len)));
}

my $fd;
sub msg {
	my ($d) = @_;
	my $l = bencode($d);
	my $cookie = $$ . '_' . rand_str(10);
	my $r;
	while (1) {
		send($fd, "$cookie $l", 0) or die $!;
		my $err = '';
		alarm(1);
		recv($fd, $r, 0xffff, 0) or $err = "$!";
		alarm(0);
		$err =~ /interrupt/i and next;
		$err and die $err;
		last;
	}
	$r =~ s/^\Q$cookie\E +//s or die $r;
	$r =~ s/[\r\n]+$//s;
	return $r ? bdecode($r, 1) : undef;
}

socket($fd, AF_INET, SOCK_DGRAM, 0) or die $!;
connect($fd, sockaddr_in($$DEST[1], inet_aton($$DEST[0]))) or die $!;

msg({command => 'ping'})->{result} eq 'pong' or die;

my (@calls, %calls);
my %NOENC;

sub send_receive {
	my ($send_fd, $receive_fd, $payload, $destination) = @_;

	send($send_fd, $payload, 0, $destination) or die $!;
	my $x;
	my $err = '';
	alarm(1);
	recv($receive_fd, $x, 0xffff, 0) or $err = "$!";
	alarm(0);
	$err && $err !~ /interrupt/i and die $err;
	return $x;
}

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

	my $session_key = prf_n(128, $master_key, xor_112($master_salt, "\0\0\0\0\0\0\0"));
	my $auth_key = prf_n(160, $master_key, xor_112($master_salt, "\1\0\0\0\0\0\0"));
	my $session_salt = prf_n(112, $master_key, xor_112($master_salt, "\2\0\0\0\0\0\0"));
#	print("RTP keys generated for master key " . unpack("H8", $master_key) . "... and salt " .
#		unpack("H8", $master_salt) . "... are: " .
#		unpack("H8", $session_key) . "..., " .
#		unpack("H*", $auth_key) . ", " .
#		unpack("H8", $session_salt) . "...\n");

	return ($session_key, $auth_key, $session_salt);
}

sub gen_rtcp_session_keys {
	my ($master_key, $master_salt) = @_;

	my $session_key = prf_n(128, $master_key, xor_112($master_salt, "\3\0\0\0\0\0\0"));
	my $auth_key = prf_n(160, $master_key, xor_112($master_salt, "\4\0\0\0\0\0\0"));
	my $session_salt = prf_n(112, $master_key, xor_112($master_salt, "\5\0\0\0\0\0\0"));
#	print("RTCP keys generated for master key " . unpack("H8", $master_key) . "... and salt " .
#		unpack("H8", $master_salt) . "... are: " .
#		unpack("H8", $session_key) . "..., " .
#		unpack("H*", $auth_key) . ", " .
#		unpack("H8", $session_salt) . "...\n");

	return ($session_key, $auth_key, $session_salt);
}

sub aes_cm_iv_rtp {
	my ($ctx, $r) = @_;

	my ($hdr, $seq, $ts, $ssrc) = unpack('a2na4a4', $r);
	my $iv = xor_128($$ctx{rtp_session_salt} . "\0\0",
		$ssrc . "\0\0\0\0\0\0\0\0", pack("Nnn", $$ctx{rtp_roc}, $seq, 0));
	return $iv;
}

sub aes_cm_iv_rtcp {
	my ($ctx, $r) = @_;

	my $idx = $$ctx{rtcp_index} || 0;
	my ($hdr, $ssrc) = unpack('a4a4', $r);
	my $iv = xor_128($$ctx{rtcp_session_salt} . "\0\0",
		$ssrc . "\0\0\0\0\0\0\0\0", pack("Nn", $idx, 0));
	return $iv;
}

sub aes_f8_iv_rtp {
	my ($ctx, $r) = @_;

	my ($hdr, $fields) = unpack('a1a11', $r);
	my $iv = pack('Ca*N', 0, $fields, $$ctx{rtp_roc});
	return $iv;
}

sub aes_f8_iv_rtcp {
	my ($ctx, $r) = @_;

	my ($fields) = unpack('a8', $r);
	my $iv = pack('a*Na*', "\0\0\0\0", (($$ctx{rtcp_index} || 0) | 0x80000000), $fields);
	return $iv;
}

sub append_mki {
	my ($ctx_dir, $pack_r) = @_;

	$$ctx_dir{rtp_mki_len} or return;

	my $mki = pack('N', $$ctx_dir{rtp_mki});
	while (length($mki) < $$ctx_dir{rtp_mki_len}) {
		$mki = "\x00" . $mki;
	}
	if (length($mki) > $$ctx_dir{rtp_mki_len}) {
		$mki = substr($mki, -$$ctx_dir{rtp_mki_len});
	}
	$$pack_r .= $mki;
}

sub rtcp_encrypt {
	my ($r, $ctx, $dir) = @_;

	if (!$$ctx{$dir}{rtcp_session_key}) {
		($$ctx{$dir}{rtcp_session_key}, $$ctx{$dir}{rtcp_session_auth_key}, $$ctx{$dir}{rtcp_session_salt})
			= gen_rtcp_session_keys($$ctx{$dir}{rtp_master_key}, $$ctx{$dir}{rtp_master_salt});
	}

	($NOENC && $NOENC{rtcp_packet}) and return $NOENC{rtcp_packet};

	my $iv = $$ctx{$dir}{crypto_suite}{iv_rtcp}->($$ctx{$dir}, $r);
	my ($hdr, $to_enc) = unpack('a8a*', $r);
	my $enc = $$ctx{$dir}{crypto_suite}{enc_func}->($to_enc, $$ctx{$dir}{rtcp_session_key},
		$iv, $$ctx{$dir}{rtcp_session_salt});
	my $pkt = $hdr . $enc;
	$pkt .= pack("N", (($$ctx{$dir}{rtcp_index} || 0) | 0x80000000));

	my $hmac = hmac_sha1($pkt, $$ctx{$dir}{rtcp_session_auth_key});

	append_mki($$ctx{$dir}, \$pkt);

	#$pkt .= pack("N", 1); # mki
	$pkt .= substr($hmac, 0, 10);

	$$ctx{$dir}{rtcp_index}++;

	$NOENC{rtcp_packet} = $pkt;

	return $pkt;
}

sub rtp_encrypt {
	my ($r, $ctx, $dir) = @_;

	if (!$$ctx{$dir}{rtp_session_key}) {
		($$ctx{$dir}{rtp_session_key}, $$ctx{$dir}{rtp_session_auth_key}, $$ctx{$dir}{rtp_session_salt})
			= gen_rtp_session_keys($$ctx{$dir}{rtp_master_key}, $$ctx{$dir}{rtp_master_salt});
	}

	($NOENC && $NOENC{rtp_packet}) and return $NOENC{rtp_packet};

	my ($hdr, $seq, $h2, $to_enc) = unpack('a2na8a*', $r);
	my $roc = $$ctx{$dir}{rtp_roc} || 0;
	$seq == 0 and $roc++;
	$$ctx{$dir}{rtp_roc} = $roc;

	my $iv = $$ctx{$dir}{crypto_suite}{iv_rtp}->($$ctx{$dir}, $r);
	my $enc = $$ctx{$dir}{crypto_suite}{enc_func}->($to_enc, $$ctx{$dir}{rtp_session_key},
		$iv, $$ctx{$dir}{rtp_session_salt});
	my $pkt = pack('a*na*a*', $hdr, $seq, $h2, $enc);

	my $hmac = hmac_sha1($pkt . pack("N", $$ctx{$dir}{rtp_roc}), $$ctx{$dir}{rtp_session_auth_key});
#	print("HMAC for packet " . unpack("H*", $pkt) . " ROC $roc is " . unpack("H*", $hmac) . "\n");

	append_mki($$ctx{$dir}, \$pkt);

	#$pkt .= pack("N", 1); # mki
	$pkt .= substr($hmac, 0, $$ctx{$dir}{crypto_suite}{auth_tag});

	$NOENC{rtp_packet} = $pkt;

	return $pkt;
}

my @crypto_suites = (
	{
		str		=> 'AES_CM_128_HMAC_SHA1_80',
		auth_tag	=> 10,
		enc_func	=> \&aes_cm,
		iv_rtp		=> \&aes_cm_iv_rtp,
		iv_rtcp		=> \&aes_cm_iv_rtcp,
	},
	{
		str		=> 'AES_CM_128_HMAC_SHA1_32',
		auth_tag	=> 4,
		enc_func	=> \&aes_cm,
		iv_rtp		=> \&aes_cm_iv_rtp,
		iv_rtcp		=> \&aes_cm_iv_rtcp,
	},
	{
		str		=> 'F8_128_HMAC_SHA1_80',
		auth_tag	=> 10,
		enc_func	=> \&aes_f8,
		iv_rtp		=> \&aes_f8_iv_rtp,
		iv_rtcp		=> \&aes_f8_iv_rtcp,
	},
);
$SUITES and @crypto_suites = grep {my $x = $$_{str}; grep {$x eq $_} @$SUITES} @crypto_suites;
my %crypto_suites = map {$$_{str} => $_} @crypto_suites;

sub savp_sdp {
	my ($ctx, $ctx_o) = @_;

	if (!$$ctx{out}{crypto_suite}) {
		$$ctx{out}{crypto_suite} = $$ctx_o{in}{crypto_suite} ? $$ctx_o{in}{crypto_suite}
			: $crypto_suites[rand(@crypto_suites)];

		$$ctx{out}{rtp_mki_len} = 0;
		if (rand() > .5) {
			$$ctx{out}{rtp_mki_len} = int(rand(120)) + 1;
			$$ctx{out}{rtp_mki} = int(rand(2**30)) | 1;
			if ($$ctx{out}{rtp_mki_len} < 32) {
				$$ctx{out}{rtp_mki} &= (0xffffffff >> (32 - ($$ctx{out}{rtp_mki_len})));
			}
		}
	}

	if (!$$ctx{out}{rtp_master_key}) {
		$$ctx{out}{rtp_master_key} = rand_str(16);
		$$ctx{out}{rtp_master_salt} = rand_str(14);
		if ($NOENC && $NOENC{rtp_master_key}) {
			$$ctx{out}{rtp_master_key} = $NOENC{rtp_master_key};
			$$ctx{out}{rtp_master_salt} = $NOENC{rtp_master_salt};
		}
		$NOENC{rtp_master_key} = $$ctx{out}{rtp_master_key};
		$NOENC{rtp_master_salt} = $$ctx{out}{rtp_master_salt};
	}

	my $ret = "a=crypto:0 $$ctx{out}{crypto_suite}{str} inline:" . encode_base64($$ctx{out}{rtp_master_key} . $$ctx{out}{rtp_master_salt}, '');
	if ($$ctx{out}{rtp_mki_len}) {
		$ret .= "|$$ctx{out}{rtp_mki}:$$ctx{out}{rtp_mki_len}";
	}

	$ret .= "\n";
	return $ret;
}

sub rtcp_sr {
	my @now = Time::HiRes::gettimeofday();
	my $secs = $now[0] + 2208988800;
	my $frac = $now[1] / 1000000 * 2**32;
	my $sr = pack('CCnN NNN NN', (2 << 6) | 1, 200, 12, rand(2**32), $secs, $frac,
		12345, 0, 0);
	$sr .= pack('N CCCC NNNN', 0, 0, 0, 0, 0, 0, 0, 0, 0);
	return $sr;
}

sub rtcp_rtpfb {
	return pack('CCn NN', (2 << 6) | 1, 205, 2, rand() * 2**32, rand() * 2**32);
}

sub rtcp_avp {
	my ($recv, $ctx, $ctx_o) = @_;
	my $sr = rtcp_sr();
	my $exp = $sr;
	$$recv{name} eq 'RTP/SAVP' and $exp = rtcp_encrypt($sr, $ctx_o, 'in');
	$$recv{name} eq 'RTP/SAVPF' and $exp = rtcp_encrypt($sr, $ctx_o, 'in');
	return ($sr, $exp);
}

sub rtcp_savp {
	my ($recv, $ctx, $ctx_o) = @_;
	my $sr = rtcp_sr();
	my $enc = rtcp_encrypt($sr, $ctx, 'out');
	my $exp = $enc;
	$$recv{name} eq 'RTP/AVP' and $exp = $sr;
	$$recv{name} eq 'RTP/AVPF' and $exp = $sr;
	return ($enc, $exp);
}

sub rtcp_avpf {
	my ($recv, $ctx, $ctx_o) = @_;
	my $sr = rtcp_sr();
	my $fb = rtcp_rtpfb();
	my $exp = $sr;
	$$recv{name} eq 'RTP/AVPF' and $exp .= $fb;
	$$recv{name} eq 'RTP/SAVP' and $exp = rtcp_encrypt($sr, $ctx_o, 'in');
	$$recv{name} eq 'RTP/SAVPF' and $exp = rtcp_encrypt($sr . $fb, $ctx_o, 'in');
	return ($sr . $fb, $exp);
}

sub rtcp_savpf {
	my ($recv, $ctx, $ctx_o) = @_;
	my $sr = rtcp_sr();
	my $fb = rtcp_rtpfb();
	my $enc = rtcp_encrypt($sr . $fb, $ctx, 'out');
	my $exp = $enc;
	$$recv{name} eq 'RTP/AVP' and $exp = $sr;
	$$recv{name} eq 'RTP/AVPF' and $exp = $sr . $fb;
	$$recv{name} eq 'RTP/SAVP' and $exp = rtcp_encrypt($sr, $ctx_o, 'in');
	return ($enc, $exp);
}

sub rtp {
	my ($ctx) = @_;
	my $seq = $$ctx{rtp_seqnum};
	defined($seq) or $seq = int(rand(0xfffff)) + 1;
	my $hdr = pack("CCnNN", 0x80, 0x00, $seq, rand(2**32), rand(2**32));
	my $pack = $hdr . rand_str($PAYLOAD);
	$$ctx{rtp_seqnum} = (++$seq & 0xffff);
	return $pack;
}

sub rtp_avp {
	my ($recv, $ctx, $ctx_o) = @_;
	my $pack = rtp($ctx);
	my $exp = $pack;
	$$recv{name} eq 'RTP/SAVP' and $exp = rtp_encrypt($pack, $ctx_o, 'in');
	$$recv{name} eq 'RTP/SAVPF' and $exp = rtp_encrypt($pack, $ctx_o, 'in');
	return ($pack, $exp);
}

sub rtp_savp {
	my ($recv, $ctx, $ctx_o) = @_;
	my $pack = rtp($ctx);
	my $enc = rtp_encrypt($pack, $ctx, 'out');
	my $exp = $enc;
	$$recv{name} eq 'RTP/AVP' and $exp = $pack;
	$$recv{name} eq 'RTP/AVPF' and $exp = $pack;
	return ($enc, $exp);
}

sub savp_crypto {
	my ($sdp, $ctx, $ctx_o) = @_;

	my @a = $sdp =~ /[\r\n]a=crypto:\d+ (\w+) inline:([\w\/+]{40})(?:\|(?:2\^(\d+)|(\d+)))?(?:\|(\d+):(\d+))?[\r\n]/sig;
	@a or die;
	my $i = 0;
	while (@a >= 6) {
		$$ctx[$i]{in}{crypto_suite} = $crypto_suites{$a[0]} or die;
		my $ks = decode_base64($a[1]);
		length($ks) == 30 or die;
		($$ctx[$i]{in}{rtp_master_key}, $$ctx[$i]{in}{rtp_master_salt}) = unpack('a16a14', $ks);
		$$ctx[$i]{in}{rtp_mki} = $a[4];
		$$ctx[$i]{in}{rtp_mki_len} = $a[5];
		undef($$ctx[$i]{in}{rtp_session_key});
		undef($$ctx[$i]{in}{rtcp_session_key});

		$i++;
		@a = @a[6 .. $#a];
	}
}

sub hexdump {
	my $o = '';
	for my $a (@_) {
		$o .= "<< " . unpack("H*", $a) . " >> ";
	}
	return $o;
}

my $RTP_COUNT = 0;

sub do_rtp {
	my ($rtcp) = @_;
	for my $c (@calls) {
		$c or next;
		for my $i ([0,1],[1,0]) {
			my ($a, $b) = @$i;
			my $A = $$c{sides}[$a];
			my $B = $$c{sides}[$b];

			my $rtp_fds = $$A{rtp_fds};
			my $rtcp_fds = $$A{rtcp_fds};
			my $rtp_fds_o = $$B{rtp_fds};
			my $rtcp_fds_o = $$B{rtcp_fds};

			my $pr = $$A{proto};;
			my $trans = $$A{transport};
			my $trans_o = $$B{transport};
			my $tcx = $$A{trans_contexts};
			my $tcx_o = $$B{trans_contexts};
			my $outputs = $$A{outputs};

			for my $j (0 .. ($$A{streams_active} - 1)) {
				my ($bj_a, $bj_b) = ($j, $j);
				$$A{bundle}
					and $bj_a = 0;
				$$B{bundle}
					and $bj_b = 0;

				my $addr = inet_pton($$pr{family}, $$outputs[$j][1]);
				my ($payload, $expect) = $$trans{rtp_func}($trans_o, $$tcx[$j], $$tcx_o[$j]);
				my $dst = $$pr{sockaddr}($$outputs[$j][0], $addr);
				my $repl = send_receive($$rtp_fds[$bj_a], $$rtp_fds_o[$bj_b], $payload, $dst);
				$RTP_COUNT++;
				if ($repl eq '') {
					warn("no rtp reply received, port $$outputs[$j][0]");
					$KEEPGOING or undef($c);
				}
				$NOENC and $repl = $expect;
				!$repl && $KEEPGOING and next;
				$repl eq $expect or die hexdump($repl, $expect) . " $$trans{name} > $$trans_o{name}, $$c{callid}, RTP port $$outputs[$j][0]";

				$rtcp or next;
				($payload, $expect) = $$trans{rtcp_func}($trans_o, $$tcx[$j], $$tcx_o[$j]);
				my $dstport = $$outputs[$j][0] + 1;
				my $sendfd = $$rtcp_fds[$bj_a];
				my $expfd = $$rtcp_fds_o[$bj_b];
				if ($$A{rtcpmux}) {
					$dstport--;
					$sendfd = $$rtp_fds[$bj_a];
				}
				if ($$B{rtcpmux}) {
					$expfd = $$rtp_fds_o[$bj_b];
				}
				$dst = $$pr{sockaddr}($dstport, $addr);
				$repl = send_receive($sendfd, $expfd, $payload, $dst);
				$NOENC and $repl = $expect;
				!$repl && $KEEPGOING and next;
				$repl eq $expect or die hexdump($repl, $expect) . " $$trans{name} > $$trans_o{name}, $$c{callid}, RTCP";
			}
		}
	}
}

my %proto_defs = (
	ipv4 => {
		code		=> 'I',
		family		=> AF_INET,
		reply		=> '4',
		address		=> $IP,
		sockaddr	=> \&sockaddr_in,
		family_str	=> 'IP4',
		direction	=> 'internal',
	},
	ipv6 => {
		code		=> 'E',
		family		=> AF_INET6,
		reply		=> '6',
		address		=> $IPV6,
		sockaddr	=> \&sockaddr_in6,
		family_str	=> 'IP6',
		direction	=> 'external',
	},
);
my @protos_avail;
$IP and push(@protos_avail, $proto_defs{ipv4});
$IPV6 and push(@protos_avail, $proto_defs{ipv6});
my @sides = qw(A B);

my @transports = (
	{
		name => 'RTP/AVP',
		rtp_func => \&rtp_avp,
		rtcp_func => \&rtcp_avp,
	},
	{
		name => 'RTP/AVPF',
		rtp_func => \&rtp_avp,
		rtcp_func => \&rtcp_avpf,
	},
	{
		name => 'RTP/SAVP',
		sdp_media_params => \&savp_sdp,
		sdp_parse_func => \&savp_crypto,
		rtp_func => \&rtp_savp,
		rtcp_func => \&rtcp_savp,
	},
	{
		name => 'RTP/SAVPF',
		sdp_media_params => \&savp_sdp,
		sdp_parse_func => \&savp_crypto,
		rtp_func => \&rtp_savp,
		rtcp_func => \&rtcp_savpf,
	},
);
my %transports = map {$$_{name} => $_} @transports;

sub callid {
	my $i = rand_str(50);
	return $i;
}

my $NUM_STREAMS = 0;

sub port_setup {
	my ($r, $j) = @_;

	my $pr = $$r{proto};
	my $rtp_fds = $$r{rtp_fds};
	my $rtcp_fds = $$r{rtcp_fds};
	my $ports = $$r{ports};
	my $ips = $$r{ips};
	my $tcx = $$r{trans_contexts};
	$$tcx[$j] or $$tcx[$j] = {};

	while (1) {
		socket(my $rtp, $$pr{family}, SOCK_DGRAM, 0) or die $!;
		socket(my $rtcp, $$pr{family}, SOCK_DGRAM, 0) or die $!;
		my $port = rand(0x7000) << 1 + 1024;
		bind($rtp, $$pr{sockaddr}($port,
			inet_pton($$pr{family}, $$pr{address}))) or next;
		bind($rtcp, $$pr{sockaddr}($port + 1,
			inet_pton($$pr{family}, $$pr{address}))) or next;

		$$rtp_fds[$j] = $rtp;
		$$rtcp_fds[$j] = $rtcp;

		my $addr = getsockname($rtp);
		my $ip;
		($$ports[$j], $ip) = $$pr{sockaddr}($addr);
		$$ips[$j] = inet_ntop($$pr{family}, $ip);

		last;
	}
}

sub side_setup {
	my ($i) = @_;
	my $r = {};

	my $pr = $$r{proto} = $protos_avail[rand(@protos_avail)];
	$$r{transport} = ($PROTOS && $$PROTOS[$i] && $transports{$$PROTOS[$i]})
			? $transports{$$PROTOS[$i]}
			: $transports[rand(@transports)];
	$$r{trans_contexts} = [];
	$$r{outputs} = [];

	$$r{num_streams} = int(rand($STREAMS));
	$$r{streams_seen} = 0;
	$$r{streams_active} = 0;
	$$r{rtp_fds} = [];
	$$r{rtcp_fds} = [];
	$$r{ports} = [];
	$$r{ips} = [];

	for my $j (0 .. $$r{num_streams}) {
		port_setup($r, $j);
	}

	$$r{tag} = rand_str(15);
	$RTCPMUX and $$r{want_rtcpmux} = rand() >= .3;
	$BUNDLE and $$r{want_bundle} = rand() >= .3;
	$$r{want_bundle} and $$r{want_rtcpmux} = 1;

	return $r;
}

sub call_setup {
	my ($c) = @_;

	$$c{setup} = 1;
	$$c{callid} = callid();

	$$c{sides}[0] = side_setup(0);
	$$c{sides}[1] = side_setup(1);
}

sub offer_answer {
	my ($c, $a, $b, $op) = @_;

	$$c{setup} or call_setup($c);

	my $callid = $$c{callid} || ($$c{callid} = callid());

	my $A = $$c{sides}[$a];
	my $B = $$c{sides}[$b];

	my $pr = $$A{proto};
	my $pr_o = $$B{proto};
	my $ips_t = $$A{ips};
	my $ports_t = $$A{ports};
	my $tr = $$A{transport};
	my $tr_o = $$B{transport};
	my $tcx = $$A{trans_contexts};
	my $tcx_o = $$B{trans_contexts};

	my $sdp = <<"!";
v=0
o=blah 123 123 IN $$pr{family_str} $$ips_t[0]
s=session
c=IN $$pr{family_str} $$ips_t[0]
t=0 0
!
	my $ul = $$A{num_streams};
	$op eq 'answer' && $$A{streams_seen} < $$A{num_streams}
		and $ul = $$A{streams_seen};

	$$A{want_bundle} && $op eq 'offer' and
		$$A{bundle} = 1,
		$sdp .= "a=group:BUNDLE " . join(' ', (0 .. $ul)) . "\n";

	for my $i (0 .. $ul) {
		my $bi = $i;
		$$A{bundle}
			and $bi = 0;

		my $p = $$ports_t[$bi];
		my $cp = $p + 1;
		$$A{bundle} && $$A{want_rtcpmux} && $op eq 'offer'
			and $cp = $p;

		$sdp .= <<"!";
m=audio $p $$tr{name} 8
a=rtpmap:8 PCMA/8000
!
		if ($$A{want_rtcpmux} && $op eq 'offer') {
			$sdp .= "a=rtcp-mux\n";
			$sdp .= "a=rtcp:$cp\n";
			$$A{rtcpmux} = 1;
		}
		else {
			rand() >= .5 and $sdp .= "a=rtcp:$cp\n";
		}
		$$tr{sdp_media_params} and $sdp .= $$tr{sdp_media_params}($$tcx[$i], $$tcx_o[$i]);

		$$A{bundle} and
			$sdp .= "a=mid:$i\n";
	}

	for my $x (($ul + 1) .. $$A{streams_seen}) {
		$sdp .= "m=audio 0 $$tr{name} 0\n";
	}

	$op eq 'offer' and print("transport is $$tr{name} -> $$tr_o{name}\n");

	#print(Dumper($op, $A, $B, $sdp) . "\n\n\n\n");
	#print("sdp $op in:\n$sdp\n\n");

	my $dict = {sdp => $sdp, command => $op, 'call-id' => $$c{callid},
		flags => [ 'trust address' ],
		replace => [ 'origin', 'session connection' ],
		#direction => [ $$pr{direction}, $$pr_o{direction} ],
		'received from' => [ qw(IP4 127.0.0.1) ],
		'rtcp-mux' => ['demux'],
	};
	#$viabranch and $dict->{'via-branch'} = $viabranch;
	if ($op eq 'offer') {
		$dict->{'from-tag'} = $$A{tag};
		rand() > .5 and $$dict{'to-tag'} = $$B{tag};
	}
	elsif ($op eq 'answer') {
		$dict->{'from-tag'} = $$B{tag},
		$dict->{'to-tag'} = $$A{tag};
	}
	if (!$LAZY
		|| ($op eq 'offer' && !$$c{established})
		|| (rand() > .5))
	{
		$$dict{'address family'} = $$pr_o{family_str};
		$$dict{'transport protocol'} = $$tr_o{name};
	}

	#print(Dumper($dict) . "\n\n");
	my $o = msg($dict);

	$$o{result} eq 'ok' or die;
	#print("sdp $op out:\n$$o{sdp}\n\n\n\n");
	my ($rp_af, $rp_add) = $$o{sdp} =~ /c=IN IP([46]) (\S+)/s or die;
	$$B{rtcpmux} and ($$o{sdp} =~ /a=rtcp-mux/s or die);
	my @rp_ports = $$o{sdp} =~ /m=audio (\d+) \Q$$tr_o{name}\E /gs or die;
	$$B{streams_seen} = $#rp_ports;
	$rp_af ne $$pr_o{reply} and die "incorrect address family reply code";
	$NUM_STREAMS -= $$B{streams_active};
	$$B{streams_active} = 0;
	my $old_outputs = $$B{outputs};
	my $rpl_t = $$B{outputs} = [];
	for my $i (0 .. $#rp_ports) {
		my $rpl = $rp_ports[$i];

		if ($rpl == 0) {
			$op eq 'offer' and $$B{streams_seen}--;
			if ($$A{rtp_fds}[$i]) {
				undef($$A{rtp_fds}[$i]);
			}
			next;
		}

		$$B{ports}[$i] or next;

		$$B{streams_active}++;
		$NUM_STREAMS++;
		push(@$rpl_t, [$rpl,$rp_add]);
		my $oa = shift(@$old_outputs);
		if (defined($oa) && $$oa[0] != $rpl) {
			print("port change: $$oa[0] -> $rpl\n");
			#print(Dumper($i, $c) . "\n");
			undef($$tcx_o[$i]{out}{rtcp_index});
			undef($$tcx_o[$i]{out}{rtp_roc});
		}
	}
	$$tr_o{sdp_parse_func} and $$tr_o{sdp_parse_func}($$o{sdp}, $tcx_o, $tcx);
	#print(Dumper($op, $A, $B) . "\n\n\n\n");

	$op eq 'answer' and $$c{established} = 1;
}

sub offer {
	my ($c, $a, $b) = @_;
	return offer_answer($c, $a, $b, 'offer');
}
sub answer {
	my ($c, $a, $b) = @_;
	return offer_answer($c, $a, $b, 'answer');
}

for my $iter (1 .. $NUM) {
	($iter % 10 == 0) and print("$iter calls established\n"), do_rtp();

	my $c = {};
	offer($c, 0, 1);
	answer($c, 1, 0);
	push(@calls, $c);
	$calls{$$c{callid}} = $c;
}

print("all calls established\n");

#print(Dumper(\@calls) . "\n");

my $end = time() + $RUNTIME;
my $rtptime = Time::HiRes::gettimeofday();
my $rtcptime = $rtptime;
my $countstart = $rtptime;
my $countstop = $countstart + $STATS_INTERVAL;
my $last_reinv = $rtptime;
while (time() < $end) {
	my $now = Time::HiRes::gettimeofday();
	$now <= $rtptime and Time::HiRes::sleep($rtptime - $now);
	$rtptime += $INTERVAL / 1000.0;

	my $rtcp = 0;
	if ($now >= $rtcptime) {
		$rtcp = 1;
		$rtcptime += $RTCP_INTERVAL;
	}

	if ($now >= $countstop) {
		my $span = $now - $countstart;
		printf("[%05d] %d RTP packets sent in %.1f seconds = %.1f packets per stream per second\n",
			$$,
			$RTP_COUNT, $span,
			$RTP_COUNT / $span / $NUM_STREAMS);
		$RTP_COUNT = 0;
		$countstart = $now;
		$countstop = $countstart + $STATS_INTERVAL;
	}

	do_rtp($rtcp);

	@calls = sort {rand() < .5} grep(defined, @calls);

	if ($REINVITES && $now >= $last_reinv + 15) {
		$last_reinv = $now;
		my $c = $calls[rand(@calls)];
		print("simulating re-invite on $$c{callid}\n");
		for my $i (0,1) {
			my $s = $$c{sides}[$i];
			for my $j (0 .. $$s{num_streams}) {
				if (rand() < .5) {
					print("\tside $sides[$i] stream #$j: new port\n");
					port_setup($s, $j);
					#print("\n" . Dumper($i, $c) . "\n");
					undef($$s{trans_contexts}[$j]{in}{rtcp_index});
					undef($$s{trans_contexts}[$j]{in}{rtp_roc});
				}
				else {
					print("\tside $sides[$i] stream #$j: same port\n");
				}
			}
		}
		offer($c, 0, 1);
		answer($c, 1, 0);
	}
}

if (!$NODEL) {
	print("deleting\n");
	for my $c (@calls) {
		$c or next;
		my $callid = $$c{callid};
		my $fromtag = $$c{sides}[0]{tag};
		my $totag = $$c{sides}[1]{tag};
		my $dict = { command => 'delete', 'call-id' => $callid, 'from-tag' => $fromtag,
			'to-tag' => $totag,
		};
		msg($dict);
	}
}
print("done\n");
