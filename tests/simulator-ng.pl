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
use NGCP::Rtpclient::SRTP;

my ($NUM, $RUNTIME, $STREAMS, $PAYLOAD, $INTERVAL, $RTCP_INTERVAL, $STATS_INTERVAL)
	= (1000, 30, 1, 160, 20, 5, 5);
my ($NODEL, $IP, $IPV6, $KEEPGOING, $REINVITES, $PROTOS, $DEST, $SUITES, $NOENC, $RTCPMUX, $BUNDLE, $LAZY,
	$CHANGE_SSRC, $PORT_LATCHING, $RECORD);
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
		'change-ssrc'   => \$CHANGE_SSRC,
		'port-latching' => \$PORT_LATCHING,
		'record'	=> \$RECORD,
) or die;

($IP || $IPV6) or die("at least one of --local-ip or --local-ipv6 must be given");

$SIG{ALRM} = sub { print "alarm!\n"; };
setrlimit(RLIMIT_NOFILE, 8000, 8000);

$PROTOS and $PROTOS = [split(/\s*[,;:]+\s*/, $PROTOS)];
$PROTOS && @$PROTOS == 1 and $$PROTOS[1] = $$PROTOS[0];
$DEST and $DEST = [$DEST =~ /^(?:([a-z.-]+)(?::(\d+))?|([\d.]+)(?::(\d+))?|([\da-f:]+)|\[([\da-f:]+)\]:(\d+))$/si];
my $dest_host = $$DEST[0] || $$DEST[2] || $$DEST[4] || $$DEST[5] || 'localhost';
my $dest_port = $$DEST[1] || $$DEST[3] || $$DEST[6] || 2223;
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

my @dests = getaddrinfo($dest_host, $dest_port, AF_UNSPEC, SOCK_DGRAM);
while (@dests >= 5) {
	my ($fam, $type, $prot, $addr, $canon, @dests) = @dests;
	socket($fd, $fam, $type, $prot) or undef($fd), next;
	connect($fd, $addr) or undef($fd), next;
	last;
}
$fd or die($!);

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

sub rtcp_encrypt {
	my ($r, $ctx, $dir) = @_;

	my $dctx = $$ctx{$dir};

	if (!$$dctx{rtcp_session_key}) {
		($$dctx{rtcp_session_key}, $$dctx{rtcp_session_auth_key}, $$dctx{rtcp_session_salt})
			= NGCP::Rtpclient::SRTP::gen_rtcp_session_keys($$dctx{rtp_master_key},
				$$dctx{rtp_master_salt});
	}

	($NOENC && $NOENC{rtcp_packet}) and return $NOENC{rtcp_packet};

	my $iv = $$dctx{crypto_suite}{iv_rtcp}->($dctx, $r);
	my ($hdr, $to_enc) = unpack('a8a*', $r);
	my $enc = $$dctx{unenc_srtcp} ? $to_enc :
		$$dctx{crypto_suite}{enc_func}->($to_enc, $$dctx{rtcp_session_key},
		$iv, $$dctx{rtcp_session_salt});
	my $pkt = $hdr . $enc;
	$pkt .= pack("N", (($$dctx{rtcp_index} || 0) | ($$dctx{unenc_srtcp} ? 0 : 0x80000000)));

	my $hmac = hmac_sha1($pkt, $$dctx{rtcp_session_auth_key});

	NGCP::Rtpclient::SRTP::append_mki(\$pkt, @$dctx{qw(rtp_mki_len rtp_mki)});

	#$pkt .= pack("N", 1); # mki
	$pkt .= substr($hmac, 0, 10);

	$$dctx{rtcp_index}++;

	$NOENC{rtcp_packet} = $pkt;

	return $pkt;
}

sub rtp_encrypt {
	my ($r, $ctx, $dir) = @_;

	my $dctx = $$ctx{$dir};

	if (!$$dctx{rtp_session_key}) {
		($$dctx{rtp_session_key}, $$dctx{rtp_session_auth_key}, $$dctx{rtp_session_salt})
			= NGCP::Rtpclient::SRTP::gen_rtp_session_keys($$dctx{rtp_master_key},
				$$dctx{rtp_master_salt});
	}

	($NOENC && $NOENC{rtp_packet}) and return $NOENC{rtp_packet};

	my ($pkt, $roc) = NGCP::Rtpclient::SRTP::encrypt_rtp(@$dctx{qw(crypto_suite rtp_session_key
		rtp_session_salt rtp_session_auth_key rtp_roc rtp_mki rtp_mki_len unenc_srtp unauth_srtp)}, $r);
	$roc == ($$dctx{rtp_roc} // 0) or print("ROC is now $roc\n");
	$$dctx{rtp_roc} = $roc;

	$NOENC{rtp_packet} = $pkt;

	return $pkt;
}

$SUITES and @NGCP::Rtpclient::SRTP::crypto_suites = grep {my $x = $$_{str}; grep {$x eq $_} @$SUITES}
	@NGCP::Rtpclient::SRTP::crypto_suites;

sub savp_sdp {
	my ($ctx, $ctx_o) = @_;

	if (!$$ctx{out}{crypto_suite}) {
		if ($$ctx{in}{crypto_suite}) {
			$$ctx{out}{crypto_suite} = $$ctx{in}{crypto_suite};
			$$ctx{out}{crypto_tag} = $$ctx{in}{crypto_tag};
			$$ctx{out}{unenc_srtp} = $$ctx{in}{unenc_srtp};
			$$ctx{out}{unenc_srtcp} = $$ctx{in}{unenc_srtcp};
			$$ctx{out}{unauth_srtp} = $$ctx{in}{unauth_srtp};
		}
		else {
			$$ctx{out}{crypto_suite} =
				$NGCP::Rtpclient::SRTP::crypto_suites[rand(@NGCP::Rtpclient::SRTP::crypto_suites)];
			print("using crypto suite $$ctx{out}{crypto_suite}{str}\n");
			$$ctx{out}{crypto_tag} = int(rand(100));
			$$ctx{out}{unenc_srtp} = rand() < .5 ? 0 : 1;
			$$ctx{out}{unenc_srtcp} = rand() < .5 ? 0 : 1;
			$$ctx{out}{unauth_srtp} = rand() < .5 ? 0 : 1;
		}

		$$ctx{out}{rtp_mki_len} = 0;
		if (rand() > .5) {
			$$ctx{out}{rtp_mki_len} = int(rand(120)) + 1;
			$$ctx{out}{rtp_mki} = int(rand(2**30)) | 1;
			if ($$ctx{out}{rtp_mki_len} < 32) {
				$$ctx{out}{rtp_mki} &= (0xffffffff >> (32 - ($$ctx{out}{rtp_mki_len})));
			}
		}
	}

	if (!$$ctx{out}{rtp_master_key} || rand() < .2) {
		$$ctx{out}{rtp_master_key} and print("new key\n");
		$$ctx{out}{rtp_master_key} = rand_str($$ctx{out}{crypto_suite}{key_length});
		$$ctx{out}{rtp_master_salt} = rand_str($$ctx{out}{crypto_suite}{salt_length});
		undef($$ctx{out}{rtp_session_key});
		undef($$ctx{out}{rtcp_session_key});
		if ($NOENC && $NOENC{rtp_master_key}) {
			$$ctx{out}{rtp_master_key} = $NOENC{rtp_master_key};
			$$ctx{out}{rtp_master_salt} = $NOENC{rtp_master_salt};
		}
		$NOENC{rtp_master_key} = $$ctx{out}{rtp_master_key};
		$NOENC{rtp_master_salt} = $$ctx{out}{rtp_master_salt};
	}

	my $ret = "a=crypto:$$ctx{out}{crypto_tag} $$ctx{out}{crypto_suite}{str} inline:" . encode_base64($$ctx{out}{rtp_master_key} . $$ctx{out}{rtp_master_salt}, '');
	$$ctx{out}{rtp_mki_len} and $ret .= "|$$ctx{out}{rtp_mki}:$$ctx{out}{rtp_mki_len}";

	$$ctx{out}{unenc_srtp} and $ret .= " UNENCRYPTED_SRTP";
	$$ctx{out}{unenc_srtcp} and $ret .= " UNENCRYPTED_SRTCP";
	$$ctx{out}{unauth_srtp} and $ret .= " UNAUTHENTICATED_SRTP";

	$ret .= "\n";
	return $ret;
}

sub rtcp_sr {
	my ($ssrc) = @_;
	my @now = Time::HiRes::gettimeofday();
	my $secs = $now[0] + 2208988800;
	my $frac = $now[1] / 1000000 * 2**32;
	my $sr = pack('CCnN NNN NN', (2 << 6) | 1, 200, 12, $ssrc, $secs, $frac,
		12345, rand(12345), rand(4321));
	$sr .= pack('N CCCC NNNN', rand(2**32), rand(256), rand(256), rand(256), rand(256),
		rand(2**32), rand(2**32), rand(2**32), rand(2**32));
	# sdes
	$sr .= pack('CCn N CC a* CC a* CC a* C C N CC a* CC a* C CCC N CC a* C',
		(2 << 6) | 3, 202, 16,
		rand(2 ** 32), # csrc
		1, 7, 'blah123', # cname
		2, 6, 'foobar', # name
		3, 7, 'foo@bar', # email,
		0, # eol
		0, # padding
		rand(2 ** 32), # csrc
		4, 5, '54321', # phone
		5, 3, 'foo', # loc
		0, # eol
		0,0,0, # padding
		rand(2 ** 32), # csrc
		6, 5, 'fubar', # tool
		0, # eol
	);
	return $sr;
}

sub rtcp_rtpfb {
	return pack('CCn NN', (2 << 6) | 1, 205, 2, rand() * 2**32, rand() * 2**32);
}

sub rtcp_avp {
	my ($recv, $ctx, $ctx_o) = @_;
	my $ssrc = $$ctx{ssrc} // ($$ctx{ssrc} = rand(2**32));
	my $sr = rtcp_sr($ssrc);
	my $exp = $sr;
	$$recv{srtp} and $exp = rtcp_encrypt($exp, $ctx_o, 'in');
	return ($sr, $exp);
}

sub rtcp_savp {
	my ($recv, $ctx, $ctx_o) = @_;
	my $ssrc = $$ctx{ssrc} // ($$ctx{ssrc} = rand(2**32));
	my $sr = rtcp_sr($ssrc);
	my $enc = rtcp_encrypt($sr, $ctx, 'out');
	my $exp = $sr;
	$$recv{srtp} and $exp = rtcp_encrypt($exp, $ctx_o, 'in');
	return ($enc, $exp);
}

sub rtcp_avpf {
	my ($recv, $ctx, $ctx_o) = @_;
	my $ssrc = $$ctx{ssrc} // ($$ctx{ssrc} = rand(2**32));
	my $sr = rtcp_sr($ssrc);
	my $fb = rtcp_rtpfb();
	my $exp = $sr;
	$$recv{avpf} and $exp .= $fb;
	$$recv{srtp} and $exp = rtcp_encrypt($exp, $ctx_o, 'in');
	return ($sr . $fb, $exp);
}

sub rtcp_savpf {
	my ($recv, $ctx, $ctx_o) = @_;
	my $ssrc = $$ctx{ssrc} // ($$ctx{ssrc} = rand(2**32));
	my $sr = rtcp_sr($ssrc);
	my $fb = rtcp_rtpfb();
	my $enc = rtcp_encrypt($sr . $fb, $ctx, 'out');
	my $exp = $sr;
	$$recv{avpf} and $exp .= $fb;
	$$recv{srtp} and $exp = rtcp_encrypt($exp, $ctx_o, 'in');
	return ($enc, $exp);
}

sub rtp {
	my ($ctx) = @_;
	my $ssrc = $$ctx{ssrc} // ($$ctx{ssrc} = rand(2**32));
	my $seq = $$ctx{rtp_seqnum};
	defined($seq) or $seq = int(rand(0xfffe)) + 1;
	my $hdr = pack("CCnNN", 0x80, 0x00, $seq, rand(2**32), $ssrc);
	my $pack = $hdr . rand_str($PAYLOAD);
	$$ctx{rtp_seqnum} = (++$seq & 0xffff);
	return $pack;
}

sub rtp_avp {
	my ($recv, $ctx, $ctx_o) = @_;
	my $pack = rtp($ctx);
	my $exp = $pack;
	$$recv{srtp} and $exp = rtp_encrypt($exp, $ctx_o, 'in');
	return ($pack, $exp);
}

sub rtp_savp {
	my ($recv, $ctx, $ctx_o) = @_;
	my $pack = rtp($ctx);
	my $enc = rtp_encrypt($pack, $ctx, 'out');
	my $exp = $pack;
	$$recv{srtp} and $exp = rtp_encrypt($pack, $ctx_o, 'in');
	return ($enc, $exp);
}

sub savp_crypto {
	my ($sdp, $ctx, $ctx_o) = @_;

	my @a = $sdp =~ /[\r\n]a=crypto:(\d+) (\w+) inline:([\w\/+=]{40,})(?:\|(?:2\^(\d+)|(\d+)))?(?:\|(\d+):(\d+))?(?: (.*?))?[\r\n]/sig;
	@a or die;
	my $i = 0;
	while (@a >= 8) {
		$$ctx[$i]{in}{crypto_suite} = $NGCP::Rtpclient::SRTP::crypto_suites{$a[1]} or die;
		$$ctx[$i]{in}{crypto_tag} = $a[0];
		($$ctx[$i]{in}{rtp_master_key}, $$ctx[$i]{in}{rtp_master_salt})
			= NGCP::Rtpclient::SRTP::decode_inline_base64($a[2], $$ctx[$i]{in}{crypto_suite});
		$$ctx[$i]{in}{rtp_mki} = $a[5];
		$$ctx[$i]{in}{rtp_mki_len} = $a[6];
		undef($$ctx[$i]{in}{rtp_session_key});
		undef($$ctx[$i]{in}{rtcp_session_key});
		($a[7] || '') =~ /UNENCRYPTED_SRTP/ and $$ctx[$i]{in}{unenc_srtp} = 1;
		($a[7] || '') =~ /UNENCRYPTED_SRTCP/ and $$ctx[$i]{in}{unenc_srtcp} = 1;
		($a[7] || '') =~ /UNAUTHENTICATED_SRTP/ and $$ctx[$i]{in}{unauth_srtp} = 1;

		$i++;
		@a = @a[8 .. $#a];
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
		srtp => 0,
		avpf => 0,
	},
	{
		name => 'RTP/AVPF',
		rtp_func => \&rtp_avp,
		rtcp_func => \&rtcp_avpf,
		srtp => 0,
		avpf => 1,
	},
	{
		name => 'RTP/SAVP',
		sdp_media_params => \&savp_sdp,
		sdp_parse_func => \&savp_crypto,
		rtp_func => \&rtp_savp,
		rtcp_func => \&rtcp_savp,
		srtp => 1,
		avpf => 0,
	},
	{
		name => 'RTP/SAVPF',
		sdp_media_params => \&savp_sdp,
		sdp_parse_func => \&savp_crypto,
		rtp_func => \&rtp_savp,
		rtcp_func => \&rtcp_savpf,
		srtp => 1,
		avpf => 1,
	},
	{
		name => 'UDP/TLS/RTP/SAVP',
		sdp_media_params => \&savp_sdp,
		sdp_parse_func => \&savp_crypto,
		rtp_func => \&rtp_savp,
		rtcp_func => \&rtcp_savp,
		srtp => 1,
		avpf => 0,
	},
	{
		name => 'UDP/TLS/RTP/SAVPF',
		sdp_media_params => \&savp_sdp,
		sdp_parse_func => \&savp_crypto,
		rtp_func => \&rtp_savp,
		rtcp_func => \&rtcp_savpf,
		srtp => 1,
		avpf => 1,
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
		my $port = (rand(0x7000) << 1) + 1024;
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
m=audio $p $$tr{name} 0 8 111
a=rtpmap:8 PCMA/8000
a=rtpmap:111 opus/48000/2
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

	my @flags = ('trust address');
	my $dict = {sdp => $sdp, command => $op, 'call-id' => $$c{callid},
		flags => \@flags,
		replace => [ 'origin', 'session connection' ],
		#direction => [ $$pr{direction}, $$pr_o{direction} ],
		'received from' => [ qw(IP4 127.0.0.1) ],
		'rtcp-mux' => ['demux'],
		label => rand(),
	};
	$PORT_LATCHING and push(@flags, 'port latching');
	$RECORD and push(@flags, 'record call');
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

		if ($$tr_o{srtp} && $op eq 'offer') {
			my (@opts, @opt);
			rand() < .5 and push(@opts, (qw(unencrypted_srtp encrypted_srtp))[rand(2)]);
			rand() < .5 and push(@opts, (qw(unencrypted_srtcp encrypted_srtcp))[rand(2)]);
			rand() < .5 and push(@opts, (qw(unauthenticated_srtp authenticated_srtp))[rand(2)]);
			$$dict{SDES} = \@opts;
		}
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

	if ($CHANGE_SSRC && rand() < .001) {
		my $c = $calls[rand(@calls)];
		my $s = $$c{sides}[rand(2)];
		my $st = rand($$s{num_streams});
		my $d = (qw(in out))[rand(2)];
		my $stc = $$s{trans_contexts}[$st];
		my $ct = $$stc{$d};
		if (defined($$ct{rtp_roc}) && $$stc{ssrc}) {
			my $nssrc = rand(2 ** 32);
			print("change SSRC from $$stc{ssrc} to $nssrc\n");
			$$stc{ssrc} = $nssrc;
			$$ct{roc} = 0;
		}
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
