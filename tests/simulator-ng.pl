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

my ($NUM, $RUNTIME, $STREAMS) = (1000, 30, 1);
my ($NODEL, $IP, $IPV6, $KEEPGOING, $REINVITES, $BRANCHES);
GetOptions(
		'no-delete'	=> \$NODEL,
		'num-calls=i'	=> \$NUM,
		'local-ip=s'	=> \$IP,
		'local-ipv6=s'	=> \$IPV6,
		'runtime=i'	=> \$RUNTIME,
		'keep-going'	=> \$KEEPGOING,		# don't stop sending rtp if a packet doesn't go through
		'reinvites'	=> \$REINVITES,
		'branches'	=> \$BRANCHES,
		'max-streams=i'	=> \$STREAMS,
) or die;

($IP || $IPV6) or die("at least one of --local-ip or --local-ipv6 must be given");

$SIG{ALRM} = sub { print "alarm!\n"; };
setrlimit(RLIMIT_NOFILE, 8000, 8000);

# global for now
#my $srtp_master_key = pack("H*", 'E1F97A0D3E018BE0D64FA32C06DE4139');
#my $srtp_master_salt = pack("H*", '0EC675AD498AFEEBB6960B3AABE6');
#my ($srtp_session_key, $srtp_session_auth_key, $srtp_session_salt)
#	= gen_rtp_session_keys($srtp_master_key, $srtp_master_salt);
#my ($srtcp_session_key, $srtcp_session_auth_key, $srtcp_session_salt)
#	= gen_rtcp_session_keys($srtp_master_key, $srtp_master_salt);

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
connect($fd, sockaddr_in(2223, inet_aton("127.0.0.1"))) or die $!;

msg({command => 'ping'})->{result} eq 'pong' or die;

my (@calls, %branches);

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

	return ($session_key, $auth_key, $session_salt);
}

sub gen_rtcp_session_keys {
	my ($master_key, $master_salt) = @_;

	my $session_key = prf_n(128, $master_key, xor_112($master_salt, "\3\0\0\0\0"));
	my $auth_key = prf_n(160, $master_key, xor_112($master_salt, "\4\0\0\0\0"));
	my $session_salt = prf_n(112, $master_key, xor_112($master_salt, "\5\0\0\0\0"));

	return ($session_key, $auth_key, $session_salt);
}

sub rtcp_encrypt {
	my ($r, $ctx, $dir) = @_;

	if (!$$ctx{rtcp_session_key}) {
		($$ctx{$dir}{rtcp_session_key}, $$ctx{$dir}{rtcp_session_auth_key}, $$ctx{$dir}{rtcp_session_salt})
			= gen_rtp_session_keys($$ctx{$dir}{rtp_master_key}, $$ctx{$dir}{rtp_master_salt});
	}

	my $idx = $$ctx{$dir}{rtcp_index} || 0;
	my ($hdr, $ssrc, $to_enc) = unpack('a4a4a*', $r);
	my $iv = xor_128($$ctx{$dir}{rtcp_session_salt} . "\0\0",
		$ssrc . "\0\0\0\0\0\0\0\0", pack("Nn", $idx, 0));
	my $enc = aes_cm($to_enc, $$ctx{$dir}{rtcp_session_key}, $iv);
	my $pkt = $hdr . $ssrc . $enc;
	$pkt .= pack("N", ($idx | 0x80000000));

	my $hmac = hmac_sha1($pkt, $$ctx{$dir}{rtcp_session_auth_key});

	#$pkt .= pack("N", 1); # mki
	$pkt .= substr($hmac, 0, 10);

	$$ctx{$dir}{rtcp_index} = ++$idx;

	return $pkt;
}

sub rtp_encrypt {
	my ($r, $ctx, $dir) = @_;

	if (!$$ctx{$dir}{rtp_session_key}) {
		($$ctx{$dir}{rtp_session_key}, $$ctx{$dir}{rtp_session_auth_key}, $$ctx{$dir}{rtp_session_salt})
			= gen_rtp_session_keys($$ctx{$dir}{rtp_master_key}, $$ctx{$dir}{rtp_master_salt});
	}

	my $roc = $$ctx{$dir}{rtp_roc} || 0;
	my ($hdr, $seq, $ts, $ssrc, $to_enc) = unpack('a2na4a4a*', $r);
	$seq == 0 and $roc++;
	my $iv = xor_128($$ctx{$dir}{rtp_session_salt} . "\0\0",
		$ssrc . "\0\0\0\0\0\0\0\0", pack("Nnn", $roc, $seq, 0));
	my $enc = aes_cm($to_enc, $$ctx{$dir}{rtp_session_key}, $iv);
	my $pkt = pack("a*na*a*a*", $hdr, $seq, $ts, $ssrc, $enc);

	my $hmac = hmac_sha1($pkt . pack("N", $roc), $$ctx{$dir}{rtp_session_auth_key});

	#$pkt .= pack("N", 1); # mki
	$pkt .= substr($hmac, 0, 10);

	$$ctx{$dir}{rtp_roc} = $roc;

	return $pkt;
}

sub savp_sdp {
	my ($ctx) = @_;
	if (!$$ctx{out}{rtp_master_key}) {
		$$ctx{out}{rtp_master_key} = rand_str(16);
		$$ctx{out}{rtp_master_salt} = rand_str(14);
	}
	return "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" . encode_base64($$ctx{out}{rtp_master_key} . $$ctx{out}{rtp_master_salt}, '') . "\n";
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
	return ($sr, $exp);
}

sub rtcp_savp {
	my ($recv, $ctx, $ctx_o) = @_;
	my $sr = rtcp_sr();
	my $enc = rtcp_encrypt($sr, $ctx, 'out');
	my $exp = $enc;
	$$recv{name} eq 'RTP/AVP' and $exp = $sr;
	return ($enc, $exp);
}

sub rtcp_avpf {
	my ($recv, $ctx, $ctx_o) = @_;
	my $sr = rtcp_sr();
	my $fb = rtcp_rtpfb();
	my $exp = $sr;
	$$recv{name} eq 'RTP/AVPF' and $exp .= $fb;
	return ($sr . $fb, $exp);
}

sub rtp {
	my ($ctx) = @_;
	my $seq = $$ctx{rtp_seqnum} || (int(rand(0xfffff)) + 1);
	my $hdr = pack("CCnNN", 0x80, 0x00, $seq, rand(2**32), rand(2**32));
	my $pack = $hdr . rand_str(100);
	$$ctx{rtp_seqnum} = (++$seq & 0xffff);
	return $pack;
}

sub rtp_avp {
	my ($recv, $ctx, $ctx_o) = @_;
	my $pack = rtp($ctx);
	my $exp = $pack;
	$$recv{name} eq 'RTP/SAVP' and $exp = rtp_encrypt($pack, $ctx_o, 'in');
	return ($pack, $exp);
}

sub rtp_savp {
	my ($recv, $ctx, $ctx_o) = @_;
	my $pack = rtp($ctx);
	my $enc = rtp_encrypt($pack, $ctx, 'out');
	my $exp = $enc;
	$$recv{name} eq 'RTP/AVP' and $exp = $pack;
	return ($enc, $exp);
}

sub savp_crypto {
	my ($sdp, $ctx) = @_;

	my @a = $sdp =~ /[\r\n]a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:([\w\/+]{40})(?:\|(?:2\^(\d+)|(\d+)))?(?:\|(\d+):(\d+))?[\r\n]/si;
	@a or die;
	my $ks = decode_base64($a[0]);
	length($ks) == 30 or die;
	($$ctx{in}{rtp_master_key}, $$ctx{in}{rtp_master_salt}) = unpack('a16a14', $ks);
	$$ctx{in}{rtp_mki} = $a[3];
	$$ctx{in}{rtp_mki_len} = $a[4];
}

sub hexdump {
	my $o = '';
	for my $a (@_) {
		$o .= "<< " . unpack("H*", $a) . " >> ";
	}
	return $o;
}

sub do_rtp {
	print("sending rtp\n");
	for my $c (@calls) {
		$c or next;
		my ($fds,$outputs,$protos,$cfds,$trans,$tctxs)
			= @$c{qw(fds outputs protos rtcp_fds transports trans_contexts)};
		for my $j (0 .. $#{$$fds[0]}) {
			for my $i ([0,1],[1,0]) {
				my ($a, $b) = @$i;
				my $pr = $$protos[$a];
				my $tcx = $$tctxs[$a];
				my $tcx_o = $$tctxs[$b];
				my $addr = inet_pton($$pr{family}, $$outputs[$b][$j][1]);
				my ($payload, $expect) = $$trans[$a]{rtp_func}($$trans[$b], $tcx, $tcx_o);
				my $dst = $$pr{sockaddr}($$outputs[$b][$j][0], $addr);
				my $repl = send_receive($$fds[$a][$j], $$fds[$b][$j], $payload, $dst);
				if ($repl eq '') {
					warn("no rtp reply received, ports $$outputs[$b][$j][0] and $$outputs[$a][$j][0]");
					$KEEPGOING or undef($c);
				}
				$repl eq $expect or die hexdump($repl, $expect);

				($payload, $expect) = $$trans[$a]{rtcp_func}($$trans[$b], $tcx, $tcx_o);
				$dst = $$pr{sockaddr}($$outputs[$b][$j][0] + 1, $addr);
				$repl = send_receive($$cfds[$a][$j], $$cfds[$b][$j], $payload, $dst);
				$repl eq $expect or die hexdump($repl, $expect);
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
#	{
#		name => 'RTP/AVPF',
#		rtp_func => &rtp_avpf,
#		rtcp_func => \&rtcp_avpf,
#	},
	{
		name => 'RTP/SAVP',
		sdp_media_params => \&savp_sdp,
		sdp_parse_func => \&savp_crypto,
		rtp_func => \&rtp_savp,
		rtcp_func => \&rtcp_savp,
	},
);

sub callid {
	my $i = rand_str(50);
	$BRANCHES or return [$i];
	rand() < .5 and return [$i];
	if (rand() < .5) {
		my @k = keys(%branches);
		@k and $i = $k[rand(@k)];
	}
	my $b = rand_str(20);
	push(@{$branches{$i}}, $b);
	return [$i, $b];
}

sub update_lookup {
	my ($c, $i) = @_;
	my $j = $i ^ 1;

	my $c_v = $$c{callid_viabranch} || ($$c{callid_viabranch} = callid());
	my ($callid, $viabranch) = @$c_v;

	my $protos = $$c{protos} || ($$c{protos} = []);
	my $trans = $$c{transports} || ($$c{transports} = []);
	my $tctxs = $$c{trans_contexts} || ($$c{trans_contexts} = []);
	my $fds_a = $$c{fds} || ($$c{fds} = []);
	my $cfds_a = $$c{rtcp_fds} || ($$c{rtcp_fds} = []);
	for my $x (0,1) {
		$$protos[$x] and next;
		$$protos[$x] = $protos_avail[rand(@protos_avail)];
		undef($$fds_a[$x]);
	}
	for my $x (0,1) {
		$$trans[$x] and next;
		#$$trans[$x] = $transports[rand(@transports)];
		$$trans[$x] = $transports[rand(@transports)];
	}
	my ($pr, $pr_o) = @$protos[$i, $j];
	my ($tr, $tr_o) = @$trans[$i, $j];
	my $tcx = $$tctxs[$i] || ($$tctxs[$i] = {});
	my $tcx_o = $$tctxs[$j] || ($$tctxs[$j] = {});
	my @commands = qw(offer answer);

	my $ports_a = $$c{ports} || ($$c{ports} = []);
	my $ports_t = $$ports_a[$i] || ($$ports_a[$i] = []);
	my $ips_a = $$c{ips} || ($$c{ips} = []);
	my $ips_t = $$ips_a[$i] || ($$ips_a[$i] = []);
	my $fds_t = $$fds_a[$i] || ($$fds_a[$i] = []);
	my $fds_o = $$fds_a[$j];
	my $cfds_t = $$cfds_a[$i] || ($$cfds_a[$i] = []);
	my $cfds_o = $$cfds_a[$j];
	my $num_streams = int(rand($STREAMS));
	($fds_o && @$fds_o) and $num_streams = $#$fds_o;
	for my $j (0 .. $num_streams) {
		if (!$$fds_t[$j]) {
			while (1) {
				undef($$fds_t[$j]);
				undef($$cfds_t[$j]);
				socket($$fds_t[$j], $$pr{family}, SOCK_DGRAM, 0) or die $!;
				socket($$cfds_t[$j], $$pr{family}, SOCK_DGRAM, 0) or die $!;
				my $port = rand(0x7000) << 1 + 1024;
				bind($$fds_t[$j], $$pr{sockaddr}($port,
					inet_pton($$pr{family}, $$pr{address}))) or next;
				bind($$cfds_t[$j], $$pr{sockaddr}($port + 1,
					inet_pton($$pr{family}, $$pr{address}))) or next;
				last;
			}
			my $addr = getsockname($$fds_t[$j]);
			my $ip;
			($$ports_t[$j], $ip) = $$pr{sockaddr}($addr);
			$$ips_t[$j] = inet_ntop($$pr{family}, $ip);
		}
	}

	my $tags = $$c{tags} || ($$c{tags} = []);
	$$tags[$i] or $$tags[$i] = rand_str(15);

	my $sdp = <<"!";
v=0
o=blah 123 123 IN $$pr{family_str} $$ips_t[0]
s=session
c=IN $$pr{family_str} $$ips_t[0]
t=0 0
!
	for my $p (@$ports_t) {
		my $cp = $p + 1;
		$sdp .= <<"!";
m=audio $p $$tr{name} 8
a=rtpmap:8 PCMA/8000
a=rtcp:$cp
!
		$$tr{sdp_media_params} and $sdp .= $$tr{sdp_media_params}($tcx);
	}
	print("transport is $$tr{name} -> $$tr_o{name}\n"); # XXX

	my $dict = {sdp => $sdp, command => $commands[$i], 'call-id' => $callid,
		'from-tag' => $$tags[0],
		flags => [ qw( trust-address ) ],
		replace => [ qw( origin session-connection ) ],
		direction => [ $$pr{direction}, $$pr_o{direction} ],
		'received-from' => [ qw(IP4 127.0.0.1) ],
		'transport-protocol' => $$tr_o{name},
	};
	$viabranch and $dict->{'via-branch'} = $viabranch;
	$i == 1 and $dict->{'to-tag'} = $$tags[1];

	my $o = msg($dict);

	$$o{result} eq 'ok' or die;
	my ($rp_af, $rp_add) = $$o{sdp} =~ /c=IN IP([46]) (\S+)/s or die;
	my @rp_ports = $$o{sdp} =~ /m=audio (\d+) \Q$$tr_o{name}\E /gs or die;
	$rp_af ne $$pr_o{reply} and die "incorrect address family reply code";
	my $rpl_a = $$c{outputs} || ($$c{outputs} = []);
	my $rpl_t = $$rpl_a[$i] || ($$rpl_a[$i] = []);
	for my $rpl (@rp_ports) {
		$rpl == 0 and die "mediaproxy ran out of ports";
		push(@$rpl_t, [$rpl,$rp_add]);
	}
	$$tr_o{sdp_parse_func} and $$tr_o{sdp_parse_func}($$o{sdp}, $tcx_o);
}

for my $iter (1 .. $NUM) {
	($iter % 10 == 0) and print("$iter\n"), do_rtp();

	my $c = {};
	update_lookup($c, 0);
	update_lookup($c, 1);
	push(@calls, $c);
}

my $end = time() + $RUNTIME;
while (time() < $end) {
	sleep(1);
	do_rtp();

	@calls = sort {rand() < .5} grep(defined, @calls);

	if ($REINVITES) {
		my $c = $calls[rand(@calls)];
		print("simulating re-invite on $$c{callid_viabranch}[0]");
		for my $i (0,1) {
			if (rand() < .5) {
				print(", side $sides[$i]: new port");
				undef($$c{fds}[$i]);
			}
			else {
				print(", side $sides[$i]: same port");
			}
		}
		print("\n");
		update_lookup($c, 0);
		update_lookup($c, 1);
	}
}

if (!$NODEL) {
	print("deleting\n");
	for my $c (@calls) {
		$c or next;
		my ($tags, $c_v) = @$c{qw(tags callid_viabranch)};
		my ($callid, $viabranch) = @$c_v;
		my $dict = { command => 'delete', 'call-id' => $callid, 'from-tag' => $$tags[0],
			'to-tag' => $$tags[1],
		};
		$BRANCHES && rand() < .7 and $$dict{'via-branch'} = $viabranch;
		msg($dict);
	}
}
print("done\n");
