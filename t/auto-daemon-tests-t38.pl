#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use IPC::Open3;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --jitter-buffer=10))
		or die;


my ($sock_a, $sock_b, $port_a, $port_b, $ssrc, $resp, $srtp_ctx_a, $srtp_ctx_b, @ret1, @ret2);



sub t38_gw_test {
	my ($testname, $rev, $pcm_cmd, $t38_cmd, $fec, $num_ec) = @_;

	my ($pcm_pid, $pcm_src, $pcm_sink);
	ok($pcm_pid = open3($pcm_sink, $pcm_src, '>&STDERR', $pcm_cmd),
		"$testname - spandsp_send_fax_pcm");

	unlink('out.tif');
	ok (! -e 'out.tif', 'output file does not exists');

	my ($t38_pid, $t38_src, $t38_sink);
	ok($t38_pid = open3($t38_sink, $t38_src, '>&STDERR', $t38_cmd),
		"$testname - spandsp_recv_fax_t38");

	my ($buf, $rin);
	my $seq = -1;
	my $t38_pkt = '';
	my $udptl_seq = 0;
	my @udptl_ec_in;
	my @udptl_ec_out;
	my $done = 0;
	my $sqo = 1000;
	my $tso = 3000;
	my $ts = -1;

	my $pcm_sock = $rev ? $sock_a : $sock_b;
	my $pcm_port = $rev ? $port_b : $port_a;
	my $t38_sock = $rev ? $sock_b : $sock_a;
	my $t38_port = $rev ? $port_a : $port_b;

	# speed is controlled by the PCM generator
	while (!$done && sysread($pcm_src, $buf = '', 160) == 160) {
		# send generated PCM to rtpengine
		snd($pcm_sock, $pcm_port, rtp(8, $sqo += 1, $tso += 160, 0x1234, $buf));
		# it will also have generated a block of PCM
		if ($seq == -1) {
			($seq, $ts, $ssrc, $buf) = rcv($pcm_sock, $pcm_port, rtpmre(8 | 0x80, -1, -1, -1, '(' . ("." x 160) . ')'));
		}
		else {
			($buf) = rcv($pcm_sock, $pcm_port, rtpmre(8, $seq += 1, $ts += 160, $ssrc, '(' . ("." x 160) . ')'));
		}
		# write it back to our PCM endpoint
		is length($buf), 160, 'buf length ok';
		ok (syswrite($pcm_sink, $buf), 'PCM writeback');

		# read from our local T.38 producer?
		$rin = '';
		vec($rin, fileno($t38_src),  1) = 1;
		while (select(my $rout = $rin, undef, undef, 0) == 1) {
			my $ret = sysread($t38_src, $buf = '', 1);
			ok (defined($ret), 'T.38 read ok');

			if ($ret == 0) {
				# EOF
				$done = 1;
				ok (waitpid($t38_pid, 0), 'T.38 spandsp finished');
				undef($t38_pid);
				last;
			}

			$t38_pkt .= $buf;
			# complete packet?
			my ($seq_out, $len, $pkt) = unpack('SSa*', $t38_pkt);
			next unless defined($pkt); # nope
			next if length($pkt) < $len; # nope

			# extract...
			substr($t38_pkt, 0, $len + 4) = '';
			substr($pkt, $len) = '';

			ok ($len > 0 && $len < 0x80, 'local packet short enough');

			# save for EC
			$udptl_ec_out[$seq_out] = $pkt;

			# redundancy:
			my $ec_method = 0x00;
			my $ec_ents = 0;
			my $ec_list = '';
			if (!$fec) {
				for my $ec_seq (reverse(($seq_out - $num_ec) .. ($seq_out - 1))) {
					last if $ec_seq < 0 || !exists($udptl_ec_out[$ec_seq]);
					my $ecpkt = $udptl_ec_out[$ec_seq];
					ok (length($ecpkt) < 0x80, 'EC packet short enough');
					$ec_list .= pack('ca*', length($ecpkt), $ecpkt);
					$ec_ents++;
				}
			}

			# pack into UDPTL with redundancy
			my $udptl = pack('nca*cca*', $seq_out, length($pkt), $pkt, $ec_method, $ec_ents, $ec_list);

			# send
			snd($t38_sock, $t38_port, $udptl);
		}

		# read from our UDPTL source?
		$rin = '';
		vec($rin, fileno($t38_sock),  1) = 1;
		while (select(my $rout = $rin, undef, undef, 0) == 1) {
			my ($enc_seq, $len, $pkt) = rcv($t38_sock, $t38_port, qr/^(..)(.)(.*)$/s);

			# allow for duplicates, as they're generated in some cases
			ok ($enc_seq == $udptl_seq || $enc_seq == $udptl_seq + 1, 'UDPTL seq');
			$udptl_seq = $enc_seq;

			$len = ord($len);
			ok ($len > 0 && $len < 0x80, 'remote packet short enough');

			# extract...
			my $ifp = substr($pkt, 0, $len, '');
			ok (length($ifp) == $len, 'length matches');

			$udptl_ec_in[$enc_seq] = $ifp;

			my $red = substr($pkt, 0, 1, '');
			ok ($red eq ($fec ? "\x80" : "\x00"), 'redundacy method');

			my $nec = substr($pkt, 0, 1, '');
			ok ($nec eq chr($enc_seq > 3 ? 3 : $enc_seq), 'num EC packets');
			$nec = ord($nec);

			if (!$fec) {
				# check EC packets
				for my $ec_seq (reverse(($enc_seq - $nec) .. ($enc_seq - 1))) {
					my $len = substr($pkt, 0, 1, '');
					$len = ord($len);
					ok ($len > 0 && $len < 0x80, 'EC packet short enough');
					my $ec = substr($pkt, 0, $len, '');
					ok ($ec eq $udptl_ec_in[$ec_seq], 'EC packet matches');
				}
			}

			# everything passed, write to T.38 end
			ok (syswrite($t38_sink, pack('SSa*', $enc_seq, length($ifp), $ifp)), 'T.38 writeback');
		}
	}

	# delete to stop PCM player
	rtpe_req('delete', 'T.38 forward invite', { 'from-tag' => ft() });

	undef($t38_src);
	undef($t38_sink);
	undef($pcm_src);
	undef($pcm_sink);

	if ($t38_pid) {
		ok (waitpid($t38_pid, 0), 'T.38 spandsp finished');
		undef($t38_pid);
	}
	if ($pcm_pid) {
		ok (waitpid($pcm_pid, 0), 'PCM spandsp finished');
		undef($pcm_pid);
	}

	ok (-f 'out.tif', 'output file exists');
	ok (-s 'out.tif' > 10000, 'output file large enough');
	unlink('out.tif');

}



($sock_a, $sock_b) = new_call([qw(198.51.100.1 4000)], [qw(198.51.100.3 4002)]);

($port_a) = offer('plain T.38, forward invite', { 'T.38' => [ 'decode' ], ICE => 'remove',
	'codec' => { 'transcode' => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=image 4000 udptl t38
c=IN IP4 198.51.100.1
a=sendrecv
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:262
a=T38FaxMaxDatagram:90
a=T38FaxUdpEC:t38UDPRedundancy
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('plain T.38, forward invite', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 4002 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=image PORT udptl t38
c=IN IP4 203.0.113.1
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:262
a=T38FaxMaxDatagram:90
a=T38FaxUdpEC:t38UDPRedundancy
a=sendrecv
SDP


t38_gw_test('plain T.38, forward invite', 0,
	'./spandsp_send_fax_pcm test.tif',
	'./spandsp_recv_fax_t38 out.tif',
	0, 3);




($sock_a, $sock_b) = new_call([qw(198.51.100.1 4004)], [qw(198.51.100.3 4006)]);

($port_a) = offer('plain T.38, forward invite, reverse receive', { 'T.38' => [ 'decode' ], ICE => 'remove',
	'codec' => { 'transcode' => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=image 4004 udptl t38
c=IN IP4 198.51.100.1
a=sendrecv
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:262
a=T38FaxMaxDatagram:90
a=T38FaxUdpEC:t38UDPRedundancy
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('plain T.38, forward invite, reverse receive', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 4006 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=image PORT udptl t38
c=IN IP4 203.0.113.1
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:262
a=T38FaxMaxDatagram:90
a=T38FaxUdpEC:t38UDPRedundancy
a=sendrecv
SDP


t38_gw_test('plain T.38, forward invite, reverse receive', 0,
	'./spandsp_recv_fax_pcm out.tif',
	'./spandsp_send_fax_t38 test.tif',
	0, 3);


# XXX EC/FEC tests
# XXX packet loss tests




done_testing();
