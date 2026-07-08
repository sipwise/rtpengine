#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use Test2::Tools::Compare qw();
use NGCP::Rtpclient::ICE;
use POSIX;
use Socket;
use IO::Socket::UNIX;
use Data::Dumper;
use Errno;


$ENV{RTPENGINE_EXTENDED_TESTS} or exit(); # tests only valid on amd64


local $ENV{MOCK_PEER} = ($ENV{TEST_SOCKET_PATH} || '.') . '/intf.sock';

my $kintf = IO::Socket::UNIX->new(Type => SOCK_DGRAM(), Local => $ENV{MOCK_PEER});

local $ENV{MOCK_0} = '/proc/rtpengine/control';
local $ENV{MOCK_1} = '/proc/rtpengine/42/control';

$NGCP::Rtpengine::AutoTest::launch_cb = sub {
	my $buf;

	my ($addr) = $kintf->recv($buf, 1024);
	my ($msg, $text) = unpack("i! Z*", $buf);
	is($msg, 1, "open message");
	is($text, "/proc/rtpengine/control", "open control");
	$kintf->send(pack('ii', 1, 0), 0, $addr);

	($addr) = $kintf->recv($buf, 1024);
	($msg, $text) = unpack("i! a*", $buf);
	is($msg, 3, "write message");
	is($text, "del 42\n", "del msg");
	$kintf->send(pack('ii', 3, -Errno::ENOENT), 0, $addr);

	($addr) = $kintf->recv($buf, 1024);
	($msg, $text) = unpack("i!", $buf);
	is($msg, 4, "close message");

	($addr) = $kintf->recv($buf, 1024);
	($msg, $text) = unpack("i! Z*", $buf);
	is($msg, 1, "open message");
	is($text, "/proc/rtpengine/42/control", "open table control");
	$kintf->send(pack('ii', 1, 0), 0, $addr);

	($addr) = $kintf->recv($buf, 1024);
	($msg, $text) = unpack("i! a*", $buf);
	is($msg, 3, "write message");
	my ($code, $a, $l) = unpack('i! x![L!] L!L!', $text);
	is($code, 16, "pin memory msg");
	is($l, 16777216, "pin memory size");
	$kintf->send(pack('ii', 3, length($text)), 0, $addr);

	($addr) = $kintf->recv($buf, 1024);
	($msg, $text) = unpack("i! a*", $buf);
	is($msg, 3, "write message");
	($code, $l) = unpack('i! x![L!] i! x![L!] L![18] L!', $text);
	is($code, 1, "init msg");
	is($l, 18, "last msg code");
	# skip verify msg lengths
	$kintf->send(pack('ii', 3, length($text)), 0, $addr);
};

autotest_start(qw(--config-file=none -t 42 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -f -L 7 -E --log-level-internals=7 --no-fallback
			--nftables-chain=))
		or die;


my $extended_tests = $ENV{RTPENGINE_EXTENDED_TESTS};


my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $ssrc, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx, $t_a, $t_b, $t_c, $t_d,
	$sock_cx, $sock_dx, $port_c, $port_d, $port_cx, $port_dx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $has_recv, $tmp_blob,
	$pwd_a, $pwd_b, $packet, $tid, $buf, $addr, $msg, $text,
	$code, $lfam, $laddr, $lport, $efam, $eaddr, $eport, $mismatch, $numdest,
	$intcp, @g, @decr, @ssrc, @ssrcst, @ssrci, @ptst, @ptmi, $npts, $midmap,
	@mid, $iface, $stats, @rbuf, $flags, $idx, $sfam, $saddr, $sport, $dfam, $daddr,
	$dport, $midx, @encr, @seqs, @pto, $nexf, $exmid, $exmidlen, $exmids, $tos, %dict);



undef $NGCP::Rtpengine::AutoTest::launch_cb;



sub add_target {
	my $buf;
	my ($addr) = $kintf->recv($buf, 4096);
	my ($msg, $text) = unpack("i! a*", $buf);
	is($msg, 3, "write message");
	my (%ret, $code);
	($code,
		$ret{lfam}, $ret{laddr}, $ret{lport},
		$ret{efam}, $ret{eaddr}, $ret{eport},
		$ret{mismatch}, $ret{numdest}, $ret{intcp},
		@{$ret{g}}[0..31],
		@{$ret{decr}}[0..11],
		@{$ret{ssrc}}[0..3], @{$ret{ssrcst}}[0..3], @{$ret{ssrci}}[0..3],
		@{$ret{ptst}}[0..31],
		@{$ret{ptmi}}[0..31],
		$ret{npts}, $ret{midmap},
		@{$ret{mid}}[0..15],
		$ret{iface}, $ret{stats},
		@{$ret{rbuf}}[0..3], $ret{flags})
		= unpack('i! x![L!]   (i! L x12 S  x[S])[2]    i! i! i!    (i! i! i! i!)[8]    (i! i! a32 i! a14 x![i!] i! i! i! a256 i! i! i!)   N4 Q4 i!4     Q32    i!32    i!    C   (a255 x![L!] L!)[8]    Q Q   (i! i! Q Q) s', $text);
	is($code, 2, "add target msg");
	$kintf->send(pack('ii', 3, length($text)), 0, $addr);
	return %ret;
}

sub add_destination {
	my $buf;
	my ($addr) = $kintf->recv($buf, 4096);
	my ($msg, $text) = unpack("i! a*", $buf);
	is($msg, 3, "write message");
	my (%ret, $code);
	($code,
		$ret{lfam}, $ret{laddr}, $ret{lport},
		$ret{idx},
		$ret{sfam}, $ret{saddr}, $ret{sport},
		$ret{dfam}, $ret{daddr}, $ret{dport},
		$ret{midx},
		@{$ret{encr}}[0..11],
		@{$ret{ssrc}}[0..3], @{$ret{seqs}}[0..3], @{$ret{pto}}[0..127],
		$ret{nexf},
		$ret{exmid}, $ret{exmidlen}, $ret{exmids},
		$ret{iface}, $ret{stats}, @{$ret{ssrcst}}[0..3],
		$ret{tos}, $ret{flags})
		= unpack('i! x![L!]   (i! L x12 S  x[S])     i! x![L!]     (i! L x12 S  x[S])[2]    i!    (i! i! a32 i! a14 x![i!] i! i! i! a256 i! i! i!)    L4 L4 (i! a16 c i!)[32]   i!    c c a255  x![L!]    Q Q Q4    c     i!', $text);
	is($code, 3, "add destination msg");
	$kintf->send(pack('ii', 3, length($text)), 0, $addr);
	return %ret;
}


my $del_targets = sub {
	my ($addr) = $kintf->recv($buf, 4096);
	my ($msg, $text) = unpack("i! a*", $buf);
	is($msg, 3, "write message");
	my ($code) = unpack('i!', $text);
	is($code, 9, "del target msg");
	$kintf->send(pack('ii', 3, length($text)), 0, $addr);

	($addr) = $kintf->recv($buf, 4096);
	($msg, $text) = unpack("i! a*", $buf);
	is($msg, 3, "write message");
	($code) = unpack('i!', $text);
	is($code, 9, "del target msg");
	$kintf->send(pack('ii', 3, length($text)), 0, $addr);
};


($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3000)], [qw(198.51.100.23 3001)],
							[qw(198.51.100.23 3002)], [qw(198.51.100.23 3003)]);


$NGCP::Rtpengine::req_cb = sub {
	my $buf;
	my ($addr) = $kintf->recv($buf, 1024);
	my ($msg, $text) = unpack("i! a*", $buf);
	is($msg, 3, "write message");
	my ($code, $a, $l) = unpack('i! x![L!] L!L!', $text);
	is($code, 16, "pin memory msg");
	is($l, 16777216, "pin memory size");
	$kintf->send(pack('ii', 3, length($text)), 0, $addr);
};


($port_a, $port_ax) = offer('basic', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3000 RTP/AVP 9 8 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 9 8 0
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


undef $NGCP::Rtpengine::req_cb;


($port_b, $port_bx) = answer('basic', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3002 RTP/AVP 9 8 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 9 8 0
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x7654321, "\x00" x 160));

%dict = add_target();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_b, "lport");
is($dict{mismatch}, 0, "mismatch ignore");
is($dict{numdest}, 2, "num dests");
is($dict{g}[0], 0, "rtp start idx 0");
is($dict{g}[1], 1, "rtp end idx 0");
is($dict{g}[2], 1, "rtcp start idx 0");
is($dict{g}[3], 2, "rtcp end idx 0");
is($dict{decr}[0], 1, "null cipher");
is($dict{decr}[1], 1, "null hmac");
is($dict{ssrc}[0], 0x1234567, "ssrc 0");
is($dict{ssrci}[0], -1, "ssrc index 0");
is($dict{flags}, 344, "flags");

%dict = add_destination();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_b, "lport");
is($dict{idx}, 0, "dest idx");
is($dict{sfam}, 2, "saddr fam");
is($dict{saddr}, 24182987, "saddr");
is($dict{sport}, $port_a, "sport");
is($dict{dfam}, 2, "daddr fam");
is($dict{daddr}, 392442822, "daddr");
is($dict{dport}, 3002, "dport");
is($dict{encr}[0], 1, "null cipher");
is($dict{encr}[1], 1, "null hmac");
is($dict{flags}, 0, "flags");

%dict = add_destination();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_b, "lport");
is($dict{idx}, 1, "dest idx");
is($dict{sfam}, 2, "saddr fam");
is($dict{saddr}, 24182987, "saddr");
is($dict{sport}, $port_ax, "sport");
is($dict{dfam}, 2, "daddr fam");
is($dict{daddr}, 392442822, "daddr");
is($dict{dport}, 3003, "dport");
is($dict{encr}[0], 1, "null cipher");
is($dict{encr}[1], 1, "null hmac");
is($dict{flags}, 4, "flags");

%dict = add_target();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_a, "lport");
is($dict{mismatch}, 0, "mismatch ignore");
is($dict{numdest}, 2, "num dests");
is($dict{g}[0], 0, "rtp start idx 0");
is($dict{g}[1], 1, "rtp end idx 0");
is($dict{g}[2], 1, "rtcp start idx 0");
is($dict{g}[3], 2, "rtcp end idx 0");
is($dict{decr}[0], 1, "null cipher");
is($dict{decr}[1], 1, "null hmac");
is($dict{ssrc}[0], 0x7654321, "ssrc 0");
is($dict{ssrci}[0], -1, "ssrc index 0");
is($dict{flags}, 344, "flags");

%dict = add_destination();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_a, "lport");
is($dict{idx}, 0, "dest idx");
is($dict{sfam}, 2, "saddr fam");
is($dict{saddr}, 24182987, "saddr");
is($dict{sport}, $port_b, "sport");
is($dict{dfam}, 2, "daddr fam");
is($dict{daddr}, 392442822, "daddr");
is($dict{dport}, 3000, "dport");
is($dict{encr}[0], 1, "null cipher");
is($dict{encr}[1], 1, "null hmac");
is($dict{flags}, 0, "flags");

%dict = add_destination();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_a, "lport");
is($dict{idx}, 1, "dest idx");
is($dict{sfam}, 2, "saddr fam");
is($dict{saddr}, 24182987, "saddr");
is($dict{sport}, $port_bx, "sport");
is($dict{dfam}, 2, "daddr fam");
is($dict{daddr}, 392442822, "daddr");
is($dict{dport}, 3001, "dport");
is($dict{encr}[0], 1, "null cipher");
is($dict{encr}[1], 1, "null hmac");
is($dict{flags}, 4, "flags");

rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x7654321, "\x00" x 160));

$NGCP::Rtpengine::req_cb = $del_targets;

rtpe_req('delete', 'basic', { 'delete-delay' => 0 });

undef $NGCP::Rtpengine::req_cb;




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3004)], [qw(198.51.100.23 3005)],
							[qw(198.51.100.23 3006)], [qw(198.51.100.23 3007)]);

($port_a, $port_ax) = offer('SRTP in', { 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3004 RTP/SAVP 9 8 0
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 9 8 0
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $srtp_key_b) = answer('SRTP in', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3006 RTP/AVP 9 8 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 9 8 0
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
        cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
        key => 'QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c',
};
$srtp_ctx_b = {
        cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
        key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160), $srtp_ctx_a);
     rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
     snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x7654321, "\x00" x 160));

%dict = add_target();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_b, "lport");
is($dict{mismatch}, 0, "mismatch ignore");
is($dict{numdest}, 2, "num dests");
is($dict{g}[0], 0, "rtp start idx 0");
is($dict{g}[1], 1, "rtp end idx 0");
is($dict{g}[2], 1, "rtcp start idx 0");
is($dict{g}[3], 2, "rtcp end idx 0");
is($dict{decr}[0], 2, "cipher");
is($dict{decr}[1], 2, "hmac");
is($dict{ssrc}[0], 0x1234567, "ssrc 0");
is($dict{ssrci}[0], -1, "ssrc index 0");
is($dict{flags}, 344, "flags");

%dict = add_destination();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_b, "lport");
is($dict{idx}, 0, "dest idx");
is($dict{sfam}, 2, "saddr fam");
is($dict{saddr}, 24182987, "saddr");
is($dict{sport}, $port_a, "sport");
is($dict{dfam}, 2, "daddr fam");
is($dict{daddr}, 392442822, "daddr");
is($dict{dport}, 3006, "dport");
is($dict{encr}[0], 1, "null cipher");
is($dict{encr}[1], 1, "null hmac");
is($dict{flags}, 0, "flags");

%dict = add_destination();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_b, "lport");
is($dict{idx}, 1, "dest idx");
is($dict{sfam}, 2, "saddr fam");
is($dict{saddr}, 24182987, "saddr");
is($dict{sport}, $port_ax, "sport");
is($dict{dfam}, 2, "daddr fam");
is($dict{daddr}, 392442822, "daddr");
is($dict{dport}, 3007, "dport");
is($dict{encr}[0], 1, "null cipher");
is($dict{encr}[1], 1, "null hmac");
is($dict{flags}, 4, "flags");

%dict = add_target();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_a, "lport");
is($dict{mismatch}, 0, "mismatch ignore");
is($dict{numdest}, 2, "num dests");
is($dict{g}[0], 0, "rtp start idx 0");
is($dict{g}[1], 1, "rtp end idx 0");
is($dict{g}[2], 1, "rtcp start idx 0");
is($dict{g}[3], 2, "rtcp end idx 0");
is($dict{decr}[0], 1, "null cipher");
is($dict{decr}[1], 1, "null hmac");
is($dict{ssrc}[0], 0x7654321, "ssrc 0");
is($dict{ssrci}[0], -1, "ssrc index 0");
is($dict{flags}, 344, "flags");

%dict = add_destination();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_a, "lport");
is($dict{idx}, 0, "dest idx");
is($dict{sfam}, 2, "saddr fam");
is($dict{saddr}, 24182987, "saddr");
is($dict{sport}, $port_b, "sport");
is($dict{dfam}, 2, "daddr fam");
is($dict{daddr}, 392442822, "daddr");
is($dict{dport}, 3004, "dport");
is($dict{encr}[0], 2, "cipher");
is($dict{encr}[1], 2, "hmac");
is($dict{flags}, 0, "flags");

%dict = add_destination();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_a, "lport");
is($dict{idx}, 1, "dest idx");
is($dict{sfam}, 2, "saddr fam");
is($dict{saddr}, 24182987, "saddr");
is($dict{sport}, $port_bx, "sport");
is($dict{dfam}, 2, "daddr fam");
is($dict{daddr}, 392442822, "daddr");
is($dict{dport}, 3005, "dport");
is($dict{encr}[0], 2, "cipher");
is($dict{encr}[1], 2, "hmac");
is($dict{flags}, 4, "flags");

srtp_rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x7654321, "\x00" x 160), $srtp_ctx_b);

$NGCP::Rtpengine::req_cb = $del_targets;

rtpe_req('delete', 'basic', { 'delete-delay' => 0 });

undef $NGCP::Rtpengine::req_cb;




($sock_a, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3012)],
							[qw(198.51.100.23 3014)], [qw(198.51.100.23 3015)]);

($port_a, $port_ax) = offer('rtcp-mux', { 'rtcp-mux' => 'demux' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3012 RTP/AVP 9 8 0
a=rtcp-mux
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 9 8 0
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('rtcp-mux', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3014 RTP/AVP 9 8 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 9 8 0
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
SDP

is($port_b, $port_bx, 'same port');

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x7654321, "\x00" x 160));

%dict = add_target();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_b, "lport");
is($dict{mismatch}, 0, "mismatch ignore");
is($dict{numdest}, 2, "num dests");
is($dict{g}[0], 0, "rtp start idx 0");
is($dict{g}[1], 1, "rtp end idx 0");
is($dict{g}[2], 1, "rtcp start idx 0");
is($dict{g}[3], 2, "rtcp end idx 0");
is($dict{decr}[0], 1, "null cipher");
is($dict{decr}[1], 1, "null hmac");
is($dict{ssrc}[0], 0x1234567, "ssrc 0");
is($dict{ssrci}[0], -1, "ssrc index 0");
is($dict{flags}, 472, "flags");

%dict = add_destination();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_b, "lport");
is($dict{idx}, 0, "dest idx");
is($dict{sfam}, 2, "saddr fam");
is($dict{saddr}, 24182987, "saddr");
is($dict{sport}, $port_a, "sport");
is($dict{dfam}, 2, "daddr fam");
is($dict{daddr}, 392442822, "daddr");
is($dict{dport}, 3014, "dport");
is($dict{encr}[0], 1, "null cipher");
is($dict{encr}[1], 1, "null hmac");
is($dict{flags}, 0, "flags");

%dict = add_destination();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_b, "lport");
is($dict{idx}, 1, "dest idx");
is($dict{sfam}, 2, "saddr fam");
is($dict{saddr}, 24182987, "saddr");
is($dict{sport}, $port_ax, "sport");
is($dict{dfam}, 2, "daddr fam");
is($dict{daddr}, 392442822, "daddr");
is($dict{dport}, 3015, "dport");
is($dict{encr}[0], 1, "null cipher");
is($dict{encr}[1], 1, "null hmac");
is($dict{flags}, 4, "flags");

%dict = add_target();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_a, "lport");
is($dict{mismatch}, 0, "mismatch ignore");
is($dict{numdest}, 2, "num dests");
is($dict{g}[0], 0, "rtp start idx 0");
is($dict{g}[1], 1, "rtp end idx 0");
is($dict{g}[2], 1, "rtcp start idx 0");
is($dict{g}[3], 2, "rtcp end idx 0");
is($dict{decr}[0], 1, "null cipher");
is($dict{decr}[1], 1, "null hmac");
is($dict{ssrc}[0], 0x7654321, "ssrc 0");
is($dict{ssrci}[0], -1, "ssrc index 0");
is($dict{flags}, 344, "flags");

%dict = add_destination();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_a, "lport");
is($dict{idx}, 0, "dest idx");
is($dict{sfam}, 2, "saddr fam");
is($dict{saddr}, 24182987, "saddr");
is($dict{sport}, $port_b, "sport");
is($dict{dfam}, 2, "daddr fam");
is($dict{daddr}, 392442822, "daddr");
is($dict{dport}, 3012, "dport");
is($dict{encr}[0], 1, "null cipher");
is($dict{encr}[1], 1, "null hmac");
is($dict{flags}, 0, "flags");

%dict = add_destination();
is($dict{lfam}, 2, "laddr fam");
is($dict{laddr}, 24182987, "laddr");
is($dict{lport}, $port_a, "lport");
is($dict{idx}, 1, "dest idx");
is($dict{sfam}, 2, "saddr fam");
is($dict{saddr}, 24182987, "saddr");
is($dict{sport}, $port_bx, "sport");
is($dict{dfam}, 2, "daddr fam");
is($dict{daddr}, 392442822, "daddr");
is($dict{dport}, 3012, "dport");
is($dict{encr}[0], 1, "null cipher");
is($dict{encr}[1], 1, "null hmac");
is($dict{flags}, 4, "flags");

rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x7654321, "\x00" x 160));

$NGCP::Rtpengine::req_cb = $del_targets;

rtpe_req('delete', 'basic', { 'delete-delay' => 0 });

undef $NGCP::Rtpengine::req_cb;



my $cb = sub {
	# close table control
	# XXX check fd/address?
	my ($addr) = $kintf->recv($buf, 1024);
	my ($msg, $text) = unpack("i!", $buf);
	is($msg, 4, "close message");

	($addr) = $kintf->recv($buf, 1024);
	($msg, $text) = unpack("i! Z*", $buf);
	is($msg, 1, "open message");
	is($text, "/proc/rtpengine/control", "open control");
	$kintf->send(pack('ii', 1, 0), 0, $addr);

	($addr) = $kintf->recv($buf, 1024);
	($msg, $text) = unpack("i! a*", $buf);
	is($msg, 3, "write message");
	is($text, "del 42\n", "del msg");
	$kintf->send(pack('ii', 3, -Errno::ENOENT), 0, $addr);

	($addr) = $kintf->recv($buf, 1024);
	($msg, $text) = unpack("i!", $buf);
	is($msg, 4, "close message");
};

NGCP::Rtpengine::AutoTest::shut_rtpe($cb);

undef $kintf;
unlink($ENV{MOCK_PEER});

#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
