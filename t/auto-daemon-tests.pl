#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use Test::More;
use File::Temp;
use IPC::Open3;
use Time::HiRes;
use POSIX ":sys_wait_h";
use IO::Socket;

like $ENV{LD_PRELOAD}, qr/tests-preload/, 'LD_PRELOAD present';
is $ENV{RTPE_PRELOAD_TEST_ACTIVE}, '1', 'preload library is active';
SKIP: {
	skip 'daemon is running externally', 1 if $ENV{RTPE_TEST_NO_LAUNCH};
	ok -x $ENV{RTPE_BIN}, 'RTPE_BIN points to executable';
}

my $rtpe_stdout = File::Temp::tempfile() or die;
my $rtpe_stderr = File::Temp::tempfile() or die;
my $rtpe_pid;
SKIP: {
	skip 'daemon is running externally', 1 if $ENV{RTPE_TEST_NO_LAUNCH};
	$rtpe_pid = open3(undef, '>&'.fileno($rtpe_stdout), '>&'.fileno($rtpe_stderr),
		$ENV{RTPE_BIN}, qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -c 12345 -f -L 7 -E -u 2222));
	ok $rtpe_pid, 'daemon launched in background';
}

# keep trying to connect to the control socket while daemon is starting up
my $c;
for (1 .. 300) {
	$c = NGCP::Rtpengine->new($ENV{RTPENGINE_HOST} // 'localhost', $ENV{RTPENGINE_PORT} // 2223);
	last if $c->{socket};
	Time::HiRes::usleep(100000); # 100 ms x 300 = 30 sec
}

1;
$c->{socket} or die;

my ($cid, $ft, $tt, @sockets);
my ($tag_iter) = (0);

sub new_call {
	my @ports = @_;
	for my $s (@sockets) {
		$s->close();
	}
	@sockets = ();
	$cid = $tag_iter++ . "-test-callID";
	$ft = $tag_iter++ . "-test-fromtag";
	$tt = $tag_iter++ . "-test-totag";
	for my $p (@ports) {
		my ($addr, $port) = @{$p};
		my $s = IO::Socket::IP->new(Type => &SOCK_DGRAM, Proto => 'udp',
				LocalHost => $addr, LocalPort => $port)
				or die;
		push(@sockets, $s);
	}
	return @sockets;
}
sub crlf {
	my ($s) = @_;
	$s =~ s/\r\n/\n/gs;
	return $s;
}
sub sdp_split {
	my ($s) = @_;
	return split(/--------*\n/, $s);
}
sub offer_answer {
	my ($cmd, $name, $req, $sdps) = @_;
	my ($sdp_in, $exp_sdp_out) = sdp_split($sdps);
	$req->{command} = $cmd;
	$req->{'call-id'} = $cid;
	$req->{'from-tag'} = $ft;
	$req->{sdp} = $sdp_in;
	my $resp = $c->req($req);
	is $resp->{result}, 'ok', "$name - $cmd status";
	my $regexp = "^\Q$exp_sdp_out\E\$";
	$regexp =~ s/\\\?/./gs;
	$regexp =~ s/PORT/(\\d{1,5})/gs;
	$regexp =~ s/ICEBASE/([0-9a-zA-Z]{16})/gs;
	$regexp =~ s/ICEUFRAG/([0-9a-zA-Z]{8})/gs;
	$regexp =~ s/ICEPWD/([0-9a-zA-Z]{26})/gs;
	$regexp =~ s/CRYPTO128/([0-9a-zA-Z\/+]{40})/gs;
	$regexp =~ s/CRYPTO192/([0-9a-zA-Z\/+]{51})/gs;
	$regexp =~ s/CRYPTO256/([0-9a-zA-Z\/+]{62})/gs;
	my $crlf = crlf($resp->{sdp});
	like $crlf, qr/$regexp/s, "$name - output $cmd SDP";
	my @matches = $crlf =~ qr/$regexp/s;
	return @matches;
}
sub offer {
	return offer_answer('offer', @_);
}
sub answer {
	my ($name, $req, $sdps) = @_;
	$req->{'to-tag'} = $tt;
	return offer_answer('answer', $name, $req, $sdps);
}
sub snd {
	my ($sock, $dest, $packet) = @_;
	$sock->send($packet, 0, pack_sockaddr_in($dest, inet_aton('203.0.113.1'))) or die;
}
sub rtp {
	my ($pt, $seq, $ts, $ssrc, $payload) = @_;
	print("rtp in $pt $seq $ts $ssrc\n");
	return pack('CCnNN a*', 0x80, $pt, $seq, $ts, $ssrc, $payload);
}
sub rcv {
	my ($sock, $port, $match) = @_;
	my $p = '';
	alarm(1);
	my $addr = $sock->recv($p, 65535, 0) or die;
	alarm(0);
	my ($hdr_mark, $pt, $seq, $ts, $ssrc, $payload) = unpack('CCnNN a*', $p);
	print("rtp recv $pt $seq $ts $ssrc\n");
	like $p, $match, 'received packet matches';
	my @matches = $p =~ $match;
	for my $m (@matches) {
		if (length($m) == 2) {
			($m) = unpack('n', $m);
		}
		elsif (length($m) == 4) {
			($m) = unpack('N', $m);
		}
	}
	return @matches;
}
sub escape {
	return "\Q$_[0]\E";
}
sub rtpm {
	my ($pt, $seq, $ts, $ssrc, $payload) = @_;
	print("rtp matcher $pt $seq $ts $ssrc\n");
	my $re = '';
	$re .= escape(pack('C', 0x80));
	$re .= escape(pack('C', $pt));
	$re .= $seq >= 0 ? escape(pack('n', $seq)) : '(..)';
	$re .= $ts >= 0 ? escape(pack('N', $ts)) : '(....)';
	$re .= $ssrc >= 0 ? escape(pack('N', $ssrc)) : '(....)';
	$re .= escape($payload);
	return qr/^$re$/s;
}

{
	my $r = $c->req({command => 'ping'});
	ok $r->{result} eq 'pong', 'ping works, daemon operational';
}

# SDP in/out tests, various ICE options

new_call;

offer('plain SDP, no ICE', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('plain SDP, no ICE', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('plain SDP, add default ICE', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('plain SDP, ICE removed', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
-------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('plain SDP, ICE removed', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('plain SDP, no ICE option given', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('ICE SDP, default ICE option', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=candidate:ICEBASE 1 UDP 2097152255 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 4294967295 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2097152254 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 4294967294 2001:db8:4321::1 PORT typ host
SDP

answer('plain SDP, ICE rejected, no ICE option given', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('ICE SDP with ICE force', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('plain SDP, ICE rejected, no ICE option given', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('ICE SDP with ICE force', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('ICE SDP, no ICE option given', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ice-ufrag:bmnhkfdf
a=ice-pwd:jetyhsdfgsdtjhtyjktrthsrhH
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfbhdcfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfbhdcfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=ice-ufrag:bmnhkfdf
a=ice-pwd:jetyhsdfgsdtjhtyjktrthsrhH
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfbhdcfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfbhdcfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=candidate:ICEBASE 1 UDP 2097152255 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 4294967295 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2097152254 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 4294967294 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('ICE SDP with ICE force', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('ICE SDP with ICE force', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ice-ufrag:bmnhkfdf
a=ice-pwd:jetyhsdfgsdtjhtyjktrthsrhH
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfbhdcfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfbhdcfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

# github issue #686

new_call;

offer('gh 686', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
c=IN IP4 198.51.100.1
m=audio 0 RTP/AVP 8 101
m=image 2000 udptl t38
c=IN IP4 198.51.100.1
a=T38FaxVersion:0
a=T38FaxRateManagement:transferredTCF
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
c=IN IP4 203.0.113.1
m=audio 0 RTP/AVP 8 101
m=image PORT udptl t38
c=IN IP4 203.0.113.1
a=T38FaxVersion:0
a=T38FaxRateManagement:transferredTCF
a=sendrecv
SDP

# github issue #661

new_call;

offer('gh 661 plain', { ICE => 'remove', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyH?
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8?
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 plain', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
SDP

new_call;

offer('gh 661 suppress one', { ICE => 'remove', DTLS => 'off', SDES => [ 'no-F8_128_HMAC_SHA1_80' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyH?
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8?
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:8 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 suppress one', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
SDP

new_call;

offer('gh 661 remove one', { ICE => 'remove', DTLS => 'off', SDES => [ 'no-AES_CM_128_HMAC_SHA1_32' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyH?
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8?
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 remove one', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
SDP

new_call;

offer('gh 661 remove first', { ICE => 'remove', DTLS => 'off', SDES => [ 'no-AES_CM_128_HMAC_SHA1_80' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyH?
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8?
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 remove first', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VdfhasfhsfghsrtjhasrtjhsartjhsM4Gw6chrFr
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VdfhasfhsfghsrtjhasrtjhsartjhsM4Gw6chrFr
SDP

# #661 for transcoding to RTP

offer('gh 661 plain to RTP', { ICE => 'remove', DTLS => 'off', 'transport protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('gh 661 plain to RTP', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

new_call;

offer('gh 661 remove one to RTP', { ICE => 'remove', DTLS => 'off', 'transport protocol' => 'RTP/AVP', SDES => [ 'no-AES_CM_128_HMAC_SHA1_32' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('gh 661 remove one to RTP', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

new_call;

offer('gh 661 remove first to RTP', { ICE => 'remove', DTLS => 'off', 'transport protocol' => 'RTP/AVP', SDES => [ 'no-AES_CM_128_HMAC_SHA1_80' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('gh 661 remove first to RTP', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
SDP

# #661 for transcoding from RTP

new_call;

offer('gh 661 plain from RTP', { ICE => 'remove', DTLS => 'off', 'transport protocol' => 'RTP/SAVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:3 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:4 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:5 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:6 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:7 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 plain from RTP', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('gh 661 from RTP suppress one', { ICE => 'remove', DTLS => 'off', 'transport protocol' => 'RTP/SAVP', SDES => [ 'no-F8_128_HMAC_SHA1_80' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:3 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:4 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:5 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:6 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:7 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:8 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 from RTP suppress one', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('gh 661 from RTP suppress first', { ICE => 'remove', DTLS => 'off', 'transport protocol' => 'RTP/SAVP', SDES => [ 'no-AES_CM_128_HMAC_SHA1_80' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:2 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:3 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:7 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:8 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 from RTP suppress first', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_32 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP





# codec masking gh#664

new_call;

offer('gh 664 codec masking plain', { ICE => 'remove', replace => [qw(origin session-connection)],
	flags => [qw(codec-mask-opus codec-mask-G722 codec-strip-G7221)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 120 8 0 101
c=IN IP4 198.51.100.1
a=rtpmap:120 opus/48000/2
a=fmtp:120 useinbandfec=1; usedtx=1; maxaveragebitrate=64000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

answer('gh 664 codec masking plain', { ICE => 'remove', replace => [qw(origin session-connection)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
c=IN IP4 198.51.100.3
t=0 0
m=audio 2002 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
c=IN IP4 203.0.113.1
t=0 0
m=audio PORT RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP


new_call;

offer('gh 664 codec masking a/t', { ICE => 'remove', replace => [qw(origin session-connection)],
	flags => [qw(codec-mask-opus codec-mask-G722 codec-strip-G7221 always-transcode)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 120 8 0 101
c=IN IP4 198.51.100.1
a=rtpmap:120 opus/48000/2
a=fmtp:120 useinbandfec=1; usedtx=1; maxaveragebitrate=64000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

answer('gh 664 codec masking a/t', { ICE => 'remove', replace => [qw(origin session-connection)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
c=IN IP4 198.51.100.3
t=0 0
m=audio 2002 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
c=IN IP4 203.0.113.1
t=0 0
m=audio PORT RTP/AVP 120 8 0 101
a=rtpmap:120 opus/48000/2
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:120 useinbandfec=1; usedtx=1; maxaveragebitrate=64000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP





# RTP sequencing tests

my ($sock_a, $sock_b) = new_call([qw(198.51.100.1 2010)], [qw(198.51.100.3 2012)]);

my ($port_a) = offer('two codecs, no transcoding', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2010 RTP/AVP 0 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

my ($port_b) = answer('two codecs, no transcoding', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2012 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\00" x 160));
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3000, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3000, 0x1234, "\00" x 160));
snd($sock_a, $port_b, rtp(0, 1010, 3000, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 3000, 0x1234, "\00" x 160));
snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234, "\00" x 160));
snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234, "\00" x 160));
snd($sock_a, $port_b, rtp(8, 1001, 3000, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1001, 3000, 0x1234, "\00" x 160));
snd($sock_a, $port_b, rtp(8, 1010, 3000, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1010, 3000, 0x1234, "\00" x 160));


($sock_a, $sock_b) = new_call([qw(198.51.100.1 2010)], [qw(198.51.100.3 2012)]);

($port_a) = offer('one codec with one for transcoding', { ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['PCMA'] }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2010 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('one codec with one for transcoding', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2012 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\00" x 160));
snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\00" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3160, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\00" x 160));
snd($sock_a, $port_b,  rtp(0, 1010, 4600, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\00" x 160));

snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\00" x 160));
my ($seq, $ssrc) = rcv($sock_a, $port_b, rtpm(0, -1, 4000, -1, "\00" x 160));
snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq, 4000, $ssrc, "\00" x 160));
snd($sock_b, $port_a,  rtp(0, 2001, 4000+160, 0x5678, "\00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+1, 4000+160, $ssrc, "\00" x 160));
snd($sock_b, $port_a,  rtp(0, 2010, 4000+1600, 0x5678, "\00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+10, 4000+1600, $ssrc, "\00" x 160));

snd($sock_b, $port_a,  rtp(8, 2011, 4000+160*11, 0x5678, "\00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+11, 4000+160*11, $ssrc, ")" x 160));
# #664 seq reset
snd($sock_b, $port_a,  rtp(8, 62011, 4000+160*12, 0x5678, "\00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+12, 4000+160*12, $ssrc, ")" x 160));
snd($sock_b, $port_a,  rtp(8, 62012, 4000+160*13, 0x5678, "\00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+13, 4000+160*13, $ssrc, ")" x 160));
snd($sock_b, $port_a,  rtp(0, 62013, 4000+160*14, 0x5678, "\00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+14, 4000+160*14, $ssrc, "\00" x 160));




# ptime tests

($sock_a, $sock_b) = new_call([qw(198.51.100.1 3000)], [qw(198.51.100.3 3002)]);

($port_a) = offer('default ptime in/out', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('default ptime in/out', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\00" x 160));
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4000, 5000, 0x4567, "\x88" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3000)], [qw(198.51.100.3 3002)]);

($port_a) = offer('mismatched ptime but no change requested', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:20
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

($port_b) = answer('mismatched ptime but no change requested', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:30
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\00" x 240));
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4000, 5000, 0x4567, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5160, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, 0x4567, "\x88" x 240));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3004)], [qw(198.51.100.3 3006)]);

($port_a) = offer('default ptime in, ptime=30 out, default response', {
	ICE => 'remove', replace => ['origin'], ptime => 30 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3004 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('default ptime in, ptime=30 out, default response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3006 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# A->B: 5x 20 ms packets -> 3x 30 ms
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\00" x 240));
snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\00" x 240));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\00" x 160));
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\00" x 240));

# A->B: 60 ms packet -> 2x 30 ms
# also perform TS and seq reset
snd($sock_a, $port_b, rtp(0, 8000, 500000, 0x1234, "\00" x 480));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1004, 3960, $ssrc, "\00" x 240));

# B->A: 2x 60 ms packet -> 6x 20 ms
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 480));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 5320, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5480, 0x4567, "\x88" x 480));
rcv($sock_a, $port_b, rtpm(0, 4003, 5480, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4004, 5640, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 5800, $ssrc, "\x88" x 160));

# B->A: 4x 10 ms packet -> 2x 20 ms
# out of order packet input
snd($sock_b, $port_a, rtp(0, 4003, 6040, 0x4567, "\x88" x 80));
Time::HiRes::usleep(10000);
snd($sock_b, $port_a, rtp(0, 4002, 5960, 0x4567, "\x88" x 80));
rcv($sock_a, $port_b, rtpm(0, 4006, 5960, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4004, 6120, 0x4567, "\x88" x 80));
snd($sock_b, $port_a, rtp(0, 4005, 6200, 0x4567, "\x88" x 80));
rcv($sock_a, $port_b, rtpm(0, 4007, 6120, $ssrc, "\x88" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3008)], [qw(198.51.100.3 3010)]);

($port_a) = offer('default ptime in, no change, ptime=30 response', {
	ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3008 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('default ptime in, no change, ptime=30 response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3010 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:30
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

# A->B: 20 ms unchanged
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\00" x 160));
# A->B: 30 ms unchanged
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, $ssrc, "\00" x 240));

# B->A: 20 ms unchanged
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
# B->A: 30 ms unchanged
snd($sock_b, $port_a, rtp(0, 4001, 5160, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 240));



($sock_a, $sock_b) = new_call([qw(198.51.100.1 3012)], [qw(198.51.100.3 3014)]);

($port_a) = offer('ptime=50 in, change to 30, default response', {
	ICE => 'remove', replace => ['origin'], ptime => 30 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3012 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:50
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=50 in, change to 30, default response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3014 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:50
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\00" x 240));

# B->A: 4x 30 ms -> 2x 50 ms (plus 20 ms left)
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 400));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5400, $ssrc, "\x88" x 400));
# B->A: add another 30 ms for another full 50 ms
snd($sock_b, $port_a, rtp(0, 4004, 5960, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4002, 5800, $ssrc, "\x88" x 400));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3016)], [qw(198.51.100.3 3018)]);

($port_a) = offer('ptime=50 in, change to 30, response 30, change to 50', {
	ICE => 'remove', replace => ['origin'], ptime => 30 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3016 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:50
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=50 in, change to 30, response 30, change to 50',
	{ ICE => 'remove', replace => ['origin'], ptime => 50 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:30
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:50
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\00" x 240));

# B->A: 4x 30 ms -> 2x 50 ms (plus 20 ms left)
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 400));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5400, $ssrc, "\x88" x 400));
# B->A: add another 30 ms for another full 50 ms
snd($sock_b, $port_a, rtp(0, 4004, 5960, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4002, 5800, $ssrc, "\x88" x 400));




END {
	if ($rtpe_pid) {
		kill('INT', $rtpe_pid) or die;
		# wait for daemon to terminate
		my $status = -1;
		for (1 .. 50) {
			$status = waitpid($rtpe_pid, WNOHANG);
			last if $status != 0;
			Time::HiRes::usleep(100000); # 100 ms x 50 = 5 sec
		}
		kill('KILL', $rtpe_pid) if $status == 0;
		$status == $rtpe_pid or die;
		$? == 0 or die;
	}
}

done_testing();
