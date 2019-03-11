#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
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
sub rtpe_req {
	my ($cmd, $name, $req) = @_;
	$req->{command} = $cmd;
	$req->{'call-id'} = $cid;
	my $resp = $c->req($req);
	is $resp->{result}, 'ok', "$name - '$cmd' status";
	return $resp;
}
sub offer_answer {
	my ($cmd, $name, $req, $sdps) = @_;
	my ($sdp_in, $exp_sdp_out) = sdp_split($sdps);
	$req->{'from-tag'} = $ft;
	$req->{sdp} = $sdp_in;
	my $resp = rtpe_req($cmd, $name, $req);
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
	like $crlf, qr/$regexp/s, "$name - output '$cmd' SDP";
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
	my ($sock, $port, $match, $cb, $cb_arg) = @_;
	my $p = '';
	alarm(1);
	my $addr = $sock->recv($p, 65535, 0) or die;
	alarm(0);
	my ($hdr_mark, $pt, $seq, $ts, $ssrc, $payload) = unpack('CCnNN a*', $p);
	print("rtp recv $pt $seq $ts $ssrc " . unpack('H*', $payload) . "\n");
	if ($cb) {
		$p = $cb->($hdr_mark, $pt, $seq, $ts, $ssrc, $payload, $p, $cb_arg);
	}
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
sub srtp_rcv {
	my ($sock, $port, $match, $srtp_ctx) = @_;
	return rcv($sock, $port, $match, \&srtp_dec, $srtp_ctx);
}
sub srtp_dec {
	my ($hdr_mark, $pt, $seq, $ts, $ssrc, $payload, $pack, $srtp_ctx) = @_;
	if (!$srtp_ctx->{skey}) {
		my ($key, $salt) = NGCP::Rtpclient::SRTP::decode_inline_base64($srtp_ctx->{key}, $srtp_ctx->{cs});
		@$srtp_ctx{qw(skey sauth ssalt)} = NGCP::Rtpclient::SRTP::gen_rtp_session_keys($key, $salt);
	}
	my ($dec, $out_roc, $tag, $hmac) = NGCP::Rtpclient::SRTP::decrypt_rtp(@$srtp_ctx{qw(cs skey ssalt sauth roc)}, $pack);
	$srtp_ctx->{roc} = $out_roc;
	is $tag, substr($hmac, 0, length($tag)), 'SRTP auth tag matches';
	return $dec;
}
sub escape {
	return "\Q$_[0]\E";
}
sub rtpm {
	my ($pt, $seq, $ts, $ssrc, $payload) = @_;
	print("rtp matcher $pt $seq $ts $ssrc " . unpack('H*', $payload) . "\n");
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





# media playback

# 100 ms sine wave
my $wav_file = "\x52\x49\x46\x46\x64\x06\x00\x00\x57\x41\x56\x45\x66\x6d\x74\x20\x10\x00\x00\x00\x01\x00\x01\x00\x40\x1f\x00\x00\x80\x3e\x00\x00\x02\x00\x10\x00\x64\x61\x74\x61\x40\x06\x00\x00\x00\x00\xb0\x22\x45\x41\x25\x58\x95\x64\x24\x65\xbd\x59\xb6\x43\xb4\x25\x35\x03\x5e\xe0\x3b\xc1\x8c\xa9\x0f\x9c\x6a\x9a\xc2\xa4\xe7\xb9\x55\xd7\x92\xf9\x92\x1c\x30\x3c\xb2\x54\x2e\x63\xf3\x65\xa7\x5c\x68\x48\x9b\x2b\xa1\x09\x8a\xe6\x71\xc6\x28\xad\xab\x9d\xcc\x99\x06\xa2\x5c\xb5\x81\xd1\x2d\xf3\x53\x16\xe1\x36\xe8\x50\x64\x61\x59\x66\x36\x5f\xcf\x4c\x56\x31\x04\x10\xd0\xec\xe0\xcb\x19\xb1\xa9\x9f\x98\x99\xa8\x9f\x1a\xb1\xdf\xcb\xd1\xec\x04\x10\x54\x31\xd2\x4c\x33\x5f\x5c\x66\x61\x61\xeb\x50\xde\x36\x56\x16\x2b\xf3\x83\xd1\x59\xb5\x08\xa2\xcb\x99\xac\x9d\x28\xad\x70\xc6\x8a\xe6\xa3\x09\x98\x2b\x6a\x48\xa6\x5c\xf4\x65\x2d\x63\xb3\x54\x2e\x3c\x93\x1c\x93\xf9\x53\xd7\xe9\xb9\xc1\xa4\x69\x9a\x11\x9c\x8b\xa9\x3b\xc1\x5e\xe0\x36\x03\xb2\x25\xba\x43\xb7\x59\x2a\x65\x90\x64\x29\x58\x42\x41\xb2\x22\xff\xff\x50\xdd\xbb\xbe\xdb\xa7\x6b\x9b\xdd\x9a\x42\xa6\x4b\xbc\x4b\xda\xca\xfc\xa5\x1f\xc2\x3e\x77\x56\xed\x63\x9a\x65\x3b\x5b\x1b\x46\xa9\x28\x70\x06\x6c\xe3\xd2\xc3\x4d\xab\xd1\x9c\x10\x9a\x56\xa3\x99\xb7\x67\xd4\x5b\xf6\x79\x19\x8e\x39\xd7\x52\x58\x62\x30\x66\xfd\x5d\xa2\x4a\x81\x2e\xd1\x0c\xae\xe9\x1f\xc9\x17\xaf\x9e\x9e\xa4\x99\xce\xa0\x2c\xb3\xaf\xce\xf8\xef\x33\x13\x1e\x34\xe8\x4e\x57\x60\x68\x66\x57\x60\xe9\x4e\x1c\x34\x35\x13\xf6\xef\xb0\xce\x2d\xb3\xcc\xa0\xa6\x99\x9c\x9e\x17\xaf\x22\xc9\xa9\xe9\xd6\x0c\x7c\x2e\xa7\x4a\xf8\x5d\x36\x66\x52\x62\xdb\x52\x8c\x39\x79\x19\x5c\xf6\x67\xd4\x97\xb7\x59\xa3\x0e\x9a\xd1\x9c\x4e\xab\xd0\xc3\x6e\xe3\x6e\x06\xac\x28\x18\x46\x3d\x5b\x98\x65\xef\x63\x76\x56\xc3\x3e\xa4\x1f\xc9\xfc\x4e\xda\x49\xbc\x43\xa6\xdd\x9a\x69\x9b\xdd\xa7\xbb\xbe\x4f\xdd\x01\x00\xaf\x22\x47\x41\x23\x58\x96\x64\x24\x65\xbb\x59\xba\x43\xb0\x25\x39\x03\x59\xe0\x40\xc1\x87\xa9\x15\x9c\x65\x9a\xc4\xa4\xe7\xb9\x56\xd7\x90\xf9\x94\x1c\x2e\x3c\xb3\x54\x2f\x63\xf1\x65\xa8\x5c\x68\x48\x9a\x2b\xa2\x09\x8a\xe6\x71\xc6\x27\xad\xac\x9d\xcb\x99\x08\xa2\x59\xb5\x84\xd1\x2a\xf3\x56\x16\xe0\x36\xe7\x50\x65\x61\x59\x66\x35\x5f\xd1\x4c\x54\x31\x04\x10\xd2\xec\xdd\xcb\x1c\xb1\xa5\x9f\x9b\x99\xa8\x9f\x18\xb1\xe2\xcb\xcd\xec\x07\x10\x54\x31\xd1\x4c\x33\x5f\x5d\x66\x60\x61\xec\x50\xdd\x36\x57\x16\x29\xf3\x86\xd1\x57\xb5\x09\xa2\xcb\x99\xab\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9a\x2b\x69\x48\xa7\x5c\xf2\x65\x2e\x63\xb2\x54\x31\x3c\x91\x1c\x93\xf9\x53\xd7\xe9\xb9\xc1\xa4\x6a\x9a\x10\x9c\x8a\xa9\x3f\xc1\x59\xe0\x3a\x03\xb0\x25\xb8\x43\xbd\x59\x24\x65\x95\x64\x24\x58\x46\x41\xaf\x22\x02\x00\x4e\xdd\xbb\xbe\xdd\xa7\x68\x9b\xdf\x9a\x42\xa6\x48\xbc\x50\xda\xc6\xfc\xa7\x1f\xc2\x3e\x75\x56\xef\x63\x99\x65\x3c\x5b\x1a\x46\xaa\x28\x6e\x06\x6e\xe3\xd1\xc3\x4e\xab\xd1\x9c\x0e\x9a\x57\xa3\x9a\xb7\x64\xd4\x60\xf6\x75\x19\x90\x39\xd7\x52\x55\x62\x34\x66\xf9\x5d\xa8\x4a\x7a\x2e\xd8\x0c\xa7\xe9\x23\xc9\x16\xaf\x9d\x9e\xa6\x99\xcb\xa0\x2f\xb3\xad\xce\xfa\xef\x30\x13\x21\x34\xe6\x4e\x59\x60\x66\x66\x5a\x60\xe4\x4e\x23\x34\x2e\x13\xfc\xef\xab\xce\x30\xb3\xcb\xa0\xa5\x99\x9f\x9e\x14\xaf\x24\xc9\xa7\xe9\xd8\x0c\x7b\x2e\xa8\x4a\xf7\x5d\x36\x66\x53\x62\xda\x52\x8d\x39\x78\x19\x5d\xf6\x67\xd4\x97\xb7\x59\xa3\x0d\x9a\xd2\x9c\x4e\xab\xd1\xc3\x6d\xe3\x6f\x06\xaa\x28\x19\x46\x3f\x5b\x95\x65\xf2\x63\x74\x56\xc2\x3e\xa8\x1f\xc4\xfc\x52\xda\x45\xbc\x46\xa6\xdc\x9a\x6a\x9b\xdc\xa7\xba\xbe\x51\xdd\xff\xff\xb1\x22\x45\x41\x24\x58\x97\x64\x22\x65\xbd\x59\xb7\x43\xb3\x25\x37\x03\x5b\xe0\x3e\xc1\x89\xa9\x11\x9c\x6a\x9a\xc0\xa4\xeb\xb9\x51\xd7\x94\xf9\x91\x1c\x31\x3c\xb1\x54\x2f\x63\xf3\x65\xa5\x5c\x6c\x48\x95\x2b\xa7\x09\x86\xe6\x73\xc6\x28\xad\xa9\x9d\xcf\x99\x04\xa2\x5b\xb5\x84\xd1\x29\xf3\x57\x16\xde\x36\xe9\x50\x65\x61\x57\x66\x38\x5f\xcd\x4c\x57\x31\x04\x10\xd0\xec\xe1\xcb\x17\xb1\xaa\x9f\x97\x99\xaa\x9f\x18\xb1\xe1\xcb\xce\xec\x07\x10\x53\x31\xd0\x4c\x38\x5f\x55\x66\x68\x61\xe6\x50\xe0\x36\x56\x16\x2b\xf3\x81\xd1\x5d\xb5\x04\xa2\xce\x99\xaa\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9b\x2b\x67\x48\xa9\x5c\xf1\x65\x2e\x63\xb4\x54\x2e\x3c\x93\x1c\x92\xf9\x54\xd7\xe8\xb9\xc2\xa4\x69\x9a\x10\x9c\x8c\xa9\x3c\xc1\x5c\xe0\x37\x03\xb2\x25\xb8\x43\xbc\x59\x24\x65\x95\x64\x26\x58\x43\x41\xb2\x22\xff\xff\x50\xdd\xba\xbe\xde\xa7\x68\x9b\xdd\x9a\x45\xa6\x45\xbc\x52\xda\xc5\xfc\xa8\x1f\xbf\x3e\x79\x56\xec\x63\x9b\x65\x3b\x5b\x1a\x46\xaa\x28\x6f\x06\x6e\xe3\xd0\xc3\x4f\xab\xd0\x9c\x0f\x9a\x58\xa3\x97\xb7\x68\xd4\x5c\xf6\x78\x19\x8f\x39\xd6\x52\x57\x62\x32\x66\xfb\x5d\xa6\x4a\x7b\x2e\xd8\x0c\xa6\xe9\x25\xc9\x15\xaf\x9c\x9e\xa9\x99\xc7\xa0\x33\xb3\xa9\xce\xfd\xef\x2f\x13\x21\x34\xe6\x4e\x58\x60\x67\x66\x59\x60\xe5\x4e\x23\x34\x2c\x13\x00\xf0\xa6\xce\x35\xb3\xc7\xa0\xa8\x99\x9d\x9e\x15\xaf\x24\xc9\xa8\xe9\xd5\x0c\x7e\x2e\xa5\x4a\xfa\x5d\x35\x66\x52\x62\xdb\x52\x8d\x39\x77\x19\x5e\xf6\x66\xd4\x98\xb7\x59\xa3\x0c\x9a\xd3\x9c\x4d\xab\xd1\xc3\x6e\xe3\x6e\x06\xaa\x28\x1b\x46\x3b\x5b\x9a\x65\xed\x63\x76\x56\xc4\x3e\xa3\x1f\xcb\xfc\x4b\xda\x4a\xbc\x43\xa6\xdd\x9a\x6a\x9b\xdc\xa7\xba\xbe\x51\xdd\xff\xff\xb1\x22\x44\x41\x25\x58\x96\x64\x23\x65\xbd\x59\xb6\x43\xb4\x25\x36\x03\x5c\xe0\x3d\xc1\x8a\xa9\x12\x9c\x67\x9a\xc4\xa4\xe6\xb9\x55\xd7\x93\xf9\x91\x1c\x31\x3c\xb0\x54\x31\x63\xef\x65\xab\x5c\x66\x48\x9a\x2b\xa4\x09\x87\xe6\x73\xc6\x26\xad\xad\x9d\xcb\x99\x07\xa2\x5b\xb5\x81\xd1\x2c\xf3\x56\x16\xde\x36\xeb\x50\x62\x61\x59\x66\x38\x5f\xcc\x4c\x59\x31\x01\x10\xd3\xec\xdd\xcb\x1b\xb1\xa8\x9f\x98\x99\xa9\x9f\x18\xb1\xe0\xcb\xd1\xec\x03\x10\x57\x31\xce\x4c\x37\x5f\x58\x66\x63\x61\xec\x50\xdb\x36\x5a\x16\x27\xf3\x85\xd1\x5a\xb5\x05\xa2\xce\x99\xaa\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9a\x2b\x69\x48\xa6\x5c\xf4\x65\x2e\x63\xb1\x54\x32\x3c\x8e\x1c\x96\xf9\x52\xd7\xea\xb9\xc1\xa4\x67\x9a\x13\x9c\x8a\xa9\x3c\xc1\x5e\xe0\x33\x03\xb7\x25\xb4\x43\xbf\x59\x21\x65\x99\x64\x21\x58\x48\x41\xad\x22\x03\x00\x4f\xdd\xbb\xbe\xdb\xa7\x6a\x9b\xdd\x9a\x43\xa6\x4b\xbc\x4a\xda\xcb\xfc\xa4\x1f\xc3\x3e\x76\x56\xef\x63\x96\x65\x40\x5b\x17\x46\xac\x28\x6e\x06\x6d\xe3\xd2\xc3\x4d\xab\xd2\x9c\x0d\x9a\x59\xa3\x97\xb7\x68\xd4\x5c\xf6\x77\x19\x8f\x39\xd8\x52\x55\x62\x33\x66\xfb\x5d\xa4\x4a\x7f\x2e\xd4\x0c\xab\xe9\x20\xc9\x17\xaf\x9d\x9e\xa7\x99\xc9\xa0\x32\xb3\xa9\xce\xfd\xef\x2f\x13\x20\x34\xe8\x4e\x56\x60\x6a\x66\x55\x60\xe9\x4e\x1f\x34\x31\x13\xfa\xef\xad\xce\x2e\xb3\xcc\xa0\xa7\x99\x9b\x9e\x18\xaf\x20\xc9\xac\xe9\xd2\x0c\x81\x2e\xa1\x4a\xff\x5d\x30\x66\x56\x62\xd7\x52\x90\x39\x77\x19\x5d\xf6\x67\xd4\x96\xb7\x5a\xa3\x0e\x9a\xd0\x9c\x50\xab\xcf\xc3\x6e\xe3\x6f\x06\xaa\x28\x1a\x46\x3d\x5b\x98\x65\xee\x63\x77\x56\xc1\x3e\xa7\x1f\xc8\xfc\x4c\xda\x4b\xbc\x41\xa6\xdf\x9a\x68\x9b\xdd\xa7\xba\xbe\x51\xdd";
is length($wav_file), 1644, 'embedded binary wav file';

my $pcma_1 = "\xd5\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\x55\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c";
my $pcma_2 = "\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\xd5\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\xd5\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09";
my $pcma_3 = "\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\x55\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0";
my $pcma_4 = "\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\x55\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\x55\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1";
my $pcma_5 = "\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\xd5\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34";





($sock_a) = new_call([qw(198.51.100.1 2020)]);

offer('media playback, offer only', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2020 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

my $resp = rtpe_req('play media', 'media playback, offer only', { 'from-tag' => $ft, blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

my $ts;
($seq, $ts, $ssrc) = rcv($sock_a, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_a, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_a, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_a, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_a, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 2020)], [qw(198.51.100.3 2022)]);

offer('media playback, side A', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2020 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('media playback, side A', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2022 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


$resp = rtpe_req('play media', 'media playback, side A', { 'from-tag' => $ft, blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

($seq, $ts, $ssrc) = rcv($sock_a, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_a, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_a, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_a, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_a, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 2030)], [qw(198.51.100.3 2032)]);

offer('media playback, side B', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2030 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('media playback, side B', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2032 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


$resp = rtpe_req('play media', 'media playback, side B', { 'from-tag' => $tt, blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

($seq, $ts, $ssrc) = rcv($sock_b, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_b, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_b, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_b, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_b, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));

$resp = rtpe_req('play media', 'restart media playback', { 'from-tag' => $tt, blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

$ts += 160 * 5;
my $old_ts = $ts;
($ts) = rcv($sock_b, -1, rtpm(8 | 0x80, $seq + 5, -1, $ssrc, $pcma_1));
print("ts $ts old $old_ts\n");
SKIP: {
	skip 'random timestamp too close to margin', 2 if $old_ts < 500 or $old_ts > 4294966795;
	cmp_ok($ts, '<', $old_ts + 500, 'ts within < range');
	cmp_ok($ts, '>', $old_ts - 500, 'ts within > range');
}
rcv($sock_b, -1, rtpm(8, $seq + 6, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_b, -1, rtpm(8, $seq + 7, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_b, -1, rtpm(8, $seq + 8, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_b, -1, rtpm(8, $seq + 9, $ts + 160 * 4, $ssrc, $pcma_5));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 2050)], [qw(198.51.100.3 2052)]);

offer('media playback, SRTP', { ICE => 'remove', replace => ['origin'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2050 RTP/SAVP 8
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:eMlRvW8mWU4WodT9JOvAM+pn6I0/EXOhT9n0KeKk
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:eMlRvW8mWU4WodT9JOvAM+pn6I0/EXOhT9n0KeKk
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

answer('media playback, SRTP', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2052 RTP/SAVP 8
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF
SDP


$resp = rtpe_req('play media', 'media playback, SRTP', { 'from-tag' => $ft, blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

my $srtp_ctx = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF',
};
($seq, $ts, $ssrc) = srtp_rcv($sock_a, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1), $srtp_ctx);
srtp_rcv($sock_a, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2), $srtp_ctx);
srtp_rcv($sock_a, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3), $srtp_ctx);
srtp_rcv($sock_a, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4), $srtp_ctx);
srtp_rcv($sock_a, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5), $srtp_ctx);






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

($port_a) = offer('ptime=50 in, change to 30, reverse to 50, response 30', {
	ICE => 'remove', replace => ['origin'], ptime => 30, 'ptime-reverse' => 50 }, <<SDP);
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

($port_b) = answer('ptime=50 in, change to 30, reverse to 50, response 30',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
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




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3012)], [qw(198.51.100.3 3014)]);

($port_a) = offer('ptime=50 in, change to 30, response 30', {
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

($port_b) = answer('ptime=50 in, change to 30, response 30',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3014 RTP/AVP 0
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




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3016)], [qw(198.51.100.3 3018)]);

($port_a) = offer('ptime=50 in, change to 30, reverse to 50, default response', {
	ICE => 'remove', replace => ['origin'], ptime => 30, 'ptime-reverse' => 50 }, <<SDP);
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

($port_b) = answer('ptime=50 in, change to 30, reverse to 50, default response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
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

($port_a) = offer('ptime=50 in, change to 30, reverse to 20, default response', {
	ICE => 'remove', replace => ['origin'], ptime => 30, 'ptime-reverse' => 20 }, <<SDP);
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

($port_b) = answer('ptime=50 in, change to 30, reverse to 20, default response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
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
a=ptime:20
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

# B->A: 4x 30 ms -> 6x 20 ms
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 5320, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4003, 5480, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4004, 5640, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 5800, $ssrc, "\x88" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3016)], [qw(198.51.100.3 3018)]);

($port_a) = offer('ptime=50 in, change to 30, reverse to 20, response 40', {
	ICE => 'remove', replace => ['origin'], ptime => 30, 'ptime-reverse' => 20 }, <<SDP);
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

($port_b) = answer('ptime=50 in, change to 30, reverse to 20, response 40',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:40
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
a=ptime:20
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

# B->A: 4x 30 ms -> 6x 20 ms
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 5320, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4003, 5480, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4004, 5640, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 5800, $ssrc, "\x88" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3016)], [qw(198.51.100.3 3018)]);

($port_a) = offer('ptime=30 in, no change, reverse to 20, response 40', {
	ICE => 'remove', replace => ['origin'], 'ptime-reverse' => 20 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3016 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:30
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

($port_b) = answer('ptime=30 in, no change, reverse to 20, response 40',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:40
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
a=ptime:20
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

# B->A: 4x 30 ms -> 6x 20 ms
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 5320, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4003, 5480, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4004, 5640, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 5800, $ssrc, "\x88" x 160));




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
