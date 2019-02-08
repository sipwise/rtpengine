#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use Test::More;
use File::Temp;
use IPC::Open3;
use Time::HiRes;
use POSIX ":sys_wait_h";

like $ENV{LD_PRELOAD}, qr/tests-preload/, 'LD_PRELOAD present';
is $ENV{RTPE_PRELOAD_TEST_ACTIVE}, '1', 'preload library is active';
ok -x $ENV{RTPE_BIN}, 'RTPE_BIN points to executable';

my $rtpe_stdout = File::Temp::tempfile() or die;
my $rtpe_stderr = File::Temp::tempfile() or die;
my $rtpe_pid = open3(undef, '>&'.fileno($rtpe_stdout), '>&'.fileno($rtpe_stderr),
	$ENV{RTPE_BIN}, qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
		-n 2223 -c 12345 -f -L 7 -E -u 2222));
ok $rtpe_pid, 'daemon launched in background';

# keep trying to connect to the control socket while daemon is starting up
my $c;
for (1 .. 300) {
	$c = NGCP::Rtpengine->new($ENV{RTPENGINE_HOST} // 'localhost', $ENV{RTPENGINE_PORT} // 2223);
	last if $c->{socket};
	Time::HiRes::usleep(100000); # 100 ms x 300 = 30 sec
}

1;
$c->{socket} or die;

my ($cid, $ft, $tt, $r);

sub new_call {
	undef($r);
	$cid = rand();
	$ft = rand();
	$tt = rand();
	return;
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
	$regexp =~ s/PORT/(\\d{1,5})/gs;
	$regexp =~ s/ICEBASE/([0-9a-zA-Z]{16})/gs;
	$regexp =~ s/ICEUFRAG/([0-9a-zA-Z]{8})/gs;
	$regexp =~ s/ICEPWD/([0-9a-zA-Z]{26})/gs;
	$regexp =~ s/CRYPTO128/([0-9a-zA-Z\/+]{40})/gs;
	$regexp =~ s/CRYPTO192/([0-9a-zA-Z\/+]{51})/gs;
	$regexp =~ s/CRYPTO256/([0-9a-zA-Z\/+]{62})/gs;
	like crlf($resp->{sdp}), qr/$regexp/s, "$name - output $cmd SDP";
	return;
}
sub offer {
	return offer_answer('offer', @_);
}
sub answer {
	my ($name, $req, $sdps) = @_;
	$req->{'to-tag'} = $tt;
	return offer_answer('answer', $name, $req, $sdps);
}

$r = $c->req({command => 'ping'});
ok $r->{result} eq 'pong', 'ping works, daemon operational';

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
a=crypto:3 AES_CM_192_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:4 AES_CM_192_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:5 AES_CM_256_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:6 AES_CM_256_HMAC_SHA1_32 inline:CRYPTO256
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
a=crypto:3 AES_CM_192_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:4 AES_CM_192_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:5 AES_CM_256_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:6 AES_CM_256_HMAC_SHA1_32 inline:CRYPTO256
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
a=crypto:2 AES_CM_192_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:3 AES_CM_192_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:4 AES_CM_256_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_CM_256_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:7 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:8 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_32 inline:CRYPTO128
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
a=crypto:3 AES_CM_192_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:4 AES_CM_192_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:5 AES_CM_256_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:6 AES_CM_256_HMAC_SHA1_32 inline:CRYPTO256
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
a=crypto:3 AES_CM_192_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:4 AES_CM_192_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:5 AES_CM_256_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:6 AES_CM_256_HMAC_SHA1_32 inline:CRYPTO256
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
a=crypto:3 AES_CM_192_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:4 AES_CM_192_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:5 AES_CM_256_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:6 AES_CM_256_HMAC_SHA1_32 inline:CRYPTO256
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
a=crypto:2 AES_CM_192_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:3 AES_CM_192_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:4 AES_CM_256_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_CM_256_HMAC_SHA1_32 inline:CRYPTO256
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
