#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use Test::More;
use File::Temp;
use IPC::Open3;
use Time::HiRes;

like $ENV{LD_PRELOAD}, qr/tests-preload/, 'LD_PRELOAD present';
ok -x $ENV{RTPE_BIN}, 'RTPE_BIN points to executable';

my $rtpe_stdout = File::Temp::tempfile() or die;
my $rtpe_stderr = File::Temp::tempfile() or die;
my $rtpe_pid = open3(undef, $rtpe_stdout, $rtpe_stderr,
	$ENV{RTPE_BIN}, qw(-t -1 -i 203.0.113.1 -i 2001:db8:4321::1 -n 2223 -c 12345 -f -L 7 -E -u 2222));
ok $rtpe_pid, 'daemon launched in background';

# keep trying to connect to the control socket while daemon is starting up
my $c;
for (1 .. 100) {
	$c = NGCP::Rtpengine->new($ENV{RTPENGINE_HOST} // 'localhost', $ENV{RTPENGINE_PORT} // 2223);
	last if $c->{socket};
	Time::HiRes::usleep(1000);
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
sub offer {
	my ($name, $req, $sdps) = @_;
	my ($sdp_in, $exp_sdp_out) = sdp_split($sdps);
	$req->{command} = 'offer';
	$req->{'call-id'} = $cid;
	$req->{'from-tag'} = $ft;
	$req->{sdp} = $sdp_in;
	my $resp = $c->req($req);
	is $resp->{result}, 'ok', "$name - offer status";
	is crlf($resp->{sdp}), $exp_sdp_out, "$name - output offer SDP";
	return;
}
sub answer {
	my ($name, $req, $sdps) = @_;
	my ($sdp_in, $exp_sdp_out) = sdp_split($sdps);
	$req->{command} = 'answer';
	$req->{'call-id'} = $cid;
	$req->{'from-tag'} = $ft;
	$req->{'to-tag'} = $tt;
	$req->{sdp} = $sdp_in;
	my $resp = $c->req($req);
	is $resp->{result}, 'ok', "$name - answer status";
	is crlf($resp->{sdp}), $exp_sdp_out, "$name - output answer SDP";
	return;
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
m=audio 30000 RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:30001
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
m=audio 30012 RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:30013
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
m=audio 30026 RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:30027
a=ice-ufrag:hH7xXnNd
a=ice-pwd:D3tTjJ9zZpPfF5vVVlLbB1rRhH
a=candidate:TjJ9zZpPfF5vVlLb 1 UDP 2130706431 203.0.113.1 30026 typ host
a=candidate:TjJ9zZpPfF5vVlLb 1 UDP 2130706175 2001:db8:4321::1 30022 typ host
a=candidate:TjJ9zZpPfF5vVlLb 2 UDP 2130706430 203.0.113.1 30027 typ host
a=candidate:TjJ9zZpPfF5vVlLb 2 UDP 2130706174 2001:db8:4321::1 30023 typ host
SDP

answer('plain answer, ICE removed', { ICE => 'remove' }, <<SDP);
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
m=audio 30036 RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:30037
SDP

new_call;

offer('plain offer, no ICE, ICE removed', { ICE => 'remove' }, <<SDP);
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
m=audio 30052 RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:30053
SDP

answer('plain answer, no ICE option given', { }, <<SDP);
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
m=audio 30064 RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:30065
SDP

new_call;

offer('plain offer, ICE present, default ICE option', { }, <<SDP);
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
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 30082 RTP/AVP 0
c=IN IP4 203.0.113.1
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:30083
a=candidate:TjJ9zZpPfF5vVlLb 1 UDP 2097152255 203.0.113.1 30082 typ host
a=candidate:TjJ9zZpPfF5vVlLb 1 UDP 4294967295 2001:db8:4321::1 30084 typ host
a=candidate:TjJ9zZpPfF5vVlLb 2 UDP 2097152254 203.0.113.1 30083 typ host
a=candidate:TjJ9zZpPfF5vVlLb 2 UDP 4294967294 2001:db8:4321::1 30085 typ host
SDP

answer('plain answer, ICE rejected, no ICE option given', { }, <<SDP);
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
m=audio 30096 RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:30097
a=candidate:TjJ9zZpPfF5vVlLb 1 UDP 2130706431 203.0.113.1 30096 typ host
a=candidate:TjJ9zZpPfF5vVlLb 1 UDP 2130706175 2001:db8:4321::1 30096 typ host
a=candidate:TjJ9zZpPfF5vVlLb 2 UDP 2130706430 203.0.113.1 30097 typ host
a=candidate:TjJ9zZpPfF5vVlLb 2 UDP 2130706174 2001:db8:4321::1 30097 typ host
SDP

new_call;

offer('plain offer, ICE present, ICE force', { ICE => 'force' }, <<SDP);
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
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 30108 RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:30109
a=ice-ufrag:3tTjJ9zJ
a=ice-pwd:ZpPfF5vVlLbB1rRhH7xXnNdD3t
a=candidate:TjJ9zZpPfF5vVlLb 1 UDP 2130706431 203.0.113.1 30108 typ host
a=candidate:TjJ9zZpPfF5vVlLb 1 UDP 2130706175 2001:db8:4321::1 30106 typ host
a=candidate:TjJ9zZpPfF5vVlLb 2 UDP 2130706430 203.0.113.1 30109 typ host
a=candidate:TjJ9zZpPfF5vVlLb 2 UDP 2130706174 2001:db8:4321::1 30107 typ host
SDP

answer('plain answer, ICE rejected, no ICE option given', { }, <<SDP);
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
m=audio 30130 RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:30131
a=ice-ufrag:dD3tTjJ9
a=ice-pwd:zJZpPfF5vVlLbB1rRhH7xXnNdD
a=candidate:TjJ9zZpPfF5vVlLb 1 UDP 2130706431 203.0.113.1 30130 typ host
a=candidate:TjJ9zZpPfF5vVlLb 1 UDP 2130706175 2001:db8:4321::1 30126 typ host
a=candidate:TjJ9zZpPfF5vVlLb 2 UDP 2130706430 203.0.113.1 30131 typ host
a=candidate:TjJ9zZpPfF5vVlLb 2 UDP 2130706174 2001:db8:4321::1 30127 typ host
SDP


END {
	if ($rtpe_pid) {
		kill('INT', $rtpe_pid) or die;
		waitpid($rtpe_pid, 0) or die;
	}
}

done_testing();
