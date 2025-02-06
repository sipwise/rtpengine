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


autotest_start(qw(--config-file=test1.conf)) or die;




my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $ssrc, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $has_recv);



new_call;

offer('basic call', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 0 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


new_call;

offer('interface', { 'out-interface' => 'foobar' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 0 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


new_call;

offer('template', { template => 'WebRTC' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 0 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT UDP/TLS/RTP/SAVPF 0 8
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=ice-options:trickle
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 203.0.113.2 PORT typ host
a=candidate:ICEBASE 1 UDP 2130705919 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130705663 2001:db8:4321::2 PORT typ host
a=end-of-candidates
SDP



new_call;

# A: 4 port pairs, 2 unique
# B: 4 port pairs, 2 unique

my @ports_a1 = publish('overlap intf A1', { interface => 'overlap-A' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 0 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.6
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.6
a=rtpmap:0 PCMU/8000
a=recvonly
a=rtcp:PORT
SDP

is($ports_a1[0], $ports_a1[1] - 1, 'RTP/RTCP');
cmp_ok($ports_a1[0], '>=', 3000, 'range OK');
cmp_ok($ports_a1[1], '<=', 3007, 'range OK');

# A: 3 port pairs, 1 or 2 unique
# B: 3 or 4 port pairs, 2 unique

new_call;

my @ports_a2 = publish('overlap intf A2', { interface => 'overlap-A' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 0 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.6
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.6
a=rtpmap:0 PCMU/8000
a=recvonly
a=rtcp:PORT
SDP

is($ports_a2[0], $ports_a2[1] - 1, 'RTP/RTCP');
cmp_ok($ports_a2[0], '>=', 3000, 'range OK');
cmp_ok($ports_a2[1], '<=', 3007, 'range OK');
isnt($ports_a2[0], $ports_a1[0], 'unique port');

# A: 2 port pairs, 0-2 unique
# B: 2-4 port pairs, 2 unique

new_call;

my @ports_b1 = publish('overlap intf B1', { interface => 'overlap-B' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 0 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.6
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.6
a=rtpmap:0 PCMU/8000
a=recvonly
a=rtcp:PORT
SDP

is($ports_b1[0], $ports_b1[1] - 1, 'RTP/RTCP');
cmp_ok($ports_b1[0], '>=', 3004, 'range OK');
cmp_ok($ports_b1[1], '<=', 3011, 'range OK');
isnt($ports_b1[0], $ports_a1[0], 'unique port');
isnt($ports_b1[0], $ports_a2[0], 'unique port');

# A: 2 port pairs, 0-2 unique
# B: 1-3 port pairs, 1 or 2 unique

new_call;

my @ports_b2 = publish('overlap intf B2', { interface => 'overlap-B' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 0 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.6
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.6
a=rtpmap:0 PCMU/8000
a=recvonly
a=rtcp:PORT
SDP

is($ports_b2[0], $ports_b2[1] - 1, 'RTP/RTCP');
cmp_ok($ports_b2[0], '>=', 3004, 'range OK');
cmp_ok($ports_b2[1], '<=', 3011, 'range OK');
isnt($ports_b2[0], $ports_a1[0], 'unique port');
isnt($ports_b2[0], $ports_a2[0], 'unique port');
isnt($ports_b2[0], $ports_b1[0], 'unique port');


#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
