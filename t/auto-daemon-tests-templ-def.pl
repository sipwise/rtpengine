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


autotest_start(qw(--config-file=test2.conf)) or die;




my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $ssrc, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $has_recv);



new_call;

offer('template', { }, <<SDP);
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




#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
