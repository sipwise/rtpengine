#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;


autotest_init() or die;


my ($sock_a, $sock_b, $port_a, $port_b, $ssrc, $resp, $srtp_ctx_a, $srtp_ctx_b, $crypto);




# SDES in

($sock_a, $sock_b) = new_call([qw(192.168.1.149 20010)], [qw(192.168.1.149 20012)]);

($port_a) = offer('SDES in', { ICE => 'remove',
		replace => ['origin'],
		'transport-protocol' => 'RTP/AVP',
	}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 192.168.1.149
s=tester
t=0 0
m=audio 20010 RTP/SAVP 0 8
c=IN IP4 192.168.1.149
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:zC6Ea9EK/7YmDM79CK+TAnNXTI1pVmZuCMjUPMph
----------------------------------
v=0
o=- 1545997027 1 IN IP4 192.168.1.149
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 192.168.1.149
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, undef, $crypto) = answer('SDES in', { ICE => 'remove',
		replace => ['origin'],
		DTLS => 'off',
	}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 192.168.1.149
s=tester
t=0 0
m=audio 20012 RTP/AVP 0 8
c=IN IP4 192.168.1.149
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 192.168.1.149
s=tester
t=0 0
m=audio PORT RTP/SAVP 0 8
c=IN IP4 192.168.1.149
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP


$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'zC6Ea9EK/7YmDM79CK+TAnNXTI1pVmZuCMjUPMph',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $crypto,
};


snd($sock_b, $port_a, rtp(0, 1000, 3000, 0x1234, "\x00" x 160), '192.168.1.149');
srtp_rcv($sock_a, $port_b, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_a, $port_b, rtp(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_a, '192.168.1.149');
rcv($sock_b, $port_a, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));

print("wait for restart...\n");
sleep(10);

snd($sock_b, $port_a, rtp(0, 1000, 3000, 0x1234, "\x00" x 160), '192.168.1.149');
srtp_rcv($sock_a, $port_b, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_a, $port_b, rtp(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_a, '192.168.1.149');
rcv($sock_b, $port_a, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));


done_testing();
