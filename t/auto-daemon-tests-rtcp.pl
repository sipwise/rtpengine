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
use Data::Dumper;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			--measure-rtp --mos=LQ -n 2223  -f -L 7 -E --log-level-internals=7))
		or die;


my ($sock_a, $sock_b, $sock_ax, $sock_bx,
	$port_a, $port_ax, $port_b, $port_bx,
	$resp,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_c, $srtp_ctx_d,
	$key_a, $key_b);


($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7124)],
	[qw(198.51.100.1 7125)],
	[qw(198.51.100.3 7126)],
	[qw(198.51.100.3 7127)],
);

($port_a, $port_ax) = offer('RTCP generation', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7124 RTP/AVP 0
c=IN IP4 198.51.100.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
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

($port_b, $port_bx) = answer('RTCP generation', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7126 RTP/AVP 0
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

snd($sock_a, $port_b, rtp(0,  1000, 3000+160*0, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0,  1001, 3000+160*1, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3000+160*1, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0,  1002, 3000+160*2, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3000+160*2, 0x1234, "\x00" x 160));

snd($sock_b, $port_a, rtp(0,  4000, 8000+160*0, 0x6789, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4000, 8000+160*0, 0x6789, "\x00" x 160));
snd($sock_b, $port_a, rtp(0,  4001, 8000+160*1, 0x6789, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 8000+160*1, 0x6789, "\x00" x 160));
snd($sock_b, $port_a, rtp(0,  4002, 8000+160*2, 0x6789, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 8000+160*2, 0x6789, "\x00" x 160));

# wait for RTCP. Jitter is measured from the back-to-back packets above, which
# carry 20 ms of timestamp spacing each.
sleep(6);

rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x04\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s);
rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x04\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s);

# wait for RTCP again
sleep(6);

rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x04\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s);
rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x04\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s);

$resp = rtpe_req('delete', 'delete');
is($resp->{SSRC}{4660}{packets}, 3, 'packet count');
is($resp->{SSRC}{4660}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{4660}{'average MOS'}{'packet loss'}, 0, 'packet loss');
is($resp->{SSRC}{26505}{packets}, 3, 'packet count');
is($resp->{SSRC}{26505}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{26505}{'average MOS'}{'packet loss'}, 0, 'packet loss');



($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7136)],
	[qw(198.51.100.1 7137)],
	[qw(198.51.100.3 7138)],
	[qw(198.51.100.3 7139)],
);

($port_a, $port_ax) = offer('SRTCP generation', { flags => ['generate RTCP'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7136 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
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
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx) = answer('SRTCP generation', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7138 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:aaaa7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
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
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:aaaa7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'aaaa7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};

srtp_snd($sock_a, $port_b, rtp(0,  1000, 3000+160*0, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_a, $port_b, rtp(0,  1001, 3000+160*1, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1001, 3000+160*1, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_a, $port_b, rtp(0,  1002, 3000+160*2, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1002, 3000+160*2, 0x1234, "\x00" x 160), $srtp_ctx_b);

srtp_snd($sock_b, $port_a, rtp(0,  4000, 8000+160*0, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_a, $port_b, rtpm(0, 4000, 8000+160*0, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_b, $port_a, rtp(0,  4001, 8000+160*1, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_a, $port_b, rtpm(0, 4001, 8000+160*1, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_b, $port_a, rtp(0,  4002, 8000+160*2, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_a, $port_b, rtpm(0, 4002, 8000+160*2, 0x6789, "\x00" x 160), $srtp_ctx_a);

# wait for RTCP. Jitter is measured from the back-to-back packets above, which
# carry 20 ms of timestamp spacing each.
sleep(6);

srtcp_rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s, $srtp_ctx_a);
srtcp_rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s, $srtp_ctx_b);

# wait for RTCP again
sleep(6);

srtcp_rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s, $srtp_ctx_a);
srtcp_rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s, $srtp_ctx_b);

$resp = rtpe_req('delete', 'delete');
is($resp->{SSRC}{4660}{packets}, 3, 'packet count');
is($resp->{SSRC}{4660}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{4660}{'average MOS'}{'packet loss'}, 0, 'packet loss');
is($resp->{SSRC}{26505}{packets}, 3, 'packet count');
is($resp->{SSRC}{26505}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{26505}{'average MOS'}{'packet loss'}, 0, 'packet loss');



($sock_a, $sock_b) = new_call(
	[qw(198.51.100.1 7148)],
	[qw(198.51.100.3 7150)],
);

($port_a, $port_ax) = offer('SRTCP generation with mux', { flags => ['generate RTCP'], DTLS => 'off', 'rtcp-mux' => 'require' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7148 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=rtcp-mux
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
a=rtcp-mux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

is($port_a, $port_ax, 'muxing');

($port_b, $port_bx) = answer('SRTCP generation with mux', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7150 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:aaaa7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=rtcp-mux
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
a=rtcp-mux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:aaaa7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
SDP

is($port_b, $port_bx, 'muxing');

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'aaaa7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};

srtp_snd($sock_a, $port_b, rtp(0,  1000, 3000+160*0, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_a, $port_b, rtp(0,  1001, 3000+160*1, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1001, 3000+160*1, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_a, $port_b, rtp(0,  1002, 3000+160*2, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1002, 3000+160*2, 0x1234, "\x00" x 160), $srtp_ctx_b);

srtp_snd($sock_b, $port_a, rtp(0,  4000, 8000+160*0, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_a, $port_b, rtpm(0, 4000, 8000+160*0, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_b, $port_a, rtp(0,  4001, 8000+160*1, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_a, $port_b, rtpm(0, 4001, 8000+160*1, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_b, $port_a, rtp(0,  4002, 8000+160*2, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_a, $port_b, rtpm(0, 4002, 8000+160*2, 0x6789, "\x00" x 160), $srtp_ctx_a);

# wait for RTCP. Jitter is measured from the back-to-back packets above, which
# carry 20 ms of timestamp spacing each.
sleep(6);

srtcp_rcv($sock_a, $port_b, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s, $srtp_ctx_a);
srtcp_rcv($sock_b, $port_a, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s, $srtp_ctx_b);

# wait for RTCP again
sleep(6);

srtcp_rcv($sock_a, $port_b, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s, $srtp_ctx_a);
srtcp_rcv($sock_b, $port_a, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s, $srtp_ctx_b);

$resp = rtpe_req('delete', 'delete');
is($resp->{SSRC}{4660}{packets}, 3, 'packet count');
is($resp->{SSRC}{4660}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{4660}{'average MOS'}{'packet loss'}, 0, 'packet loss');
is($resp->{SSRC}{26505}{packets}, 3, 'packet count');
is($resp->{SSRC}{26505}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{26505}{'average MOS'}{'packet loss'}, 0, 'packet loss');



($sock_a, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7160)],
	[qw(198.51.100.3 7162)],
	[qw(198.51.100.3 7163)],
);

($port_a, $port_ax) = offer('SRTCP generation with mux/demux', { flags => ['generate RTCP'], DTLS => 'off', 'rtcp-mux' => 'demux' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7160 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=rtcp-mux
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
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

isnt($port_a, $port_ax, 'demuxing');

($port_b, $port_bx) = answer('SRTCP generation with mux/demux', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7162 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:aaaa7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
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
a=rtcp-mux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:aaaa7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
SDP

is($port_b, $port_bx, 'muxing');

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'aaaa7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};

srtp_snd($sock_a, $port_b, rtp(0,  1000, 3000+160*0, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_a, $port_b, rtp(0,  1001, 3000+160*1, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1001, 3000+160*1, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_a, $port_b, rtp(0,  1002, 3000+160*2, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1002, 3000+160*2, 0x1234, "\x00" x 160), $srtp_ctx_b);

srtp_snd($sock_b, $port_a, rtp(0,  4000, 8000+160*0, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_a, $port_b, rtpm(0, 4000, 8000+160*0, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_b, $port_a, rtp(0,  4001, 8000+160*1, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_a, $port_b, rtpm(0, 4001, 8000+160*1, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_b, $port_a, rtp(0,  4002, 8000+160*2, 0x6789, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_a, $port_b, rtpm(0, 4002, 8000+160*2, 0x6789, "\x00" x 160), $srtp_ctx_a);

# wait for RTCP. Jitter is measured from the back-to-back packets above, which
# carry 20 ms of timestamp spacing each.
sleep(6);

srtcp_rcv($sock_a, $port_b, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s, $srtp_ctx_a);
srtcp_rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s, $srtp_ctx_b);

# wait for RTCP again
sleep(6);

srtcp_rcv($sock_a, $port_b, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s, $srtp_ctx_a);
srtcp_rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s, $srtp_ctx_b);

$resp = rtpe_req('delete', 'delete');
is($resp->{SSRC}{4660}{packets}, 3, 'packet count');
is($resp->{SSRC}{4660}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{4660}{'average MOS'}{'packet loss'}, 0, 'packet loss');
is($resp->{SSRC}{26505}{packets}, 3, 'packet count');
is($resp->{SSRC}{26505}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{26505}{'average MOS'}{'packet loss'}, 0, 'packet loss');




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7228)],
	[qw(198.51.100.1 7229)],
	[qw(198.51.100.3 7230)],
	[qw(198.51.100.3 7231)],
);

($port_a, $port_ax, undef, undef, $key_a) = offer('SRTCP<>SRTCP generation', { flags => ['generate RTCP'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7228 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
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
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, $port_bx, $key_b) = answer('SRTCP<>SRTCP generation', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7230 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:lj20Z7pgjRJNvZZVLAZDE5HQUA04CQKzRmLgCiRPG35fouAMtDfTPzUZq7w6Tg
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

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_256_CM_HMAC_SHA1_80},
	key => $key_a,
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_c = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_256_CM_HMAC_SHA1_80},
	key => 'lj20Z7pgjRJNvZZVLAZDE5HQUA04CQKzRmLgCiRPG35fouAMtDfTPzUZq7w6Tg',
};
$srtp_ctx_d = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $key_b,
};

srtp_snd($sock_a, $port_b, rtp(0,  1000, 3000+160*0, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_a, $port_b, rtp(0,  1001, 3000+160*1, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1001, 3000+160*1, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_a, $port_b, rtp(0,  1002, 3000+160*2, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1002, 3000+160*2, 0x1234, "\x00" x 160), $srtp_ctx_a);

srtp_snd($sock_b, $port_a, rtp(0,  4000, 8000+160*0, 0x6789, "\x00" x 160), $srtp_ctx_c);
srtp_rcv($sock_a, $port_b, rtpm(0, 4000, 8000+160*0, 0x6789, "\x00" x 160), $srtp_ctx_d);
srtp_snd($sock_b, $port_a, rtp(0,  4001, 8000+160*1, 0x6789, "\x00" x 160), $srtp_ctx_c);
srtp_rcv($sock_a, $port_b, rtpm(0, 4001, 8000+160*1, 0x6789, "\x00" x 160), $srtp_ctx_d);
srtp_snd($sock_b, $port_a, rtp(0,  4002, 8000+160*2, 0x6789, "\x00" x 160), $srtp_ctx_c);
srtp_rcv($sock_a, $port_b, rtpm(0, 4002, 8000+160*2, 0x6789, "\x00" x 160), $srtp_ctx_d);

# wait for RTCP. Jitter is measured from the back-to-back packets above, which
# carry 20 ms of timestamp spacing each.
sleep(6);

srtcp_rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s, $srtp_ctx_d);
srtcp_rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s, $srtp_ctx_a);

# wait for RTCP again
sleep(6);

srtcp_rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s, $srtp_ctx_d);
srtcp_rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s, $srtp_ctx_a);

$resp = rtpe_req('delete', 'delete');
is($resp->{SSRC}{4660}{packets}, 3, 'packet count');
is($resp->{SSRC}{4660}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{4660}{'average MOS'}{'packet loss'}, 0, 'packet loss');
is($resp->{SSRC}{26505}{packets}, 3, 'packet count');
is($resp->{SSRC}{26505}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{26505}{'average MOS'}{'packet loss'}, 0, 'packet loss');



($sock_a, $sock_b) = new_call(
	[qw(198.51.100.1 7240)],
	[qw(198.51.100.3 7242)],
);

($port_a, $port_ax, undef, undef, $key_a) = offer('SRTCP<>SRTCP generation with mux', { flags => ['generate RTCP'], DTLS => 'off', 'rtcp-mux' => 'require' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7240 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=rtcp-mux
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
a=rtcp-mux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

is($port_a, $port_ax, 'muxing');

($port_b, $port_bx, $key_b) = answer('SRTCP<>SRTCP generation with mux', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7242 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:lj20Z7pgjRJNvZZVLAZDE5HQUA04CQKzRmLgCiRPG35fouAMtDfTPzUZq7w6Tg
a=rtcp-mux
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
a=rtcp-mux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

is($port_b, $port_bx, 'muxing');

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_256_CM_HMAC_SHA1_80},
	key => $key_a,
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_c = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_256_CM_HMAC_SHA1_80},
	key => 'lj20Z7pgjRJNvZZVLAZDE5HQUA04CQKzRmLgCiRPG35fouAMtDfTPzUZq7w6Tg',
};
$srtp_ctx_d = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $key_b,
};

srtp_snd($sock_a, $port_b, rtp(0,  1000, 3000+160*0, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_a, $port_b, rtp(0,  1001, 3000+160*1, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1001, 3000+160*1, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_a, $port_b, rtp(0,  1002, 3000+160*2, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1002, 3000+160*2, 0x1234, "\x00" x 160), $srtp_ctx_a);

srtp_snd($sock_b, $port_a, rtp(0,  4000, 8000+160*0, 0x6789, "\x00" x 160), $srtp_ctx_c);
srtp_rcv($sock_a, $port_b, rtpm(0, 4000, 8000+160*0, 0x6789, "\x00" x 160), $srtp_ctx_d);
srtp_snd($sock_b, $port_a, rtp(0,  4001, 8000+160*1, 0x6789, "\x00" x 160), $srtp_ctx_c);
srtp_rcv($sock_a, $port_b, rtpm(0, 4001, 8000+160*1, 0x6789, "\x00" x 160), $srtp_ctx_d);
srtp_snd($sock_b, $port_a, rtp(0,  4002, 8000+160*2, 0x6789, "\x00" x 160), $srtp_ctx_c);
srtp_rcv($sock_a, $port_b, rtpm(0, 4002, 8000+160*2, 0x6789, "\x00" x 160), $srtp_ctx_d);

# wait for RTCP. Jitter is measured from the back-to-back packets above, which
# carry 20 ms of timestamp spacing each.
sleep(6);

srtcp_rcv($sock_a, $port_b, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s, $srtp_ctx_d);
srtcp_rcv($sock_b, $port_a, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s, $srtp_ctx_a);

# wait for RTCP again
sleep(6);

srtcp_rcv($sock_a, $port_b, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s, $srtp_ctx_d);
srtcp_rcv($sock_b, $port_a, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s, $srtp_ctx_a);

$resp = rtpe_req('delete', 'delete');
is($resp->{SSRC}{4660}{packets}, 3, 'packet count');
is($resp->{SSRC}{4660}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{4660}{'average MOS'}{'packet loss'}, 0, 'packet loss');
is($resp->{SSRC}{26505}{packets}, 3, 'packet count');
is($resp->{SSRC}{26505}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{26505}{'average MOS'}{'packet loss'}, 0, 'packet loss');



($sock_a, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7252)],
	[qw(198.51.100.3 7254)],
	[qw(198.51.100.3 7255)],
);

($port_a, $port_ax, undef, undef, $key_a) = offer('SRTCP<>SRTCP generation with mux/demux', { flags => ['generate RTCP'], DTLS => 'off', 'rtcp-mux' => 'demux' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7252 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=rtcp-mux
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
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

isnt($port_a, $port_ax, 'demuxing');

($port_b, $port_bx, $key_b) = answer('SRTCP<>SRTCP generation with mux/demux', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7254 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:lj20Z7pgjRJNvZZVLAZDE5HQUA04CQKzRmLgCiRPG35fouAMtDfTPzUZq7w6Tg
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
a=rtcp-mux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

is($port_b, $port_bx, 'muxing');

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_256_CM_HMAC_SHA1_80},
	key => $key_a,
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv',
};
$srtp_ctx_c = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_256_CM_HMAC_SHA1_80},
	key => 'lj20Z7pgjRJNvZZVLAZDE5HQUA04CQKzRmLgCiRPG35fouAMtDfTPzUZq7w6Tg',
};
$srtp_ctx_d = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $key_b,
};

srtp_snd($sock_a, $port_b, rtp(0,  1000, 3000+160*0, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000+160*0, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_a, $port_b, rtp(0,  1001, 3000+160*1, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1001, 3000+160*1, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_a, $port_b, rtp(0,  1002, 3000+160*2, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1002, 3000+160*2, 0x1234, "\x00" x 160), $srtp_ctx_a);

srtp_snd($sock_b, $port_a, rtp(0,  4000, 8000+160*0, 0x6789, "\x00" x 160), $srtp_ctx_c);
srtp_rcv($sock_a, $port_b, rtpm(0, 4000, 8000+160*0, 0x6789, "\x00" x 160), $srtp_ctx_d);
srtp_snd($sock_b, $port_a, rtp(0,  4001, 8000+160*1, 0x6789, "\x00" x 160), $srtp_ctx_c);
srtp_rcv($sock_a, $port_b, rtpm(0, 4001, 8000+160*1, 0x6789, "\x00" x 160), $srtp_ctx_d);
srtp_snd($sock_b, $port_a, rtp(0,  4002, 8000+160*2, 0x6789, "\x00" x 160), $srtp_ctx_c);
srtp_rcv($sock_a, $port_b, rtpm(0, 4002, 8000+160*2, 0x6789, "\x00" x 160), $srtp_ctx_d);

# wait for RTCP. Jitter is measured from the back-to-back packets above, which
# carry 20 ms of timestamp spacing each.
sleep(6);

srtcp_rcv($sock_a, $port_b, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s, $srtp_ctx_d);
srtcp_rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s, $srtp_ctx_a);

# wait for RTCP again
sleep(6);

srtcp_rcv($sock_a, $port_b, qr/^\x81\xc8\x00\x0c\x00\x00\x67\x89.{8}\x00\x00\x20\x80\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xea\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x67\x89\x01/s, $srtp_ctx_d);
srtcp_rcv($sock_bx, $port_ax, qr/^\x81\xc8\x00\x0c\x00\x00\x12\x34.{8}\x00\x00\x0c\xf8\x00\x00\x00\x03\x00\x00\x02\x22\x00\x00\x67\x89\x00\x00\x00\x00\x00\x00\x0f\xa2\x00\x00\x00[\x01-\x7f].{4}.{4}\x81\xca\x00\x05\x00\x00\x12\x34\x01/s, $srtp_ctx_a);

$resp = rtpe_req('delete', 'delete');
is($resp->{SSRC}{4660}{packets}, 3, 'packet count');
is($resp->{SSRC}{4660}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{4660}{'average MOS'}{'packet loss'}, 0, 'packet loss');
is($resp->{SSRC}{26505}{packets}, 3, 'packet count');
is($resp->{SSRC}{26505}{'average MOS'}{MOS}, 43, 'MOS');
is($resp->{SSRC}{26505}{'average MOS'}{'packet loss'}, 0, 'packet loss');

#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
