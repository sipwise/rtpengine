#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use NGCP::Rtpclient::ICE;
use POSIX;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --silence-detect=1))
		or die;



my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $port_c, $ssrc_a, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq,
	$ftr, $ttr, $ttr2);





($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6060)], [qw(198.51.100.14 6062)], [qw(198.51.100.14 6064)]);

($port_a) = offer('sub, multi codec, sub w diff codec',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6060 RTP/AVP 0 8
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('sub, multi codec, sub w diff codec',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6062 RTP/AVP 0 8
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, $port_c) = subscribe_request('sub, multi codec, sub w diff codec',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('sub, multi codec, sub w diff codec',
	{ 'from-tag' => ft(), 'to-tag' => $ttr, flags => ['allow transcoding'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6064 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(8, 4001, 7160, $ssrc_b, "\x2a" x 160));





($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6036)], [qw(198.51.100.14 6038)], [qw(198.51.100.14 6040)]);

($port_a) = offer('sub w tc - acc',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6036 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('sub w tc - acc',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6038 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, $port_c) = subscribe_request('sub w tc - acc',
	{ 'from-tag' => ft(), codec => { transcode => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('sub w tc - acc',
	{ 'from-tag' => ft(), 'to-tag' => $ttr, flags => ['allow transcoding'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6040 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(8, 4001, 7160, $ssrc_b, "\x2a" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6030)], [qw(198.51.100.14 6032)], [qw(198.51.100.14 6034)]);

($port_a) = offer('sub w tc - rej',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6030 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('sub w tc - rej',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6032 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, $port_c) = subscribe_request('sub w tc - rej',
	{ 'from-tag' => ft(), codec => { transcode => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('sub w tc - rej',
	{ 'from-tag' => ft(), 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6034 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6000)], [qw(198.51.100.14 6002)], [qw(198.51.100.14 6004)]);

($port_a) = offer('simple sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6000 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('simple sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6002 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, $port_c) = subscribe_request('simple sub',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('simple sub',
	{ 'from-tag' => ft(), 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6004 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6066)], [qw(198.51.100.14 6068)], [qw(198.51.100.14 6070)]);

($port_a) = offer('simple sub w label',
	{ label => 'foo' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6066 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('simple sub w label',
	{ label => 'bar' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6068 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, $port_c) = subscribe_request('simple sub w label',
	{ label => 'foo' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('simple sub w label',
	{ label => 'foo', 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6070 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6072)], [qw(198.51.100.14 6074)], [qw(198.51.100.14 6076)]);

($port_a) = offer('simple sub w to-tag label',
	{ label => 'foo' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6072 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('simple sub w to-tag label',
	{ label => 'bar' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6074 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, $port_c) = subscribe_request('simple sub w to-tag label',
	{ label => 'foo' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('simple sub w to-tag label',
	{ label => 'bar', 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6076 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6006)], [qw(198.51.100.14 6008)], [qw(198.51.100.14 6010)]);

($port_a) = offer('SRTP sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6006 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('SRTP sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6008 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, $port_c, undef, $srtp_key_a) = subscribe_request('SRTP sub',
	{ 'from-tag' => ft(), 'transport-protocol' => 'RTP/SAVP',
	SDES => ['no-AEAD_AES_256_GCM', 'no-AEAD_AES_128_GCM'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:2 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:3 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:4 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:5 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:6 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:7 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('SRTP sub',
	{ 'from-tag' => ft(), 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6010 RTP/SAVP 0
c=IN IP4 198.51.100.14
a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=recvonly
SDP


$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_256_CM_HMAC_SHA1_80},
	key => $srtp_key_a,
};

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
srtp_rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160), $srtp_ctx_a);




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6012)], [qw(198.51.100.14 6014)], [qw(198.51.100.14 6016)]);

($port_a) = offer('SRTP sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6012 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('SRTP sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6014 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, $port_c, undef, undef, undef, undef, undef, $srtp_key_a) = subscribe_request('SRTP sub',
	{ 'from-tag' => ft(), 'transport-protocol' => 'RTP/SAVP',
	SDES => ['no-AEAD_AES_256_GCM', 'no-AEAD_AES_128_GCM'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:2 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:3 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:4 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:5 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:6 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:7 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('SRTP sub',
	{ 'from-tag' => ft(), 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6016 RTP/SAVP 0
c=IN IP4 198.51.100.14
a=crypto:5 AES_CM_128_HMAC_SHA1_80 inline:DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF
a=recvonly
SDP


$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_a,
};

snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
srtp_rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160), $srtp_ctx_a);




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6018)], [qw(198.51.100.14 6020)], [qw(198.51.100.14 6022)]);

($port_a) = offer('SRTP call RTP sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6018 RTP/SAVP 0
c=IN IP4 198.51.100.14
a=crypto:123 AES_CM_128_HMAC_SHA1_80 inline:DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF
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
a=crypto:123 AES_CM_128_HMAC_SHA1_80 inline:DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF
a=crypto:124 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:125 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:126 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:127 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:128 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:129 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:130 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:131 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:132 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:133 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:134 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
SDP

($port_b) = answer('SRTP call RTP sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6020 RTP/SAVP 0
c=IN IP4 198.51.100.14
a=crypto:123 AES_CM_128_HMAC_SHA1_80 inline:eMlRvW8mWU4WodT9JOvAM+pn6I0/EXOhT9n0KeKk
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
a=crypto:123 AES_CM_128_HMAC_SHA1_80 inline:eMlRvW8mWU4WodT9JOvAM+pn6I0/EXOhT9n0KeKk
SDP


$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'eMlRvW8mWU4WodT9JOvAM+pn6I0/EXOhT9n0KeKk',
};


srtp_snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_b);
($ssrc_a) = srtp_rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160), $srtp_ctx_a);
($ssrc_b) = srtp_rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160), $srtp_ctx_a);

($ftr, $ttr, $port_c) = subscribe_request('SRTP call RTP sub',
	{ 'from-tag' => ft(), 'transport-protocol' => 'RTP/AVP', }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('SRTP call RTP sub',
	{ 'from-tag' => ft(), 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6022 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP


srtp_snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160), $srtp_ctx_a);
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6024)], [qw(198.51.100.14 6026)], [qw(198.51.100.14 6028)]);

($port_a) = offer('ICE sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6024 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('ICE sub',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6026 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc_a) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4000, 7000, 0x6543, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(0, 4000, 7000, -1, "\x00" x 160));

($ftr, $ttr, $port_c) = subscribe_request('ICE sub',
	{ 'from-tag' => ft(), ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('ICE sub',
	{ 'from-tag' => ft(), 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6028 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
a=ice-ufrag:q2758e93
a=ice-pwd:bd5e845657ecb8d6dd8e1bc6
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.14 6028 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.14 6029 typ host
SDP

@ret1 = rcv($sock_c, -1, qr/^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine.*?\x00\x06\x00\x11q2758e93:(........)\x00\x00\x00\x80\x29\x00\x08........\x00\x24\x00\x04\x6e\xff\xff\xff\x00\x08\x00\x14....................\x80\x28\x00\x04....$/s);
snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc_a, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 4001, 7160, 0x6543, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 4001, 7160, $ssrc_b, "\x00" x 160));




($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6042)], [qw(198.51.100.14 6044)], [qw(198.51.100.14 6046)]);

($port_a) = publish('publish/subscribe',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6042 RTP/AVP 0 8 9
c=IN IP4 198.51.100.14
a=sendonly
----------------------------------
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=recvonly
a=rtcp:PORT
SDP

snd($sock_a, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));

($ftr, $ttr, $port_b) = subscribe_request('publish/subscribe',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('publish/subscribe',
	{ 'from-tag' => ft(), 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6044 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_b, $port_b, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160));

($ftr, $ttr, $port_b) = subscribe_request('publish/subscribe',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('publish/subscribe',
	{ 'from-tag' => ft(), 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6046 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_a, rtp(0, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_b, $port_b, rtpm(0, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 2002, 4320, 0x3456, "\x00" x 160));






($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6048)], [qw(198.51.100.14 6050)], [qw(198.51.100.14 6052)]);

($port_a) = publish('publish/subscribe w codec-accept',
	{ codec => { accept => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6048 RTP/AVP 0 8 9
c=IN IP4 198.51.100.14
a=sendonly
----------------------------------
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=recvonly
a=rtcp:PORT
SDP

snd($sock_a, $port_a, rtp(8, 2000, 4000, 0x3456, "\x00" x 160));

($ftr, $ttr, $port_b) = subscribe_request('publish/subscribe w codec-accept',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('publish/subscribe w codec-accept',
	{ 'from-tag' => ft(), 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6050 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_a, rtp(8, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_b, $port_b, rtpm(8, 2001, 4160, 0x3456, "\x00" x 160));

($ftr, $ttr, $port_b) = subscribe_request('publish/subscribe w codec-accept',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('publish/subscribe w codec-accept',
	{ 'from-tag' => ft(), 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6052 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_a, rtp(8, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_b, $port_b, rtpm(8, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(8, 2002, 4320, 0x3456, "\x00" x 160));





($sock_a, $sock_b, $sock_c) =
	new_call([qw(198.51.100.14 6054)], [qw(198.51.100.14 6056)], [qw(198.51.100.14 6058)]);

($port_a) = publish('publish/subscribe w unsupp and t/c',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6054 RTP/AVP 96 8 9
c=IN IP4 198.51.100.14
a=sendonly
a=rtpmap:96 foobar/8000
----------------------------------
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=recvonly
a=rtcp:PORT
SDP

snd($sock_a, $port_a, rtp(8, 2000, 4000, 0x3456, "\x00" x 160));

($ftr, $ttr, $port_b) = subscribe_request('publish/subscribe w unsupp and t/c',
	{ 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('publish/subscribe w unsupp and t/c',
	{ 'from-tag' => ft(), 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6056 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_a, rtp(8, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_b, $port_b, rtpm(8, 2001, 4160, 0x3456, "\x00" x 160));

($ftr, $ttr, $port_b) = subscribe_request('publish/subscribe w unsupp and t/c',
	{ 'from-tag' => ft(), codec => { strip => ['PCMA'], transcode => ['PCMU'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is $ftr, ft(), 'from-tag matches';

subscribe_answer('publish/subscribe w unsupp and t/c',
	{ 'from-tag' => ft(), 'to-tag' => $ttr, flags => ['allow transcoding'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6058 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

snd($sock_a, $port_a, rtp(8, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_b, $port_b, rtpm(8, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_c, $port_c, rtpm(0, 2002, 4320, 0x3456, "\x29" x 160));



done_testing();
