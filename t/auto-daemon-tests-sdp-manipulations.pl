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
			-i foo/203.0.113.7 -i bar/203.0.113.8
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --silence-detect=1 --log-level-internals=7))
		or die;


# Arbitrary SDP media level manipulations

new_call;

offer('SDP media manipulations - remove video', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], 'sdp-media-remove' => ['video']}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
a=sendrecv
m=video 3000 RTP/AVP 97
c=IN IP4 198.51.100.1
a=rtpmap:97 H264/90000
a=fmtp:97 0-15
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
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
SDP

answer('SDP media manipulations - remove video', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:n2YhgclGcmcPp71u6pjbgu41KYAvsaTE3gRmJYJC
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
m=video 0 RTP/AVP 0
c=IN IP4 0.0.0.0
SDP

new_call;

offer('SDP media manipulations - remove "other"', { 'sdp-media-remove' => ['other']}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
m=video 3000 RTP/AVP 97
c=IN IP4 198.51.100.1
a=rtpmap:97 H264/90000
a=fmtp:97 0-15
a=sendrecv
m=foobar 4000 RTP/AVP 10
c=IN IP4 198.51.100.1
a=rtpmap:10 blah/90000
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
m=video PORT RTP/AVP 97
c=IN IP4 203.0.113.1
a=rtpmap:97 H264/90000
a=fmtp:97 0-15
a=sendrecv
a=rtcp:PORT
SDP

answer('SDP media manipulations - remove "other"', { }, <<SDP);
v=0
o=- 1115997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 4000 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
m=video 5000 RTP/AVP 97
c=IN IP4 203.0.113.1
a=rtpmap:97 H264/90000
a=fmtp:97 0-15
--------------------------------------
v=0
o=- 1115997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 97
c=IN IP4 203.0.113.1
a=rtpmap:97 H264/90000
a=fmtp:97 0-15
a=sendrecv
a=rtcp:PORT
m=foobar 0 RTP/AVP 0
c=IN IP4 0.0.0.0
SDP

new_call;

offer('SDP media manipulations - remove audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], 'sdp-media-remove' => ['audio']}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
a=sendrecv
m=video 3000 RTP/AVP 97
c=IN IP4 198.51.100.1
a=rtpmap:97 H264/90000
a=fmtp:97 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=video PORT RTP/AVP 97
c=IN IP4 203.0.113.1
a=rtpmap:97 H264/90000
a=fmtp:97 0-15
a=sendrecv
a=rtcp:PORT
SDP

answer('SDP media manipulations - remove audio', { ICE => 'remove' }, <<SDP);
v=0
o=- 1115997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=video 4000 RTP/AVP 97
a=rtpmap:97 H264/90000
a=fmtp:97 0-15
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1115997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 0 RTP/SAVP 0
c=IN IP4 0.0.0.0
m=video PORT RTP/AVP 97
c=IN IP4 203.0.113.1
a=rtpmap:97 H264/90000
a=fmtp:97 0-15
a=sendrecv
a=rtcp:PORT
SDP

# Arbitrary SDP manipulations

new_call;

offer('SDP attr manipulations - remove a= line on media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], 'sdp-attr' => { audio => { remove => ['test'] } }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=test
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
SDP

answer('SDP attr manipulations - remove a= line on media audio', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - remove a= line on global session', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], 'sdp-attr' => { none => { remove => ['test'] } }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=test
m=audio 2000 RTP/SAVP 0
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
SDP

answer('SDP attr manipulations - remove a= line on global session', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - remove a= line on global session and media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], 'sdp-attr' => { audio => { remove => ['test2'] }, none => { remove => ['test1'] } }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=test1
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=test2
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
SDP

answer('SDP attr manipulations - remove a= line on global session and media audio', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - add a= line on global session and media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], 'sdp-attr' => { audio => { add => ['test1'] }, none => { add => ['test2'] } }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=test2
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=test1
SDP

answer('SDP attr manipulations - add a= line on global session and media audio', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - add a= line for media audio, two times', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], 'sdp-attr' => { audio => { add => ['test1', 'test2'] } }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
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
a=test1
a=test2
SDP

answer('SDP attr manipulations - add a= line for media audio, two times', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - add a= line for media audio and remove one', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], 'sdp-attr' => { audio => { add => ['test1'], remove => ['test2'] } }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=test2
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
a=test1
SDP

answer('SDP attr manipulations - add a= line for media audio and remove one', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - remove two a= lines from global session level', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], 'sdp-attr' => { none => { remove => ['test1', 'test2'] } }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=test1
a=test2
m=audio 2000 RTP/SAVP 0
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
SDP

answer('SDP attr manipulations - remove two a= lines from global session level', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - substitute a= line for media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], 'sdp-attr' => { audio => { substitute => [['test1', 'test2']] } }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=test1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=test2
a=sendrecv
a=rtcp:PORT
SDP

answer('SDP attr manipulations - substitute a= line for media audio', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - substitute a= line for a session level', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], 'sdp-attr' => { none => { substitute => [['test1', 'test2']] } }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=test1
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=test2
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('SDP attr manipulations - substitute a= line for a session level', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - substitute two a= lines for media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], 'sdp-attr' => { audio => { substitute => [['test1', 'test2'] , ['test5', 'test6']] } }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=test1
a=test5
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=test2
a=test6
a=sendrecv
a=rtcp:PORT
SDP

answer('SDP attr manipulations - substitute two a= lines for media audio', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP


# Arbitrary SDP manipulations via `flags`

new_call;

offer('SDP attr manipulations - remove a= line on media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-remove-audio-test'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=test
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
SDP

answer('SDP attr manipulations - remove a= line on media audio', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - remove a= line on global session', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-remove-none-test'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=test
m=audio 2000 RTP/SAVP 0
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
SDP

answer('SDP attr manipulations - remove a= line on global session', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - remove a= line on global session and media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-remove-audio-test2', 'sdp-attr-remove-none-test1'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=test1
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=test2
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
SDP

answer('SDP attr manipulations - remove a= line on global session and media audio', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - add a= line on global session and media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-add-audio-test1', 'sdp-attr-add-none-test2'], }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=test2
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=test1
SDP

answer('SDP attr manipulations - add a= line on global session and media audio', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - add a= line for media audio, two times', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-add-audio-test1', 'sdp-attr-add-audio-test2'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
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
a=test1
a=test2
SDP

answer('SDP attr manipulations - add a= line for media audio, two times', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - add a= line for media audio and remove one', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-add-audio-test1', 'sdp-attr-remove-audio-test2'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=test2
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
a=test1
SDP

answer('SDP attr manipulations - add a= line for media audio and remove one', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - remove two a= lines from global session level', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-remove-none-test1', 'sdp-attr-remove-none-test2'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=test1
a=test2
m=audio 2000 RTP/SAVP 0
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
SDP

answer('SDP attr manipulations - remove two a= lines from global session level', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - substitute a= line for media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-substitute-audio-test1>test2'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=test1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=test2
a=sendrecv
a=rtcp:PORT
SDP

answer('SDP attr manipulations - substitute a= line for media audio', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - substitute a= line for a session level', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-substitute-none-test1>test2'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=test1
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=test2
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('SDP attr manipulations - substitute a= line for a session level', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - substitute two a= lines for media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-substitute-audio-test1>test2', 'sdp-attr-substitute-audio-test5>test6'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=test1
a=test5
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=test2
a=test6
a=sendrecv
a=rtcp:PORT
SDP

answer('SDP attr manipulations - substitute two a= lines for media audio', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
SDP

new_call;

offer('SDP attr manipulations - substitute a=fmtp line for media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-substitute-audio-fmtp:101..0-16>fmtp:101..0-15,32,36'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0 101
c=IN IP4 198.51.100.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15,32,36
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

answer('SDP attr manipulations - substitute a=fmtp line for media audio', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
a=ptime:20
SDP

new_call;

offer('SDP attr manipulations - substitute a=fmtp line for media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-substitute-audio-fmtp:101>fmtp:101..0-15,32,36'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0 101
c=IN IP4 198.51.100.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15,32,36
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

new_call;

offer('SDP attr manipulations - remove a=fmtp line for media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-remove-audio-fmtp:101..0-16'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0 101
c=IN IP4 198.51.100.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

answer('SDP attr manipulations - remove a=fmtp line for media audio', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
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
a=ptime:20
SDP

new_call;

offer('SDP attr manipulations - remove a=fmtp line for media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-remove-audio-fmtp:101'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0 101
c=IN IP4 198.51.100.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

new_call;

offer('SDP attr manipulations - remove a=fmtp line for media audio', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-remove-audio-fmtp', 'sdp-attr-remove-audio-rtpmap'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0 101
c=IN IP4 198.51.100.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0 101
c=IN IP4 203.0.113.1
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

new_call;

offer('SDP attr manipulations - remove sendrecv, rtcp, ptime', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-remove-audio-sendrecv', 'sdp-attr-remove-audio-rtcp', 'sdp-attr-remove-audio-ptime'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0 101
c=IN IP4 198.51.100.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
SDP

new_call;

offer('SDP attr manipulations - remove global attrs', { ICE => 'remove', DTLS => 'off', SDES => [ 'nonew' ], flags => ['sdp-attr-remove-global-something', 'sdp-attr-remove-global-rather', 'sdp-attr-remove-global-or'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=something
a=rather:else
a=or:some such
a=untouched
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=untouched
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
