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

new_call;

offer('rtpp-flags: basic A to B call', { 
    'rtpp-flags' => 'replace-origin address-family=IP4 transport-protocol=RTP/AVP',
    'from-tag' => ft(),
    }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0 8 101
a=rtpmap:0 PCMU/8000
a=fmtp:0 this-is-unknown=no
a=rtpmap:8 PCMA/8000
a=fmtp:8 this-is-unknown=no
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=fmtp:0 this-is-unknown=no
a=rtpmap:8 PCMA/8000
a=fmtp:8 this-is-unknown=no
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

#  g711 SDP answer fmtp will ingore

answer('rtpp-flags: basic A to B call', { 
    'rtpp-flags' => 'replace-origin address-family=IP4 transport-protocol=RTP/AVP',
     'from-tag' => ft(),
     'to-tag' => tt(),
    }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('rtpp-flags: basic A to B call', { 
    'rtpp-flags' => 'replace-origin address-family=IP4 transport-protocol=RTP/AVP',
    'from-tag' => ft(),
    }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 3 101
a=rtpmap:3 GSM/8000
a=fmtp:3 this-is-unknown=no
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 3 101
c=IN IP4 203.0.113.1
a=rtpmap:3 GSM/8000
a=fmtp:3 this-is-unknown=no
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

# answer without a=fmtp:3 this-is-unknown=no, GSM will be removed, no audio codec now
answer('rtpp-flags: basic A to B call', { 
    'rtpp-flags' => 'replace-origin address-family=IP4 transport-protocol=RTP/AVP',
     'from-tag' => ft(),
     'to-tag' => tt(),
    }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 3 101
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 101
c=IN IP4 203.0.113.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('rtpp-flags: basic A to B call', { 
    'rtpp-flags' => 'replace-origin address-family=IP4 transport-protocol=RTP/AVP',
    'from-tag' => ft(),
    }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 3 101
a=rtpmap:3 GSM/8000
a=fmtp:3 this-is-unknown=no
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 3 101
c=IN IP4 203.0.113.1
a=rtpmap:3 GSM/8000
a=fmtp:3 this-is-unknown=no
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

# answer with a=fmtp:3 this-is-unknown=no, GSM will be keeped
answer('rtpp-flags: basic A to B call', { 
    'rtpp-flags' => 'replace-origin address-family=IP4 transport-protocol=RTP/AVP',
     'from-tag' => ft(),
     'to-tag' => tt(),
    }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 3 101
a=rtpmap:3 GSM/8000
a=fmtp:3 this-is-unknown=no
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 3 101
c=IN IP4 203.0.113.1
a=rtpmap:3 GSM/8000
a=fmtp:3 this-is-unknown=no
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;

# AMR-WB with octet-align=0 in offer, answer without fmtp (defaults match)
new_call;

offer('AMR-WB octet-align=0 offer, answer missing fmtp - should match', {
    'rtpp-flags' => 'replace-origin address-family=IP4 transport-protocol=RTP/AVP',
    'from-tag' => ft(),
    }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 96 101
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=0
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 101
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=0
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

# Answer without fmtp: per RFC 4867 s8.1, missing fmtp = defaults = octet-align=0
# This should match the offer's octet-align=0
answer('AMR-WB octet-align=0 offer, answer missing fmtp - should match', {
    'rtpp-flags' => 'replace-origin address-family=IP4 transport-protocol=RTP/AVP',
    'from-tag' => ft(),
    'to-tag' => tt(),
    }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 96 101
a=rtpmap:96 AMR-WB/16000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 101
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

# AMR-WB with octet-align=1 in offer, answer without fmtp (incompatible)
new_call;

offer('AMR-WB octet-align=1 offer, answer missing fmtp - incompatible', {
    'rtpp-flags' => 'replace-origin address-family=IP4 transport-protocol=RTP/AVP',
    'from-tag' => ft(),
    }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 96 0 101
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 0 101
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

# Answer without fmtp: missing = defaults = octet-align=0, which != octet-align=1
# AMR-WB should be rejected, PCMU should remain
answer('AMR-WB octet-align=1 offer, answer missing fmtp - incompatible', {
    'rtpp-flags' => 'replace-origin address-family=IP4 transport-protocol=RTP/AVP',
    'from-tag' => ft(),
    'to-tag' => tt(),
    }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 96 0 101
a=rtpmap:96 AMR-WB/16000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

# AMR-WB with no fmtp in both offer and answer (both use defaults, should match)
new_call;

offer('AMR-WB no fmtp in offer or answer - defaults match', {
    'rtpp-flags' => 'replace-origin address-family=IP4 transport-protocol=RTP/AVP',
    'from-tag' => ft(),
    }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 96 101
a=rtpmap:96 AMR-WB/16000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 101
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

answer('AMR-WB no fmtp in offer or answer - defaults match', {
    'rtpp-flags' => 'replace-origin address-family=IP4 transport-protocol=RTP/AVP',
    'from-tag' => ft(),
    'to-tag' => tt(),
    }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 96 101
a=rtpmap:96 AMR-WB/16000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 101
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

done_testing();
