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


# SDP version tests

new_call;

offer('SDP version simple increments', { replace => ['SDP version'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
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

offer('SDP version simple increments', { replace => ['SDP version'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
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

offer('SDP version simple increments', { replace => ['SDP version'] }, <<SDP);
v=0
o=- 1545997027 2 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
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

offer('SDP version simple increments', { replace => ['SDP version'] }, <<SDP);
v=0
o=- 1545997027 3 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
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

offer('SDP version simple increments', { replace => ['SDP version'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
v=0
o=- 1545997027 2 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('SDP version simple increments', { replace => ['SDP version'] }, <<SDP);
v=0
o=- 1545997027 4 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
v=0
o=- 1545997027 2 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# SDP version force increase

new_call;

# there is no 'monologue->last_out_sdp', but the version still gets increased
offer('SDP version force increase', { replace => ['force-increment-sdp-ver'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
v=0
o=- 1545997027 2 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# there is 'monologue->last_out_sdp' and it's equal to the newly given SDP,
# but the version still gets increased
offer('SDP version force increase', { replace => ['force-increment-sdp-ver'] }, <<SDP);
v=0
o=- 1545997027 2 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
v=0
o=- 1545997027 3 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# there is 'monologue->last_out_sdp' and it's not equal to the newly given SDP,
# and the version gets increased, as if that would be increased with 'sdp-version'.
offer('SDP version force increase', { replace => ['force-increment-sdp-ver'] }, <<SDP);
v=0
o=- 1545997027 3 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
v=0
o=- 1545997027 4 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# SDP orign username replacements

new_call;

offer('SDP origin replace username only', { replace => ['username'] }, <<SDP);
v=0
o=test 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
v=0
o=test 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('SDP origin replace username only', { ICE => 'remove' }, <<SDP);
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

offer('SDP origin replace username only', { replace => ['username'] }, <<SDP);
v=0
o=test2 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
v=0
o=test 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('SDP origin replace username only', { ICE => 'remove' }, <<SDP);
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

offer('SDP origin replace username only', { replace => ['username'] }, <<SDP);
v=0
o=test3 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
v=0
o=test 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('SDP origin replace username only', { ICE => 'remove' }, <<SDP);
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

# SDP origin replacements, other tests

new_call;

offer('SDP replace everything', { replace => ['SDP version', 'origin', 'username', 'session-name'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
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

offer('SDP replace everything', { replace => ['SDP version', 'origin', 'username', 'session-name'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
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

offer('SDP replace everything', { replace => ['SDP version', 'origin', 'username', 'session-name'] }, <<SDP);
v=0
o=- 1545997027 2 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
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

new_call;

offer('SDP replace everything with origin-full', { replace => ['origin-full'] }, <<SDP);
v=0
o=test 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
v=0
o=test 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('SDP replace everything with origin-full', { replace => ['origin-full'] }, <<SDP);
v=0
o=test2 1545997027 2 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
v=0
o=test 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('SDP replace everything with origin-full', { replace => ['origin-full'] }, <<SDP);
v=0
o=test 1545997027 2 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
v=0
o=test 1545997027 2 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
