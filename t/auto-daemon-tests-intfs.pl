#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use POSIX;


autotest_start(qw(--config-file=none -t -1 -i foo/203.0.113.1 -i foo/2001:db8:4321::1
			-i bar/203.0.113.2 -i bar/2001:db8:4321::2
			-i blah=foo -i baz=bar
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --silence-detect=1))
		or die;


my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $ssrc, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq);





new_call;

offer('intfs selection', { direction => [qw(foo bar)] }, <<SDP);
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
c=IN IP4 203.0.113.2
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('intfs selection', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.2
s=tester
t=0 0
m=audio 3000 RTP/AVP 0
c=IN IP4 198.51.100.2
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('intfs selection and new stream', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
m=audio 2004 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.2
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.2
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('intfs selection alt', { 'from-interface' => 'foo', 'to-interface' => 'bar' }, <<SDP);
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
c=IN IP4 203.0.113.2
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('intfs selection alt', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.2
s=tester
t=0 0
m=audio 3000 RTP/AVP 0
c=IN IP4 198.51.100.2
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('intfs selection and new stream', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
m=audio 2004 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.2
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.2
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


new_call;

offer('intfs selection alias', { direction => [qw(blah baz)] }, <<SDP);
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
c=IN IP4 203.0.113.2
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('intfs selection alias', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.2
s=tester
t=0 0
m=audio 3000 RTP/AVP 0
c=IN IP4 198.51.100.2
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('intfs selection and new stream', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
m=audio 2004 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.2
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.2
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP




done_testing();
