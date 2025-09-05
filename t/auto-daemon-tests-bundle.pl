#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use POSIX;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --log-level-internals=7))
		or die;



my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $port_c, $ssrc_a, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx, $port_d, $sock_e, $port_e, $sock_cx, $port_cx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $tag_medias, $media_labels,
	$ftr, $ttr, $fts, $ttr2);



($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6150)],
		[qw(198.51.100.14 6152)],
		[qw(198.51.100.14 6154)],
		[qw(198.51.100.14 6156)]);

($port_a, undef, $port_b) = offer('control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6150 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6152 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6154 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6156 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
isnt($port_c, $port_d, 'different ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160));

snd($sock_b, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_b, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800));



($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6158)],
		[qw(198.51.100.14 6160)],
		[qw(198.51.100.14 6162)],
		[qw(198.51.100.14 6164)]);

($port_a, undef, $port_b) = offer('optional bundle offer',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6158 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6160 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('optional bundle offer',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6162 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6164 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
isnt($port_c, $port_d, 'different ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160));

snd($sock_b, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_b, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800));


# mix up bundle ports

snd($sock_a, $port_d,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_d, $port_b, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv_no($sock_c);

snd($sock_b, $port_c,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_c, $port_a, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv_no($sock_d);




undef($sock_b);


($sock_a, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6166)],
		[qw(198.51.100.14 6168)],
		[qw(198.51.100.14 6170)]);

($port_a, undef, $port_b) = offer('same-port bundle offer',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6166 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6166 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('same-port bundle offer',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6168 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6170 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
isnt($port_c, $port_d, 'different ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160));

snd($sock_a, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_a, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800));

# mix up bundle ports

snd($sock_a, $port_d,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_d, $port_b, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv_no($sock_c);

snd($sock_a, $port_c,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_c, $port_a, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv_no($sock_d);




($sock_a, $sock_b, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6200)],
		[qw(198.51.100.14 6202)],
		[qw(198.51.100.14 6204)],
		[qw(198.51.100.14 6206)]);

($port_a, undef, $port_b) = offer('optional bundle offer w bundle-accept',
	{ bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6200 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6202 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('optional bundle offer w bundle-accept',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6204 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6206 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
isnt($port_c, $port_d, 'different ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv_no($sock_b);

snd($sock_b, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_b, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800)); # XXX wrong port
rcv_no($sock_a);


# mix up bundle ports

snd($sock_a, $port_d,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv_no($sock_d);

snd($sock_b, $port_c,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv_no($sock_c);




undef($sock_b);


($sock_a, $sock_c, $sock_d) =
	new_call([qw(198.51.100.14 6208)],
		[qw(198.51.100.14 6210)],
		[qw(198.51.100.14 6212)]);

($port_a, undef, $port_b) = offer('same-port bundle offer w bundle-accept',
	{ bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6208 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6208 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_c, undef, $port_d) = answer('same-port bundle offer w bundle-accept',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6210 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6212 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP

isnt($port_a, $port_b, 'different ports');
isnt($port_a, $port_c, 'different ports');
isnt($port_a, $port_d, 'different ports');
isnt($port_b, $port_c, 'different ports');
isnt($port_b, $port_d, 'different ports');
isnt($port_c, $port_d, 'different ports');

snd($sock_a, $port_c,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));

snd($sock_c, $port_a,  rtp(0, 6000, 8000, 0x5678, "\x77" x 160));
rcv($sock_a, $port_c, rtpm(0, 6000, 8000, 0x5678, "\x77" x 160));

snd($sock_a, $port_d,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));

snd($sock_d, $port_b,  rtp(105, 7000, 9000, 0x8741, "\x22" x 800));
rcv($sock_a, $port_d, rtpm(105, 7000, 9000, 0x8741, "\x22" x 800));

# mix up bundle ports

snd($sock_a, $port_d,  rtp(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv($sock_c, $port_a, rtpm(0, 2000, 6000, 0x1234, "\x44" x 160));
rcv_no($sock_d);

snd($sock_a, $port_c,  rtp(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv($sock_d, $port_b, rtpm(105, 3000, 4000, 0x6321, "\x33" x 800));
rcv_no($sock_c);



offer('same port bundle with non unique PT',
	{ bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 6208 RTP/AVP 0 100
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=rtpmap:100 foo/8000
m=video 6208 RTP/AVP 105 100
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=rtpmap:100 bar/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 100
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=rtpmap:100 foo/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105 100
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=rtpmap:100 bar/90000
a=sendrecv
a=rtcp:PORT
SDP

answer('same port bundle with non unique PT',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6210 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 6212 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP




offer('optional bundle with non unique PT',
	{ bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
a=group:BUNDLE a v
m=audio 7106 RTP/AVP 0 100
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
a=rtpmap:100 foo/8000
m=video 7108 RTP/AVP 105 100
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=rtpmap:100 bar/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 100
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=rtpmap:100 foo/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105 100
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=rtpmap:100 bar/90000
a=sendrecv
a=rtcp:PORT
SDP

answer('same port bundle with non unique PT',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7110 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:a
m=video 7112 RTP/AVP 105
c=IN IP4 198.51.100.14
a=rtpmap:105 H264/90000
a=sendrecv
a=mid:v
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:a
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 105
c=IN IP4 203.0.113.1
a=mid:v
a=rtpmap:105 H264/90000
a=sendrecv
a=rtcp:PORT
SDP


#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
