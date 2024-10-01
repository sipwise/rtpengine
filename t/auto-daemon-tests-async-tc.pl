#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use NGCP::Rtpclient::ICE;
use POSIX;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1 --codec-num-threads=2
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --silence-detect=1 --log-level-internals=7))
		or die;


my $extended_tests = $ENV{RTPENGINE_EXTENDED_TESTS};


# 100 ms sine wave


my $pcma_1 = "\xd5\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\x55\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c";
my $pcma_2 = "\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\xd5\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\xd5\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09";
my $pcma_3 = "\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\x55\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0";
my $pcma_4 = "\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\x55\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\x55\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1";
my $pcma_5 = "\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\xd5\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34";



my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $ssrc, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $has_recv);



if ($extended_tests) {

($sock_a, $sock_b) = new_call([qw(198.51.100.43 6060)], [qw(198.51.100.43 6062)]);

($port_a) = offer('opus fmtp options, full offer list',
	{ codec => { transcode =>
		['opus/48000/2///maxaveragebitrate--40000;maxplaybackrate--32000;sprop-stereo--0;stereo--0;cbr--0;useinbandfec--0;usedtx--0;sprop-maxcapturerate--16000',
		'PCMU'],
	mask => ['all'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6060 RTP/AVP 0 8 101 13
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=rtpmap:13 CN/8000
a=ptime:20
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96 0
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=0; useinbandfec=0; cbr=0; maxplaybackrate=32000; maxaveragebitrate=40000; sprop-maxcapturerate=16000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

($port_b) = answer('opus fmtp options, full offer list',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6062 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 maxaveragebitrate=40000;maxplaybackrate=32000;stereo=0;cbr=0;useinbandfec=0;usedtx=0;sprop-maxcapturerate=16000;sprop-stereo=0
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

snd($sock_a, $port_b, rtp(0, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 8000, 5000, -1, "\x08\x83\xf9\x97\xc1\x5b\x98\x5f\xdf\x55\x5d\x26\xd7\xf9\x54\xf6\xef\xd7\x11\x03\x1e\xab\x07\xdc\x29\x89\x95\x3d\x2b\x5a\x6f\xfd\xb0\x5a\xb8\xce\x6d\xe8\x61\x9d\x30\xcd\x3a\xba\xb8\x40\xae\x03\xab\xbf\x4d\xb7\x4b\x48\x74\xaa\x66\xfa\xcd\x63\x6d\x15\xa4\x8d\x66\x7f\x9d\xa6\x1c"));



($sock_a, $sock_b) = new_call([qw(198.51.100.43 6024)], [qw(198.51.100.43 6026)]);

($port_a) = offer('opus fmtp options, accept stereo',
	{ codec => { transcode => ['PCMA'], mask => ['opus'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6024 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus fmtp options, accept stereo',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6026 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=1; useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(8, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 8000, 5000, -1, "\x0c\x87\xfc\xe4\x56\x3b\x03\xec\x1f\xa8\xa2\x3f\xda\xc0\xca\x15\xec\x3e\xd6\x05\x1d\xc1\xf3\x38\x93\x63\xe5\x28\x64\xbf\x21\x34\x71\x69\xd6\xe3\x22\x5a\x2c\x7c\xbc\x8b\x59\x6e\x40", "\x0c\x87\xfc\xe4\x56\x22\x83\xab\x48\x98\xd0\x47\xeb\xd2\x1c\xa9\x4d\xaa\x15\x4f\xee\x02\xaa\x36\x72\xf1\x17\x3f\x28\xd4\xea\x08\x71\x29\xf2\xf1\xf7\x6a\xa3\xcd\x93\x8d\xed\x23\x00\x9c"));




($sock_a, $sock_b) = new_call([qw(198.51.100.43 6000)], [qw(198.51.100.43 6002)]);

($port_a) = offer('opus fmtp options, default',
	{ codec => { transcode => ['opus'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6000 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus fmtp options, default',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6002 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 8000, 5000, -1, "\x08\x83\x10\x27\x01\x21\xc5\xb4\x16\x83\xf2\x83\x8f\x30\xa2\x91\xbf\x58\x81\xa2\xcc\x6d\x4c\xfa\x89\xd9\xa8\xef\x68\xaf\x8d\x91\x1d\x81\xf4\x1d\x62\x40\x64\x86\xaa\xa2\xc3\x8f\xa2\x62\x58\xc4\xfd\x9d\x98\x7b\xe2\x6f\xc4\x33\x5c\x27\x21\x86\xd7\x11\x2c\x49\xc5\xa7\x40"));




($sock_a, $sock_b) = new_call([qw(198.51.100.43 6004)], [qw(198.51.100.43 6006)]);

($port_a) = offer('opus fmtp options, force stereo',
	{ codec => { transcode => ['opus/48000/2///useinbandfec=1;stereo=1;sprop-stereo=1'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6004 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=1; sprop-stereo=1; useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus fmtp options, force stereo',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6006 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=1; sprop-stereo=1; useinbandfec=1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 8000, 5000, -1, "\x0c\x87\xfc\xe4\x56\x3b\x03\xec\x1f\xa8\xa2\x3f\xda\xc0\xca\x15\xec\x3e\xd6\x05\x1d\xc1\xf3\x38\x93\x63\xe5\x28\x64\xbf\x21\x34\x71\x69\xd6\xe3\x22\x5a\x2c\x7c\xbc\x8b\x59\x6e\x40", "\x0c\x87\xfc\xe4\x56\x22\x83\xab\x48\x98\xd0\x47\xeb\xd2\x1c\xa9\x4d\xaa\x15\x4f\xee\x02\xaa\x36\x72\xf1\x17\x3f\x28\xd4\xea\x08\x71\x29\xf2\xf1\xf7\x6a\xa3\xcd\x93\x8d\xed\x23\x00\x9c"));




($sock_a, $sock_b) = new_call([qw(198.51.100.43 6008)], [qw(198.51.100.43 6010)]);

($port_a) = offer('opus fmtp options, force mono',
	{ codec => { transcode => ['opus/48000/2///useinbandfec=1;stereo=0;sprop-stereo=0'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6008 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=0; useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus fmtp options, force mono',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6010 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=0; useinbandfec=1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 8000, 5000, -1, "\x08\x83\x10\x27\x01\x21\xc5\xb4\x16\x83\xf2\x83\x8f\x30\xa2\x91\xbf\x58\x81\xa2\xcc\x6d\x4c\xfa\x89\xd9\xa8\xef\x68\xaf\x8d\x91\x1d\x81\xf4\x1d\x62\x40\x64\x86\xaa\xa2\xc3\x8f\xa2\x62\x58\xc4\xfd\x9d\x98\x7b\xe2\x6f\xc4\x33\x5c\x27\x21\x86\xd7\x11\x2c\x49\xc5\xa7\x40"));




($sock_a, $sock_b) = new_call([qw(198.51.100.43 6012)], [qw(198.51.100.43 6014)]);

($port_a) = offer('opus fmtp options, stereo 1/0',
	{ codec => { transcode => ['opus/48000/2///stereo=1;sprop-stereo=0'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6012 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=1; sprop-stereo=0
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus fmtp options, stereo 1/0',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6014 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=1; useinbandfec=0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 8000, 5000, -1, "\x08\x83\x10\x27\x01\x21\xc5\xb4\x16\x83\xf2\x83\x8f\x30\xa2\x91\xbf\x58\x81\xa2\xcc\x6d\x4c\xfa\x89\xd9\xa8\xef\x68\xaf\x8d\x91\x1d\x81\xf4\x1d\x62\x40\x64\x86\xaa\xa2\xc3\x8f\xa2\x62\x58\xc4\xfd\x9d\x98\x7b\xe2\x6f\xc4\x33\x5c\x27\x21\x86\xd7\x11\x2c\x49\xc5\xa7\x40"));



($sock_a, $sock_b) = new_call([qw(198.51.100.43 6016)], [qw(198.51.100.43 6018)]);

($port_a) = offer('opus fmtp options, stereo 0/1 (mono)',
	{ codec => { transcode => ['opus/48000/2///stereo=0;sprop-stereo=1'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6016 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=1
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus fmtp options, stereo 0/1 (mono)',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6018 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=1; sprop-stereo=0; useinbandfec=0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 8000, 5000, -1, "\x0c\x87\xfc\xe4\x56\x3b\x03\xec\x1f\xa8\xa2\x3f\xda\xc0\xca\x15\xec\x3e\xd6\x05\x1d\xc1\xf3\x38\x93\x63\xe5\x28\x64\xbf\x21\x34\x71\x69\xd6\xe3\x22\x5a\x2c\x7c\xbc\x8b\x59\x6e\x40", "\x0c\x87\xfc\xe4\x56\x22\x83\xab\x48\x98\xd0\x47\xeb\xd2\x1c\xa9\x4d\xaa\x15\x4f\xee\x02\xaa\x36\x72\xf1\x17\x3f\x28\xd4\xea\x08\x71\x29\xf2\xf1\xf7\x6a\xa3\xcd\x93\x8d\xed\x23\x00\x9c"));




($sock_a, $sock_b) = new_call([qw(198.51.100.43 6020)], [qw(198.51.100.43 6022)]);

($port_a) = offer('opus fmtp options, accept default',
	{ codec => { transcode => ['PCMA'], mask => ['opus'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6020 RTP/AVP 96
a=rtpmap:96 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus fmtp options, accept default',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6022 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(8, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 8000, 5000, -1, "\x08\x83\x10\x27\x01\x21\xc5\xb4\x16\x83\xf2\x83\x8f\x30\xa2\x91\xbf\x58\x81\xa2\xcc\x6d\x4c\xfa\x89\xd9\xa8\xef\x68\xaf\x8d\x91\x1d\x81\xf4\x1d\x62\x40\x64\x86\xaa\xa2\xc3\x8f\xa2\x62\x58\xc4\xfd\x9d\x98\x7b\xe2\x6f\xc4\x33\x5c\x27\x21\x86\xd7\x11\x2c\x49\xc5\xa7\x40"));

}



#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
