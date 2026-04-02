#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use POSIX;
use JSON;


autotest_start(qw(--config-file=none -t -1
			-i def/203.0.113.1 -i def/2001:db8:4321::1
			-i alt/203.0.113.2 -i alt/2001:db8:4321::2
			-n 2223 -f -L 7 -E --log-level-internals=7))
		or die;



my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $port_c, $ssrc_a, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx, $port_d, $sock_e, $port_e, $sock_cx, $port_cx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $tag_medias, $media_labels,
	$ftr, $ttr, $fts, $ttr2, $cid, $ft, $tt, $ssrc, $cid1);

my $extended_tests = $ENV{RTPENGINE_EXTENDED_TESTS};

my $wav_file = "\x52\x49\x46\x46\x64\x06\x00\x00\x57\x41\x56\x45\x66\x6d\x74\x20\x10\x00\x00\x00\x01\x00\x01\x00\x40\x1f\x00\x00\x80\x3e\x00\x00\x02\x00\x10\x00\x64\x61\x74\x61\x40\x06\x00\x00\x00\x00\xb0\x22\x45\x41\x25\x58\x95\x64\x24\x65\xbd\x59\xb6\x43\xb4\x25\x35\x03\x5e\xe0\x3b\xc1\x8c\xa9\x0f\x9c\x6a\x9a\xc2\xa4\xe7\xb9\x55\xd7\x92\xf9\x92\x1c\x30\x3c\xb2\x54\x2e\x63\xf3\x65\xa7\x5c\x68\x48\x9b\x2b\xa1\x09\x8a\xe6\x71\xc6\x28\xad\xab\x9d\xcc\x99\x06\xa2\x5c\xb5\x81\xd1\x2d\xf3\x53\x16\xe1\x36\xe8\x50\x64\x61\x59\x66\x36\x5f\xcf\x4c\x56\x31\x04\x10\xd0\xec\xe0\xcb\x19\xb1\xa9\x9f\x98\x99\xa8\x9f\x1a\xb1\xdf\xcb\xd1\xec\x04\x10\x54\x31\xd2\x4c\x33\x5f\x5c\x66\x61\x61\xeb\x50\xde\x36\x56\x16\x2b\xf3\x83\xd1\x59\xb5\x08\xa2\xcb\x99\xac\x9d\x28\xad\x70\xc6\x8a\xe6\xa3\x09\x98\x2b\x6a\x48\xa6\x5c\xf4\x65\x2d\x63\xb3\x54\x2e\x3c\x93\x1c\x93\xf9\x53\xd7\xe9\xb9\xc1\xa4\x69\x9a\x11\x9c\x8b\xa9\x3b\xc1\x5e\xe0\x36\x03\xb2\x25\xba\x43\xb7\x59\x2a\x65\x90\x64\x29\x58\x42\x41\xb2\x22\xff\xff\x50\xdd\xbb\xbe\xdb\xa7\x6b\x9b\xdd\x9a\x42\xa6\x4b\xbc\x4b\xda\xca\xfc\xa5\x1f\xc2\x3e\x77\x56\xed\x63\x9a\x65\x3b\x5b\x1b\x46\xa9\x28\x70\x06\x6c\xe3\xd2\xc3\x4d\xab\xd1\x9c\x10\x9a\x56\xa3\x99\xb7\x67\xd4\x5b\xf6\x79\x19\x8e\x39\xd7\x52\x58\x62\x30\x66\xfd\x5d\xa2\x4a\x81\x2e\xd1\x0c\xae\xe9\x1f\xc9\x17\xaf\x9e\x9e\xa4\x99\xce\xa0\x2c\xb3\xaf\xce\xf8\xef\x33\x13\x1e\x34\xe8\x4e\x57\x60\x68\x66\x57\x60\xe9\x4e\x1c\x34\x35\x13\xf6\xef\xb0\xce\x2d\xb3\xcc\xa0\xa6\x99\x9c\x9e\x17\xaf\x22\xc9\xa9\xe9\xd6\x0c\x7c\x2e\xa7\x4a\xf8\x5d\x36\x66\x52\x62\xdb\x52\x8c\x39\x79\x19\x5c\xf6\x67\xd4\x97\xb7\x59\xa3\x0e\x9a\xd1\x9c\x4e\xab\xd0\xc3\x6e\xe3\x6e\x06\xac\x28\x18\x46\x3d\x5b\x98\x65\xef\x63\x76\x56\xc3\x3e\xa4\x1f\xc9\xfc\x4e\xda\x49\xbc\x43\xa6\xdd\x9a\x69\x9b\xdd\xa7\xbb\xbe\x4f\xdd\x01\x00\xaf\x22\x47\x41\x23\x58\x96\x64\x24\x65\xbb\x59\xba\x43\xb0\x25\x39\x03\x59\xe0\x40\xc1\x87\xa9\x15\x9c\x65\x9a\xc4\xa4\xe7\xb9\x56\xd7\x90\xf9\x94\x1c\x2e\x3c\xb3\x54\x2f\x63\xf1\x65\xa8\x5c\x68\x48\x9a\x2b\xa2\x09\x8a\xe6\x71\xc6\x27\xad\xac\x9d\xcb\x99\x08\xa2\x59\xb5\x84\xd1\x2a\xf3\x56\x16\xe0\x36\xe7\x50\x65\x61\x59\x66\x35\x5f\xd1\x4c\x54\x31\x04\x10\xd2\xec\xdd\xcb\x1c\xb1\xa5\x9f\x9b\x99\xa8\x9f\x18\xb1\xe2\xcb\xcd\xec\x07\x10\x54\x31\xd1\x4c\x33\x5f\x5d\x66\x60\x61\xec\x50\xdd\x36\x57\x16\x29\xf3\x86\xd1\x57\xb5\x09\xa2\xcb\x99\xab\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9a\x2b\x69\x48\xa7\x5c\xf2\x65\x2e\x63\xb2\x54\x31\x3c\x91\x1c\x93\xf9\x53\xd7\xe9\xb9\xc1\xa4\x6a\x9a\x10\x9c\x8a\xa9\x3f\xc1\x59\xe0\x3a\x03\xb0\x25\xb8\x43\xbd\x59\x24\x65\x95\x64\x24\x58\x46\x41\xaf\x22\x02\x00\x4e\xdd\xbb\xbe\xdd\xa7\x68\x9b\xdf\x9a\x42\xa6\x48\xbc\x50\xda\xc6\xfc\xa7\x1f\xc2\x3e\x75\x56\xef\x63\x99\x65\x3c\x5b\x1a\x46\xaa\x28\x6e\x06\x6e\xe3\xd1\xc3\x4e\xab\xd1\x9c\x0e\x9a\x57\xa3\x9a\xb7\x64\xd4\x60\xf6\x75\x19\x90\x39\xd7\x52\x55\x62\x34\x66\xf9\x5d\xa8\x4a\x7a\x2e\xd8\x0c\xa7\xe9\x23\xc9\x16\xaf\x9d\x9e\xa6\x99\xcb\xa0\x2f\xb3\xad\xce\xfa\xef\x30\x13\x21\x34\xe6\x4e\x59\x60\x66\x66\x5a\x60\xe4\x4e\x23\x34\x2e\x13\xfc\xef\xab\xce\x30\xb3\xcb\xa0\xa5\x99\x9f\x9e\x14\xaf\x24\xc9\xa7\xe9\xd8\x0c\x7b\x2e\xa8\x4a\xf7\x5d\x36\x66\x53\x62\xda\x52\x8d\x39\x78\x19\x5d\xf6\x67\xd4\x97\xb7\x59\xa3\x0d\x9a\xd2\x9c\x4e\xab\xd1\xc3\x6d\xe3\x6f\x06\xaa\x28\x19\x46\x3f\x5b\x95\x65\xf2\x63\x74\x56\xc2\x3e\xa8\x1f\xc4\xfc\x52\xda\x45\xbc\x46\xa6\xdc\x9a\x6a\x9b\xdc\xa7\xba\xbe\x51\xdd\xff\xff\xb1\x22\x45\x41\x24\x58\x97\x64\x22\x65\xbd\x59\xb7\x43\xb3\x25\x37\x03\x5b\xe0\x3e\xc1\x89\xa9\x11\x9c\x6a\x9a\xc0\xa4\xeb\xb9\x51\xd7\x94\xf9\x91\x1c\x31\x3c\xb1\x54\x2f\x63\xf3\x65\xa5\x5c\x6c\x48\x95\x2b\xa7\x09\x86\xe6\x73\xc6\x28\xad\xa9\x9d\xcf\x99\x04\xa2\x5b\xb5\x84\xd1\x29\xf3\x57\x16\xde\x36\xe9\x50\x65\x61\x57\x66\x38\x5f\xcd\x4c\x57\x31\x04\x10\xd0\xec\xe1\xcb\x17\xb1\xaa\x9f\x97\x99\xaa\x9f\x18\xb1\xe1\xcb\xce\xec\x07\x10\x53\x31\xd0\x4c\x38\x5f\x55\x66\x68\x61\xe6\x50\xe0\x36\x56\x16\x2b\xf3\x81\xd1\x5d\xb5\x04\xa2\xce\x99\xaa\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9b\x2b\x67\x48\xa9\x5c\xf1\x65\x2e\x63\xb4\x54\x2e\x3c\x93\x1c\x92\xf9\x54\xd7\xe8\xb9\xc2\xa4\x69\x9a\x10\x9c\x8c\xa9\x3c\xc1\x5c\xe0\x37\x03\xb2\x25\xb8\x43\xbc\x59\x24\x65\x95\x64\x26\x58\x43\x41\xb2\x22\xff\xff\x50\xdd\xba\xbe\xde\xa7\x68\x9b\xdd\x9a\x45\xa6\x45\xbc\x52\xda\xc5\xfc\xa8\x1f\xbf\x3e\x79\x56\xec\x63\x9b\x65\x3b\x5b\x1a\x46\xaa\x28\x6f\x06\x6e\xe3\xd0\xc3\x4f\xab\xd0\x9c\x0f\x9a\x58\xa3\x97\xb7\x68\xd4\x5c\xf6\x78\x19\x8f\x39\xd6\x52\x57\x62\x32\x66\xfb\x5d\xa6\x4a\x7b\x2e\xd8\x0c\xa6\xe9\x25\xc9\x15\xaf\x9c\x9e\xa9\x99\xc7\xa0\x33\xb3\xa9\xce\xfd\xef\x2f\x13\x21\x34\xe6\x4e\x58\x60\x67\x66\x59\x60\xe5\x4e\x23\x34\x2c\x13\x00\xf0\xa6\xce\x35\xb3\xc7\xa0\xa8\x99\x9d\x9e\x15\xaf\x24\xc9\xa8\xe9\xd5\x0c\x7e\x2e\xa5\x4a\xfa\x5d\x35\x66\x52\x62\xdb\x52\x8d\x39\x77\x19\x5e\xf6\x66\xd4\x98\xb7\x59\xa3\x0c\x9a\xd3\x9c\x4d\xab\xd1\xc3\x6e\xe3\x6e\x06\xaa\x28\x1b\x46\x3b\x5b\x9a\x65\xed\x63\x76\x56\xc4\x3e\xa3\x1f\xcb\xfc\x4b\xda\x4a\xbc\x43\xa6\xdd\x9a\x6a\x9b\xdc\xa7\xba\xbe\x51\xdd\xff\xff\xb1\x22\x44\x41\x25\x58\x96\x64\x23\x65\xbd\x59\xb6\x43\xb4\x25\x36\x03\x5c\xe0\x3d\xc1\x8a\xa9\x12\x9c\x67\x9a\xc4\xa4\xe6\xb9\x55\xd7\x93\xf9\x91\x1c\x31\x3c\xb0\x54\x31\x63\xef\x65\xab\x5c\x66\x48\x9a\x2b\xa4\x09\x87\xe6\x73\xc6\x26\xad\xad\x9d\xcb\x99\x07\xa2\x5b\xb5\x81\xd1\x2c\xf3\x56\x16\xde\x36\xeb\x50\x62\x61\x59\x66\x38\x5f\xcc\x4c\x59\x31\x01\x10\xd3\xec\xdd\xcb\x1b\xb1\xa8\x9f\x98\x99\xa9\x9f\x18\xb1\xe0\xcb\xd1\xec\x03\x10\x57\x31\xce\x4c\x37\x5f\x58\x66\x63\x61\xec\x50\xdb\x36\x5a\x16\x27\xf3\x85\xd1\x5a\xb5\x05\xa2\xce\x99\xaa\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9a\x2b\x69\x48\xa6\x5c\xf4\x65\x2e\x63\xb1\x54\x32\x3c\x8e\x1c\x96\xf9\x52\xd7\xea\xb9\xc1\xa4\x67\x9a\x13\x9c\x8a\xa9\x3c\xc1\x5e\xe0\x33\x03\xb7\x25\xb4\x43\xbf\x59\x21\x65\x99\x64\x21\x58\x48\x41\xad\x22\x03\x00\x4f\xdd\xbb\xbe\xdb\xa7\x6a\x9b\xdd\x9a\x43\xa6\x4b\xbc\x4a\xda\xcb\xfc\xa4\x1f\xc3\x3e\x76\x56\xef\x63\x96\x65\x40\x5b\x17\x46\xac\x28\x6e\x06\x6d\xe3\xd2\xc3\x4d\xab\xd2\x9c\x0d\x9a\x59\xa3\x97\xb7\x68\xd4\x5c\xf6\x77\x19\x8f\x39\xd8\x52\x55\x62\x33\x66\xfb\x5d\xa4\x4a\x7f\x2e\xd4\x0c\xab\xe9\x20\xc9\x17\xaf\x9d\x9e\xa7\x99\xc9\xa0\x32\xb3\xa9\xce\xfd\xef\x2f\x13\x20\x34\xe8\x4e\x56\x60\x6a\x66\x55\x60\xe9\x4e\x1f\x34\x31\x13\xfa\xef\xad\xce\x2e\xb3\xcc\xa0\xa7\x99\x9b\x9e\x18\xaf\x20\xc9\xac\xe9\xd2\x0c\x81\x2e\xa1\x4a\xff\x5d\x30\x66\x56\x62\xd7\x52\x90\x39\x77\x19\x5d\xf6\x67\xd4\x96\xb7\x5a\xa3\x0e\x9a\xd0\x9c\x50\xab\xcf\xc3\x6e\xe3\x6f\x06\xaa\x28\x1a\x46\x3d\x5b\x98\x65\xee\x63\x77\x56\xc1\x3e\xa7\x1f\xc8\xfc\x4c\xda\x4b\xbc\x41\xa6\xdf\x9a\x68\x9b\xdd\xa7\xba\xbe\x51\xdd";
is length($wav_file), 1644, 'embedded binary wav file';



if ($extended_tests) {

($sock_a, $sock_b, $sock_c) = new_call([qw(198.51.100.4 4114)], [qw(198.51.100.4 4116)], [qw(198.51.100.4 4118)]);

($port_a) = offer('mixed sub manual w/ immediate audio player', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4114 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('mixed sub manual w/ immediate audio player', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4116 RTP/AVP 0
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($cid, $ft, $port_c) = create('mixed sub manual w/ immediate audio player', {
	codec => { offer => ['G722'] },
	'audio player' => 'force',
	'call-id' => cid(),
}, <<SDP);
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 9
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=sendrecv
a=rtcp:PORT
SDP

is($cid, cid(), 'same call');

create_answer('mixed sub manual w/ immediate audio player', {
	'from-tag' => $ft,
}, <<SDP);
v=0
o=- 111111111 22222222 IN IP4 203.0.113.1
s=22222222
t=0 0
m=audio 4118 RTP/AVP 9
c=IN IP4 198.51.100.4
SDP


# no media playback without subscriptions (XXX change this?)
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

snd($sock_a, $port_b, rtp (0, 1000, 3000, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

snd($sock_b, $port_a, rtp (0, 8000, 10000, 0x2d8c, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 8000, 10000, 0x2d8c, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

snd($sock_c, $port_c, rtp (9, 8200, 10200, 0x2e54, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);


rtpe_req('connect', 'mixed sub manual w/ immediate audio player', {
		'from-tag' => ft(),
		'to-tag' => $ft,
		flags => [qw,directional,],
});

# player not active yet (no media)
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

# add media to start player
snd($sock_a, $port_b, rtp (0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
($seq, $ts, $ssrc) = rcv($sock_c, $port_c, rtpm(9 | 0x80, -1, -1, -1, "\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\x2a\x84\x20\x84\x20\x84\x04\x8e\x16\x9d\x5d\xfe\xdb\xd8\xd1\xd3\xd9\xd9\x9b\xdc\xd9\xd7\xd7\xd8\xd6\xd9\xda\xdb\xd9\xd7\xda\xd7\x9a\xd9\xd8\xd8\xd6\xd9\xd7\xda\xd9\xd9\xd9\xd6\xda\xd7\xda\xda\xd9\xd9\xd6\xda\xd7\xdb\xda\xda\xd9\xd7\xdb\xd8\xd6\xda\xdb\xdb\xd8\xd6\xda\xd8\xd6\xdb\xdb\xdc\xd3\xdf\xd9\xd6\xd9\xd9\xdc\xd2\x9e\x1b\x96\x3f\x8b\x20\xb5\x0c\xba\x3f\xbe\xd5\x6d\xf0\xd5\xdb\x7b\xdf\xdc\xf6\xf1\xdd\xd8\xdd\xdf\xfd\xf8\xf1\xfc\xdd\xda\x9e\xff\x7d\xf2\xfc\xbb\xd8\xdb\xfc"));

# untriggered media
rcv($sock_c, $port_c, rtpm(9, $seq +  1, $ts +  160, $ssrc, "\xff\xf5\xfb\xbb\xdc\xd9\xfe\xdd\xf8\xf8\xf7\xdf\xdd\xfe\xdc\xfe\xfd\xf6\xff\xde\xfd\xfe\xde\xff\xf9\xfa\xdf\xfd\xfc\xff\xdf\xfb\xfb\xde\xfd\xfd\xfc\xff\xff\xfb\xdf\xfc\xfc\xfc\xfb\xdf\xfa\xfe\xdf\xfc\xfc\xf9\xff\xfd\xfd\xfe\xfe\xdf\xfa\xfc\xfc\xfc\xfc\xfc\xff\xfc\xfd\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfb\xdf\xfb\xff\xff\xff\xff\xfc\xfd\xfc\xfc\xfb\xfe\xdf\xfa\xfc\xfc\xfb\xfc\xfb\xdf\xfc\xfa\xfb\xdf\xf9\xf9\xfe\xdf\xfa\xf9\xfc\xfc\xfc\xfb\xdf\xf8\xfb\xfe\xfc\xfc\xfb\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfb\xdf\xf3\xfe\xfa\xfa\xfb\xdf\xf6\xfa\xf8\xf7\xde\xf4\xdf\xf6\xf8\xf7\xfb\xdf\xf7\xdd\xf9\xfb\xf9\xf7\xfb\xf9\xfb\xdf\xf7\xf9\xf9\xfb"));

# catch up to delay caused by rcv_no above
rcv($sock_c, $port_c, rtpm(9, $seq +  2, $ts +  320, $ssrc, "\xfb\xf9\xf9\xfb\xfb\xf9\xf9\xfb\xfb\xf8\xf8\xfb\xfb\xf8\xf8\xfa\xfa\xf8\xf8\xfa\xfa\xf8\xf8\xfa\xfa\xf7\xfa\xfa\xfa\xfa\xfa\xfa\xf7\xfa\xfa\xfa\xfa\xfa\xfa\xf7\xfa\xde\xf2\xde\xf2\xde\xf0\xfa\xdc\xf3\xdc\xf3\xdf\xf3\xfb\xfb\xfb\xfb\xfb\xfa\xf8\xf8\xfa\xfa\xf8\xf8\xfa\xde\xee\xde\xf5\xfb\xfa\xf8\xde\xf1\xdf\xf6\xf8\xf8\xf8\xfa\xf8\xfa\xde\xf1\xfa\xfa\xf8\xf8\xfa\xd9\xf3\xf8\xf8\xfa\xde\xf1\xdc\xf6\xf8\xf8\xf8\xde\xf3\xfb\xf8\xf8\xfa\xde\xf3\xf8\xf8\xfa\xde\xf1\xdf\xf6\xf8\xf8\xf8\xde\xf5\xf8\xf8\xf8\xf8\xf8\xde\xf5\xf5\xf8\xfa\xfa\xf8\xde\xf5\xf5\xf8\xfa\xde\xf1\xde\xf5\xf5\xf8\xfa\xdc\xf8\xf8\xf5\xf5\xf8\xfa\xd9\xf8\xf5\xf8\xf8\xf5"));
rcv($sock_c, $port_c, rtpm(9, $seq +  3, $ts +  480, $ssrc, "\xf8\xdc\xde\xef\xfb\xdf\xf0\xfb\xd6\xf4\xf3\xdf\xf9\xf3\xf9\xd9\xfb\xf5\xfb\xdf\xf2\xf7\xdd\xdf\xf7\xdf\xf5\xf5\xf7\xdd\xdf\xf9\xfb\xf9\xf3\xfb\xdf\xf9\xdf\xf9\xf7\xf5\xf5\xdf\xfb\xdf\xf9\xf7\xf9\xf5\xfb\xdf\xf9\xfb\xfb\xf6\xf6\xf9\xdf\xfb\xfb\xfb\xf9\xf4\xf9\xdf\xf6\xdf\xf6\xf9\xf6\xf9\xfb\xdf\xf8\xf8\xfb\xf6\xf6\xfb\xdc\xfb\xdf\xf4\xf6\xfb\xf6\xdf\xf4\xdc\xdf\xf4\xf6\xfb\xf8\xf6\xdc\xdf\xf4\xf8\xfb\xfb\xf4\xfb\xda\xf2\xdf\xf6\xfb\xf8\xf8\xdf\xf4\xfb\xfb\xfb\xf8\xf8\xdf\xf3\xf8\xfb\xdf\xf2\xfb\xdc\xf8\xf6\xdc\xfb\xf4\xf8\xdf\xf8\xf5\xfb\xdf\xf1\xf6\xdc\xf8\xf8\xfb\xdf\xf4\xf6\xdf\xf6\xf8\xfb\xdc\xf8\xf5\xfb\xf8\xf5\xfb\xdc\xf5\xf8"));
rcv($sock_c, $port_c, rtpm(9, $seq +  4, $ts +  640, $ssrc, "\xfa\xf5\xf8\xfa\xdc\xf8\xf5\xf5\xf8\xde\xf5\xf8\xf8\xf5\xf8\xfa\xdc\xf8\xf5\xf5\xf8\xfa\xdc\xf8\xf8\xf5\xf5\xf8\xfa\xd9\xf8\xf8\xf5\xf5\xf8\xfa\xd9\xf8\xfa\xfa\xf5\xf3\xde\xf8\xde\xf8\xf8\xf5\xf1\xfa\xde\xfa\xde\xf3\xf8\xf3\xf6\xdc\xfb\xda\xf6\xf8\xf4\xf6\xfb\xf8\xdc\xdf\xf6\xf8\xf6\xf8\xf6\xdf\xfb\xfb\xfb\xf8\xf6\xf8\xfb\xdc\xf8\xf8\xfa\xf5\xf3\xdf\xf8\xf8\xdc\xfa\xf8\xef\xdf\xf8\xf6\xdc\xf8\xdf\xf0\xf8\xfb\xf8\xfb\xfb\xdf\xf4\xf8\xf8\xfa\xfa\xf8\xfa\xde\xf1\xf8\xfa\xde\xf1\xf6\xda\xf4\xfb\xf6\xdf\xf6\xf6\xdd\xf8\xfb\xf8\xf8\xfb\xf8\xf8\xfa\xfa\xf8\xf8\xfa\xde\xf3\xf8\xf8\xfa\xde\xf3\xde\xf3\xf8\xf8\xfb\xdc\xf5\xfa\xf8\xf5\xf8\xfa"));
rcv($sock_c, $port_c, rtpm(9, $seq +  5, $ts +  800, $ssrc, "\xd9\xf5\xf8\xfa\xfa\xf8\xf5\xde\xf5\xf8\xfa\xde\xf3\xf5\xfb\xdf\xf5\xf8\xdc\xf8\xf3\xf6\xdc\xf8\xf8\xdf\xf3\xf6\xfb\xdf\xf6\xfb\xfb\xf8\xf6\xdc\xfb\xf8\xf6\xfb\xfb\xf8\xfa\xdc\xf8\xf5\xf5\xf8\xfa\xde\xf5\xfa\xde\xf1\xf6\xfb\xdf\xf5\xf6\xd8\xf6\xf8\xf2\xdf\xf9\xf6\xda\xf4\xdf\xf3\xf7\xf9\xf7\xd9\xfb\xdf\xf3\xf7\xf7\xf9\xdd\xdb\xfb\xf7\xf2\xf4\xfa\xdb\xdf\xfb\xf9\xf3\xf6\xf6\xde\xde\xdf\xf4\xf6\xf6\xf5\xfa\xde\xfb\xde\xf4\xf8\xf6\xf8\xf9\xfb\xdd\xf9\xfb\xf9\xf7\xfb\xf9\xfb\xdd\xf9\xfb\xf9\xf6\xdf\xf3\xdf\xf9\xfb\xdf\xf4\xdf\xf4\xf7\xfb\xfb\xdf\xf6\xfb\xfb\xf9\xf6\xdf\xf9\xf9\xfb\xfb\xf6\xf9\xfb\xdf\xf6\xfb\xfb\xf8\xf6\xfb\xdf\xf6\xdf"));
rcv($sock_c, $port_c, rtpm(9, $seq +  6, $ts +  960, $ssrc, "\xf6\xfb\xf6\xf8\xfb\xdf\xf8\xf8\xfa\xf8\xf3\xfb\xdc\xf8\xf8\xde\xf5\xf1\xf6\xda\xf0\xf9\xd8\xfb\xf6\xf4\xdf\xf4\xf6\xdd\xdf\xf6\xf9\xfb\xfb\xf9\xf9\xdf\xf4\xfb\xf9\xf8\xfb\xdf\xf4\xfb\xf8\xf8\xfb\xfb\xde\xf1\xfb\xfb\xfb\xfa\xf8\xde\xf3\xfb\xf8\xf8\xde\xf3\xda\xf0\xf9\xf6\xdf\xf9\xf6\xda\xf3\xfb\xf4\xfb\xdd\xf9\xdd\xf9\xf9\xf6\xf9\xf9\xfb\xdc\xf8\xf8\xf6\xdf\xf4\xf6\xdf\xf6\xdf\xf6\xdf\xf6\xf6\xfb\xfb\xdf\xf6\xfb\xfb\xf8\xf6\xfb\xdf\xf6\xf8\xfb\xfb\xf8\xf8\xde\xf3\xf8\xfb\xfb\xfa\xde\xf3\xf8\xfb\xfb\xfa\xfa\xde\xf1\xf8\xfa\xfa\xfa\xfa\xdc\xf5\xf5\xf8\xfa\xde\xf1\xfa\xdc\xf5\xf5\xf8\xde\xf3\xdf\xf6\xf6\xf6\xf8\xdc\xdf\xf8\xf8\xf6\xf4"));
rcv($sock_c, $port_c, rtpm(9, $seq +  7, $ts + 1120, $ssrc, "\xf4\xdf\xdf\xfb\xdf\xf4\xf4\xf4\xf8\xdc\xdf\xfb\xfb\xf6\xf4\xf6\xdf\xfb\xdc\xfb\xfb\xf5\xf2\xfb\xf8\xdf\xf8\xdc\xfb\xf5\xf4\xf6\xdf\xf6\xfb\xdf\xf8\xfb\xfb\xfa\xf8\xf5\xfa\xdc\xf5\xf5\xf8\xfa\xf8\xf3\xda\xf6\xf6\xfb\xdf\xf6\xf6\xdc\xfb\xdf\xf2\xfb\xfb\xfb\xfb\xdf\xf6\xf6\xfb\xdf\xf6\xf8\xdf\xf8\xf8\xf8\xfa\xfa\xf8\xf8\xfa\xde\xf1\xf8\xfa\xde\xf1\xf8\xde\xf3\xfb\xf6\xdf\xf6\xfb\xdf\xf6\xfb\xf8\xfb\xde\xf1\xdf\xf6\xf8\xf8\xfb\xdf\xf3\xdf\xf4\xf8\xfb\xfb\xfb\xf8\xfa\xfa\xf8\xf8\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa"));
rcv($sock_c, $port_c, rtpm(9, $seq +  8, $ts + 1280, $ssrc, "\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xde\xee\xd6\xef\xdc\xdf\xf4\xda\xec\xdd\xf6\xda\xf9\xf4\xdb\xef\xda\xf3\xd6\xf7\xfa\xd9\xf2\xfe\xf8\xda\xf7\xde\xfa\xf8\xf7\xfe\xd9\xf7\xdc\xfa\xfa\xf6\xfc\xdc\xfb\xd9\xf8\xf5\xf6\xfb\xd9\xfb\xd7\xf2\xf6\xfa\xfc\xfe\xd9\xd9\xf6\xf4\xf7\xde\xf6\xd8\xd8\xf7\xf6\xf7\xde\xf4\xdd\xd4\xfc\xf1\xf6\xdf\xf4\xfc\xd4\xdf\xf0\xf4\xfc\xf8\xf9\xd7\xdd\xf4\xf3\xfc\xf9\xfb\xd7\xdd\xf7\xf7\xfb\xf8\xf6\xd7\xdc"));
rcv($sock_c, $port_c, rtpm(9, $seq +  9, $ts + 1440, $ssrc, "\xf8\xf7\xfb\xf7\xf8\xdb\xdd\xfe\xf9\xf8\xf5\xf8\xdd\xdd\xfe\xfe\xf9\xf7\xfc\xfc\xdc\xfe\xfe\xfa\xf8\xfa\xfb\xdc\xfb\xdc\xf9\xf6\xf9\xf7\xdb\xf5\xfb\xda\xf5\xf8\xfa\xde\xf6\xfa\xdb\xf5\xf8\xfb\xdb\xf3\xfb\xd9\xfa\xf6\xfa\xde\xf6\xfa\xde\xfa\xfa\xf9\xdf\xf6\xf7\xdd\xfb\xdd\xf9\xf9\xf5\xf7\xfb\xdf\xf9\xfb\xfb\xf7\xf7\xdf\xf9\xfb\xfb\xf9\xf6\xfb\xdf\xf6\xfb\xf9\xf9\xf9\xf9\xdf\xf4\xf9\xf9\xf8\xf8\xf8\xdf\xf4\xf8\xf8\xf8\xf8\xf8\xde\xf3\xfb\xfb\xfb\xfa\xfa\xdc\xf5\xf5\xf8\xfa\xde\xf1\xdf\xf6\xfb\xf8\xf5\xdf\xf4\xdf\xf6\xf8\xf6\xf8\xfb\xdf\xf8\xf8\xf8\xf5\xf5\xf8\xdc\xde\xf3\xf8\xf8\xf3\xfb\xdc\xdf\xf2\xdc\xfb\xf6\xf6\xdf\xf6\xf8\xdf\xf8"));
rcv($sock_c, $port_c, rtpm(9, $seq + 10, $ts + 1600, $ssrc, "\xf8\xf6\xdc\xf6\xf8\xfb\xfb\xfb\xf5\xfb\xdc\xf5\xf8\xf8\xf8\xf8\xf5\xde\xf8\xf8\xf8\xf8\xf8\xf5\xfa\xdc\xf8\xf8\xf7\xfa\xf7\xf8\xde\xf7\xde\xf0\xf8\xf8\xf8\xde\xf3\xdc\xf5\xf3\xdf\xf8\xfa\xf5\xfb\xde\xf1\xf8\xdf\xf8\xf3\xf8\xdf\xf6\xf8\xfb\xfb\xf6\xfb\xdf\xf4\xfb\xdf\xf1\xf6\xdf\xfb\xf6\xf8\xdc\xf8\xf6\xdf\xf6\xf6\xf8\xfb\xdf\xf6\xdf\xf4\xf6\xf8\xfb\xdf\xf6\xdf\xf4\xf6\xf6\xfb\xdf\xf8\xdf\xf6\xf6\xf2\xfb\xdf\xfb\xdc\xfb\xf8\xf2\xf9\xf9\xdf\xfb\xfb\xfb\xf6\xf4\xf8\xdc\xdf\xf6\xf8\xf8\xf6\xf8\xfb\xdc\xf8\xf8\xfa\xfa\xf5\xf5\xde\xf5\xf5\xdf\xf8\xf3\xf8\xdf\xf4\xf6\xdc\xfb\xf6\xf6\xdf\xf6\xfb\xdf\xf6\xf8\xf6\xdc\xf8\xfb\xfb\xf8\xf8\xf8"));
rcv($sock_c, $port_c, rtpm(9, $seq + 11, $ts + 1760, $ssrc, "\xfa\xde\xf1\xf8\xfa\xdc\xf5\xf5\xf8\xf8\xfa\xde\xf3\xf8\xf5\xfb\xdc\xfa\xfa\xf8\xf3\xfb\xdf\xf5\xfb\xde\xf3\xf6\xf6\xdc\xdf\xf8\xfb\xf8\xf4\xf4\xdf\xfb\xdf\xf4\xfb\xfb\xf6\xf8\xfb\xdc\xf8\xfa\xfa\xf8\xf3\xde\xf3\xda\xf4\xf6\xfb\xf8\xfb\xdf\xf8\xf8\xf8\xf8\xf8\xf5\xfa\xdc\xf5\xf5\xf8\xdc\xf8\xf3\xdf\xf0\xfb\xdf\xf8\xdc\xf4\xfb\xf6\xf6\xdf\xf8\xdc\xfb\xf8\xf5\xf6\xdf\xf2\xfb\xdc\xfb\xdf\xf4\xf8\xf6\xf8\xf8\xdf\xfb\xf8\xf8\xf8\xf5\xf8\xde\xf3\xf8\xfa\xde\xf1\xfb\xdf\xf6\xf6\xf8\xdf\xf8\xfb\xfa\xf8\xf3\xdf\xf6\xdf\xf6\xf8\xfb\xfb\xfa\xf8\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa"));
rcv($sock_c, $port_c, rtpm(9, $seq + 12, $ts + 1920, $ssrc, "\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xde\xee\xd8\xf8\xf7\xdc\xf4\xdc\xef\xda\xf4\xfb\xda\xf0\xdd\xf3\xd8\xf6\xdf\xf9\xf4\xdf\xef\xd5\xf9\xf9\xf9\xf9\xf9\xf0\xdb\xf7\xda\xf3\xda\xf7\xf5\xde\xfa\xd9\xf5\xfc\xf8\xf6\xdc\xfb\xd7\xf1\xf7\xdc\xf7\xde\xfa\xd8\xf7\xf7\xde\xf7\xfe\xdc\xdb\xf4\xf4\xfe\xfa\xf7\xd8\xd7\xf2\xf3\xdc\xf9\xf5\xd9\xd5\xf5\xf1\xfb\xdc\xf8\xfc\xd6\xfb"));

# push media
snd($sock_a, $port_b, rtp (0, 1002, 3320, 0x1234, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, 0x1234, "\x44" x 160));
snd($sock_b, $port_a, rtp (0, 8001, 10160, 0x2d8c, "\x55" x 160));
rcv($sock_a, $port_b, rtpm(0, 8001, 10160, 0x2d8c, "\x55" x 160));
rcv($sock_c, $port_c, rtpm(9, $seq + 13, $ts + 2080, $ssrc, "\xf1\xf6\xdb\xf8\xfc\xd7\xfb\xf3\xf6\xde\xfb\xdd\xd8\xfe\xf3\xf5\xfe\xdf\xfc\xda\xdf\xf1\xf4\xf8\xdf\xfc\xdc\xdd\xf5\xf6\xfb\xdf\xfb\xdf\xdf\xf8\xf4\xf6\xfe\xfe\x1e\x99\x2c\x87\x22\x84\x0b\xaf\xb5\xbb\x1f\xb9\x57\xd3\xfa\x74\xf6\xff\xff\xd9\xd3\x9f\x76\xf7\xfd\xfb\xdb\xd7\xda\xfb\xfc\xf8\xb6\x5e\xd8\xd6\xbe\x5e\xfc\xb6\x7d\xdd\xd8\xda\x9d\x5f\xf9\xbb\x5d\xdc\xda\xdd\x9b\x7c\xfb\x9d\x5e\xdf\xde\x9a\x5e\xfd\xfe\x9a\x7f\xdd\xda\xdc\xdd\xdf\xfe\xdb\x7c\x9d\xdb\xdf\xfe\x9b\x7e\x9b\xfc\x1e\x98\x36\x8a\x20\xa9\x4c\x99\x79\x7a\xd8\x7b\xf2\xff\xd9\xdf\xf9\xde\xfe\x79\xf8\xfd\xdf\xfc\xfd\xbe\x5f\xf8\x79\xfe\x9e\xfc\xfb\x5d\xff\xfb\xfe\xbe\xdf"));

rtpe_req('delete', 'delete');




($sock_a, $sock_b, $sock_c) = new_call([qw(198.51.100.4 4078)], [qw(198.51.100.4 4080)], [qw(198.51.100.4 4082)]);

($port_a) = offer('mixed sub manual', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4078 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('mixed sub manual', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4080 RTP/AVP 0
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($cid, $ft, $port_c) = create('mixed sub manual', {
	codec => { offer => ['G722'] },
	'call-id' => cid(),
}, <<SDP);
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 9
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=sendrecv
a=rtcp:PORT
SDP

is($cid, cid(), 'same call');

create_answer('mixed sub manual', {
	'from-tag' => $ft,
}, <<SDP);
v=0
o=- 111111111 22222222 IN IP4 203.0.113.1
s=22222222
t=0 0
m=audio 4082 RTP/AVP 9
c=IN IP4 198.51.100.4
SDP


# no media playback without subscriptions (XXX change this?)
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

snd($sock_a, $port_b, rtp (0, 1000, 3000, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

snd($sock_b, $port_a, rtp (0, 8000, 10000, 0x2d8c, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 8000, 10000, 0x2d8c, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

snd($sock_c, $port_c, rtp (9, 8200, 10200, 0x2e54, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);


rtpe_req('connect', 'mixed sub manual', {
		'from-tag' => ft(),
		'to-tag' => $ft,
		flags => [qw,directional,],
		'audio player' => 'force',
});

# player not active yet (no media)
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

# add media to start player
snd($sock_a, $port_b, rtp (0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
($seq, $ts, $ssrc) = rcv($sock_c, $port_c, rtpm(9 | 0x80, -1, -1, -1, "\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\x2a\x84\x20\x84\x20\x84\x04\x8e\x16\x9d\x5d\xfe\xdb\xd8\xd1\xd3\xd9\xd9\x9b\xdc\xd9\xd7\xd7\xd8\xd6\xd9\xda\xdb\xd9\xd7\xda\xd7\x9a\xd9\xd8\xd8\xd6\xd9\xd7\xda\xd9\xd9\xd9\xd6\xda\xd7\xda\xda\xd9\xd9\xd6\xda\xd7\xdb\xda\xda\xd9\xd7\xdb\xd8\xd6\xda\xdb\xdb\xd8\xd6\xda\xd8\xd6\xdb\xdb\xdc\xd3\xdf\xd9\xd6\xd9\xd9\xdc\xd2\x9e\x1b\x96\x3f\x8b\x20\xb5\x0c\xba\x3f\xbe\xd5\x6d\xf0\xd5\xdb\x7b\xdf\xdc\xf6\xf1\xdd\xd8\xdd\xdf\xfd\xf8\xf1\xfc\xdd\xda\x9e\xff\x7d\xf2\xfc\xbb\xd8\xdb\xfc"));

# untriggered media
rcv($sock_c, $port_c, rtpm(9, $seq +  1, $ts +  160, $ssrc, "\xff\xf5\xfb\xbb\xdc\xd9\xfe\xdd\xf8\xf8\xf7\xdf\xdd\xfe\xdc\xfe\xfd\xf6\xff\xde\xfd\xfe\xde\xff\xf9\xfa\xdf\xfd\xfc\xff\xdf\xfb\xfb\xde\xfd\xfd\xfc\xff\xff\xfb\xdf\xfc\xfc\xfc\xfb\xdf\xfa\xfe\xdf\xfc\xfc\xf9\xff\xfd\xfd\xfe\xfe\xdf\xfa\xfc\xfc\xfc\xfc\xfc\xff\xfc\xfd\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfb\xdf\xfb\xff\xff\xff\xff\xfc\xfd\xfc\xfc\xfb\xfe\xdf\xfa\xfc\xfc\xfb\xfc\xfb\xdf\xfc\xfa\xfb\xdf\xf9\xf9\xfe\xdf\xfa\xf9\xfc\xfc\xfc\xfb\xdf\xf8\xfb\xfe\xfc\xfc\xfb\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfb\xdf\xf3\xfe\xfa\xfa\xfb\xdf\xf6\xfa\xf8\xf7\xde\xf4\xdf\xf6\xf8\xf7\xfb\xdf\xf7\xdd\xf9\xfb\xf9\xf7\xfb\xf9\xfb\xdf\xf7\xf9\xf9\xfb"));

# catch up to delay caused by rcv_no above
rcv($sock_c, $port_c, rtpm(9, $seq +  2, $ts +  320, $ssrc, "\xfb\xf9\xf9\xfb\xfb\xf9\xf9\xfb\xfb\xf8\xf8\xfb\xfb\xf8\xf8\xfa\xfa\xf8\xf8\xfa\xfa\xf8\xf8\xfa\xfa\xf7\xfa\xfa\xfa\xfa\xfa\xfa\xf7\xfa\xfa\xfa\xfa\xfa\xfa\xf7\xfa\xde\xf2\xde\xf2\xde\xf0\xfa\xdc\xf3\xdc\xf3\xdf\xf3\xfb\xfb\xfb\xfb\xfb\xfa\xf8\xf8\xfa\xfa\xf8\xf8\xfa\xde\xee\xde\xf5\xfb\xfa\xf8\xde\xf1\xdf\xf6\xf8\xf8\xf8\xfa\xf8\xfa\xde\xf1\xfa\xfa\xf8\xf8\xfa\xd9\xf3\xf8\xf8\xfa\xde\xf1\xdc\xf6\xf8\xf8\xf8\xde\xf3\xfb\xf8\xf8\xfa\xde\xf3\xf8\xf8\xfa\xde\xf1\xdf\xf6\xf8\xf8\xf8\xde\xf5\xf8\xf8\xf8\xf8\xf8\xde\xf5\xf5\xf8\xfa\xfa\xf8\xde\xf5\xf5\xf8\xfa\xde\xf1\xde\xf5\xf5\xf8\xfa\xdc\xf8\xf8\xf5\xf5\xf8\xfa\xd9\xf8\xf5\xf8\xf8\xf5"));
rcv($sock_c, $port_c, rtpm(9, $seq +  3, $ts +  480, $ssrc, "\xf8\xdc\xde\xef\xfb\xdf\xf0\xfb\xd6\xf4\xf3\xdf\xf9\xf3\xf9\xd9\xfb\xf5\xfb\xdf\xf2\xf7\xdd\xdf\xf7\xdf\xf5\xf5\xf7\xdd\xdf\xf9\xfb\xf9\xf3\xfb\xdf\xf9\xdf\xf9\xf7\xf5\xf5\xdf\xfb\xdf\xf9\xf7\xf9\xf5\xfb\xdf\xf9\xfb\xfb\xf6\xf6\xf9\xdf\xfb\xfb\xfb\xf9\xf4\xf9\xdf\xf6\xdf\xf6\xf9\xf6\xf9\xfb\xdf\xf8\xf8\xfb\xf6\xf6\xfb\xdc\xfb\xdf\xf4\xf6\xfb\xf6\xdf\xf4\xdc\xdf\xf4\xf6\xfb\xf8\xf6\xdc\xdf\xf4\xf8\xfb\xfb\xf4\xfb\xda\xf2\xdf\xf6\xfb\xf8\xf8\xdf\xf4\xfb\xfb\xfb\xf8\xf8\xdf\xf3\xf8\xfb\xdf\xf2\xfb\xdc\xf8\xf6\xdc\xfb\xf4\xf8\xdf\xf8\xf5\xfb\xdf\xf1\xf6\xdc\xf8\xf8\xfb\xdf\xf4\xf6\xdf\xf6\xf8\xfb\xdc\xf8\xf5\xfb\xf8\xf5\xfb\xdc\xf5\xf8"));
rcv($sock_c, $port_c, rtpm(9, $seq +  4, $ts +  640, $ssrc, "\xfa\xf5\xf8\xfa\xdc\xf8\xf5\xf5\xf8\xde\xf5\xf8\xf8\xf5\xf8\xfa\xdc\xf8\xf5\xf5\xf8\xfa\xdc\xf8\xf8\xf5\xf5\xf8\xfa\xd9\xf8\xf8\xf5\xf5\xf8\xfa\xd9\xf8\xfa\xfa\xf5\xf3\xde\xf8\xde\xf8\xf8\xf5\xf1\xfa\xde\xfa\xde\xf3\xf8\xf3\xf6\xdc\xfb\xda\xf6\xf8\xf4\xf6\xfb\xf8\xdc\xdf\xf6\xf8\xf6\xf8\xf6\xdf\xfb\xfb\xfb\xf8\xf6\xf8\xfb\xdc\xf8\xf8\xfa\xf5\xf3\xdf\xf8\xf8\xdc\xfa\xf8\xef\xdf\xf8\xf6\xdc\xf8\xdf\xf0\xf8\xfb\xf8\xfb\xfb\xdf\xf4\xf8\xf8\xfa\xfa\xf8\xfa\xde\xf1\xf8\xfa\xde\xf1\xf6\xda\xf4\xfb\xf6\xdf\xf6\xf6\xdd\xf8\xfb\xf8\xf8\xfb\xf8\xf8\xfa\xfa\xf8\xf8\xfa\xde\xf3\xf8\xf8\xfa\xde\xf3\xde\xf3\xf8\xf8\xfb\xdc\xf5\xfa\xf8\xf5\xf8\xfa"));
rcv($sock_c, $port_c, rtpm(9, $seq +  5, $ts +  800, $ssrc, "\xd9\xf5\xf8\xfa\xfa\xf8\xf5\xde\xf5\xf8\xfa\xde\xf3\xf5\xfb\xdf\xf5\xf8\xdc\xf8\xf3\xf6\xdc\xf8\xf8\xdf\xf3\xf6\xfb\xdf\xf6\xfb\xfb\xf8\xf6\xdc\xfb\xf8\xf6\xfb\xfb\xf8\xfa\xdc\xf8\xf5\xf5\xf8\xfa\xde\xf5\xfa\xde\xf1\xf6\xfb\xdf\xf5\xf6\xd8\xf6\xf8\xf2\xdf\xf9\xf6\xda\xf4\xdf\xf3\xf7\xf9\xf7\xd9\xfb\xdf\xf3\xf7\xf7\xf9\xdd\xdb\xfb\xf7\xf2\xf4\xfa\xdb\xdf\xfb\xf9\xf3\xf6\xf6\xde\xde\xdf\xf4\xf6\xf6\xf5\xfa\xde\xfb\xde\xf4\xf8\xf6\xf8\xf9\xfb\xdd\xf9\xfb\xf9\xf7\xfb\xf9\xfb\xdd\xf9\xfb\xf9\xf6\xdf\xf3\xdf\xf9\xfb\xdf\xf4\xdf\xf4\xf7\xfb\xfb\xdf\xf6\xfb\xfb\xf9\xf6\xdf\xf9\xf9\xfb\xfb\xf6\xf9\xfb\xdf\xf6\xfb\xfb\xf8\xf6\xfb\xdf\xf6\xdf"));
rcv($sock_c, $port_c, rtpm(9, $seq +  6, $ts +  960, $ssrc, "\xf6\xfb\xf6\xf8\xfb\xdf\xf8\xf8\xfa\xf8\xf3\xfb\xdc\xf8\xf8\xde\xf5\xf1\xf6\xda\xf0\xf9\xd8\xfb\xf6\xf4\xdf\xf4\xf6\xdd\xdf\xf6\xf9\xfb\xfb\xf9\xf9\xdf\xf4\xfb\xf9\xf8\xfb\xdf\xf4\xfb\xf8\xf8\xfb\xfb\xde\xf1\xfb\xfb\xfb\xfa\xf8\xde\xf3\xfb\xf8\xf8\xde\xf3\xda\xf0\xf9\xf6\xdf\xf9\xf6\xda\xf3\xfb\xf4\xfb\xdd\xf9\xdd\xf9\xf9\xf6\xf9\xf9\xfb\xdc\xf8\xf8\xf6\xdf\xf4\xf6\xdf\xf6\xdf\xf6\xdf\xf6\xf6\xfb\xfb\xdf\xf6\xfb\xfb\xf8\xf6\xfb\xdf\xf6\xf8\xfb\xfb\xf8\xf8\xde\xf3\xf8\xfb\xfb\xfa\xde\xf3\xf8\xfb\xfb\xfa\xfa\xde\xf1\xf8\xfa\xfa\xfa\xfa\xdc\xf5\xf5\xf8\xfa\xde\xf1\xfa\xdc\xf5\xf5\xf8\xde\xf3\xdf\xf6\xf6\xf6\xf8\xdc\xdf\xf8\xf8\xf6\xf4"));
rcv($sock_c, $port_c, rtpm(9, $seq +  7, $ts + 1120, $ssrc, "\xf4\xdf\xdf\xfb\xdf\xf4\xf4\xf4\xf8\xdc\xdf\xfb\xfb\xf6\xf4\xf6\xdf\xfb\xdc\xfb\xfb\xf5\xf2\xfb\xf8\xdf\xf8\xdc\xfb\xf5\xf4\xf6\xdf\xf6\xfb\xdf\xf8\xfb\xfb\xfa\xf8\xf5\xfa\xdc\xf5\xf5\xf8\xfa\xf8\xf3\xda\xf6\xf6\xfb\xdf\xf6\xf6\xdc\xfb\xdf\xf2\xfb\xfb\xfb\xfb\xdf\xf6\xf6\xfb\xdf\xf6\xf8\xdf\xf8\xf8\xf8\xfa\xfa\xf8\xf8\xfa\xde\xf1\xf8\xfa\xde\xf1\xf8\xde\xf3\xfb\xf6\xdf\xf6\xfb\xdf\xf6\xfb\xf8\xfb\xde\xf1\xdf\xf6\xf8\xf8\xfb\xdf\xf3\xdf\xf4\xf8\xfb\xfb\xfb\xf8\xfa\xfa\xf8\xf8\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa"));
rcv($sock_c, $port_c, rtpm(9, $seq +  8, $ts + 1280, $ssrc, "\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xde\xee\xd6\xef\xdc\xdf\xf4\xda\xec\xdd\xf6\xda\xf9\xf4\xdb\xef\xda\xf3\xd6\xf7\xfa\xd9\xf2\xfe\xf8\xda\xf7\xde\xfa\xf8\xf7\xfe\xd9\xf7\xdc\xfa\xfa\xf6\xfc\xdc\xfb\xd9\xf8\xf5\xf6\xfb\xd9\xfb\xd7\xf2\xf6\xfa\xfc\xfe\xd9\xd9\xf6\xf4\xf7\xde\xf6\xd8\xd8\xf7\xf6\xf7\xde\xf4\xdd\xd4\xfc\xf1\xf6\xdf\xf4\xfc\xd4\xdf\xf0\xf4\xfc\xf8\xf9\xd7\xdd\xf4\xf3\xfc\xf9\xfb\xd7\xdd\xf7\xf7\xfb\xf8\xf6\xd7\xdc"));
rcv($sock_c, $port_c, rtpm(9, $seq +  9, $ts + 1440, $ssrc, "\xf8\xf7\xfb\xf7\xf8\xdb\xdd\xfe\xf9\xf8\xf5\xf8\xdd\xdd\xfe\xfe\xf9\xf7\xfc\xfc\xdc\xfe\xfe\xfa\xf8\xfa\xfb\xdc\xfb\xdc\xf9\xf6\xf9\xf7\xdb\xf5\xfb\xda\xf5\xf8\xfa\xde\xf6\xfa\xdb\xf5\xf8\xfb\xdb\xf3\xfb\xd9\xfa\xf6\xfa\xde\xf6\xfa\xde\xfa\xfa\xf9\xdf\xf6\xf7\xdd\xfb\xdd\xf9\xf9\xf5\xf7\xfb\xdf\xf9\xfb\xfb\xf7\xf7\xdf\xf9\xfb\xfb\xf9\xf6\xfb\xdf\xf6\xfb\xf9\xf9\xf9\xf9\xdf\xf4\xf9\xf9\xf8\xf8\xf8\xdf\xf4\xf8\xf8\xf8\xf8\xf8\xde\xf3\xfb\xfb\xfb\xfa\xfa\xdc\xf5\xf5\xf8\xfa\xde\xf1\xdf\xf6\xfb\xf8\xf5\xdf\xf4\xdf\xf6\xf8\xf6\xf8\xfb\xdf\xf8\xf8\xf8\xf5\xf5\xf8\xdc\xde\xf3\xf8\xf8\xf3\xfb\xdc\xdf\xf2\xdc\xfb\xf6\xf6\xdf\xf6\xf8\xdf\xf8"));
rcv($sock_c, $port_c, rtpm(9, $seq + 10, $ts + 1600, $ssrc, "\xf8\xf6\xdc\xf6\xf8\xfb\xfb\xfb\xf5\xfb\xdc\xf5\xf8\xf8\xf8\xf8\xf5\xde\xf8\xf8\xf8\xf8\xf8\xf5\xfa\xdc\xf8\xf8\xf7\xfa\xf7\xf8\xde\xf7\xde\xf0\xf8\xf8\xf8\xde\xf3\xdc\xf5\xf3\xdf\xf8\xfa\xf5\xfb\xde\xf1\xf8\xdf\xf8\xf3\xf8\xdf\xf6\xf8\xfb\xfb\xf6\xfb\xdf\xf4\xfb\xdf\xf1\xf6\xdf\xfb\xf6\xf8\xdc\xf8\xf6\xdf\xf6\xf6\xf8\xfb\xdf\xf6\xdf\xf4\xf6\xf8\xfb\xdf\xf6\xdf\xf4\xf6\xf6\xfb\xdf\xf8\xdf\xf6\xf6\xf2\xfb\xdf\xfb\xdc\xfb\xf8\xf2\xf9\xf9\xdf\xfb\xfb\xfb\xf6\xf4\xf8\xdc\xdf\xf6\xf8\xf8\xf6\xf8\xfb\xdc\xf8\xf8\xfa\xfa\xf5\xf5\xde\xf5\xf5\xdf\xf8\xf3\xf8\xdf\xf4\xf6\xdc\xfb\xf6\xf6\xdf\xf6\xfb\xdf\xf6\xf8\xf6\xdc\xf8\xfb\xfb\xf8\xf8\xf8"));
rcv($sock_c, $port_c, rtpm(9, $seq + 11, $ts + 1760, $ssrc, "\xfa\xde\xf1\xf8\xfa\xdc\xf5\xf5\xf8\xf8\xfa\xde\xf3\xf8\xf5\xfb\xdc\xfa\xfa\xf8\xf3\xfb\xdf\xf5\xfb\xde\xf3\xf6\xf6\xdc\xdf\xf8\xfb\xf8\xf4\xf4\xdf\xfb\xdf\xf4\xfb\xfb\xf6\xf8\xfb\xdc\xf8\xfa\xfa\xf8\xf3\xde\xf3\xda\xf4\xf6\xfb\xf8\xfb\xdf\xf8\xf8\xf8\xf8\xf8\xf5\xfa\xdc\xf5\xf5\xf8\xdc\xf8\xf3\xdf\xf0\xfb\xdf\xf8\xdc\xf4\xfb\xf6\xf6\xdf\xf8\xdc\xfb\xf8\xf5\xf6\xdf\xf2\xfb\xdc\xfb\xdf\xf4\xf8\xf6\xf8\xf8\xdf\xfb\xf8\xf8\xf8\xf5\xf8\xde\xf3\xf8\xfa\xde\xf1\xfb\xdf\xf6\xf6\xf8\xdf\xf8\xfb\xfa\xf8\xf3\xdf\xf6\xdf\xf6\xf8\xfb\xfb\xfa\xf8\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa"));
rcv($sock_c, $port_c, rtpm(9, $seq + 12, $ts + 1920, $ssrc, "\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xde\xee\xd8\xf8\xf7\xdc\xf4\xdc\xef\xda\xf4\xfb\xda\xf0\xdd\xf3\xd8\xf6\xdf\xf9\xf4\xdf\xef\xd5\xf9\xf9\xf9\xf9\xf9\xf0\xdb\xf7\xda\xf3\xda\xf7\xf5\xde\xfa\xd9\xf5\xfc\xf8\xf6\xdc\xfb\xd7\xf1\xf7\xdc\xf7\xde\xfa\xd8\xf7\xf7\xde\xf7\xfe\xdc\xdb\xf4\xf4\xfe\xfa\xf7\xd8\xd7\xf2\xf3\xdc\xf9\xf5\xd9\xd5\xf5\xf1\xfb\xdc\xf8\xfc\xd6\xfb"));

# push media
snd($sock_a, $port_b, rtp (0, 1002, 3320, 0x1234, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, 0x1234, "\x44" x 160));
snd($sock_b, $port_a, rtp (0, 8001, 10160, 0x2d8c, "\x55" x 160));
rcv($sock_a, $port_b, rtpm(0, 8001, 10160, 0x2d8c, "\x55" x 160));
rcv($sock_c, $port_c, rtpm(9, $seq + 13, $ts + 2080, $ssrc, "\xf1\xf6\xdb\xf8\xfc\xd7\xfb\xf3\xf6\xde\xfb\xdd\xd8\xfe\xf3\xf5\xfe\xdf\xfc\xda\xdf\xf1\xf4\xf8\xdf\xfc\xdc\xdd\xf5\xf6\xfb\xdf\xfb\xdf\xdf\xf8\xf4\xf6\xfe\xfe\x1e\x99\x2c\x87\x22\x84\x0b\xaf\xb5\xbb\x1f\xb9\x57\xd3\xfa\x74\xf6\xff\xff\xd9\xd3\x9f\x76\xf7\xfd\xfb\xdb\xd7\xda\xfb\xfc\xf8\xb6\x5e\xd8\xd6\xbe\x5e\xfc\xb6\x7d\xdd\xd8\xda\x9d\x5f\xf9\xbb\x5d\xdc\xda\xdd\x9b\x7c\xfb\x9d\x5e\xdf\xde\x9a\x5e\xfd\xfe\x9a\x7f\xdd\xda\xdc\xdd\xdf\xfe\xdb\x7c\x9d\xdb\xdf\xfe\x9b\x7e\x9b\xfc\x1e\x98\x36\x8a\x20\xa9\x4c\x99\x79\x7a\xd8\x7b\xf2\xff\xd9\xdf\xf9\xde\xfe\x79\xf8\xfd\xdf\xfc\xfd\xbe\x5f\xf8\x79\xfe\x9e\xfc\xfb\x5d\xff\xfb\xfe\xbe\xdf"));

rtpe_req('delete', 'delete');




($sock_a, $sock_b, $sock_c) = new_call([qw(198.51.100.4 4090)], [qw(198.51.100.4 4092)], [qw(198.51.100.4 4094)]);

($port_a) = offer('mixed sub manual PCM', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4090 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('mixed sub manual PCM', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4092 RTP/AVP 0
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($cid, $ft, $port_c) = create('mixed sub manual', {
	'audio player' => 'force',
	'call-id' => cid(),
}, <<SDP);
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

is($cid, cid(), 'same call');

create_answer('mixed sub manual PCM', { 'from-tag' => $ft, 'audio player' => 'force', }, <<SDP);
v=0
o=- 111111111 22222222 IN IP4 203.0.113.1
s=22222222
t=0 0
m=audio 4094 RTP/AVP 0
c=IN IP4 198.51.100.4
SDP


# no media playback without subscriptions (XXX change this?)
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

snd($sock_a, $port_b, rtp (0, 1000, 3000, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

snd($sock_b, $port_a, rtp (0, 8000, 10000, 0x2d8c, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 8000, 10000, 0x2d8c, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

snd($sock_c, $port_c, rtp (9, 8200, 10200, 0x2e54, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);


# connect A side
rtpe_req('connect', 'mixed sub manual PCM', {
		'from-tag' => ft(),
		'to-tag' => $ft,
		flags => [qw,directional,],
		'audio player' => 'force',
});

# player not active yet (no media)
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);

# add media to start player
snd($sock_a, $port_b, rtp (0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
($seq, $ts, $ssrc) = rcv($sock_c, $port_c, rtpm(0 | 0x80, -1, -1, -1, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"));

# untriggered media
rcv($sock_c, $port_c, rtpm(0, $seq +  1, $ts +  160, $ssrc, "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"));

# catch up to the delay caused by rcv_no above
rcv($sock_c, $port_c, rtpm(0, $seq +  2, $ts +  320, $ssrc, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"));
rcv($sock_c, $port_c, rtpm(0, $seq +  3, $ts +  480, $ssrc, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"));
rcv($sock_c, $port_c, rtpm(0, $seq +  4, $ts +  640, $ssrc, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"));
rcv($sock_c, $port_c, rtpm(0, $seq +  5, $ts +  800, $ssrc, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"));
rcv($sock_c, $port_c, rtpm(0, $seq +  6, $ts +  960, $ssrc, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"));
rcv($sock_c, $port_c, rtpm(0, $seq +  7, $ts + 1120, $ssrc, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"));
rcv($sock_c, $port_c, rtpm(0, $seq +  8, $ts + 1280, $ssrc, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"));
rcv($sock_c, $port_c, rtpm(0, $seq +  9, $ts + 1440, $ssrc, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"));
rcv($sock_c, $port_c, rtpm(0, $seq + 10, $ts + 1600, $ssrc, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"));
rcv($sock_c, $port_c, rtpm(0, $seq + 11, $ts + 1760, $ssrc, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"));
rcv($sock_c, $port_c, rtpm(0, $seq + 12, $ts + 1920, $ssrc, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"));

# push media
snd($sock_a, $port_b, rtp (0, 1002, 3320, 0x1234, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, 0x1234, "\x44" x 160));
snd($sock_b, $port_a, rtp (0, 8001, 10160, 0x2d8c, "\x55" x 160));
rcv($sock_a, $port_b, rtpm(0, 8001, 10160, 0x2d8c, "\x55" x 160));
rcv($sock_c, $port_c, rtpm(0, $seq + 13, $ts + 2080, $ssrc, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44"));

snd($sock_a, $port_b, rtp (0, 1003, 3480, 0x1234, "\x77" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3480, 0x1234, "\x77" x 160));
snd($sock_b, $port_a, rtp (0, 8002, 10320, 0x2d8c, "\x99" x 160));
rcv($sock_a, $port_b, rtpm(0, 8002, 10320, 0x2d8c, "\x99" x 160));
rcv($sock_c, $port_c, rtpm(0, $seq + 14, $ts + 2240, $ssrc, "\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77"));

# connect in B side
rtpe_req('connect', 'mixed sub manual PCM', {
		'from-tag' => tt(),
		'to-tag' => $ft,
		flags => [qw,directional,],
		'audio player' => 'force',
});

snd($sock_a, $port_b, rtp (0, 1004, 3640, 0x1234, "\xbb" x 160));
rcv($sock_b, $port_a, rtpm(0, 1004, 3640, 0x1234, "\xbb" x 160));
snd($sock_b, $port_a, rtp (0, 8003, 10480, 0x2d8c, "\x99" x 160));
rcv($sock_a, $port_b, rtpm(0, 8003, 10480, 0x2d8c, "\x99" x 160));
rcv($sock_c, $port_c, rtpm(0, $seq + 15, $ts + 2400, $ssrc, "\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94"));

snd($sock_a, $port_b, rtp (0, 1005, 3800, 0x1234, "\xcc" x 160));
rcv($sock_b, $port_a, rtpm(0, 1005, 3800, 0x1234, "\xcc" x 160));
snd($sock_b, $port_a, rtp (0, 8004, 10640, 0x2d8c, "\x99" x 160));
rcv($sock_a, $port_b, rtpm(0, 8004, 10640, 0x2d8c, "\x99" x 160));
rcv($sock_c, $port_c, rtpm(0, $seq + 16, $ts + 2560, $ssrc, "\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97"));

snd($sock_a, $port_b, rtp (0, 1006, 3960, 0x1234, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3960, 0x1234, "\x44" x 160));
snd($sock_b, $port_a, rtp (0, 8005, 10800, 0x2d8c, "\x99" x 160));
rcv($sock_a, $port_b, rtpm(0, 8005, 10800, 0x2d8c, "\x99" x 160));
rcv($sock_c, $port_c, rtpm(0, $seq + 17, $ts + 2720, $ssrc, "\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c"));

snd($sock_a, $port_b, rtp (0, 1007, 4120, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1007, 4120, 0x1234, "\x11" x 160));
snd($sock_b, $port_a, rtp (0, 8006, 10960, 0x2d8c, "\x99" x 160));
rcv($sock_a, $port_b, rtpm(0, 8006, 10960, 0x2d8c, "\x99" x 160));
rcv($sock_c, $port_c, rtpm(0, $seq +  18, $ts + 2880, $ssrc, "\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x9c\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f"));


rtpe_req('delete', 'delete');



($sock_a, $sock_b) = new_call([qw(198.51.100.10 4070)], [qw(198.51.100.10 4072)]);

($port_a) = offer('extended connect w "all" bidirectional', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 4070 RTP/AVP 0 8
c=IN IP4 198.51.100.10
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('extended connect w "all" bidirectional', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 4072 RTP/AVP 0 8
c=IN IP4 198.51.100.10
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$cid1 = cid();
$ft = ft();
$tt = tt();

($sock_c, $sock_d) = new_call_nc([qw(198.51.100.10 4074)], [qw(198.51.100.10 4076)]);

($port_c) = offer('extended connect w "all" bidirectional', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 4074 RTP/AVP 0 8
c=IN IP4 198.51.100.10
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_d) = answer('extended connect w "all" bidirectional', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 4076 RTP/AVP 0 8
c=IN IP4 198.51.100.10
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_a, $port_b, rtp (0, 1000, 3000, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5000, 7000, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5000, 7000, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect w "all" bidirectional', {
		'to-tag' => $tt,
		'to-call-id' => $cid1,
		flags => [qw,directional bidirectional all,],
});


snd($sock_a, $port_b, rtp (0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


# calls are merged now

rtpe_req('connect', 'extended connect w "all" bidirectional', {
		'to-tag' => $ft,
		'to-call-id' => $cid1,
		flags => [qw,directional bidirectional all,],
});

snd($sock_a, $port_b, rtp (0, 1002, 3320, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1002, 3320, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1002, 3320, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect w "all" bidirectional', {
		'to-tag' => ft(),
		'to-call-id' => cid(),
		flags => [qw,directional bidirectional all,],
});

snd($sock_a, $port_b, rtp (0, 1006, 3800, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3800, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1006, 3800, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1006, 3800, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('connect', 'extended connect w "all" bidirectional', {
		'to-tag' => tt(),
		'to-call-id' => $cid1,
		flags => [qw,directional bidirectional all,],
});

snd($sock_a, $port_b, rtp (0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('unsubscribe', 'extended connect w "all" bidirectional', {
		'from-tag' => tt(),
		'to-tag' => $tt,
		flags => [qw,directional bidirectional,],
});

snd($sock_a, $port_b, rtp (0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('unsubscribe', 'extended connect w "all" bidirectional', {
		'from-tag' => ft(),
		'to-tag' => $ft,
		flags => [],
});

snd($sock_a, $port_b, rtp (0, 1011, 4760, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3011, 6760, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3011, 6760, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5011, 8760, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5011, 8760, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5011, 8760, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7011, 10760, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7011, 10760, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);





($sock_a, $sock_b) = new_call([qw(198.51.100.8 4070)], [qw(198.51.100.8 4072)]);

($port_a) = offer('extended connect w from-tags bidirectional', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4070 RTP/AVP 0 8
c=IN IP4 198.51.100.8
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('extended connect w from-tags bidirectional', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4072 RTP/AVP 0 8
c=IN IP4 198.51.100.8
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$cid1 = cid();
$ft = ft();
$tt = tt();

($sock_c, $sock_d) = new_call_nc([qw(198.51.100.8 4074)], [qw(198.51.100.8 4076)]);

($port_c) = offer('extended connect w from-tags bidirectional', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4074 RTP/AVP 0 8
c=IN IP4 198.51.100.8
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_d) = answer('extended connect w from-tags bidirectional', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4076 RTP/AVP 0 8
c=IN IP4 198.51.100.8
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_a, $port_b, rtp (0, 1000, 3000, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5000, 7000, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5000, 7000, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect w from-tags bidirectional', {
		'from-tags' => [ft(), tt()],
		'to-tag' => $tt,
		'to-call-id' => $cid1,
		flags => [qw,directional bidirectional,],
});


snd($sock_a, $port_b, rtp (0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect w from-tags bidirectional', {
		'from-tags' => [ft(), tt()],
		'to-tag' => $ft,
		'to-call-id' => $cid1,
		flags => [qw,directional bidirectional,],
});

snd($sock_a, $port_b, rtp (0, 1002, 3320, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1002, 3320, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1002, 3320, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


# calls are merged now, so can connect all tags

rtpe_req('connect', 'extended connect w from-tags bidirectional', {
		'from-tags' => [$ft, $tt, tt()],
		'to-tag' => ft(),
		'to-call-id' => cid(),
		flags => [qw,directional bidirectional,],
});

snd($sock_a, $port_b, rtp (0, 1006, 3800, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3800, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1006, 3800, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1006, 3800, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('connect', 'extended connect w from-tags bidirectional', {
		'from-tags' => [$ft, $tt, ft()],
		'to-tag' => tt(),
		'to-call-id' => $cid1,
		flags => [qw,directional bidirectional,],
});

snd($sock_a, $port_b, rtp (0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('unsubscribe', 'extended connect w from-tags bidirectional', {
		'from-tag' => tt(),
		'to-tag' => $tt,
		flags => [qw,directional bidirectional,],
});

snd($sock_a, $port_b, rtp (0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('unsubscribe', 'extended connect w from-tags bidirectional', {
		'from-tag' => ft(),
		'to-tag' => $ft,
		flags => [],
});

snd($sock_a, $port_b, rtp (0, 1011, 4760, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3011, 6760, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3011, 6760, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5011, 8760, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5011, 8760, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5011, 8760, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7011, 10760, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7011, 10760, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);





($sock_a, $sock_b) = new_call([qw(198.51.100.8 4052)], [qw(198.51.100.8 4054)]);

($port_a) = offer('extended connect w from-tags', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4052 RTP/AVP 0 8
c=IN IP4 198.51.100.8
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('extended connect w from-tags', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4054 RTP/AVP 0 8
c=IN IP4 198.51.100.8
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$cid1 = cid();
$ft = ft();
$tt = tt();

($sock_c, $sock_d) = new_call_nc([qw(198.51.100.8 4056)], [qw(198.51.100.8 4058)]);

($port_c) = offer('extended connect w from-tags', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4056 RTP/AVP 0 8
c=IN IP4 198.51.100.8
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_d) = answer('extended connect w from-tags', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio 4058 RTP/AVP 0 8
c=IN IP4 198.51.100.8
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.8
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_a, $port_b, rtp (0, 1000, 3000, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5000, 7000, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5000, 7000, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect w from-tags', {
		'from-tags' => [ft(), tt()],
		'to-tag' => $tt,
		'to-call-id' => $cid1,
		flags => [qw,directional,],
});


snd($sock_a, $port_b, rtp (0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


# calls are merged now

rtpe_req('connect', 'extended connect w from-tags', {
		'from-tags' => [ft(), tt(), $tt],
		'to-tag' => $ft,
		'to-call-id' => $cid1,
		flags => [qw,directional,],
});

snd($sock_a, $port_b, rtp (0, 1002, 3320, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect w from-tags', {
		'from-tags' => [$ft, $tt, tt()],
		'to-tag' => ft(),
		'to-call-id' => $cid1,
		flags => [qw,directional,],
});

snd($sock_a, $port_b, rtp (0, 1006, 3800, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3800, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1006, 3800, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('connect', 'extended connect w from-tags', {
		'from-tags' => [$ft, $tt, ft()],
		'to-tag' => tt(),
		'to-call-id' => $cid1,
		flags => [qw,directional,],
});

snd($sock_a, $port_b, rtp (0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('unsubscribe', 'extended connect w from-tags', {
		'from-tag' => tt(),
		'to-tag' => $tt,
		flags => [qw,directional,],
});

snd($sock_a, $port_b, rtp (0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('unsubscribe', 'extended connect w from-tags', {
		'from-tag' => ft(),
		'to-tag' => $ft,
		flags => [],
});

snd($sock_a, $port_b, rtp (0, 1011, 4760, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3011, 6760, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3011, 6760, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3011, 6760, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5011, 8760, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5011, 8760, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5011, 8760, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7011, 10760, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7011, 10760, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);






($sock_a, $sock_b) = new_call([qw(198.51.100.4 4070)], [qw(198.51.100.4 4072)]);

($port_a) = offer('extended connect bidirectional', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4070 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('extended connect bidirectional', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4072 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$cid1 = cid();
$ft = ft();
$tt = tt();

($sock_c, $sock_d) = new_call_nc([qw(198.51.100.4 4074)], [qw(198.51.100.4 4076)]);

($port_c) = offer('extended connect bidirectional', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4074 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_d) = answer('extended connect bidirectional', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4076 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_a, $port_b, rtp (0, 1000, 3000, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5000, 7000, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5000, 7000, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect bidirectional', {
		'from-tag' => ft(),
		'to-tag' => $tt,
		'to-call-id' => $cid1,
		flags => [qw,directional bidirectional,],
});


snd($sock_a, $port_b, rtp (0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect bidirectional', {
		'from-tag' => ft(),
		'to-tag' => $ft,
		'to-call-id' => $cid1,
		flags => [qw,directional bidirectional,],
});

snd($sock_a, $port_b, rtp (0, 1002, 3320, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1002, 3320, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect bidirectional', {
		'from-tag' => tt(),
		'to-tag' => $ft,
		'to-call-id' => $cid1,
		flags => [qw,directional bidirectional,],
});

snd($sock_a, $port_b, rtp (0, 1003, 3480, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3480, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1003, 3480, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1003, 3480, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3003, 5480, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3003, 5480, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3003, 5480, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5003, 7480, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5003, 7480, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5003, 7480, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5003, 7480, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7003, 9480, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7003, 9480, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7003, 9480, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect bidirectional', {
		'from-tag' => tt(),
		'to-tag' => $tt,
		'to-call-id' => $cid1,
		flags => [qw,directional bidirectional,],
});

snd($sock_a, $port_b, rtp (0, 1004, 3640, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1004, 3640, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1004, 3640, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1004, 3640, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3004, 5640, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3004, 5640, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3004, 5640, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3004, 5640, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5004, 7640, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5004, 7640, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5004, 7640, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5004, 7640, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7004, 9640, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7004, 9640, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7004, 9640, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7004, 9640, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('connect', 'extended connect bidirectional', {
		'from-tag' => $ft,
		'to-tag' => ft(),
		'to-call-id' => $cid1,
		flags => [qw,directional bidirectional,],
});

snd($sock_a, $port_b, rtp (0, 1006, 3800, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3800, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1006, 3800, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1006, 3800, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('connect', 'extended connect bidirectional', {
		'from-tag' => $ft,
		'to-tag' => tt(),
		'to-call-id' => $cid1,
		flags => [qw,directional bidirectional,],
});

snd($sock_a, $port_b, rtp (0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect bidirectional', {
		'from-tag' => $tt,
		'to-tag' => ft(),
		'to-call-id' => $cid1,
		flags => [qw,directional bidirectional,],
});

snd($sock_a, $port_b, rtp (0, 1008, 4120, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1008, 4120, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1008, 4120, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1008, 4120, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3008, 6120, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3008, 6120, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3008, 6120, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3008, 6120, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5008, 8120, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5008, 8120, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5008, 8120, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5008, 8120, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7008, 10120, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7008, 10120, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7008, 10120, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7008, 10120, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('connect', 'extended connect bidirectional', {
		'from-tag' => $tt,
		'to-tag' => tt(),
		'to-call-id' => $cid1,
		flags => [qw,directional bidirectional,],
});

snd($sock_a, $port_b, rtp (0, 1009, 4440, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1009, 4440, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1009, 4440, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1009, 4440, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3009, 6440, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3009, 6440, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3009, 6440, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3009, 6440, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5009, 8440, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5009, 8440, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5009, 8440, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5009, 8440, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7009, 10440, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7009, 10440, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7009, 10440, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7009, 10440, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('unsubscribe', 'extended connect bidirectional', {
		'from-tag' => tt(),
		'to-tag' => $tt,
		flags => [qw,directional bidirectional,],
});

snd($sock_a, $port_b, rtp (0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('unsubscribe', 'extended connect bidirectional', {
		'from-tag' => ft(),
		'to-tag' => $ft,
		flags => [],
});

snd($sock_a, $port_b, rtp (0, 1011, 4760, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3011, 6760, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3011, 6760, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5011, 8760, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5011, 8760, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5011, 8760, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7011, 10760, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7011, 10760, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);








($sock_a, $sock_b) = new_call([qw(198.51.100.4 4052)], [qw(198.51.100.4 4054)]);

($port_a) = offer('extended connect', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4052 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('extended connect', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4054 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$cid1 = cid();
$ft = ft();
$tt = tt();

($sock_c, $sock_d) = new_call_nc([qw(198.51.100.4 4056)], [qw(198.51.100.4 4058)]);

($port_c) = offer('extended connect', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4056 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_d) = answer('extended connect', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4058 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_a, $port_b, rtp (0, 1000, 3000, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5000, 7000, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5000, 7000, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect', {
		'from-tag' => ft(),
		'to-tag' => $tt,
		'to-call-id' => $cid1,
		flags => [qw,directional,],
});


snd($sock_a, $port_b, rtp (0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect', {
		'from-tag' => ft(),
		'to-tag' => $ft,
		'to-call-id' => $cid1,
		flags => [qw,directional,],
});

snd($sock_a, $port_b, rtp (0, 1002, 3320, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3002, 5320, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5002, 7320, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7002, 9320, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect', {
		'from-tag' => tt(),
		'to-tag' => $ft,
		'to-call-id' => $cid1,
		flags => [qw,directional,],
});

snd($sock_a, $port_b, rtp (0, 1003, 3480, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3480, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3003, 5480, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3003, 5480, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5003, 7480, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5003, 7480, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5003, 7480, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5003, 7480, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7003, 9480, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7003, 9480, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7003, 9480, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect', {
		'from-tag' => tt(),
		'to-tag' => $tt,
		'to-call-id' => $cid1,
		flags => [qw,directional,],
});

snd($sock_a, $port_b, rtp (0, 1004, 3640, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1004, 3640, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3004, 5640, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3004, 5640, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5004, 7640, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5004, 7640, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5004, 7640, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5004, 7640, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7004, 9640, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7004, 9640, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7004, 9640, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7004, 9640, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('connect', 'extended connect', {
		'from-tag' => $ft,
		'to-tag' => ft(),
		'to-call-id' => $cid1,
		flags => [qw,directional,],
});

snd($sock_a, $port_b, rtp (0, 1006, 3800, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3800, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1006, 3800, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3006, 5800, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5006, 7800, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7006, 9800, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('connect', 'extended connect', {
		'from-tag' => $ft,
		'to-tag' => tt(),
		'to-call-id' => $cid1,
		flags => [qw,directional,],
});

snd($sock_a, $port_b, rtp (0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1007, 3960, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3007, 5960, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5007, 7960, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7007, 9960, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect', {
		'from-tag' => $tt,
		'to-tag' => ft(),
		'to-call-id' => $cid1,
		flags => [qw,directional,],
});

snd($sock_a, $port_b, rtp (0, 1008, 4120, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1008, 4120, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1008, 4120, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1008, 4120, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3008, 6120, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3008, 6120, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3008, 6120, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5008, 8120, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5008, 8120, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5008, 8120, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5008, 8120, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7008, 10120, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7008, 10120, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7008, 10120, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7008, 10120, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('connect', 'extended connect', {
		'from-tag' => $tt,
		'to-tag' => tt(),
		'to-call-id' => $cid1,
		flags => [qw,directional,],
});

snd($sock_a, $port_b, rtp (0, 1009, 4440, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1009, 4440, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1009, 4440, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1009, 4440, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3009, 6440, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3009, 6440, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3009, 6440, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3009, 6440, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5009, 8440, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5009, 8440, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5009, 8440, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5009, 8440, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7009, 10440, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7009, 10440, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7009, 10440, 0x1a04, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 7009, 10440, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('unsubscribe', 'extended connect', {
		'from-tag' => tt(),
		'to-tag' => $tt,
		flags => [qw,directional,],
});

snd($sock_a, $port_b, rtp (0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_c, $port_d, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv($sock_d, $port_c, rtpm(0, 1010, 4600, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3010, 6600, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv($sock_a, $port_b, rtpm(0, 5010, 8600, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv($sock_a, $port_b, rtpm(0, 7010, 10600, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);



rtpe_req('unsubscribe', 'extended connect', {
		'from-tag' => ft(),
		'to-tag' => $ft,
		flags => [],
});

snd($sock_a, $port_b, rtp (0, 1011, 4760, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3011, 6760, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3011, 6760, 0x1a04, "\x22" x 160));
rcv($sock_d, $port_c, rtpm(0, 3011, 6760, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5011, 8760, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5011, 8760, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5011, 8760, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7011, 10760, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7011, 10760, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);





($sock_a, $sock_b) = new_call([qw(198.51.100.4 4036)], [qw(198.51.100.4 4038)]);

($port_a) = offer('extended connect control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4036 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('extended connect control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4038 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$cid1 = cid();
$ft = ft();
$tt = tt();

($sock_c, $sock_d) = new_call_nc([qw(198.51.100.4 4040)], [qw(198.51.100.4 4042)]);

($port_c) = offer('extended connect control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4040 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_d) = answer('extended connect control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4042 RTP/AVP 0 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_a, $port_b, rtp (0, 1000, 3000, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5000, 7000, 0x1234, "\x33" x 160));
rcv($sock_d, $port_c, rtpm(0, 5000, 7000, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv($sock_c, $port_d, rtpm(0, 7000, 9000, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


rtpe_req('connect', 'extended connect control', { 'from-tag' => ft(), 'to-tag' => $tt, 'to-call-id' => $cid1 });


snd($sock_a, $port_b, rtp (0, 1001, 3160, 0x1234, "\x11" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_b, $port_a, rtp (0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_c, $port_d, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);


snd($sock_c, $port_d, rtp (0, 5001, 7160, 0x1234, "\x33" x 160));
rcv($sock_b, $port_a, rtpm(0, 5001, 7160, 0x1234, "\x33" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);

snd($sock_d, $port_c, rtp (0, 7001, 9160, 0x1a04, "\x44" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);





($sock_a) = new_call([qw(198.51.100.16 5000)]);

($cid, $ft, $port_a) = create('basic', { }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

create_answer('basic', { 'from-tag' => $ft }, <<SDP);
v=0
o=- 111111111 22222222 IN IP4 203.0.113.1
s=22222222
t=0 0
m=audio 5000 RTP/AVP 0 8
c=IN IP4 198.51.100.16
SDP

$resp = rtpe_req('play media', 'media player', { 'from-tag' => $ft, blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

($seq, $ts, $ssrc) = rcv($sock_a, $port_a, rtpm(0 | 0x80, -1, -1, -1, "\xff\x9e\x8f\x89\x86\x86\x89\x8e\x9c\xd2\x20\x10\x0a\x06\x06\x09\x0e\x1b\x44\xa2\x91\x8a\x87\x86\x88\x8d\x99\xbb\x26\x12\x0b\x07\x06\x08\x0d\x18\x35\xa9\x94\x8b\x87\x86\x88\x8c\x97\xaf\x2c\x15\x0c\x07\x06\x07\x0c\x15\x2c\xaf\x97\x8c\x88\x86\x87\x8b\x94\xa9\x35\x18\x0d\x08\x06\x07\x0b\x12\x26\xbb\x99\x8d\x88\x86\x87\x8a\x91\xa2\x44\x1b\x0e\x09\x06\x06\x0a\x10\x20\xd2\x9c\x8e\x89\x86\x86\x89\x8f\x9e\x7e\x1e\x0f\x09\x06\x06\x09\x0e\x1c\x52\xa0\x90\x8a\x86\x86\x89\x8e\x9b\xc4\x22\x11\x0a\x07\x06\x08\x0d\x19\x3b\xa6\x92\x8b\x87\x86\x88\x8d\x98\xb5\x29\x14\x0b\x07\x06\x08\x0c\x17\x2f\xac\x95\x8c\x87\x86\x87\x8c\x95\xac\x2f\x17\x0c\x08\x06"));




($sock_a) = new_call([qw(198.51.100.16 5002)]);

($cid, $ft, $port_a) = create('diff codec', { }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

create_answer('diff codec', { 'from-tag' => $ft }, <<SDP);
v=0
o=- 111111111 22222222 IN IP4 203.0.113.1
s=22222222
t=0 0
m=audio 5002 RTP/AVP 8
c=IN IP4 198.51.100.16
SDP

$resp = rtpe_req('play media', 'media player', { 'from-tag' => $ft, blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

($seq, $ts, $ssrc) = rcv($sock_a, $port_a, rtpm(8 | 0x80, -1, -1, -1, "\xd5\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\x55\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c"));

} # extended tests



new_call;

create('types', { media => [ { type => 'audio' }, { type => 'video' } ] }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=sendrecv
a=rtcp:PORT
SDP
# XXX invalid, no video codecs. should fail?


new_call;

create('types 2', { media => [ { type => 'video' }, { type => 'audio' },  ] }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=video PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP
# XXX invalid, no video codecs. should fail?


new_call;

create('types & codecs', {
	codec => { offer => ['opus'] }, # ignored
	media => [
		{
			type => 'audio',
			codecs => [qw,PCMA G722 PCMU,],
		},
		{
			type => 'video',
			codecs => [qw,VP8/90000 VP9/90000,],
		},
	] }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 8 9 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 96 97
c=IN IP4 203.0.113.1
a=rtpmap:96 VP8/90000
a=rtpmap:97 VP9/90000
a=sendrecv
a=rtcp:PORT
SDP




new_call;

create('codecs', { codec => { offer => ['G722', 'opus'] } }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 9 96
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP


new_call;

create('SRTP', { 'transport-protocol' => 'RTP/SAVP' }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/SAVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP


new_call;

create('ICE', { ICE => 'force' }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP



new_call;

create('family', { 'address-family' => 'IP6' }, <<SDP);
v=0
o=- SDP_VERSION IN IP6 2001:db8:4321::1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP6 2001:db8:4321::1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


new_call;

create('interface', { interface => 'alt' }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 203.0.113.2
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.2
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP



($sock_a, $sock_b) = new_call([qw(198.51.100.4 4020)], [qw(198.51.100.4 4022)]);

($port_a) = offer('offer/answer repeat', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4020 RTP/AVP 0 9 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 9 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('offer/answer repeat', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4022 RTP/AVP 9
c=IN IP4 198.51.100.4
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 9
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp (9, 1000, 3000, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(9, 1000, 3000, 0x1234, "\x11" x 160));

snd($sock_b, $port_a, rtp (9, 3000, 5000, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(9, 3000, 5000, 0x1a04, "\x22" x 160));


($cid, $tt, $port_ax) = create('offer/answer repeat', { 'from-tag' => tt() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 9
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=sendrecv
a=rtcp:PORT
SDP

is($port_a, $port_ax, 'same port');
is($cid, cid(), 'call ID match');
is($tt, tt(), 'tag match');

create_answer('offer/answer repeat', { 'from-tag' => tt() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4022 RTP/AVP 9
c=IN IP4 198.51.100.4
SDP


($cid, $ft, $port_bx) = create('offer/answer repeat', { 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 9
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=sendrecv
a=rtcp:PORT
SDP

is($port_b, $port_bx, 'same port');
is($cid, cid(), 'call ID match');
is($ft, ft(), 'tag match');

create_answer('offer/answer repeat', { 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4020 RTP/AVP 9
c=IN IP4 198.51.100.4
SDP


snd($sock_a, $port_b, rtp (9, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(9, 1001, 3160, 0x1234, "\x11" x 160));

snd($sock_b, $port_a, rtp (9, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(9, 3001, 5160, 0x1a04, "\x22" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.4 4024)], [qw(198.51.100.4 4026)]);

($port_a) = offer('offer/answer repeat w t/c', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4024 RTP/AVP 0
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('offer/answer repeat w t/c', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4026 RTP/AVP 0
c=IN IP4 198.51.100.4
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp (0, 1000, 3000, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x11" x 160));

snd($sock_b, $port_a, rtp (0, 3000, 5000, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3000, 5000, 0x1a04, "\x22" x 160));


($cid, $tt, $port_ax) = create('offer/answer repeat w t/c', { 'from-tag' => tt() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

is($port_a, $port_ax, 'same port');
is($cid, cid(), 'call ID match');
is($tt, tt(), 'tag match');

create_answer('offer/answer repeat w t/c', { 'from-tag' => tt() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4026 RTP/AVP 0
c=IN IP4 198.51.100.4
SDP


($cid, $ft, $port_bx) = create('offer/answer repeat w t/c', { 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

is($port_b, $port_bx, 'same port');
is($cid, cid(), 'call ID match');
is($ft, ft(), 'tag match');

create_answer('offer/answer repeat w t/c', { 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4024 RTP/AVP 0
c=IN IP4 198.51.100.4
SDP


snd($sock_a, $port_b, rtp (0, 1001, 3160, 0x1234, "\x11" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x11" x 160));

snd($sock_b, $port_a, rtp (0, 3001, 5160, 0x1a04, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 3001, 5160, 0x1a04, "\x22" x 160));



($cid, $ft, $port_bx) = create('offer/answer repeat w t/c', { 'from-tag' => ft(), codec => { offer => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

is($port_b, $port_bx, 'same port');
is($cid, cid(), 'call ID match');
is($ft, ft(), 'tag match');

create_answer('offer/answer repeat w t/c', { 'from-tag' => ft() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4024 RTP/AVP 8
c=IN IP4 198.51.100.4
SDP


snd($sock_a, $port_b, rtp (8, 1002, 3320, 0x1234, "\x44" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, 0x1234, "\x66" x 160));

snd($sock_b, $port_a, rtp (0, 3002, 5320, 0x1a04, "\x55" x 160));
rcv($sock_a, $port_b, rtpm(8, 3002, 5320, 0x1a04, "\x73" x 160));






new_call;

offer('offer/answer repeat w strip', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4000 RTP/AVP 0 9 8
c=IN IP4 198.51.100.4
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 9 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('offer/answer repeat w strip', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 5000 RTP/AVP 0 9 8
c=IN IP4 198.51.100.4
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 9 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

create('offer/answer repeat w t/c', { 'from-tag' => tt(), codec => { strip => [ 'G722' ] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP



done_testing();
#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
