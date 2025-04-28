#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use POSIX;
use Data::Dumper;
use Bencode;
use Socket;


autotest_start(qw(--config-file=test4.conf))
		or die;



my ($resp, $sock_sig, $sock_a, $sock_b, $sock_tc,
	$port_a, $port_b, $port_tc, $cookie, $addr_sig, $port_sig, $seq, $ts, $ssrc);


$sock_sig = IO::Socket::IP->new(Type => &SOCK_DGRAM, Proto => 'udp', LocalHost => '203.0.113.42', LocalPort => 3334);

($sock_a, $sock_b) = new_call([qw(198.51.100.14 3000)], [qw(198.51.100.14 3002)]);


($port_a) = offer('control passthrough', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
c=IN IP4 198.51.100.14
t=0 0
m=audio 3000 RTP/AVP 8
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('control passthrough', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
c=IN IP4 198.51.100.14
t=0 0
m=audio 3002 RTP/AVP 8
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x7654321, "\x00" x 160));

snd($sock_a, $port_b, rtp(8, 5000, 9000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 5000, 9000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(8, 6000, 10000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 6000, 10000, 0x7654321, "\x00" x 160));

rcv_no($sock_sig);



($sock_a, $sock_b) = new_call([qw(198.51.100.14 3004)], [qw(198.51.100.14 3006)]);

($port_a) = offer('control transcode', { codec => { transcode => [ 'G722' ] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
c=IN IP4 198.51.100.14
t=0 0
m=audio 3004 RTP/AVP 8
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
t=0 0
m=audio PORT RTP/AVP 8 9
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('control transcode', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
c=IN IP4 198.51.100.14
t=0 0
m=audio 3006 RTP/AVP 9
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234567, "\x00" x 160));
Time::HiRes::usleep(20000);
snd($sock_a, $port_b, rtp(8, 1001, 3160, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(9, 1000, 3000, 0x1234567, "\x34\x8a\x20\x85\x21\x84\x04\x8a\x0e\x91\xd2\xd3\xd5\xd6\xd6\xd7\xd8\xd8\xd7\xd8\xd8\xd8\xd8\xd8\xd8\xd8\xd8\xd8\xd9\xd9\xd9\xd9\xda\xda\xda\xda\xdb\xdb\xdb\xdc\xd9\xda\xda\xda\xda\xda\xdb\xdc\xd9\xd9\xda\xda\xd9\xd9\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xda\xda\xda\xda\xd9\xd9\xd9\xd9\xd9\xd8\xd8\xd8\xd8\xd7\xdd\xd8\xd8\xd8\xd7\xdd\xd6\xdc\xd8\xd8\xd8\xd5\xdb\xda\xda\xdb\xdc\xd7\xda\xd9\xd8\xd7\xde\xdb\xda\xd9\xd8\xd8\xd5\xdb\xdd\xd8\xd8\xd8\xd7\xdc\xd5\xdb\xdf\xda\xda\xd7\xdf\xd8\xd5\xdd\xda\xdb\xd8\xd8\xd9\xd6\xdf\xdb\xdc\xd5\xdb\xde\xd5\xda\xdd\xda\xd9\xd8\xd9\xd8\xd6\xff\xd8\xd7\xfe\xd5\xda\xd8\xda\xdf\xd8\xda\xda\xda\xd9\xd9\xdc\xd8"));

snd($sock_b, $port_a, rtp(9, 2000, 4000, 0x7654321, "\x34\x8a\x20\x85\x21\x84\x04\x8a\x0e\x91\xd2\xd3\xd5\xd6\xd6\xd7\xd8\xd8\xd7\xd8\xd8\xd8\xd8\xd8\xd8\xd8\xd8\xd8\xd9\xd9\xd9\xd9\xda\xda\xda\xda\xdb\xdb\xdb\xdc\xd9\xda\xda\xda\xda\xda\xdb\xdc\xd9\xd9\xda\xda\xd9\xd9\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xda\xda\xda\xda\xd9\xd9\xd9\xd9\xd9\xd8\xd8\xd8\xd8\xd7\xdd\xd8\xd8\xd8\xd7\xdd\xd6\xdc\xd8\xd8\xd8\xd5\xdb\xda\xda\xdb\xdc\xd7\xda\xd9\xd8\xd7\xde\xdb\xda\xd9\xd8\xd8\xd5\xdb\xdd\xd8\xd8\xd8\xd7\xdc\xd5\xdb\xdf\xda\xda\xd7\xdf\xd8\xd5\xdd\xda\xdb\xd8\xd8\xd9\xd6\xdf\xdb\xdc\xd5\xdb\xde\xd5\xda\xdd\xda\xd9\xd8\xd9\xd8\xd6\xff\xd8\xd7\xfe\xd5\xda\xd8\xda\xdf\xd8\xda\xda\xda\xd9\xd9\xdc\xd8"));
Time::HiRes::usleep(20000);
snd($sock_b, $port_a, rtp(9, 2001, 4160, 0x7654321, "\x34\x8a\x20\x85\x21\x84\x04\x8a\x0e\x91\xd2\xd3\xd5\xd6\xd6\xd7\xd8\xd8\xd7\xd8\xd8\xd8\xd8\xd8\xd8\xd8\xd8\xd8\xd9\xd9\xd9\xd9\xda\xda\xda\xda\xdb\xdb\xdb\xdc\xd9\xda\xda\xda\xda\xda\xdb\xdc\xd9\xd9\xda\xda\xd9\xd9\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xda\xda\xda\xda\xd9\xd9\xd9\xd9\xd9\xd8\xd8\xd8\xd8\xd7\xdd\xd8\xd8\xd8\xd7\xdd\xd6\xdc\xd8\xd8\xd8\xd5\xdb\xda\xda\xdb\xdc\xd7\xda\xd9\xd8\xd7\xde\xdb\xda\xd9\xd8\xd8\xd5\xdb\xdd\xd8\xd8\xd8\xd7\xdc\xd5\xdb\xdf\xda\xda\xd7\xdf\xd8\xd5\xdd\xda\xdb\xd8\xd8\xd9\xd6\xdf\xdb\xdc\xd5\xdb\xde\xd5\xda\xdd\xda\xd9\xd8\xd9\xd8\xd6\xff\xd8\xd7\xfe\xd5\xda\xd8\xda\xdf\xd8\xda\xda\xda\xd9\xd9\xdc\xd8"));
rcv($sock_a, $port_b, rtpm(8, 2000, 4000, 0x7654321, "\x54\xd5\x54\xd4\x57\xd6\x51\xd0\x50\xd7\xc5\x17\x04\x03\x00\x01\x00\x00\x01\x01\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"));

rcv_no($sock_sig);



($sock_a, $sock_b, $sock_tc) = new_call(
	[qw(198.51.100.14 3008)], [qw(198.51.100.14 3010)],
	[qw(198.51.100.18 3012)]
);


($port_a) = offer('G.711 transform', { codec => { transcode => ['PCMU'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
c=IN IP4 198.51.100.14
t=0 0
m=audio 3008 RTP/AVP 8
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

rcv_no($sock_sig);

$NGCP::Rtpengine::req_cb = sub {
	my ($cid, $tag);
	($port_sig, $addr_sig, $cookie, $cid, $tag, $port_tc) = rcv($sock_sig, -1, qr/^(.{16}) d7:command9:transform7:call-id\d+:(\w{8} for .*?)8:from-tag\d+:(\w{8} for .*?)5:mediald4:type5:audio5:codecld5:inputd5:codec4:PCMA12:payload typei8e10:clock ratei8000e8:channelsi1e6:format0:7:options0:e6:outputd5:codec4:PCMU12:payload typei0e10:clock ratei8000e8:channelsi1e6:format0:7:options0:eee11:destinationd6:family3:IP47:address11:203.0.113.14:porti(\d{5})eeee8:instance12:.{12}e$/);
	snd($sock_sig, $port_sig, $cookie . ' ' . Bencode::bencode( {
				result => 'ok',
				'call-id' => 'foobar',
				'from-tag' => 'yolo',
				'media' => [
					{
						id => 'id',
						family => 'IP4',
						address => '198.51.100.18',
						port => 3012,
					},
				],
			} ), $addr_sig );
};

($port_b) = answer('G.711 transform', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
c=IN IP4 198.51.100.14
t=0 0
m=audio 3010 RTP/AVP 0
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$NGCP::Rtpengine::req_cb = undef;

rcv_no($sock_sig);

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv_no($sock_a);
rcv_no($sock_tc);
rcv_no($sock_sig);

snd($sock_a, $port_b, rtp(8, 1001, 3160, 0x7894561, "\x00" x 160));
rcv_no($sock_b);
rcv_no($sock_a);
rcv($sock_tc, -1, rtpm(8, 1001, 3160, 0x7894561, "\x00" x 160));
rcv_no($sock_sig);

snd($sock_tc, $port_tc, rtp(0, 1001, 3160, 0x7894561, "\x22" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x7894561, "\x22" x 160));
rcv_no($sock_a);
rcv_no($sock_tc);
rcv_no($sock_sig);

snd($sock_b, $port_a, rtp(0, 1300, 3300, 0x1234693, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 1300, 3300, 0x1234693, "\x2a" x 160));
rcv_no($sock_a);
rcv_no($sock_tc);
rcv_no($sock_sig);

$NGCP::Rtpengine::req_cb = sub {
	($port_sig, $addr_sig, $cookie) = rcv($sock_sig, -1, qr/^(.{16}) d7:command6:delete7:call-id6:foobar8:from-tag4:yolo12:delete delayi0ee$/);
	snd($sock_sig, $port_sig, $cookie . ' ' . Bencode::bencode( { result => 'ok', } ), $addr_sig );
};

rtpe_req('delete', 'delete call', { 'delete-delay' => 0 } );

$NGCP::Rtpengine::req_cb = undef;



($sock_a, $sock_b, $sock_tc) = new_call(
	[qw(198.51.100.14 3040)], [qw(198.51.100.14 3042)],
	[qw(198.51.100.18 3044)]
);


$NGCP::Rtpengine::req_cb = sub {
	my ($cid, $tag);
	($port_sig, $addr_sig, $cookie, $cid, $tag, $port_tc) = rcv($sock_sig, -1, qr/^(.{16}) d7:command9:transform7:call-id\d+:(\w{8} for .*?)8:from-tag\d+:(\w{8} for .*?)5:mediald4:type5:audio5:codecld5:inputd5:codec4:PCMA12:payload typei8e10:clock ratei8000e8:channelsi1e6:format0:7:options0:e6:outputd5:codec4:PCMU12:payload typei0e10:clock ratei8000e8:channelsi1e6:format0:7:options0:eee11:destinationd6:family3:IP47:address11:203.0.113.14:porti(\d{5})eeee8:instance12:.{12}e$/);
	snd($sock_sig, $port_sig, $cookie . ' ' . Bencode::bencode( {
				result => 'ok',
				'call-id' => $cid,
				'from-tag' => $tag,
				'media' => [
					{
						id => 'id',
						family => 'IP4',
						address => '198.51.100.18',
						port => 3044,
					},
				],
			} ), $addr_sig );
};

($port_a) = offer('G.711 transform reverse', { codec => { transcode => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
c=IN IP4 198.51.100.14
t=0 0
m=audio 3040 RTP/AVP 0
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$NGCP::Rtpengine::req_cb = undef;

rcv_no($sock_sig);

($port_b) = answer('G.711 transform reverse', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
c=IN IP4 198.51.100.14
t=0 0
m=audio 3042 RTP/AVP 8
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.14
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


rcv_no($sock_sig);

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234567, "\x00" x 160));
rcv_no($sock_a);
rcv_no($sock_tc);
rcv_no($sock_sig);

snd($sock_a, $port_b, rtp(0, 1201, 3360, 0x7894629, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1201, 3360, 0x7894629, "\x2a" x 160));
rcv_no($sock_a);
rcv_no($sock_tc);
rcv_no($sock_sig);

snd($sock_b, $port_a, rtp(8, 1500, 3500, 0x123475b, "\x00" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv($sock_tc, -1, rtpm(8, 1500, 3500, 0x123475b, "\x00" x 160));
rcv_no($sock_sig);

snd($sock_tc, $port_tc, rtp(0, 1500, 3500, 0x789475b, "\x22" x 160));
rcv($sock_a, $port_b, rtpm(0, 1500, 3500, 0x789475b, "\x22" x 160));
rcv_no($sock_b);
rcv_no($sock_tc);
rcv_no($sock_sig);



done_testing();
#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
