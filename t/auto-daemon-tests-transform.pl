#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use POSIX;
use Data::Dumper;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -f -L 7 -E --log-level-internals=7))
		or die;



my ($resp, $sock_a, $sock_b, $port_a, $seq, $ts, $ssrc);


($sock_a) = new_call([qw(198.51.100.14 6150)]);

$resp = rtpe_req('transform', 'simple transform',
	{
		media => [
			{
				type => 'audio',
				codec => [
					{
						input => {
							codec => 'PCMA',
							'payload type' => 8,
							'clock rate' => 8000,
							channels => 1,
						},
						output => {
							codec => 'PCMU',
							'payload type' => 0,
							'clock rate' => 8000,
							channels => 1,
						},
					},
				],
				destination => {
					family => 'IP4',
					address => '198.51.100.14',
					port => 6150,
				},
			},
		],
	}
);

is($resp->{media}[0]{address}, '203.0.113.1', 'address ok');
$port_a = $resp->{media}[0]{port};
snd($sock_a, $port_a, rtp(8, 2000, 4000, 0x3456, "\x00" x 160));
($seq, $ts, $ssrc) = rcv($sock_a, $port_a, rtpm(0, -1, -1, -1, "\x29" x 160));
snd($sock_a, $port_a, rtp(8, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_a, rtpm(0, $seq + 1, $ts + 160, $ssrc, "\x29" x 160));

rtpe_req('delete', 'delete call');


($sock_a) = new_call([qw(198.51.100.14 6152)]);

$resp = rtpe_req('transform', 'no-op transform',
	{
		media => [
			{
				type => 'audio',
				codec => [
					{
						input => {
							codec => 'G722',
							'payload type' => 9,
							'clock rate' => 8000,
							channels => 1,
						},
						output => {
							codec => 'G722',
							'payload type' => 9,
							'clock rate' => 8000,
							channels => 1,
						},
					},
				],
				destination => {
					family => 'IP4',
					address => '198.51.100.14',
					port => 6152,
				},
			},
		],
	}
);

is($resp->{media}[0]{address}, '203.0.113.1', 'address ok');
$port_a = $resp->{media}[0]{port};
snd($sock_a, $port_a, rtp(9, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_a, rtpm(9, 2000, 4000, 0x3456, "\x00" x 160));
snd($sock_a, $port_a, rtp(9, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_a, rtpm(9, 2001, 4160, 0x3456, "\x00" x 160));

rtpe_req('delete', 'delete call');


($sock_a) = new_call([qw(198.51.100.14 6154)]);

$resp = rtpe_req('transform', 'multiple transforms',
	{
		media => [
			{
				type => 'audio',
				codec => [
					{
						input => {
							codec => 'G722',
							'payload type' => 9,
							'clock rate' => 8000,
							channels => 1,
						},
						output => {
							codec => 'G722',
							'payload type' => 9,
							'clock rate' => 8000,
							channels => 1,
						},
					},
					{
						input => {
							codec => 'PCMA',
							'payload type' => 8,
							'clock rate' => 8000,
							channels => 1,
						},
						output => {
							codec => 'PCMU',
							'payload type' => 0,
							'clock rate' => 8000,
							channels => 1,
						},
					},
					{
						input => {
							codec => 'PCMU',
							'payload type' => 0,
							'clock rate' => 8000,
							channels => 1,
						},
						output => {
							codec => 'PCMA',
							'payload type' => 8,
							'clock rate' => 8000,
							channels => 1,
						},
					},
				],
				destination => {
					family => 'IP4',
					address => '198.51.100.14',
					port => 6154,
				},
			},
		],
	}
);

is($resp->{media}[0]{address}, '203.0.113.1', 'address ok');
$port_a = $resp->{media}[0]{port};
snd($sock_a, $port_a, rtp(9, 2000, 4000, 0x3456, "\x00" x 160));
($seq, $ts, $ssrc) = rcv($sock_a, $port_a, rtpm(9, -1, -1, -1, "\x00" x 160));
snd($sock_a, $port_a, rtp(9, 2001, 4160, 0x3456, "\x00" x 160));
($seq, $ts, $ssrc) = rcv($sock_a, $port_a, rtpm(9, $seq + 1, $ts + 160, $ssrc, "\x00" x 160));

snd($sock_a, $port_a, rtp(8, 2000, 4000, 0x346a, "\x00" x 160));
($seq, $ts, $ssrc) = rcv($sock_a, $port_a, rtpm(0, -1, -1, -1, "\x29" x 160));
snd($sock_a, $port_a, rtp(8, 2001, 4160, 0x346a, "\x00" x 160));
($seq, $ts, $ssrc) = rcv($sock_a, $port_a, rtpm(0, $seq + 1, $ts + 160, $ssrc, "\x29" x 160));

snd($sock_a, $port_a, rtp(0, 2000, 4000, 0x347e, "\x00" x 160));
($seq, $ts, $ssrc) = rcv($sock_a, $port_a, rtpm(8, -1, -1, -1, "\x2a" x 160));
snd($sock_a, $port_a, rtp(0, 2001, 4160, 0x347e, "\x00" x 160));
($seq, $ts, $ssrc) = rcv($sock_a, $port_a, rtpm(8, $seq + 1, $ts + 160, $ssrc, "\x2a" x 160));

rtpe_req('delete', 'delete call');


done_testing();
#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
