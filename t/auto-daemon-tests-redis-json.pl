#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use Test2::Tools::Compare qw(like);
use Socket qw(AF_INET SOCK_STREAM sockaddr_in pack_sockaddr_in inet_aton);
use JSON;
use Data::Dumper;

$Data::Dumper::Sortkeys = 1;


# fake Redis listener
my $redis_listener;
socket($redis_listener, AF_INET, SOCK_STREAM, 0) or die;
bind($redis_listener, sockaddr_in(6379, inet_aton('203.0.113.42'))) or die;
listen($redis_listener, 10) or die;

my $redis_fd;


sub redis_i {
	my ($i, $n) = @_;
	my $buf;
	alarm(1);
	recv($redis_fd, $buf, length($i), 0) or die;
	alarm(0);
	is($buf, $i, $n);
}
sub redis_io {
	my ($i, $o, $n) = @_;
	redis_i($i, $n);
	send($redis_fd, $o, 0) or die;
};


$NGCP::Rtpengine::AutoTest::launch_cb = sub {
	# accept Redis connection and read preamble

	accept($redis_fd, $redis_listener) or die;

	redis_io("*2\r\n\$4\r\nAUTH\r\n\$4\r\nauth\r\n",	"+OK\r\n",			"AUTH");
	redis_io("*2\r\n\$6\r\nSELECT\r\n\$1\r\n2\r\n",		"+OK\r\n",			"SELECT 1");
	redis_io("*1\r\n\$4\r\nINFO\r\n",			"\$13\r\nrole:master\r\n\r\n",	"INFO");
	redis_io("*2\r\n\$4\r\nTYPE\r\n\$5\r\ncalls\r\n",	"+none\r\n",			"TYPE");

	redis_io("*1\r\n\$4\r\nPING\r\n",			"+PONG\r\n",			"PING");
	redis_io("*2\r\n\$4\r\nKEYS\r\n\$1\r\n*\r\n",		"*0\r\n",			"KEYS");
};


autotest_start(qw(--config-file=none -t -1 -i foo/203.0.113.1 -i foo/2001:db8:4321::1
			--redis-format=json
			-i bar/203.0.113.2 -i bar/2001:db8:4321::2
			-n 2223 -f -L 7 -E --redis=auth@203.0.113.42:6379/2))
		or die;



my $json_exp;
$NGCP::Rtpengine::req_cb = sub {
	redis_io("*1\r\n\$4\r\nPING\r\n", "+PONG\r\n", "req PING");
	redis_i("*5\r\n\$3\r\nSET\r\n\$" . length(cid()) . "\r\n" . cid() . "\r\n\$", "req intro");
	# dumbly expect 4-digit number as length
	my $buf;
	alarm(1);
	recv($redis_fd, $buf, 6, 0) or die;
	alarm(0);
	is(substr($buf, 4, 2), "\r\n", "4-digit number");
	my $len = int($buf);
	alarm(1);
	recv($redis_fd, $buf, $len, 0) or die;
	alarm(0);
	my $json = decode_json($buf);
	#print Dumper($json);
	like($json, $json_exp, "JSON");
	redis_io("\r\n\$2\r\nEX\r\n\$5\r\n86400\r\n",
		"+OK\r\n",
		"req EXPIRE");
};



new_call;

$json_exp = {
  'associated_tags-0' => [
			   '1'
			 ],
  'associated_tags-1' => [
			   '0'
			 ],
  'json' => {
	      'block_dtmf' => '0',
	      'call_flags' => 65536,
	      'created' => qr/^\d+$/,
	      'created_from' => qr//,
	      'created_from_addr' => qr//,
	      'deleted' => '0',
	      'destroyed' => '0',
	      'last_signal' => qr/^\d+$/,
	      'ml_deleted' => '0',
	      'num_maps' => '2',
	      'num_medias' => '2',
	      'num_sfds' => '4',
	      'num_streams' => '4',
	      'num_tags' => '2',
	      'recording_metadata' => '',
	      'redis_hosted_db' => '2',
	      'tos' => '0'
	    },
  'map-0' => {
	       'endpoint' => '198.51.100.1:3000',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '0'
	     },
  'map-1' => {
	       'endpoint' => '',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '1'
	     },
  'map_sfds-0' => [
		    'loc-0',
		    '0',
		    '1'
		  ],
  'map_sfds-1' => [
		    'loc-0',
		    '2',
		    '3'
		  ],
  'maps-1' => [
		'0'
	      ],
  'maps-0' => [
		'1'
	      ],
  'media-1' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0 8',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '2228236',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '1',
		 'type' => 'audio'
	       },
  'media-0' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0 8',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '65548',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '0',
		 'type' => 'audio'
	       },
  'medias-1' => [
		  '1'
		],
  'medias-0' => [
		  '0'
		],
  'payload_types-0' => [
			 '0/PCMU/8000///0/20',
			 '8/PCMA/8000///0/20'
		       ],
  'payload_types-1' => [
			 '0/PCMU/8000///0/20',
			 '8/PCMA/8000///0/20'
		       ],
  'rtcp_sinks-0' => [],
  'rtcp_sinks-1' => [
		      '3'
		    ],
  'rtcp_sinks-2' => [],
  'rtcp_sinks-3' => [
		      '1'
		    ],
  'rtp_sinks-0' => [
		     '2'
		   ],
  'rtp_sinks-1' => [],
  'rtp_sinks-2' => [
		     '0'
		   ],
  'rtp_sinks-3' => [],
  'sfd-0' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '0'
	     },
  'sfd-1' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '1'
	     },
  'sfd-2' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '2'
	     },
  'sfd-3' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '3'
	     },
  'ssrc_table-0' => [],
  'ssrc_table-1' => [],
  'stream-0' => {
		  'advertised_endpoint' => '',
		  'component' => '1',
		  'endpoint' => '',
		  'last_packet' => qr/^\d+$/,
		  'media' => '1',
		  'ps_flags' => '65536',
		  'rtcp_sibling' => '1',
		  'sfd' => '0',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-1' => {
		  'advertised_endpoint' => '',
		  'component' => '2',
		  'endpoint' => '',
		  'last_packet' => qr/^\d+$/,
		  'media' => '1',
		  'ps_flags' => '131072',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '1',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-2' => {
		  'advertised_endpoint' => '198.51.100.1:3000',
		  'component' => '1',
		  'endpoint' => '198.51.100.1:3000',
		  'last_packet' => qr/^\d+$/,
		  'media' => '0',
		  'ps_flags' => '68222976',
		  'rtcp_sibling' => '3',
		  'sfd' => '2',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-3' => {
		  'advertised_endpoint' => '198.51.100.1:3001',
		  'component' => '2',
		  'endpoint' => '198.51.100.1:3001',
		  'last_packet' => qr/^\d+$/,
		  'media' => '0',
		  'ps_flags' => '68288513',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '3',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream_sfds-0' => [
		       '0'
		     ],
  'stream_sfds-1' => [
		       '1'
		     ],
  'stream_sfds-2' => [
		       '2'
		     ],
  'stream_sfds-3' => [
		       '3'
		     ],
  'streams-1' => [
		   '0',
		   '1'
		 ],
  'streams-0' => [
		   '2',
		   '3'
		 ],
  'media-subscriptions-0' => [
			 '1/1/0/0'
		       ],
  'media-subscriptions-1' => [
			 '0/1/0/0'
		       ],
  'tag-0' => {
	       'block_dtmf' => '0',
	       'created' => qr/^\d+$/,
	       'desired_family' => 'IP4',
	       'deleted' => '0',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	       'tag' => ft()
	     },
  'tag-1' => {
	       'block_dtmf' => '0',
	       'created' => qr/^\d+$/,
	       'desired_family' => 'IP4',
	       'deleted' => '0',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	     }
};

offer('simple call',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$json_exp = {
  'associated_tags-0' => [
			   '1'
			 ],
  'associated_tags-1' => [
			   '0'
			 ],
  'json' => {
	      'block_dtmf' => '0',
	      'call_flags' => 1376256,
	      'created' => qr/^\d+$/,
	      'created_from' => qr//,
	      'created_from_addr' => qr//,
	      'deleted' => '0',
	      'destroyed' => '0',
	      'last_signal' => qr/^\d+$/,
	      'ml_deleted' => '0',
	      'num_maps' => '2',
	      'num_medias' => '2',
	      'num_sfds' => '4',
	      'num_streams' => '4',
	      'num_tags' => '2',
	      'recording_metadata' => '',
	      'redis_hosted_db' => '2',
	      'tos' => '0'
	    },
  'map-0' => {
	       'endpoint' => '198.51.100.1:3000',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '0'
	     },
  'map-1' => {
	       'endpoint' => '198.51.100.4:3000',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '0'
	     },
  'map_sfds-0' => [
		    'loc-0',
		    '0',
		    '1'
		  ],
  'map_sfds-1' => [
		    'loc-0',
		    '2',
		    '3'
		  ],
  'maps-1' => [
		'0'
	      ],
  'maps-0' => [
		'1'
	      ],
  'media-1' => {
		 'desired_family' => 'IP4',
		 'format_str' => '8',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '2293772',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '1',
		 'type' => 'audio'
	       },
  'media-0' => {
		 'desired_family' => 'IP4',
		 'format_str' => '8',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '65548',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '0',
		 'type' => 'audio'
	       },
  'medias-1' => [
		  '1'
		],
  'medias-0' => [
		  '0'
		],
  'payload_types-0' => [
			 '8/PCMA/8000///0/20'
		       ],
  'payload_types-1' => [
			 '8/PCMA/8000///0/20'
		       ],
  'rtcp_sinks-0' => [],
  'rtcp_sinks-1' => [
		      '3'
		    ],
  'rtcp_sinks-2' => [],
  'rtcp_sinks-3' => [
		      '1'
		    ],
  'rtp_sinks-0' => [
		     '2'
		   ],
  'rtp_sinks-1' => [],
  'rtp_sinks-2' => [
		     '0'
		   ],
  'rtp_sinks-3' => [],
  'sfd-0' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '0'
	     },
  'sfd-1' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '1'
	     },
  'sfd-2' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '2'
	     },
  'sfd-3' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '3'
	     },
  'ssrc_table-0' => [],
  'ssrc_table-1' => [],
  'stream-0' => {
		  'advertised_endpoint' => '198.51.100.4:3000',
		  'component' => '1',
		  'endpoint' => '198.51.100.4:3000',
		  'last_packet' => qr/^\d+$/,
		  'media' => '1',
		  'ps_flags' => '1114112',
		  'rtcp_sibling' => '1',
		  'sfd' => '0',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-1' => {
		  'advertised_endpoint' => '198.51.100.4:3001',
		  'component' => '2',
		  'endpoint' => '198.51.100.4:3001',
		  'last_packet' => qr/^\d+$/,
		  'media' => '1',
		  'ps_flags' => '1179649',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '1',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-2' => {
		  'advertised_endpoint' => '198.51.100.1:3000',
		  'component' => '1',
		  'endpoint' => '198.51.100.1:3000',
		  'last_packet' => qr/^\d+$/,
		  'media' => '0',
		  'ps_flags' => '1114112',
		  'rtcp_sibling' => '3',
		  'sfd' => '2',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-3' => {
		  'advertised_endpoint' => '198.51.100.1:3001',
		  'component' => '2',
		  'endpoint' => '198.51.100.1:3001',
		  'last_packet' => qr/^\d+$/,
		  'media' => '0',
		  'ps_flags' => '1179649',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '3',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream_sfds-0' => [
		       '0'
		     ],
  'stream_sfds-1' => [
		       '1'
		     ],
  'stream_sfds-2' => [
		       '2'
		     ],
  'stream_sfds-3' => [
		       '3'
		     ],
  'streams-1' => [
		   '0',
		   '1'
		 ],
  'streams-0' => [
		   '2',
		   '3'
		 ],
  'media-subscriptions-0' => [
			 '1/1/0/0'
		       ],
  'media-subscriptions-1' => [
			 '0/1/0/0'
		       ],
  'tag-0' => {
	       'block_dtmf' => '0',
	       'created' => qr/^\d+$/,
	       'deleted' => '0',
	       'desired_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	       'tag' => ft()
	     },
  'tag-1' => {
	       'block_dtmf' => '0',
	       'created' => qr/^\d+$/,
	       'deleted' => '0',
	       'desired_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	       'tag' => tt()
	     }
};

answer('simple call',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 8
c=IN IP4 198.51.100.4
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP






new_call;

$json_exp = {
  'associated_tags-0' => [
			   '1'
			 ],
  'associated_tags-1' => [
			   '0'
			 ],
  'json' => {
	      'block_dtmf' => '0',
	      'call_flags' => 65536,
	      'created' => qr/^\d+$/,
	      'created_from' => qr//,
	      'created_from_addr' => qr//,
	      'deleted' => '0',
	      'destroyed' => '0',
	      'last_signal' => qr/^\d+$/,
	      'ml_deleted' => '0',
	      'num_maps' => '2',
	      'num_medias' => '2',
	      'num_sfds' => '4',
	      'num_streams' => '4',
	      'num_tags' => '2',
	      'recording_metadata' => '',
	      'redis_hosted_db' => '2',
	      'tos' => '0'
	    },
  'map-0' => {
	       'endpoint' => '198.51.100.14:6088',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '0'
	     },
  'map-1' => {
	       'endpoint' => '',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '1'
	     },
  'map_sfds-0' => [
		    'loc-0',
		    '0',
		    '1'
		  ],
  'map_sfds-1' => [
		    'loc-0',
		    '2',
		    '3'
		  ],
  'maps-1' => [
		'0'
	      ],
  'maps-0' => [
		'1'
	      ],
  'media-1' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0 8',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '2228236',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '1',
		 'type' => 'audio'
	       },
  'media-0' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0 8',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '65548',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '0',
		 'type' => 'audio'
	       },
  'medias-1' => [
		  '1'
		],
  'medias-0' => [
		  '0'
		],
  'payload_types-0' => [
			 '0/PCMU/8000///0/20',
			 '8/PCMA/8000///0/20'
		       ],
  'payload_types-1' => [
			 '0/PCMU/8000///0/20',
			 '8/PCMA/8000///0/20'
		       ],
  'rtcp_sinks-0' => [],
  'rtcp_sinks-1' => [
		      '3'
		    ],
  'rtcp_sinks-2' => [],
  'rtcp_sinks-3' => [
		      '1'
		    ],
  'rtp_sinks-0' => [
		     '2'
		   ],
  'rtp_sinks-1' => [],
  'rtp_sinks-2' => [
		     '0'
		   ],
  'rtp_sinks-3' => [],
  'sfd-0' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '0'
	     },
  'sfd-1' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '1'
	     },
  'sfd-2' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '2'
	     },
  'sfd-3' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '3'
	     },
  'ssrc_table-0' => [],
  'ssrc_table-1' => [],
  'stream-0' => {
		  'advertised_endpoint' => '',
		  'component' => '1',
		  'endpoint' => '',
		  'last_packet' => qr/^\d+$/,
		  'media' => '1',
		  'ps_flags' => '65536',
		  'rtcp_sibling' => '1',
		  'sfd' => '0',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-1' => {
		  'advertised_endpoint' => '',
		  'component' => '2',
		  'endpoint' => '',
		  'last_packet' => qr/^\d+$/,
		  'media' => '1',
		  'ps_flags' => '131072',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '1',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-2' => {
		  'advertised_endpoint' => '198.51.100.14:6088',
		  'component' => '1',
		  'endpoint' => '198.51.100.14:6088',
		  'last_packet' => qr/^\d+$/,
		  'media' => '0',
		  'ps_flags' => '68222976',
		  'rtcp_sibling' => '3',
		  'sfd' => '2',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-3' => {
		  'advertised_endpoint' => '198.51.100.14:6089',
		  'component' => '2',
		  'endpoint' => '198.51.100.14:6089',
		  'last_packet' => qr/^\d+$/,
		  'media' => '0',
		  'ps_flags' => '68288513',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '3',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream_sfds-0' => [
		       '0'
		     ],
  'stream_sfds-1' => [
		       '1'
		     ],
  'stream_sfds-2' => [
		       '2'
		     ],
  'stream_sfds-3' => [
		       '3'
		     ],
  'streams-1' => [
		   '0',
		   '1'
		 ],
  'streams-0' => [
		   '2',
		   '3'
		 ],
  'media-subscriptions-0' => [
			 '1/1/0/0'
		       ],
  'media-subscriptions-1' => [
			 '0/1/0/0'
		       ],
  'tag-0' => {
	       'block_dtmf' => '0',
	       'created' => qr/^\d+$/,
	       'deleted' => '0',
	       'desired_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	       'tag' => ft()
	     },
  'tag-1' => {
	       'block_dtmf' => '0',
	       'created' => qr/^\d+$/,
	       'deleted' => '0',
	       'desired_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	     }
};

offer('sub to multiple tags',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6088 RTP/AVP 0 8
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

$json_exp = {
  'associated_tags-0' => [
			   '1'
			 ],
  'associated_tags-1' => [
			   '0'
			 ],
  'json' => {
	      'block_dtmf' => '0',
	      'call_flags' => 1376256,
	      'created' => qr/^\d+$/,
	      'created_from' => qr//,
	      'created_from_addr' => qr//,
	      'deleted' => '0',
	      'destroyed' => '0',
	      'last_signal' => qr/^\d+$/,
	      'ml_deleted' => '0',
	      'num_maps' => '2',
	      'num_medias' => '2',
	      'num_sfds' => '4',
	      'num_streams' => '4',
	      'num_tags' => '2',
	      'recording_metadata' => '',
	      'redis_hosted_db' => '2',
	      'tos' => '0'
	    },
  'map-0' => {
	       'endpoint' => '198.51.100.14:6088',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '0'
	     },
  'map-1' => {
	       'endpoint' => '198.51.100.14:6090',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '0'
	     },
  'map_sfds-0' => [
		    'loc-0',
		    '0',
		    '1'
		  ],
  'map_sfds-1' => [
		    'loc-0',
		    '2',
		    '3'
		  ],
  'maps-1' => [
		'0'
	      ],
  'maps-0' => [
		'1'
	      ],
  'media-1' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0 8',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '2293772',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '1',
		 'type' => 'audio'
	       },
  'media-0' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0 8',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '65548',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '0',
		 'type' => 'audio'
	       },
  'medias-1' => [
		  '1'
		],
  'medias-0' => [
		  '0'
		],
  'payload_types-0' => [
			 '0/PCMU/8000///0/20',
			 '8/PCMA/8000///0/20'
		       ],
  'payload_types-1' => [
			 '0/PCMU/8000///0/20',
			 '8/PCMA/8000///0/20'
		       ],
  'rtcp_sinks-0' => [],
  'rtcp_sinks-1' => [
		      '3'
		    ],
  'rtcp_sinks-2' => [],
  'rtcp_sinks-3' => [
		      '1'
		    ],
  'rtp_sinks-0' => [
		     '2'
		   ],
  'rtp_sinks-1' => [],
  'rtp_sinks-2' => [
		     '0'
		   ],
  'rtp_sinks-3' => [],
  'sfd-0' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '0'
	     },
  'sfd-1' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '1'
	     },
  'sfd-2' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '2'
	     },
  'sfd-3' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '3'
	     },
  'ssrc_table-0' => [],
  'ssrc_table-1' => [],
  'stream-0' => {
		  'advertised_endpoint' => '198.51.100.14:6090',
		  'component' => '1',
		  'endpoint' => '198.51.100.14:6090',
		  'last_packet' => qr/^\d+$/,
		  'media' => '1',
		  'ps_flags' => '1114112',
		  'rtcp_sibling' => '1',
		  'sfd' => '0',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-1' => {
		  'advertised_endpoint' => '198.51.100.14:6091',
		  'component' => '2',
		  'endpoint' => '198.51.100.14:6091',
		  'last_packet' => qr/^\d+$/,
		  'media' => '1',
		  'ps_flags' => '1179649',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '1',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-2' => {
		  'advertised_endpoint' => '198.51.100.14:6088',
		  'component' => '1',
		  'endpoint' => '198.51.100.14:6088',
		  'last_packet' => qr/^\d+$/,
		  'media' => '0',
		  'ps_flags' => '1114112',
		  'rtcp_sibling' => '3',
		  'sfd' => '2',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-3' => {
		  'advertised_endpoint' => '198.51.100.14:6089',
		  'component' => '2',
		  'endpoint' => '198.51.100.14:6089',
		  'last_packet' => qr/^\d+$/,
		  'media' => '0',
		  'ps_flags' => '1179649',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '3',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream_sfds-0' => [
		       '0'
		     ],
  'stream_sfds-1' => [
		       '1'
		     ],
  'stream_sfds-2' => [
		       '2'
		     ],
  'stream_sfds-3' => [
		       '3'
		     ],
  'streams-1' => [
		   '0',
		   '1'
		 ],
  'streams-0' => [
		   '2',
		   '3'
		 ],
  'media-subscriptions-0' => [
			 '1/1/0/0'
		       ],
  'media-subscriptions-1' => [
			 '0/1/0/0'
		       ],
  'tag-0' => {
	       'block_dtmf' => '0',
	       'created' => qr/^\d+$/,
	       'deleted' => '0',
	       'desired_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	       'tag' => ft()
	     },
  'tag-1' => {
	       'block_dtmf' => '0',
	       'created' => qr/^\d+$/,
	       'deleted' => '0',
	       'desired_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	       'tag' => tt()
	     }
};

answer('sub to multiple tags',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6090 RTP/AVP 0 8
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

$json_exp = {
          'associated_tags-0' => [
                                   '1'
                                 ],
          'associated_tags-1' => [
                                   '0'
                                 ],
          'associated_tags-2' => [],
          'json' => {
                      'block_dtmf' => '0',
		      'call_flags' => 1376256,
                      'created' => qr/^\d+$/,
                      'created_from' => qr//,
                      'created_from_addr' => qr//,
                      'deleted' => '0',
                      'destroyed' => '0',
                      'last_signal' => qr/^\d+$/,
                      'ml_deleted' => '0',
                      'num_maps' => '4',
                      'num_medias' => '4',
                      'num_sfds' => '8',
                      'num_streams' => '8',
                      'num_tags' => '3',
                      'recording_metadata' => '',
                      'redis_hosted_db' => '2',
                      'tos' => '0'
                    },
          'map-0' => {
                       'endpoint' => '198.51.100.14:6088',
                       'intf_preferred_family' => 'IP4',
                       'logical_intf' => 'foo',
                       'num_ports' => '2',
                       'wildcard' => '0'
                     },
          'map-1' => {
                       'endpoint' => '198.51.100.14:6090',
                       'intf_preferred_family' => 'IP4',
                       'logical_intf' => 'foo',
                       'num_ports' => '2',
                       'wildcard' => '0'
                     },
          'map-2' => {
                       'endpoint' => '',
                       'intf_preferred_family' => 'IP4',
                       'logical_intf' => 'foo',
                       'num_ports' => '2',
                       'wildcard' => '1'
                     },
          'map-3' => {
                       'endpoint' => '',
                       'intf_preferred_family' => 'IP4',
                       'logical_intf' => 'foo',
                       'num_ports' => '2',
                       'wildcard' => '1'
                     },
          'map_sfds-0' => [
                            'loc-0',
                            '0',
                            '1'
                          ],
          'map_sfds-1' => [
                            'loc-0',
                            '2',
                            '3'
                          ],
          'map_sfds-2' => [
                            'loc-0',
                            '4',
                            '5'
                          ],
          'map_sfds-3' => [
                            'loc-0',
                            '6',
                            '7'
                          ],
          'maps-1' => [
                        '0'
                      ],
          'maps-0' => [
                        '1'
                      ],
          'maps-2' => [
                        '2'
                      ],
          'maps-3' => [
                        '3'
                      ],
          'media-1' => {
                         'desired_family' => 'IP4',
                         'format_str' => '0 8',
                         'index' => '1',
                         'logical_intf' => 'foo',
                         'media_flags' => '2293772',
                         'protocol' => 'RTP/AVP',
                         'ptime' => '0',
                         'tag' => '1',
                         'type' => 'audio'
                       },
          'media-0' => {
                         'desired_family' => 'IP4',
                         'format_str' => '0 8',
                         'index' => '1',
                         'logical_intf' => 'foo',
                         'media_flags' => '65548',
                         'protocol' => 'RTP/AVP',
                         'ptime' => '0',
                         'tag' => '0',
                         'type' => 'audio'
                       },
          'media-2' => {
                         'desired_family' => 'IP4',
                         'format_str' => '0 8',
                         'index' => '1',
                         'logical_intf' => 'foo',
                         'media_flags' => '2097156',
                         'protocol' => 'RTP/AVP',
                         'ptime' => '0',
                         'tag' => '2',
                         'type' => 'audio'
                       },
          'media-3' => {
                         'desired_family' => 'IP4',
                         'format_str' => '0 8',
                         'index' => '2',
                         'logical_intf' => 'foo',
                         'media_flags' => '2097156',
                         'protocol' => 'RTP/AVP',
                         'ptime' => '0',
                         'tag' => '2',
                         'type' => 'audio'
                       },
          'medias-1' => [
                          '1'
                        ],
          'medias-0' => [
                          '0'
                        ],
          'medias-2' => [
                          '2',
                          '3'
                        ],
          'payload_types-0' => [
                                 '0/PCMU/8000///0/20',
                                 '8/PCMA/8000///0/20'
                               ],
          'payload_types-1' => [
                                 '0/PCMU/8000///0/20',
                                 '8/PCMA/8000///0/20'
                               ],
          'payload_types-2' => [
                                 '0/PCMU/8000///0/20',
                                 '8/PCMA/8000///0/20'
                               ],
          'payload_types-3' => [
                                 '0/PCMU/8000///0/20',
                                 '8/PCMA/8000///0/20'
                               ],
          'rtcp_sinks-0' => [],
          'rtcp_sinks-1' => [
                              '3',
                              '7'
                            ],
          'rtcp_sinks-2' => [],
          'rtcp_sinks-3' => [
                              '1',
                              '5'
                            ],
          'rtcp_sinks-4' => [],
          'rtcp_sinks-5' => [],
          'rtcp_sinks-6' => [],
          'rtcp_sinks-7' => [],
          'rtp_sinks-0' => [
                             '2',
                             '6'
                           ],
          'rtp_sinks-1' => [],
          'rtp_sinks-2' => [
                             '0',
                             '4'
                           ],
          'rtp_sinks-3' => [],
          'rtp_sinks-4' => [],
          'rtp_sinks-5' => [],
          'rtp_sinks-6' => [],
          'rtp_sinks-7' => [],
          'sfd-0' => {
                       'fd' => qr/^\d+$/,
                       'local_intf_uid' => '0',
                       'localport' => qr/^\d+$/,
                       'logical_intf' => 'foo',
                       'pref_family' => 'IP4',
                       'stream' => '0'
                     },
          'sfd-1' => {
                       'fd' => qr/^\d+$/,
                       'local_intf_uid' => '0',
                       'localport' => qr/^\d+$/,
                       'logical_intf' => 'foo',
                       'pref_family' => 'IP4',
                       'stream' => '1'
                     },
          'sfd-2' => {
                       'fd' => qr/^\d+$/,
                       'local_intf_uid' => '0',
                       'localport' => qr/^\d+$/,
                       'logical_intf' => 'foo',
                       'pref_family' => 'IP4',
                       'stream' => '2'
                     },
          'sfd-3' => {
                       'fd' => qr/^\d+$/,
                       'local_intf_uid' => '0',
                       'localport' => qr/^\d+$/,
                       'logical_intf' => 'foo',
                       'pref_family' => 'IP4',
                       'stream' => '3'
                     },
          'sfd-4' => {
                       'fd' => qr/^\d+$/,
                       'local_intf_uid' => '0',
                       'localport' => qr/^\d+$/,
                       'logical_intf' => 'foo',
                       'pref_family' => 'IP4',
                       'stream' => '4'
                     },
          'sfd-5' => {
                       'fd' => qr/^\d+$/,
                       'local_intf_uid' => '0',
                       'localport' => qr/^\d+$/,
                       'logical_intf' => 'foo',
                       'pref_family' => 'IP4',
                       'stream' => '5'
                     },
          'sfd-6' => {
                       'fd' => qr/^\d+$/,
                       'local_intf_uid' => '0',
                       'localport' => qr/^\d+$/,
                       'logical_intf' => 'foo',
                       'pref_family' => 'IP4',
                       'stream' => '6'
                     },
          'sfd-7' => {
                       'fd' => qr/^\d+$/,
                       'local_intf_uid' => '0',
                       'localport' => qr/^\d+$/,
                       'logical_intf' => 'foo',
                       'pref_family' => 'IP4',
                       'stream' => '7'
                     },
          'ssrc_table-0' => [],
          'ssrc_table-1' => [],
          'ssrc_table-2' => [],
          'stream-0' => {
                          'advertised_endpoint' => '198.51.100.14:6090',
                          'component' => '1',
                          'endpoint' => '198.51.100.14:6090',
                          'last_packet' => qr/^\d+$/,
                          'media' => '1',
                          'ps_flags' => '1114112',
                          'rtcp_sibling' => '1',
                          'sfd' => '0',
                          'stats-bytes' => '0',
                          'stats-errors' => '0',
                          'stats-packets' => '0'
                        },
          'stream-1' => {
                          'advertised_endpoint' => '198.51.100.14:6091',
                          'component' => '2',
                          'endpoint' => '198.51.100.14:6091',
                          'last_packet' => qr/^\d+$/,
                          'media' => '1',
                          'ps_flags' => '68288513',
                          'rtcp_sibling' => '4294967295',
                          'sfd' => '1',
                          'stats-bytes' => '0',
                          'stats-errors' => '0',
                          'stats-packets' => '0'
                        },
          'stream-2' => {
                          'advertised_endpoint' => '198.51.100.14:6088',
                          'component' => '1',
                          'endpoint' => '198.51.100.14:6088',
                          'last_packet' => qr/^\d+$/,
                          'media' => '0',
                          'ps_flags' => '1114112',
                          'rtcp_sibling' => '3',
                          'sfd' => '2',
                          'stats-bytes' => '0',
                          'stats-errors' => '0',
                          'stats-packets' => '0'
                        },
          'stream-3' => {
                          'advertised_endpoint' => '198.51.100.14:6089',
                          'component' => '2',
                          'endpoint' => '198.51.100.14:6089',
                          'last_packet' => qr/^\d+$/,
                          'media' => '0',
                          'ps_flags' => '68288513',
                          'rtcp_sibling' => '4294967295',
                          'sfd' => '3',
                          'stats-bytes' => '0',
                          'stats-errors' => '0',
                          'stats-packets' => '0'
                        },
          'stream-4' => {
                          'advertised_endpoint' => '',
                          'component' => '1',
                          'endpoint' => '',
                          'last_packet' => qr/^\d+$/,
                          'media' => '2',
                          'ps_flags' => '65536',
                          'rtcp_sibling' => '5',
                          'sfd' => '4',
                          'stats-bytes' => '0',
                          'stats-errors' => '0',
                          'stats-packets' => '0'
                        },
          'stream-5' => {
                          'advertised_endpoint' => '',
                          'component' => '2',
                          'endpoint' => '',
                          'last_packet' => qr/^\d+$/,
                          'media' => '2',
                          'ps_flags' => '131072',
                          'rtcp_sibling' => '4294967295',
                          'sfd' => '5',
                          'stats-bytes' => '0',
                          'stats-errors' => '0',
                          'stats-packets' => '0'
                        },
          'stream-6' => {
                          'advertised_endpoint' => '',
                          'component' => '1',
                          'endpoint' => '',
                          'last_packet' => qr/^\d+$/,
                          'media' => '3',
                          'ps_flags' => '65536',
                          'rtcp_sibling' => '7',
                          'sfd' => '6',
                          'stats-bytes' => '0',
                          'stats-errors' => '0',
                          'stats-packets' => '0'
                        },
          'stream-7' => {
                          'advertised_endpoint' => '',
                          'component' => '2',
                          'endpoint' => '',
                          'last_packet' => qr/^\d+$/,
                          'media' => '3',
                          'ps_flags' => '131072',
                          'rtcp_sibling' => '4294967295',
                          'sfd' => '7',
                          'stats-bytes' => '0',
                          'stats-errors' => '0',
                          'stats-packets' => '0'
                        },
          'stream_sfds-0' => [
                               '0'
                             ],
          'stream_sfds-1' => [
                               '1'
                             ],
          'stream_sfds-2' => [
                               '2'
                             ],
          'stream_sfds-3' => [
                               '3'
                             ],
          'stream_sfds-4' => [
                               '4'
                             ],
          'stream_sfds-5' => [
                               '5'
                             ],
          'stream_sfds-6' => [
                               '6'
                             ],
          'stream_sfds-7' => [
                               '7'
                             ],
          'streams-1' => [
                           '0',
                           '1'
                         ],
          'streams-0' => [
                           '2',
                           '3'
                         ],
          'streams-2' => [
                           '4',
                           '5'
                         ],
          'streams-3' => [
                           '6',
                           '7'
                         ],
          'media-subscriptions-0' => [
                                 '1/1/0/0'
                               ],
          'media-subscriptions-1' => [
                                 '0/1/0/0'
                               ],
          'media-subscriptions-2' => [
                                 '0/0/0/0'
                               ],
          'tag-0' => {
                       'block_dtmf' => '0',
                       'created' => qr/^\d+$/,
                       'deleted' => '0',
		       'desired_family' => 'IP4',
                       'logical_intf' => 'foo',
		       'ml_flags' => 0,
                       'tag' => ft()
                     },
          'tag-1' => {
                       'block_dtmf' => '0',
                       'created' => qr/^\d+$/,
                       'deleted' => '0',
		       'desired_family' => 'IP4',
                       'logical_intf' => 'foo',
		       'ml_flags' => 0,
                       'tag' => tt()
                     },
          'tag-2' => {
                       'block_dtmf' => '0',
                       'created' => qr/^\d+$/,
                       'deleted' => '0',
		       'desired_family' => 'IP4',
                       'logical_intf' => 'foo',
		       'ml_flags' => 0,
                       'tag' => qr//
                     }
        };

my ($ftr, $ttr, $fts) = subscribe_request('sub to multiple tags',
	{ 'from-tags' => [ft(), tt()] }, <<SDP);
v=0
o=- SDP_VERSION IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP


$json_exp->{'media-1'}{media_flags} = '2293772';
$json_exp->{'media-0'}{media_flags} = '65548';
$json_exp->{'media-2'}{format_str} = '8';
$json_exp->{'media-2'}{media_flags} = '2162692';
$json_exp->{'media-3'}{format_str} = '8';
$json_exp->{'media-3'}{media_flags} = '2162692';
$json_exp->{'payload_types-2'}[0] = '8/PCMA/8000///0/20';
$#{$json_exp->{'payload_types-2'}} = 0;
$json_exp->{'payload_types-3'}[0] = '8/PCMA/8000///0/20';
$#{$json_exp->{'payload_types-3'}} = 0;
$json_exp->{'stream-1'}{ps_flags} = '1179649';
$json_exp->{'stream-3'}{ps_flags} = '1179649';
$json_exp->{'stream-4'}{advertised_endpoint} = '198.51.100.14:6092';
$json_exp->{'stream-4'}{endpoint} = '198.51.100.14:6092';
$json_exp->{'stream-4'}{ps_flags} = '1114112';
$json_exp->{'stream-5'}{advertised_endpoint} = '198.51.100.14:6093';
$json_exp->{'stream-5'}{endpoint} = '198.51.100.14:6093';
$json_exp->{'stream-5'}{ps_flags} = '1179649';
$json_exp->{'stream-6'}{advertised_endpoint} = '198.51.100.14:6094';
$json_exp->{'stream-6'}{endpoint} = '198.51.100.14:6094';
$json_exp->{'stream-6'}{ps_flags} = '1114112';
$json_exp->{'stream-7'}{advertised_endpoint} = '198.51.100.14:6095';
$json_exp->{'stream-7'}{endpoint} = '198.51.100.14:6095';
$json_exp->{'stream-7'}{ps_flags} = '1179649';

subscribe_answer('sub to multiple tags',
	{ 'to-tag' => $ttr, flags => ['allow transcoding'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6092 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
m=audio 6094 RTP/AVP 8
c=IN IP4 198.51.100.14
a=recvonly
SDP






new_call;

$json_exp = {
  'associated_tags-0' => [],
  'json' => {
	      'block_dtmf' => '0',
	      'call_flags' => 0,
	      'created' => qr//,
	      'created_from' => qr//,
	      'created_from_addr' => qr//,
	      'deleted' => '0',
	      'destroyed' => '0',
	      'last_signal' => qr//,
	      'ml_deleted' => '0',
	      'num_maps' => '1',
	      'num_medias' => '1',
	      'num_sfds' => '2',
	      'num_streams' => '2',
	      'num_tags' => '1',
	      'recording_metadata' => '',
	      'redis_hosted_db' => '2',
	      'tos' => '0'
	    },
  'map-0' => {
	       'endpoint' => '',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '1'
	     },
  'map_sfds-0' => [
		    'loc-0',
		    '0',
		    '1'
		  ],
  'maps-0' => [
		'0'
	      ],
  'media-0' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0 8 9',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '65544',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '0',
		 'type' => 'audio'
	       },
  'medias-0' => [
		  '0'
		],
  'payload_types-0' => [
			 '0/PCMU/8000///0/20'
		       ],
  'rtcp_sinks-0' => [],
  'rtcp_sinks-1' => [],
  'rtp_sinks-0' => [],
  'rtp_sinks-1' => [],
  'sfd-0' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '0'
	     },
  'sfd-1' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '1'
	     },
  'ssrc_table-0' => [],
  'stream-0' => {
		  'advertised_endpoint' => '198.51.100.14:6042',
		  'component' => '1',
		  'endpoint' => '198.51.100.14:6042',
		  'last_packet' => qr//,
		  'media' => '0',
		  'ps_flags' => '1114112',
		  'rtcp_sibling' => '1',
		  'sfd' => '0',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-1' => {
		  'advertised_endpoint' => '198.51.100.14:6043',
		  'component' => '2',
		  'endpoint' => '198.51.100.14:6043',
		  'last_packet' => qr//,
		  'media' => '0',
		  'ps_flags' => '1179649',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '1',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream_sfds-0' => [
		       '0'
		     ],
  'stream_sfds-1' => [
		       '1'
		     ],
  'streams-0' => [
		   '0',
		   '1'
		 ],
  'media-subscriptions-0' => [],
  'tag-0' => {
	       'block_dtmf' => '0',
	       'created' => qr//,
	       'deleted' => '0',
	       'desired_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	       'tag' => ft()
	     }
};

publish('publish/subscribe',
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

$json_exp = {
  'associated_tags-0' => [],
  'associated_tags-1' => [],
  'json' => {
	      'block_dtmf' => '0',
	      'call_flags' => 0,
	      'created' => qr//,
	      'created_from' => qr//,
	      'created_from_addr' => qr//,
	      'deleted' => '0',
	      'destroyed' => '0',
	      'last_signal' => qr//,
	      'ml_deleted' => '0',
	      'num_maps' => '2',
	      'num_medias' => '2',
	      'num_sfds' => '4',
	      'num_streams' => '4',
	      'num_tags' => '2',
	      'recording_metadata' => '',
	      'redis_hosted_db' => '2',
	      'tos' => '0'
	    },
  'map-0' => {
	       'endpoint' => '',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '1'
	     },
  'map-1' => {
	       'endpoint' => '',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '1'
	     },
  'map_sfds-0' => [
		    'loc-0',
		    '0',
		    '1'
		  ],
  'map_sfds-1' => [
		    'loc-0',
		    '2',
		    '3'
		  ],
  'maps-0' => [
		'0'
	      ],
  'maps-1' => [
		'1'
	      ],
  'media-0' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0 8 9',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '65544',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '0',
		 'type' => 'audio'
	       },
  'media-1' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0 8 9',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '2097156',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '1',
		 'type' => 'audio'
	       },
  'medias-0' => [
		  '0'
		],
  'medias-1' => [
		  '1'
		],
  'payload_types-0' => [
			 '0/PCMU/8000///0/20'
		       ],
  'payload_types-1' => [
			 '0/PCMU/8000///0/20'
		       ],
  'rtcp_sinks-0' => [],
  'rtcp_sinks-1' => [
		      '3'
		    ],
  'rtcp_sinks-2' => [],
  'rtcp_sinks-3' => [],
  'rtp_sinks-0' => [
		     '2'
		   ],
  'rtp_sinks-1' => [],
  'rtp_sinks-2' => [],
  'rtp_sinks-3' => [],
  'sfd-0' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '0'
	     },
  'sfd-1' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '1'
	     },
  'sfd-2' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '2'
	     },
  'sfd-3' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '3'
	     },
  'ssrc_table-0' => [],
  'ssrc_table-1' => [],
  'stream-0' => {
		  'advertised_endpoint' => '198.51.100.14:6042',
		  'component' => '1',
		  'endpoint' => '198.51.100.14:6042',
		  'last_packet' => qr//,
		  'media' => '0',
		  'ps_flags' => '1114112',
		  'rtcp_sibling' => '1',
		  'sfd' => '0',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-1' => {
		  'advertised_endpoint' => '198.51.100.14:6043',
		  'component' => '2',
		  'endpoint' => '198.51.100.14:6043',
		  'last_packet' => qr//,
		  'media' => '0',
		  'ps_flags' => '68288513',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '1',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-2' => {
		  'advertised_endpoint' => '',
		  'component' => '1',
		  'endpoint' => '',
		  'last_packet' => qr//,
		  'media' => '1',
		  'ps_flags' => '65536',
		  'rtcp_sibling' => '3',
		  'sfd' => '2',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-3' => {
		  'advertised_endpoint' => '',
		  'component' => '2',
		  'endpoint' => '',
		  'last_packet' => qr//,
		  'media' => '1',
		  'ps_flags' => '131072',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '3',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream_sfds-0' => [
		       '0'
		     ],
  'stream_sfds-1' => [
		       '1'
		     ],
  'stream_sfds-2' => [
		       '2'
		     ],
  'stream_sfds-3' => [
		       '3'
		     ],
  'streams-0' => [
		   '0',
		   '1'
		 ],
  'streams-1' => [
		   '2',
		   '3'
		 ],
  'media-subscriptions-0' => [],
  'media-subscriptions-1' => [
			 '0/0/0/0'
		       ],
  'tag-0' => {
	       'block_dtmf' => '0',
	       'created' => qr//,
	       'deleted' => '0',
	       'desired_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	       'tag' => ft()
	     },
  'tag-1' => {
	       'block_dtmf' => '0',
	       'created' => qr//,
	       'deleted' => '0',
	       'desired_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	       'tag' => qr//,
	     }
};

($ftr, $ttr, undef) = subscribe_request('publish/subscribe',
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

$json_exp = {
  'associated_tags-0' => [],
  'associated_tags-1' => [],
  'json' => {
	      'block_dtmf' => '0',
	      'call_flags' => 0,
	      'created' => qr//,
	      'created_from' => qr//,
	      'created_from_addr' => qr//,
	      'deleted' => '0',
	      'destroyed' => '0',
	      'last_signal' => qr//,
	      'ml_deleted' => '0',
	      'num_maps' => '2',
	      'num_medias' => '2',
	      'num_sfds' => '4',
	      'num_streams' => '4',
	      'num_tags' => '2',
	      'recording_metadata' => '',
	      'redis_hosted_db' => '2',
	      'tos' => '0'
	    },
  'map-0' => {
	       'endpoint' => '',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '1'
	     },
  'map-1' => {
	       'endpoint' => '',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '1'
	     },
  'map_sfds-0' => [
		    'loc-0',
		    '0',
		    '1'
		  ],
  'map_sfds-1' => [
		    'loc-0',
		    '2',
		    '3'
		  ],
  'maps-0' => [
		'0'
	      ],
  'maps-1' => [
		'1'
	      ],
  'media-0' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0 8 9',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '65544',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '0',
		 'type' => 'audio'
	       },
  'media-1' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '2162692',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '1',
		 'type' => 'audio'
	       },
  'medias-0' => [
		  '0'
		],
  'medias-1' => [
		  '1'
		],
  'payload_types-0' => [
			 '0/PCMU/8000///0/20'
		       ],
  'payload_types-1' => [
			 '0/PCMU/8000///0/20'
		       ],
  'rtcp_sinks-0' => [],
  'rtcp_sinks-1' => [
		      '3'
		    ],
  'rtcp_sinks-2' => [],
  'rtcp_sinks-3' => [],
  'rtp_sinks-0' => [
		     '2'
		   ],
  'rtp_sinks-1' => [],
  'rtp_sinks-2' => [],
  'rtp_sinks-3' => [],
  'sfd-0' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '0'
	     },
  'sfd-1' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '1'
	     },
  'sfd-2' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '2'
	     },
  'sfd-3' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '3'
	     },
  'ssrc_table-0' => [],
  'ssrc_table-1' => [],
  'stream-0' => {
		  'advertised_endpoint' => '198.51.100.14:6042',
		  'component' => '1',
		  'endpoint' => '198.51.100.14:6042',
		  'last_packet' => qr//,
		  'media' => '0',
		  'ps_flags' => '1114112',
		  'rtcp_sibling' => '1',
		  'sfd' => '0',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-1' => {
		  'advertised_endpoint' => '198.51.100.14:6043',
		  'component' => '2',
		  'endpoint' => '198.51.100.14:6043',
		  'last_packet' => qr//,
		  'media' => '0',
		  'ps_flags' => '1179649',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '1',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-2' => {
		  'advertised_endpoint' => '198.51.100.14:6044',
		  'component' => '1',
		  'endpoint' => '198.51.100.14:6044',
		  'last_packet' => qr//,
		  'media' => '1',
		  'ps_flags' => '1114112',
		  'rtcp_sibling' => '3',
		  'sfd' => '2',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-3' => {
		  'advertised_endpoint' => '198.51.100.14:6045',
		  'component' => '2',
		  'endpoint' => '198.51.100.14:6045',
		  'last_packet' => qr//,
		  'media' => '1',
		  'ps_flags' => '1179649',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '3',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream_sfds-0' => [
		       '0'
		     ],
  'stream_sfds-1' => [
		       '1'
		     ],
  'stream_sfds-2' => [
		       '2'
		     ],
  'stream_sfds-3' => [
		       '3'
		     ],
  'streams-0' => [
		   '0',
		   '1'
		 ],
  'streams-1' => [
		   '2',
		   '3'
		 ],
  'media-subscriptions-0' => [],
  'media-subscriptions-1' => [
			 '0/0/0/0'
		       ],
  'tag-0' => {
	       'block_dtmf' => '0',
	       'created' => qr//,
	       'deleted' => '0',
	       'desired_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	       'tag' => ft()
	     },
  'tag-1' => {
	       'block_dtmf' => '0',
	       'created' => qr//,
	       'deleted' => '0',
	       'desired_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	       'tag' => qr//,
	     }
};

subscribe_answer('publish/subscribe',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6044 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP

$json_exp = {
  'associated_tags-0' => [],
  'associated_tags-1' => [],
  'associated_tags-2' => [],
  'json' => {
	      'block_dtmf' => '0',
	      'call_flags' => 0,
	      'created' => qr//,
	      'created_from' => qr//,
	      'created_from_addr' => qr//,
	      'deleted' => '0',
	      'destroyed' => '0',
	      'last_signal' => qr//,
	      'ml_deleted' => '0',
	      'num_maps' => '3',
	      'num_medias' => '3',
	      'num_sfds' => '6',
	      'num_streams' => '6',
	      'num_tags' => '3',
	      'recording_metadata' => '',
	      'redis_hosted_db' => '2',
	      'tos' => '0'
	    },
  'map-0' => {
	       'endpoint' => '',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '1'
	     },
  'map-1' => {
	       'endpoint' => '',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '1'
	     },
  'map-2' => {
	       'endpoint' => '',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'num_ports' => '2',
	       'wildcard' => '1'
	     },
  'map_sfds-0' => [
		    'loc-0',
		    '0',
		    '1'
		  ],
  'map_sfds-1' => [
		    'loc-0',
		    '2',
		    '3'
		  ],
  'map_sfds-2' => [
		    'loc-0',
		    '4',
		    '5'
		  ],
  'maps-0' => [
		'0'
	      ],
  'maps-1' => [
		'1'
	      ],
  'maps-2' => [
		'2'
	      ],
  'media-0' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0 8 9',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '65544',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '0',
		 'type' => 'audio'
	       },
  'media-1' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '2162692',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '1',
		 'type' => 'audio'
	       },
  'media-2' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0 8 9',
		 'index' => '1',
		 'logical_intf' => 'foo',
		 'media_flags' => '2097156',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '2',
		 'type' => 'audio'
	       },
  'medias-0' => [
		  '0'
		],
  'medias-1' => [
		  '1'
		],
  'medias-2' => [
		  '2'
		],
  'payload_types-0' => [
			 '0/PCMU/8000///0/20'
		       ],
  'payload_types-1' => [
			 '0/PCMU/8000///0/20'
		       ],
  'payload_types-2' => [
			 '0/PCMU/8000///0/20'
		       ],
  'rtcp_sinks-0' => [],
  'rtcp_sinks-1' => [
		      '3',
		      '5'
		    ],
  'rtcp_sinks-2' => [],
  'rtcp_sinks-3' => [],
  'rtcp_sinks-4' => [],
  'rtcp_sinks-5' => [],
  'rtp_sinks-0' => [
		     '2',
		     '4'
		   ],
  'rtp_sinks-1' => [],
  'rtp_sinks-2' => [],
  'rtp_sinks-3' => [],
  'rtp_sinks-4' => [],
  'rtp_sinks-5' => [],
  'sfd-0' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '0'
	     },
  'sfd-1' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '1'
	     },
  'sfd-2' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '2'
	     },
  'sfd-3' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '3'
	     },
  'sfd-4' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '4'
	     },
  'sfd-5' => {
	       'fd' => qr//,
	       'local_intf_uid' => '0',
	       'localport' => qr//,
	       'logical_intf' => 'foo',
	       'pref_family' => 'IP4',
	       'stream' => '5'
	     },
  'ssrc_table-0' => [],
  'ssrc_table-1' => [],
  'ssrc_table-2' => [],
  'stream-0' => {
		  'advertised_endpoint' => '198.51.100.14:6042',
		  'component' => '1',
		  'endpoint' => '198.51.100.14:6042',
		  'last_packet' => qr//,
		  'media' => '0',
		  'ps_flags' => '1114112',
		  'rtcp_sibling' => '1',
		  'sfd' => '0',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-1' => {
		  'advertised_endpoint' => '198.51.100.14:6043',
		  'component' => '2',
		  'endpoint' => '198.51.100.14:6043',
		  'last_packet' => qr//,
		  'media' => '0',
		  'ps_flags' => '68288513',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '1',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-2' => {
		  'advertised_endpoint' => '198.51.100.14:6044',
		  'component' => '1',
		  'endpoint' => '198.51.100.14:6044',
		  'last_packet' => qr//,
		  'media' => '1',
		  'ps_flags' => '1114112',
		  'rtcp_sibling' => '3',
		  'sfd' => '2',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-3' => {
		  'advertised_endpoint' => '198.51.100.14:6045',
		  'component' => '2',
		  'endpoint' => '198.51.100.14:6045',
		  'last_packet' => qr//,
		  'media' => '1',
		  'ps_flags' => '1179649',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '3',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-4' => {
		  'advertised_endpoint' => '',
		  'component' => '1',
		  'endpoint' => '',
		  'last_packet' => qr//,
		  'media' => '2',
		  'ps_flags' => '65536',
		  'rtcp_sibling' => '5',
		  'sfd' => '4',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream-5' => {
		  'advertised_endpoint' => '',
		  'component' => '2',
		  'endpoint' => '',
		  'last_packet' => qr//,
		  'media' => '2',
		  'ps_flags' => '131072',
		  'rtcp_sibling' => '4294967295',
		  'sfd' => '5',
		  'stats-bytes' => '0',
		  'stats-errors' => '0',
		  'stats-packets' => '0'
		},
  'stream_sfds-0' => [
		       '0'
		     ],
  'stream_sfds-1' => [
		       '1'
		     ],
  'stream_sfds-2' => [
		       '2'
		     ],
  'stream_sfds-3' => [
		       '3'
		     ],
  'stream_sfds-4' => [
		       '4'
		     ],
  'stream_sfds-5' => [
		       '5'
		     ],
  'streams-0' => [
		   '0',
		   '1'
		 ],
  'streams-1' => [
		   '2',
		   '3'
		 ],
  'streams-2' => [
		   '4',
		   '5'
		 ],
  'media-subscriptions-0' => [],
  'media-subscriptions-1' => [
			 '0/0/0/0'
		       ],
  'media-subscriptions-2' => [
			 '0/0/0/0'
		       ],
  'tag-0' => {
	       'block_dtmf' => '0',
	       'created' => qr//,
	       'deleted' => '0',
	       'desired_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	       'tag' => ft()
	     },
  'tag-1' => {
	       'block_dtmf' => '0',
	       'created' => qr//,
	       'deleted' => '0',
	       'desired_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	       'tag' => qr//,
	     },
  'tag-2' => {
	       'block_dtmf' => '0',
	       'created' => qr//,
	       'deleted' => '0',
	       'desired_family' => 'IP4',
	       'logical_intf' => 'foo',
	       'ml_flags' => 0,
	       'tag' => qr//,
	     }
};

($ftr, $ttr, undef) = subscribe_request('publish/subscribe',
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

$json_exp->{'media-2'}{format_str} = '0';
$json_exp->{'media-2'}{media_flags} = '2162692';
$json_exp->{'stream-1'}{ps_flags}  = '1179649';
$json_exp->{'stream-4'}{advertised_endpoint} = '198.51.100.14:6046';
$json_exp->{'stream-4'}{endpoint}  = '198.51.100.14:6046';
$json_exp->{'stream-4'}{ps_flags}  = '1114112';
$json_exp->{'stream-5'}{advertised_endpoint} = '198.51.100.14:6047';
$json_exp->{'stream-5'}{endpoint}  = '198.51.100.14:6047';
$json_exp->{'stream-5'}{ps_flags}  = '1179649';

subscribe_answer('publish/subscribe',
	{ 'to-tag' => $ttr }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6046 RTP/AVP 0
c=IN IP4 198.51.100.14
a=recvonly
SDP




done_testing();
