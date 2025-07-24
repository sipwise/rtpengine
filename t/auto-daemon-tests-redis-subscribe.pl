#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use Test2::Tools::Compare qw();
use Socket qw(AF_INET SOCK_STREAM sockaddr_in pack_sockaddr_in inet_aton);
use Bencode;
use Data::Dumper;

$Data::Dumper::Sortkeys = 1;


# fake Redis listener
my $redis_listener;
socket($redis_listener, AF_INET, SOCK_STREAM, 0) or die;
bind($redis_listener, sockaddr_in(6379, inet_aton('203.0.113.42'))) or die;
listen($redis_listener, 10) or die;

my ($redis_fd, $redis_notify, $redis_subscribe);


sub redis_rd {
	my ($fd, $len) = @_;
	my $buf;
	alarm(1);
	recv($fd, $buf, $len, 0) or die;
	alarm(0);
	return $buf;
}
sub redis_i {
	my ($fd, $i, $n) = @_;
	my $buf = redis_rd($fd, length($i));
	is($buf, $i, $n);
}
sub redis_io {
	my ($fd, $i, $o, $n) = @_;
	redis_i($fd, $i, $n);
	send($fd, $o, 0) or die;
};


$NGCP::Rtpengine::AutoTest::launch_cb = sub {
	# accept Redis connection and read preamble

	accept($redis_fd, $redis_listener) or die;

	redis_io($redis_fd, "*1\r\n\$4\r\nPING\r\n",
		"+PONG\r\n",
		"PING 1");
	redis_io($redis_fd, "*2\r\n\$6\r\nSELECT\r\n\$1\r\n2\r\n",
		"+OK\r\n",
		"SELECT 1");
	redis_io($redis_fd, "*1\r\n\$4\r\nINFO\r\n",
		"\$13\r\nrole:master\r\n\r\n",
		"INFO 1");
	redis_io($redis_fd, "*2\r\n\$4\r\nTYPE\r\n\$5\r\ncalls\r\n",
		"+none\r\n",
		"TYPE 1");

	# second FD, notification socket

	accept($redis_notify, $redis_listener) or die;

	redis_io($redis_notify, "*1\r\n\$4\r\nPING\r\n",
		"+PONG\r\n",
		"PING 2");
	redis_io($redis_notify, "*2\r\n\$6\r\nSELECT\r\n\$1\r\n2\r\n",
		"+OK\r\n",
		"SELECT 2");
	redis_io($redis_notify, "*1\r\n\$4\r\nINFO\r\n",
		"\$13\r\nrole:master\r\n\r\n",
		"INFO 2");
	redis_io($redis_notify, "*2\r\n\$4\r\nTYPE\r\n\$5\r\ncalls\r\n",
		"+none\r\n",
		"TYPE 2");

	# two more sockets from different threads

	my @fds;
	accept($fds[0], $redis_listener) or die;
	accept($fds[1], $redis_listener) or die;

	# notification socket re-init

	redis_io($redis_notify, "*1\r\n\$4\r\nPING\r\n",
		"+PONG\r\n",
		"PING 2+1");

	for my $i (0, 1) {
		my $fd = $fds[$i];

		my $s = redis_rd($fd, 10);

		if ($s eq "*2\r\n\$10\r\np") {
			$redis_subscribe = $fd;

			redis_io($fd, "subscribe\r\n\$16\r\n__keyspace\@3__:*\r\n",
				"*3\r\n\$10\r\npsubscribe\r\n\$16\r\n__keyspace\@3__:*\r\n:1\r\n",
				"psubscribe");
		}
		elsif ($s eq "*1\r\n\$4\r\nPI") {
			# dup restore socket

			redis_io($fd, "NG\r\n",
				"+PONG\r\n",
				"PING 3");
			redis_io($fd, "*2\r\n\$6\r\nSELECT\r\n\$1\r\n2\r\n",
				"+OK\r\n",
				"SELECT 3");
			redis_io($fd, "*1\r\n\$4\r\nINFO\r\n",
				"\$13\r\nrole:master\r\n\r\n",
				"INFO 3");
			redis_io($fd, "*2\r\n\$4\r\nTYPE\r\n\$5\r\ncalls\r\n",
				"+none\r\n",
				"TYPE 3");

			# check conn, select DB, get keys, reset DB

			redis_io($fd, "*1\r\n\$4\r\nPING\r\n",
				"+PONG\r\n",
				"PING 4");
			redis_io($fd, "*2\r\n\$6\r\nSELECT\r\n\$1\r\n3\r\n",
				"+OK\r\n",
				"SELECT 4");
			redis_io($fd, "*2\r\n\$4\r\nKEYS\r\n\$1\r\n*\r\n",
				"*0\r\n",
				"KEYS 4");
			redis_io($fd, "*2\r\n\$6\r\nSELECT\r\n\$1\r\n2\r\n",
				"+OK\r\n",
				"SELECT 4+1");
		}
	}

	# restore from main socket

	redis_io($redis_fd, "*1\r\n\$4\r\nPING\r\n",
		"+PONG\r\n",
		"PING 5");
	redis_io($redis_fd, "*2\r\n\$4\r\nKEYS\r\n\$1\r\n*\r\n",
		"*0\r\n",
		"KEYS 5");
};


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E
			--redis=203.0.113.42:6379/2
			--subscribe-keyspace=3
		))
		or die;



my $json_exp;
$NGCP::Rtpengine::req_cb = sub {
	redis_io($redis_fd, "*1\r\n\$4\r\nPING\r\n", "+PONG\r\n", "req PING");
	redis_i($redis_fd, "*5\r\n\$3\r\nSET\r\n\$" . length(cid()) . "\r\n" . cid() . "\r\n\$", "req intro");
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
	my $json = Bencode::bdecode($buf, 1);
	#print Dumper($json);
	Test2::Tools::Compare::like($json, $json_exp, "JSON");
	redis_io($redis_fd, "\r\n\$2\r\nEX\r\n\$5\r\n86400\r\n",
		"+OK\r\n",
		"req outro");
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
	       'logical_intf' => 'default',
	       'num_ports' => '2',
	       'wildcard' => '0'
	     },
  'map-1' => {
	       'endpoint' => '',
	       'intf_preferred_family' => 'IP4',
	       'logical_intf' => 'default',
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
		 'logical_intf' => 'default',
		 'media_flags' => '274880135180',
		 'protocol' => 'RTP/AVP',
		 'ptime' => '0',
		 'tag' => '1',
		 'type' => 'audio'
	       },
  'media-0' => {
		 'desired_family' => 'IP4',
		 'format_str' => '0 8',
		 'index' => '1',
		 'logical_intf' => 'default',
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
			 '0/PCMU/8000//0/20//',
			 '8/PCMA/8000//0/20//'
		       ],
  'payload_types-1' => [
			 '0/PCMU/8000//0/20//',
			 '8/PCMA/8000//0/20//'
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
	       'logical_intf' => 'default',
	       'pref_family' => 'IP4',
	       'stream' => '0'
	     },
  'sfd-1' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'default',
	       'pref_family' => 'IP4',
	       'stream' => '1'
	     },
  'sfd-2' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'default',
	       'pref_family' => 'IP4',
	       'stream' => '2'
	     },
  'sfd-3' => {
	       'fd' => qr/^\d+$/,
	       'local_intf_uid' => '0',
	       'localport' => qr/^\d+$/,
	       'logical_intf' => 'default',
	       'pref_family' => 'IP4',
	       'stream' => '3'
	     },
  'ssrc_table-0' => [],
  'ssrc_table-1' => [],
  'stream-0' => {
		  'advertised_endpoint' => '',
		  'component' => '1',
		  'endpoint' => '',
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
	       'desired_family' => 'IP4',
	       'deleted' => '0',
	       'logical_intf' => 'default',
	       'ml_flags' => 0,
	       'tag' => ft()
	     },
  'tag-1' => {
	       'block_dtmf' => '0',
	       'created' => qr/^\d+$/,
	       'desired_family' => 'IP4',
	       'deleted' => '0',
	       'logical_intf' => 'default',
	       'ml_flags' => 0,
	     }
};



my ($port_a, $port_b) = offer('simple call',
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

cmp_ok($port_a, '>=', 30000, 'RTP port in range');
cmp_ok($port_a, '<=', 39998, 'RTP port in range');
is($port_b, $port_a + 1, 'RTCP port');

undef($NGCP::Rtpengine::req_cb);

my $resp = rtpe_req('list', 'list', {});
is($#{$resp->{calls}}, 0, 'calls len');
is($resp->{calls}[0], cid(), 'call ID');



# add foreign call with out-of-range port

my $dict = {
          'associated_tags-0' => [
                                   \'1'
                                 ],
          'associated_tags-1' => [
                                   \'0'
                                 ],
          'json' => {
                      'block_dtmf' => \'0',
                      'call_flags' => \'65536',
                      'created' => \(time() * 1000000),
                      'created_from' => '224.247.6.0:2',
                      'created_from_addr' => '224.247.6.0',
                      'deleted' => \'0',
                      'destroyed' => \'0',
                      'last_signal' => \(time() * 1000000),
                      'ml_deleted' => \'0',
                      'num_maps' => \'2',
                      'num_medias' => \'2',
                      'num_sfds' => \'4',
                      'num_streams' => \'4',
                      'num_tags' => \'2',
                      'recording_metadata' => '',
                      'redis_hosted_db' => \'2',
                      'tos' => \'0'
                    },
          'map-0' => {
                       'endpoint' => '198.51.100.1:3000',
                       'intf_preferred_family' => 'IP4',
                       'logical_intf' => 'default',
                       'num_ports' => \'2',
                       'wildcard' => \'0'
                     },
          'map-1' => {
                       'endpoint' => '',
                       'intf_preferred_family' => 'IP4',
                       'logical_intf' => 'default',
                       'num_ports' => \'2',
                       'wildcard' => \'1'
                     },
          'map_sfds-0' => [
                            'loc-0',
                            \'0',
                            \'1'
                          ],
          'map_sfds-1' => [
                            'loc-0',
                            \'2',
                            \'3'
                          ],
          'maps-0' => [
                        \'1'
                      ],
          'maps-1' => [
                        \'0'
                      ],
          'media-0' => {
                         'desired_family' => 'IP4',
                         'format_str' => '0 8',
                         'index' => \'1',
                         'logical_intf' => 'default',
                         'maxptime' => \'0',
                         'media_flags' => \'65548',
                         'protocol' => 'RTP/AVP',
                         'ptime' => \'0',
                         'tag' => \'0',
                         'type' => 'audio'
                       },
          'media-1' => {
                         'desired_family' => 'IP4',
                         'format_str' => '0 8',
                         'index' => \'1',
                         'logical_intf' => 'default',
                         'maxptime' => \'0',
                         'media_flags' => \'274880135180',
                         'protocol' => 'RTP/AVP',
                         'ptime' => \'0',
                         'tag' => \'1',
                         'type' => 'audio'
                       },
          'media-subscriptions-0' => [
                                       '1/1/0/0'
                                     ],
          'media-subscriptions-1' => [
                                       '0/1/0/0'
                                     ],
          'medias-0' => [
                          \'0'
                        ],
          'medias-1' => [
                          \'1'
                        ],
          'payload_types-0' => [
                                 '0/PCMU/8000//0/20//',
                                 '8/PCMA/8000//0/20//'
                               ],
          'payload_types-1' => [
                                 '0/PCMU/8000//0/20//',
                                 '8/PCMA/8000//0/20//'
                               ],
          'rtcp_sinks-0' => [
                              \'3'
                            ],
          'rtcp_sinks-1' => [
                              \'3'
                            ],
          'rtcp_sinks-2' => [
                              \'1'
                            ],
          'rtcp_sinks-3' => [
                              \'1'
                            ],
          'rtp_sinks-0' => [
                             \'2'
                           ],
          'rtp_sinks-1' => [],
          'rtp_sinks-2' => [
                             \'0'
                           ],
          'rtp_sinks-3' => [],
          'sfd-0' => {
                       'fd' => \'9',
                       'local_intf_uid' => \'0',
                       'localport' => \'7872',
                       'logical_intf' => 'default',
                       'pref_family' => 'IP4',
                       'stream' => \'0'
                     },
          'sfd-1' => {
                       'fd' => \'15',
                       'local_intf_uid' => \'0',
                       'localport' => \'7873',
                       'logical_intf' => 'default',
                       'pref_family' => 'IP4',
                       'stream' => \'1'
                     },
          'sfd-2' => {
                       'fd' => \'16',
                       'local_intf_uid' => \'0',
                       'localport' => \'8206',
                       'logical_intf' => 'default',
                       'pref_family' => 'IP4',
                       'stream' => \'2'
                     },
          'sfd-3' => {
                       'fd' => \'17',
                       'local_intf_uid' => \'0',
                       'localport' => \'8207',
                       'logical_intf' => 'default',
                       'pref_family' => 'IP4',
                       'stream' => \'3'
                     },
          'ssrc_table-0' => [],
          'ssrc_table-1' => [],
          'stream-0' => {
                          'advertised_endpoint' => '',
                          'component' => \'1',
                          'endpoint' => '',
                          'media' => \'1',
                          'ps_flags' => \'65536',
                          'rtcp_sibling' => \'1',
                          'sfd' => \'0',
                          'stats-bytes' => \'0',
                          'stats-errors' => \'0',
                          'stats-packets' => \'0'
                        },
          'stream-1' => {
                          'advertised_endpoint' => '',
                          'component' => \'2',
                          'endpoint' => '',
                          'media' => \'1',
                          'ps_flags' => \'131072',
                          'rtcp_sibling' => \'4294967295',
                          'sfd' => \'1',
                          'stats-bytes' => \'0',
                          'stats-errors' => \'0',
                          'stats-packets' => \'0'
                        },
          'stream-2' => {
                          'advertised_endpoint' => '198.51.100.1:3000',
                          'component' => \'1',
                          'endpoint' => '198.51.100.1:3000',
                          'media' => \'0',
                          'ps_flags' => \'68222976',
                          'rtcp_sibling' => \'3',
                          'sfd' => \'2',
                          'stats-bytes' => \'0',
                          'stats-errors' => \'0',
                          'stats-packets' => \'0'
                        },
          'stream-3' => {
                          'advertised_endpoint' => '198.51.100.1:3001',
                          'component' => \'2',
                          'endpoint' => '198.51.100.1:3001',
                          'media' => \'0',
                          'ps_flags' => \'1179649',
                          'rtcp_sibling' => \'4294967295',
                          'sfd' => \'3',
                          'stats-bytes' => \'0',
                          'stats-errors' => \'0',
                          'stats-packets' => \'0'
                        },
          'stream_sfds-0' => [
                               \'0'
                             ],
          'stream_sfds-1' => [
                               \'1'
                             ],
          'stream_sfds-2' => [
                               \'2'
                             ],
          'stream_sfds-3' => [
                               \'3'
                             ],
          'streams-0' => [
                           \'2',
                           \'3'
                         ],
          'streams-1' => [
                           \'0',
                           \'1'
                         ],
          'tag-0' => {
                       'block_dtmf' => \'0',
                       'created' => \(time() * 1000000),
                       'deleted' => \'0',
                       'desired_family' => 'IP4',
                       'logical_intf' => 'default',
                       'ml_flags' => \'0',
                       'sdp_orig_address_address' => '198.51.101.40',
                       'sdp_orig_address_address_type' => 'IP4',
                       'sdp_orig_address_network_type' => 'IN',
                       'sdp_orig_parsed' => \'1',
                       'sdp_orig_session_id' => \'1545997027',
                       'sdp_orig_username' => '-',
                       'sdp_orig_version_num' => \'1',
                       'sdp_orig_version_str' => \'1',
                       'sdp_session_name' => 'tester',
                       'sdp_session_timing' => '0 0',
                       'tag' => 'ML1'
                     },
          'tag-1' => {
                       'block_dtmf' => \'0',
                       'created' => \(time() * 1000000),
                       'deleted' => \'0',
                       'desired_family' => 'IP4',
                       'last_sdp_orig_address_address' => '198.51.101.40',
                       'last_sdp_orig_address_address_type' => 'IP4',
                       'last_sdp_orig_address_network_type' => 'IN',
                       'last_sdp_orig_parsed' => \'1',
                       'last_sdp_orig_session_id' => \'1545997027',
                       'last_sdp_orig_username' => '-',
                       'last_sdp_orig_version_num' => \'1',
                       'last_sdp_orig_version_str' => \'1',
                       'logical_intf' => 'default',
                       'ml_flags' => \'0',
                       'sdp_session_name' => '',
                       'sdp_session_timing' => ''
                     },
          'tag_aliases-0' => [],
          'tag_aliases-1' => []
        };

my $bdict = Bencode::bencode($dict),
send($redis_subscribe, "*4\r\n\$8\r\npmessage\r\n\$16\r\n__keyspace\@3__:*\r\n\$21\r\n__keyspace\@3__:foobar\r\n\$3\r\nset\r\n", 0);

redis_io($redis_notify, "*1\r\n\$4\r\nPING\r\n",
	"+PONG\r\n",
	"PING");
redis_io($redis_notify, "*2\r\n\$6\r\nSELECT\r\n\$1\r\n3\r\n",
	"+OK\r\n",
	"SELECT");
redis_io($redis_notify, "*2\r\n\$3\r\nGET\r\n\$6\r\nfoobar\r\n",
	"\$" . length($bdict) . "\r\n$bdict\r\n",
	"GET");

sleep(1); # wait for call to be created

$resp = rtpe_req('list', 'list', {});
my @calls = @{$resp->{calls}};
@calls = sort(@calls);
is($#calls, 1, 'calls len');
is($calls[0], cid(), 'call ID');
is($calls[1], 'foobar', 'call ID');

rtpe_req('delete', 'delete', {'call-id' => 'foobar', 'delete delay' => 0});

$resp = rtpe_req('list', 'list', {});
is($#{$resp->{calls}}, 0, 'calls len');
is($resp->{calls}[0], cid(), 'call ID');

done_testing();
