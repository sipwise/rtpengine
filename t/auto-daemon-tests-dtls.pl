#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use Test2::Tools::Compare qw();
use NGCP::Rtpclient::ICE;
use NGCP::Rtpclient::DTLS;
use POSIX;
use IO::Multiplex;

$ENV{RTPENGINE_EXTENDED_TESTS} or exit();


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -f -L 7 -E --log-level-internals=7))
		or die;

my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $ssrc, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx, $t_a, $t_b, $t_c, $t_d,
	$sock_cx, $sock_dx, $port_c, $port_d, $port_cx, $port_dx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $has_recv, $tmp_blob,
	$pwd_a, $pwd_b, $packet, $tls_id_a, $tls_id_b, $dtls, $mux, $fingerprint,
	$fingerprint_a, $fingerprint_b, @components, $packet, $tid);





my $dtls_func = sub {
	my ($tag, $data) = @_;
	my $component = $components[$tag];
	my ($sock, $port) = @$component;
	snd($sock, $port, $data);
};

sub mux_input {
	my ($self, $mux, $fh, $input) = @_;
	my $peer = $mux->udp_peer($fh);
	$dtls->input($fh, $input, $peer);

	for my $comp (@$dtls) {
		$comp->{_connected} or return;
	}

	ok(1, 'DTLS connected');
	$mux->endloop();
};




($sock_a) = new_call([qw(198.51.100.35 3060)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

offer('re-invite bkw passive port change B', {
	'transport-protocol' => 'RTP/AVP',
	SDES => 'off',
	'rtcp-mux' => 'demux',
	DTLS => 'passive',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3060 RTP/SAVP 0
a=setup:actpass
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


($port_a, $port_ax, undef, $tls_id_a) = answer('re-invite bkw passive port change B', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:passive
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_ax, 'rtcp-mux');

# passive connect
$mux->add($sock_a);
@components = ([$sock_a, $port_a]);
$dtls->connect();
$mux->loop();


$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

offer('re-invite bkw passive port change B', {
	'rtcp-mux' => 'demux',
	DTLS => 'passive',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3060 RTP/SAVP 0
a=setup:actpass
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


($port_b, $port_bx, undef, $tls_id_b) = answer('re-invite bkw passive port change A/B', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 2998 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:passive
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

isnt($port_a, $port_b, 'different port');
isnt($tls_id_a, $tls_id_b, 'different TLS ID');
is($port_b, $port_bx, 'rtcp-mux');

# active connect
$mux->add($sock_a);
@components = ([$sock_a, $port_b]);
$dtls->connect();
$mux->loop();


rtpe_req('delete', 'delete');




($sock_a, $sock_b) = new_call([qw(198.51.100.35 3056)], [qw(198.51.100.35 3058)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

offer('re-invite bkw passive port change A/B', {
	'transport-protocol' => 'RTP/AVP',
	SDES => 'off',
	'rtcp-mux' => 'demux',
	DTLS => 'passive',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3056 RTP/SAVP 0
a=setup:actpass
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


($port_a, $port_ax, undef, $tls_id_a) = answer('re-invite bkw passive port change A/B', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:passive
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_ax, 'rtcp-mux');

# passive connect
$mux->add($sock_a);
@components = ([$sock_a, $port_a]);
$dtls->connect();
$mux->loop();


$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_b]]);
$fingerprint = $dtls->[0]->fingerprint();

offer('re-invite bkw passive port change A/B', {
	'rtcp-mux' => 'demux',
	DTLS => 'passive',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3058 RTP/SAVP 0
a=setup:actpass
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


($port_b, $port_bx, undef, $tls_id_b) = answer('re-invite bkw passive port change A/B', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 2998 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:passive
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

isnt($port_a, $port_b, 'different port');
isnt($tls_id_a, $tls_id_b, 'different TLS ID');
is($port_b, $port_bx, 'rtcp-mux');

# active connect
$mux->add($sock_b);
@components = ([$sock_b, $port_b]);
$dtls->connect();
$mux->loop();


rtpe_req('delete', 'delete');




($sock_a, $sock_b) = new_call([qw(198.51.100.35 3052)], [qw(198.51.100.35 3054)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

offer('re-invite bkw passive port change A', {
	'transport-protocol' => 'RTP/AVP',
	SDES => 'off',
	'rtcp-mux' => 'demux',
	DTLS => 'passive',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3052 RTP/SAVP 0
a=setup:actpass
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


($port_a, $port_ax, undef, $tls_id_a) = answer('re-invite bkw passive port change A', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:passive
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_ax, 'rtcp-mux');

# passive connect
$mux->add($sock_a);
@components = ([$sock_a, $port_a]);
$dtls->connect();
$mux->loop();


$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_b]]);
$fingerprint = $dtls->[0]->fingerprint();

offer('re-invite bkw passive port change A', {
	'rtcp-mux' => 'demux',
	DTLS => 'passive',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3054 RTP/SAVP 0
a=setup:actpass
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


($port_b, $port_bx, undef, $tls_id_b) = answer('re-invite bkw passive port change A', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:passive
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_b, 'same port');
isnt($tls_id_a, $tls_id_b, 'different TLS ID');
is($port_b, $port_bx, 'rtcp-mux');

# active connect
$mux->add($sock_b);
@components = ([$sock_b, $port_b]);
$dtls->connect();
$mux->loop();


rtpe_req('delete', 'delete');




($sock_a) = new_call([qw(198.51.100.35 3050)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

offer('re-invite bkw force passive', {
	'transport-protocol' => 'RTP/AVP',
	SDES => 'off',
	'rtcp-mux' => 'demux',
	DTLS => 'passive',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3050 RTP/SAVP 0
a=setup:actpass
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


($port_a, $port_ax, undef, $tls_id_a) = answer('re-invite bkw force passive', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:passive
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_ax, 'rtcp-mux');

# active connect
$mux->add($sock_a);
@components = ([$sock_a, $port_a]);
$dtls->connect();
$mux->loop();


offer('re-invite bkw force passive', {
	'rtcp-mux' => 'demux',
	DTLS => 'passive',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3050 RTP/SAVP 0
a=setup:actpass
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


($port_b, $port_bx, undef, $tls_id_b) = answer('re-invite bkw force passive', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:passive
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_b, 'same port');
is($tls_id_a, $tls_id_b, 'same TLS ID');
is($port_b, $port_bx, 'rtcp-mux');

rcv_no($sock_a);


rtpe_req('delete', 'delete');




($sock_a) = new_call([qw(198.51.100.35 3048)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

offer('re-invite bkw passive', {
	'transport-protocol' => 'RTP/AVP',
	SDES => 'off',
	'rtcp-mux' => 'demux',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3048 RTP/SAVP 0
a=setup:active
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


($port_a, $port_ax, undef, $tls_id_a) = answer('re-invite bkw passive', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:passive
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_ax, 'rtcp-mux');

# active connect
$mux->add($sock_a);
@components = ([$sock_a, $port_a]);
$dtls->connect();
$mux->loop();


offer('re-invite bkw passive', {
	'rtcp-mux' => 'demux',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3048 RTP/SAVP 0
a=setup:active
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


($port_b, $port_bx, undef, $tls_id_b) = answer('re-invite bkw passive', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:passive
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_b, 'same port');
is($tls_id_a, $tls_id_b, 'same TLS ID');
is($port_b, $port_bx, 'rtcp-mux');

rcv_no($sock_a);


rtpe_req('delete', 'delete');




($sock_a) = new_call([qw(198.51.100.35 3046)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

offer('re-invite bkw', {
	'transport-protocol' => 'RTP/AVP',
	SDES => 'off',
	'rtcp-mux' => 'demux',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3046 RTP/SAVP 0
a=setup:actpass
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


($port_a, $port_ax, undef, $tls_id_a) = answer('re-invite bkw', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:active
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_ax, 'rtcp-mux');

# passive connect
$mux->add($sock_a);
@components = ([$sock_a, $port_a]);
$dtls->accept();
$mux->loop();


offer('re-invite bkw', {
	'rtcp-mux' => 'demux',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3046 RTP/SAVP 0
a=setup:actpass
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


($port_b, $port_bx, undef, $tls_id_b) = answer('re-invite bkw', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:active
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_b, 'same port');
is($tls_id_a, $tls_id_b, 'same TLS ID');
is($port_b, $port_bx, 'rtcp-mux');

rcv_no($sock_a);


rtpe_req('delete', 'delete');




($sock_a) = new_call([qw(198.51.100.35 3042)], [qw(198.51.100.35 3044)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

($port_a, $port_ax, undef, $tls_id_a) = offer('re-invite fwd with B port change', {
	'transport-protocol' => 'RTP/SAVP',
	SDES => 'off',
	'rtcp-mux' => 'require',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_ax, 'rtcp-mux');

answer('re-invite fwd with B port change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3042 RTP/SAVP 0
a=setup:active
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# active connect
$mux->add($sock_a);
@components = ([$sock_a, $port_a]);
$dtls->connect();
$mux->loop();



($port_b, $port_bx, undef, $tls_id_b) = offer('re-invite fwd with B port change', {
	'transport-protocol' => 'RTP/SAVP',
	SDES => 'off',
	'rtcp-mux' => 'require',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_b, 'same port');
is($tls_id_a, $tls_id_b, 'same TLS ID');
is($port_b, $port_bx, 'rtcp-mux');

rcv_no($sock_a);


# reset DTLS
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

answer('re-invite fwd with B port change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3042 RTP/SAVP 0
a=setup:active
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# active connect
$mux->add($sock_a);
@components = ([$sock_a, $port_a]);
$dtls->connect();
$mux->loop();


rtpe_req('delete', 'delete');



($sock_a) = new_call([qw(198.51.100.35 3040)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

($port_a, $port_ax, undef, $tls_id_a) = offer('re-invite fwd with role change', {
	'transport-protocol' => 'RTP/SAVP',
	SDES => 'off',
	'rtcp-mux' => 'require',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_ax, 'rtcp-mux');

answer('re-invite fwd with role change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3040 RTP/SAVP 0
a=setup:active
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# active connect
$mux->add($sock_a);
@components = ([$sock_a, $port_a]);
$dtls->connect();
$mux->loop();



($port_b, $port_bx, undef, $tls_id_b) = offer('re-invite fwd with role change', {
	'transport-protocol' => 'RTP/SAVP',
	SDES => 'off',
	'rtcp-mux' => 'require',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_b, 'same port');
is($tls_id_a, $tls_id_b, 'same TLS ID');
is($port_b, $port_bx, 'rtcp-mux');

rcv_no($sock_a);


# reset DTLS
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

answer('re-invite fwd with role change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3040 RTP/SAVP 0
a=setup:passive
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# passive connect
$mux->add($sock_a);
@components = ([$sock_a, $port_a]);
$dtls->accept();
$mux->loop();



rtpe_req('delete', 'delete');



($sock_a) = new_call([qw(198.51.100.35 3038)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

($port_a, $port_ax, undef, $tls_id_a) = offer('re-invite fwd passive', {
	'transport-protocol' => 'RTP/SAVP',
	SDES => 'off',
	'rtcp-mux' => 'require',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_ax, 'rtcp-mux');

answer('re-invite fwd passive', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3038 RTP/SAVP 0
a=setup:passive
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# passive connect
$mux->add($sock_a);
@components = ([$sock_a, $port_a]);
$dtls->accept();
$mux->loop();



($port_b, $port_bx, undef, $tls_id_b) = offer('re-invite fwd passive', {
	'transport-protocol' => 'RTP/SAVP',
	SDES => 'off',
	'rtcp-mux' => 'require',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_b, 'same port');
is($tls_id_a, $tls_id_b, 'same TLS ID');
is($port_b, $port_bx, 'rtcp-mux');

rcv_no($sock_a);


answer('re-invite fwd passive', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3038 RTP/SAVP 0
a=setup:passive
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

rcv_no($sock_a);



rtpe_req('delete', 'delete');



($sock_a) = new_call([qw(198.51.100.35 3036)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

($port_a, $port_ax, undef, $tls_id_a) = offer('re-invite fwd', {
	'transport-protocol' => 'RTP/SAVP',
	SDES => 'off',
	'rtcp-mux' => 'require',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_ax, 'rtcp-mux');

answer('re-invite fwd', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3036 RTP/SAVP 0
a=setup:active
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

rcv_no($sock_a);

# active connect
$mux->add($sock_a);
@components = ([$sock_a, $port_a]);
$dtls->connect();
$mux->loop();



($port_b, $port_bx, undef, $tls_id_b) = offer('re-invite fwd', {
	'transport-protocol' => 'RTP/SAVP',
	SDES => 'off',
	'rtcp-mux' => 'require',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_b, 'same port');
is($tls_id_a, $tls_id_b, 'same TLS ID');
is($port_b, $port_bx, 'rtcp-mux');

rcv_no($sock_a);


answer('re-invite fwd', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3036 RTP/SAVP 0
a=setup:active
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

rcv_no($sock_a);



rtpe_req('delete', 'delete');



($sock_a) = new_call([qw(198.51.100.35 3034)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

($port_a, $port_ax, undef, $tls_id_a) = offer('re-invite fwd with A port change', {
	'transport-protocol' => 'RTP/SAVP',
	SDES => 'off',
	'rtcp-mux' => 'require',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_a, $port_ax, 'rtcp-mux');

answer('re-invite fwd with A port change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3034 RTP/SAVP 0
a=setup:active
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

rcv_no($sock_a);

# active connect
$mux->add($sock_a);
@components = ([$sock_a, $port_a]);
$dtls->connect();
$mux->loop();



($port_b, $port_bx, undef, $tls_id_b) = offer('re-invite fwd with A port change', {
	'transport-protocol' => 'RTP/SAVP',
	SDES => 'off',
	'rtcp-mux' => 'require',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 2998 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

isnt($port_a, $port_b, 'new port');
isnt($tls_id_a, $tls_id_b, 'new TLS ID');
is($port_b, $port_bx, 'rtcp-mux');

rcv_no($sock_a);

# reset DTLS
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();


answer('re-invite fwd with A port change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3034 RTP/SAVP 0
a=setup:active
a=fingerprint:sha-256 $fingerprint
a=rtcp-mux
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

rcv_no($sock_a);

# active connect to new port
$mux->add($sock_a);
@components = ([$sock_a, $port_b]);
$dtls->connect();
$mux->loop();




rtpe_req('delete', 'delete');



($sock_a) = new_call([qw(198.51.100.35 3032)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

($port_a, $port_ax, undef, $tls_id_a, $ufrag_a, $pwd_a, undef, $port_b) = offer('ICE + DTLS fwd early start', {
	'transport-protocol' => 'RTP/SAVP',
	SDES => 'off',
	'rtcp-mux' => 'require',
	ICE => 'force',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.99
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
SDP

is($port_a, $port_b, 'same port');

# send check and receive response
($packet, $tid) = NGCP::Rtpclient::ICE::stun_req(0, 65534, 1, 'ydfgd', $ufrag_a, $pwd_a);
snd($sock_a, $port_a, $packet);
rcv($sock_a, -1, qr/^\x01\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine/s);

# active connect
$mux->add($sock_a);
@components = ([$sock_a, $port_a]);
$dtls->connect();
$mux->loop();

rtpe_req('delete', 'delete');




($sock_a) = new_call([qw(198.51.100.35 3028)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a]]);
$fingerprint = $dtls->[0]->fingerprint();

offer('ICE + DTLS bkw early start', {
	'transport-protocol' => 'RTP/AVP',
	ICE => 'remove',
	'rtcp-mux' => 'demux',
}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3028 RTP/SAVP 0
a=setup:actpass
a=fingerprint:sha-256 $fingerprint
a=tls-id:xxxxxxxxxxxxxxxx
a=ice-pwd:bd5e8b
a=ice-ufrag:q275
a=candidate:aaa 1 UDP 2130706431 198.51.100.35 3028 typ host
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# receive check and respond
@ret1 = rcv($sock_a, -1, qr/^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine.*?\x00\x06\x00\x0dq275:(........)\x00\x00\x00\x80\x29\x00\x08........\x00\x24\x00\x04\x6e\xff\xff\xff\x00\x08\x00\x14....................\x80\x28\x00\x04....$/s);
snd($sock_a, $ret1[0], NGCP::Rtpclient::ICE::stun_succ($ret1[0], $ret1[2], 'bd5e8b'));

# passive connect (accept) DTLS
$mux->add($sock_a);
@components = ([$sock_a, $ret1[0]]);
$dtls->accept();
$mux->loop();

rtpe_req('delete', 'delete');



($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.35 3008)], [qw(198.51.100.35 3009)],
							[qw(198.51.100.35 3010)], [qw(198.51.100.35 3011)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$mux->add($sock_a);
$mux->add($sock_ax);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a], [$sock_ax]]);
$fingerprint = $dtls->[0]->fingerprint();

($port_a, $port_ax) = offer('DTLS bkw', { 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3008 RTP/SAVP 0
a=setup:actpass
a=fingerprint:sha-256 $fingerprint
a=tls-id:xxxxxxxxxxxxxxxx
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('DTLS bkw', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3010 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=setup:active
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

@components = ([$sock_a, $port_b], [$sock_ax, $port_bx]);

$dtls->accept();

$mux->loop();

rtpe_req('delete', 'delete');



($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.35 3000)], [qw(198.51.100.35 3001)],
							[qw(198.51.100.35 3002)], [qw(198.51.100.35 3003)]);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$mux->add($sock_b);
$mux->add($sock_bx);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_b], [$sock_bx]]);
$fingerprint = $dtls->[0]->fingerprint();

($port_a, $port_ax) = offer('DTLS fwd', { 'transport-protocol' => 'RTP/SAVP', SDES => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

($port_b, $port_bx) = answer('DTLS fwd', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3002 RTP/SAVP 0
a=setup:active
a=fingerprint:sha-256 $fingerprint
a=tls-id:xxxxxxxxxxxxxxxx
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

@components = ([$sock_b, $port_a], [$sock_bx, $port_ax]);

$dtls->connect();

$mux->loop();

rtpe_req('delete', 'delete');



($sock_a, $sock_ax, $sock_b, $sock_bx, $sock_c, $sock_cx, $sock_d, $sock_dx) = new_call(
	[qw(198.51.100.35 3016)], [qw(198.51.100.35 3017)],
	[qw(198.51.100.35 3018)], [qw(198.51.100.35 3019)],
	[qw(198.51.100.35 3020)], [qw(198.51.100.35 3021)],
	[qw(198.51.100.35 3022)], [qw(198.51.100.35 3023)],
);

$mux = IO::Multiplex->new();
$mux->set_callback_object(__PACKAGE__);
$mux->add($sock_a);
$mux->add($sock_ax);
$dtls = NGCP::Rtpclient::DTLS::Group->new($mux, $dtls_func, [[$sock_a], [$sock_ax]]);
$fingerprint = $dtls->[0]->fingerprint();

($port_a, $port_ax, $port_c, $port_cx) = offer('bundle DTLS bkw', { 'transport-protocol' => 'RTP/AVP', bundle => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
a=group:BUNDLE 1 2
m=audio 3016 RTP/SAVP 0
a=setup:actpass
a=fingerprint:sha-256 $fingerprint
a=tls-id:xxxxxxxxxxxxxxxx
a=mid:1
m=audio 3020 RTP/SAVP 8
a=setup:actpass
a=fingerprint:sha-256 $fingerprint
a=tls-id:xxxxxxxxxxxxxxxx
a=mid:2
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=mid:2
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx, $fingerprint_a, $tls_id_a, $port_d, $port_dx, $fingerprint_b, $tls_id_b) = answer('bundle DTLS bkw', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3018 RTP/AVP 0
m=audio 3022 RTP/AVP 8
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
a=group:BUNDLE 1 2
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=setup:active
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=mid:2
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=setup:active
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

is($port_b, $port_d, 'same port');
is($port_bx, $port_dx, 'same port');
is($fingerprint_a, $fingerprint_b, 'same fingerprint');
is($tls_id_a, $tls_id_b, 'same TLS ID');

@components = ([$sock_a, $port_b], [$sock_ax, $port_bx]);

$dtls->accept();

$mux->loop();

rcv_no($sock_c);
rcv_no($sock_cx);

rtpe_req('delete', 'delete');



#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
