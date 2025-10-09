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
	$fingerprint_a, $fingerprint_b, @components);





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

	$mux->endloop();
};

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
