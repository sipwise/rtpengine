package NGCP::Rtpengine::AutoTest;

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use Test::More;
use File::Temp;
use IPC::Open3;
use Time::HiRes;
use POSIX ":sys_wait_h";
use IO::Socket;
use Exporter;


our @ISA;
our @EXPORT;

BEGIN {
	require Exporter;
	@ISA = qw(Exporter);
	our @EXPORT = qw(autotest_start new_call offer answer ft tt snd srtp_snd rtp rcv srtp_rcv
		srtp_dec escape rtpm reverse_tags new_tt crlf sdp_split rtpe_req offer_answer);
};


my $rtpe_stdout;
my $rtpe_stderr;
my $rtpe_pid;
my $c;
my ($cid, $ft, $tt, @sockets, $tag_iter);


sub autotest_start {
	my (@cmdline) = @_;

	like $ENV{LD_PRELOAD}, qr/tests-preload/, 'LD_PRELOAD present';
	is $ENV{RTPE_PRELOAD_TEST_ACTIVE}, '1', 'preload library is active';
	SKIP: {
		skip 'daemon is running externally', 1 if $ENV{RTPE_TEST_NO_LAUNCH};
		ok -x $ENV{RTPE_BIN}, 'RTPE_BIN points to executable';
	}

	$rtpe_stdout = File::Temp::tempfile() or die;
	$rtpe_stderr = File::Temp::tempfile() or die;
	SKIP: {
		skip 'daemon is running externally', 1 if $ENV{RTPE_TEST_NO_LAUNCH};
		$rtpe_pid = open3(undef, '>&'.fileno($rtpe_stdout), '>&'.fileno($rtpe_stderr),
			$ENV{RTPE_BIN}, @cmdline);
		ok $rtpe_pid, 'daemon launched in background';
	}

	# keep trying to connect to the control socket while daemon is starting up
	for (1 .. 300) {
		$c = NGCP::Rtpengine->new($ENV{RTPENGINE_HOST} // '127.0.0.1', $ENV{RTPENGINE_PORT} // 2223);
		last if $c->{socket};
		Time::HiRes::usleep(100000); # 100 ms x 300 = 30 sec
	}

	1;
	$c->{socket} or die;

	$tag_iter = 0;

	my $r = $c->req({command => 'ping'});
	ok $r->{result} eq 'pong', 'ping works, daemon operational';

	return 1;
}

sub new_call {
	my @ports = @_;
	for my $s (@sockets) {
		$s->close();
	}
	@sockets = ();
	$cid = $tag_iter++ . "-test-callID";
	$ft = $tag_iter++ . "-test-fromtag";
	$tt = $tag_iter++ . "-test-totag";
	print("new call $cid\n");
	for my $p (@ports) {
		my ($addr, $port) = @{$p};
		my $s = IO::Socket::IP->new(Type => &SOCK_DGRAM, Proto => 'udp',
				LocalHost => $addr, LocalPort => $port)
				or die;
		push(@sockets, $s);
	}
	return @sockets;
}
sub crlf {
	my ($s) = @_;
	$s =~ s/\r\n/\n/gs;
	return $s;
}
sub sdp_split {
	my ($s) = @_;
	return split(/--------*\n/, $s);
}
sub rtpe_req {
	my ($cmd, $name, $req) = @_;
	$req->{command} = $cmd;
	$req->{'call-id'} = $cid;
	my $resp = $c->req($req);
	is $resp->{result}, 'ok', "$name - '$cmd' status";
	return $resp;
}
sub offer_answer {
	my ($cmd, $name, $req, $sdps) = @_;
	my ($sdp_in, $exp_sdp_out) = sdp_split($sdps);
	$req->{'from-tag'} = $ft;
	$req->{sdp} = $sdp_in;
	my $resp = rtpe_req($cmd, $name, $req);
	my $regexp = "^\Q$exp_sdp_out\E\$";
	$regexp =~ s/\\\?/./gs;
	$regexp =~ s/PORT/(\\d{1,5})/gs;
	$regexp =~ s/ICEBASE/([0-9a-zA-Z]{16})/gs;
	$regexp =~ s/ICEUFRAG/([0-9a-zA-Z]{8})/gs;
	$regexp =~ s/ICEPWD/([0-9a-zA-Z]{26})/gs;
	$regexp =~ s/CRYPTO128/([0-9a-zA-Z\/+]{40})/gs;
	$regexp =~ s/CRYPTO192/([0-9a-zA-Z\/+]{51})/gs;
	$regexp =~ s/CRYPTO256/([0-9a-zA-Z\/+]{62})/gs;
	$regexp =~ s/LOOPER/([0-9a-f]{12})/gs;
	my $crlf = crlf($resp->{sdp});
	like $crlf, qr/$regexp/s, "$name - output '$cmd' SDP";
	my @matches = $crlf =~ qr/$regexp/s;
	return @matches;
}
sub offer {
	return offer_answer('offer', @_);
}
sub answer {
	my ($name, $req, $sdps) = @_;
	$req->{'to-tag'} = $tt;
	return offer_answer('answer', $name, $req, $sdps);
}
sub snd {
	my ($sock, $dest, $packet) = @_;
	$sock->send($packet, 0, pack_sockaddr_in($dest, inet_aton('203.0.113.1'))) or die;
}
sub srtp_snd {
	my ($sock, $dest, $packet, $srtp_ctx) = @_;
	if (!$srtp_ctx->{skey}) {
		my ($key, $salt) = NGCP::Rtpclient::SRTP::decode_inline_base64($srtp_ctx->{key}, $srtp_ctx->{cs});
		@$srtp_ctx{qw(skey sauth ssalt)} = NGCP::Rtpclient::SRTP::gen_rtp_session_keys($key, $salt);
	}
	my ($enc, $out_roc) = NGCP::Rtpclient::SRTP::encrypt_rtp(@$srtp_ctx{qw(cs skey ssalt sauth roc)},
		'', 0, 0, 0, $packet);
	$srtp_ctx->{roc} = $out_roc;
	$sock->send($enc, 0, pack_sockaddr_in($dest, inet_aton('203.0.113.1'))) or die;
}
sub rtp {
	my ($pt, $seq, $ts, $ssrc, $payload) = @_;
	print("rtp in $pt $seq $ts $ssrc\n");
	return pack('CCnNN a*', 0x80, $pt, $seq, $ts, $ssrc, $payload);
}
sub rcv {
	my ($sock, $port, $match, $cb, $cb_arg) = @_;
	my $p = '';
	alarm(1);
	my $addr = $sock->recv($p, 65535, 0) or die;
	alarm(0);
	my ($hdr_mark, $pt, $seq, $ts, $ssrc, $payload) = unpack('CCnNN a*', $p);
	if ($payload) {
		print("rtp recv $pt $seq $ts $ssrc " . unpack('H*', $payload) . "\n");
	}
	if ($cb) {
		$p = $cb->($hdr_mark, $pt, $seq, $ts, $ssrc, $payload, $p, $cb_arg);
	}
	like $p, $match, 'received packet matches';
	my @matches = $p =~ $match;
	for my $m (@matches) {
		if (length($m) == 2) {
			($m) = unpack('n', $m);
		}
		elsif (length($m) == 4) {
			($m) = unpack('N', $m);
		}
	}
	return @matches;
}
sub srtp_rcv {
	my ($sock, $port, $match, $srtp_ctx) = @_;
	return rcv($sock, $port, $match, \&srtp_dec, $srtp_ctx);
}
sub srtp_dec {
	my ($hdr_mark, $pt, $seq, $ts, $ssrc, $payload, $pack, $srtp_ctx) = @_;
	if (!$srtp_ctx->{skey}) {
		my ($key, $salt) = NGCP::Rtpclient::SRTP::decode_inline_base64($srtp_ctx->{key}, $srtp_ctx->{cs});
		@$srtp_ctx{qw(skey sauth ssalt)} = NGCP::Rtpclient::SRTP::gen_rtp_session_keys($key, $salt);
	}
	my ($dec, $out_roc, $tag, $hmac) = NGCP::Rtpclient::SRTP::decrypt_rtp(@$srtp_ctx{qw(cs skey ssalt sauth roc)}, $pack);
	$srtp_ctx->{roc} = $out_roc;
	is $tag, substr($hmac, 0, length($tag)), 'SRTP auth tag matches';
	return $dec;
}
sub escape {
	return "\Q$_[0]\E";
}
sub rtpm {
	my ($pt, $seq, $ts, $ssrc, $payload) = @_;
	print("rtp matcher $pt $seq $ts $ssrc " . unpack('H*', $payload) . "\n");
	my $re = '';
	$re .= escape(pack('C', 0x80));
	$re .= escape(pack('C', $pt));
	$re .= $seq >= 0 ? escape(pack('n', $seq)) : '(..)';
	$re .= $ts >= 0 ? escape(pack('N', $ts)) : '(....)';
	$re .= $ssrc >= 0 ? escape(pack('N', $ssrc)) : '(....)';
	$re .= escape($payload);
	return qr/^$re$/s;
}

sub ft { return $ft; }
sub tt { return $tt; }

sub reverse_tags {
	($tt, $ft) = ($ft, $tt);
}
sub new_tt {
	$tt = $tag_iter++ . "-test-totag";
}



END {
	if ($rtpe_pid) {
		kill('INT', $rtpe_pid) or die;
		# wait for daemon to terminate
		my $status = -1;
		for (1 .. 50) {
			$status = waitpid($rtpe_pid, WNOHANG);
			last if $status != 0;
			Time::HiRes::usleep(100000); # 100 ms x 50 = 5 sec
		}
		kill('KILL', $rtpe_pid) if $status == 0;
		$status == $rtpe_pid or die;
		$? == 0 or die;
	}
}



1;
