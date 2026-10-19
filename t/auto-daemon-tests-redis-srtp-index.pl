#!/usr/bin/perl

# The SRTP and SRTCP indexes of egress SSRCs must survive a Redis takeover.
#
# rtpengine keeps one SSRC context per egress SSRC in the sink media's
# ssrc_hash_out. When it terminates SDES toward an endpoint, the SRTP index in
# that context (ROC << 16 | seq) is what it encrypts with. A node that takes
# the call over from Redis must carry on with the same ROC, or every packet it
# sends fails authentication at the endpoint once the ROC is non-zero.

use strict;
use warnings;
use Bencode;
use JSON;
use NGCP::Rtpengine::AutoTest;
use NGCP::Rtpengine::FakeRedis;
use NGCP::Rtpclient::SRTP;
use Test::More;

my $redis_format = $ENV{RTPE_REDIS_FORMAT} // 'json';

# Fake Redis server that answers every command, in a forked child: the
# daemon writes from the poller thread as well as after a signalling request.
my $redis_listener = redis_listen('203.0.113.42');
redis_serve($redis_listener);

sub decode_record {
	my ($record) = @_;
	return $redis_format eq 'json' ? decode_json($record) : Bencode::bdecode($record, 1);
}

sub encode_record {
	my ($record) = @_;
	return encode_json($record) if $redis_format eq 'json';
	my $as_strings;
	$as_strings = sub {
		my ($value) = @_;
		return { map { $_ => $as_strings->($value->{$_}) } keys %$value }
			if ref($value) eq 'HASH';
		return [ map { $as_strings->($_) } @$value ] if ref($value) eq 'ARRAY';
		my $copy = $value;
		return \$copy;
	};
	return Bencode::bencode($as_strings->($record));
}

# All entries for one SSRC in the record's lists whose name matches $prefix.
sub ssrc_entries {
	my ($decoded, $prefix, $ssrc) = @_;
	my @ret;
	for my $key (sort keys %$decoded) {
		next unless $key =~ /^\Q$prefix\E-\d+$/;
		for my $ent (@{$decoded->{$key}}) {
			push(@ret, { list => $key, %$ent }) if $ent->{ssrc} == $ssrc;
		}
	}
	return @ret;
}

sub egress_ssrcs {
	my ($query, $tag) = @_;
	return [ map { $_->{SSRC} } @{$query->{tags}{$tag}{medias}[0]{'egress SSRCs'} // []} ];
}

sub redis_rtpe_req {
	my (@request) = @_;
	my $before = redis_sets_seen();
	my $response = rtpe_req(@request);
	return ($response, redis_record_after($before));
}

my @daemon_args = (qw(--config-file=none -t -1 -i 203.0.113.1 -n 2234 -f -L 7 -E
	--redis-num-threads=1),
	"--redis=203.0.113.42:6379/14", "--redis-format=$redis_format");
$NGCP::Rtpengine::AutoTest::port = 2234;
autotest_start(@daemon_args) or die;


# SDES toward A, plain RTP toward B: rtpengine encrypts B's media toward A
# with its own key and its own SRTP index.

my ($sock_a, $sock_b) = new_call([qw(198.51.100.1 7300)], [qw(198.51.100.3 7302)]);
my ($call_id, $from_tag, $to_tag) = (cid(), ft(), tt());
my $ssrc = 0x5ec0de01;

my $sdp_a = "v=0\r\no=- 1 1 IN IP4 198.51.100.1\r\ns=tester\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n"
	. "m=audio 7300 RTP/SAVP 8\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n"
	. "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c\r\n";
my $sdp_b = "v=0\r\no=- 2 1 IN IP4 198.51.100.3\r\ns=tester\r\nc=IN IP4 198.51.100.3\r\nt=0 0\r\n"
	. "m=audio 7302 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n";
my %offer = ('call-id' => $call_id, 'from-tag' => $from_tag, 'transport-protocol' => 'RTP/AVP',
	sdp => $sdp_a);
my %answer = ('call-id' => $call_id, 'from-tag' => $from_tag, 'to-tag' => $to_tag, sdp => $sdp_b);

my ($resp) = redis_rtpe_req('offer', 'SDES <> RTP offer', \%offer);
my ($port_a) = $resp->{sdp} =~ /^m=audio (\d+) RTP\/AVP /m or die;
($resp) = redis_rtpe_req('answer', 'SDES <> RTP answer', \%answer);
my ($port_b) = $resp->{sdp} =~ /^m=audio (\d+) RTP\/SAVP /m or die;
my ($key_to_a) = $resp->{sdp} =~ /^a=crypto:\d+ AES_CM_128_HMAC_SHA1_80 inline:(\S+)/m or die;

my $srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $key_to_a,
};

# B's sequence numbers wrap: the egress context toward A goes to ROC 1.
my $ts = 1000;
for my $seq (65533, 65534, 65535, 0, 1, 2) {
	     snd($sock_b, $port_a, rtp(8, $seq, $ts, $ssrc, "\x00" x 160));
	srtp_rcv($sock_a, $port_b, rtpm(8, $seq, $ts, $ssrc, "\x00" x 160), $srtp_ctx_a);
	$ts += 160;
}
is($srtp_ctx_a->{roc}, 1, 'receiver at ROC 1 after the wrap');

# A re-INVITE writes the call to Redis with the media state as it is now.
my $record;
($resp, $record) = redis_rtpe_req('offer', 're-offer', { %offer, 'to-tag' => $to_tag });
is($resp->{result}, 'ok', 're-offer ok');
($resp, $record) = redis_rtpe_req('answer', 're-answer', \%answer);
is($resp->{result}, 'ok', 're-answer ok');

my $decoded = decode_record($record);
my @out = ssrc_entries($decoded, 'ssrc_out_table', $ssrc);
is(scalar(@out), 1, "$redis_format egress SSRC stored once");
my %out = %{$out[0] // {}};
is($out{out_srtp_index}, 0x10002, "$redis_format egress SRTP index stored, ROC 1");
is($out{out_payload_type}, 8, "$redis_format egress payload type stored");
ok(defined($out{out_srtcp_index}), "$redis_format egress SRTCP index stored");
my @in = ssrc_entries($decoded, 'ssrc_table', $ssrc);
is(scalar(@in), 1, "$redis_format ingress SSRC stored once");
my %in = %{$in[0] // {}};
ok(defined($in{in_srtp_index}), "$redis_format ingress SRTP index stored");
ok(defined($in{list}) && defined($out{list})
	&& $in{list} ne ('ssrc_table-' . ($out{list} =~ /(\d+)$/)[0]),
	"$redis_format ingress and egress entries belong to different medias");

# ssrc_table list of A's media: the one that does not hold B's ingress SSRC
my ($table_a) = grep { /^ssrc_table-\d+$/ && !grep { $_->{ssrc} == $ssrc } @{$decoded->{$_}} }
	sort keys %$decoded;
ok(defined($table_a), "$redis_format ssrc_table of A's media present");


# Takeover: a fresh daemon restores the call from that record.

NGCP::Rtpengine::AutoTest::shut_rtpe();
autotest_start(@daemon_args) or die;

my $query = rtpe_req('query', 'query restored call', { 'call-id' => $call_id });
is_deeply(egress_ssrcs($query, $from_tag), [$ssrc], 'egress SSRC toward A restored');
is_deeply(egress_ssrcs($query, $to_tag), [], 'no egress SSRC created toward B');

# The restored node must encrypt toward A with ROC 1.
     snd($sock_b, $port_a, rtp(8, 3, $ts, $ssrc, "\x00" x 160));
srtp_rcv($sock_a, $port_b, rtpm(8, 3, $ts, $ssrc, "\x00" x 160), $srtp_ctx_a);
is($srtp_ctx_a->{roc}, 1, 'receiver still at ROC 1');


# A record written by a node without ssrc_out_table lists restores as before:
# each ingress entry is looked up in both hashes of its media.

my %legacy = %$decoded;
delete @legacy{grep { /^ssrc_out_table-/ } keys %legacy};
NGCP::Rtpengine::AutoTest::shut_rtpe();
redis_serve_next_get(encode_record(\%legacy));
autotest_start(@daemon_args) or die;

$query = rtpe_req('query', 'query call restored from legacy record', { 'call-id' => $call_id });
is_deeply([ map { $_->{SSRC} } @{$query->{tags}{$to_tag}{medias}[0]{'ingress SSRCs'} // []} ],
	[$ssrc], 'legacy record: ingress SSRC from B restored');
# documents unchanged legacy behaviour: the ingress entry is mirrored into the egress hash
is_deeply(egress_ssrcs($query, $to_tag), [$ssrc],
	'legacy record: ingress SSRC also looked up in egress hash (legacy behaviour kept)');
is_deeply(egress_ssrcs($query, $from_tag), [], 'legacy record: no egress SSRC toward A');


# A record in the format used before 19af8034: one combined entry per SSRC, in
# the ssrc_table of the media it belongs to, with both in_* and out_* fields.
# The egress index toward A is restored through the legacy path.

my %combined = %legacy;
$combined{$table_a} = [ { ssrc => $ssrc, in_srtp_index => 0, in_srtcp_index => 0,
	in_payload_type => 8, out_srtp_index => 0x10002, out_srtcp_index => 0,
	out_payload_type => 8 } ];
NGCP::Rtpengine::AutoTest::shut_rtpe();
redis_serve_next_get(encode_record(\%combined));
autotest_start(@daemon_args) or die;

$query = rtpe_req('query', 'query call restored from combined record', { 'call-id' => $call_id });
is_deeply(egress_ssrcs($query, $from_tag), [$ssrc], 'combined record: egress SSRC toward A restored');

$ts += 160;
     snd($sock_b, $port_a, rtp(8, 4, $ts, $ssrc, "\x00" x 160));
srtp_rcv($sock_a, $port_b, rtpm(8, 4, $ts, $ssrc, "\x00" x 160), $srtp_ctx_a);
is($srtp_ctx_a->{roc}, 1, 'combined record: receiver still at ROC 1');

NGCP::Rtpengine::AutoTest::shut_rtpe();
done_testing;
