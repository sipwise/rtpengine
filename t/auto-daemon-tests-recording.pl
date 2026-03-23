#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use POSIX;


my $spooldir = "/tmp/rtpengine-recording-test-$$";
mkdir $spooldir or die "Cannot create spooldir '$spooldir': $!";

END {
	system("rm", "-rf", $spooldir);
}

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -c 12345 -f -L 7 -E -u 2222
			--recording-method=pcap),
			"--recording-dir=$spooldir")
		or die;

my ($sock_a, $sock_b, $port_a, $port_b, $resp);


# Test: recording-file parameter is honoured - pcap is written to the explicit path
{
	my $explicit_pcap = "$spooldir/explicit-test.pcap";

	($sock_a, $sock_b) = new_call([qw(198.51.100.1 2010)], [qw(198.51.100.3 2012)]);

	($port_a) = offer('explicit recording-file', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2010 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

	($port_b) = answer('explicit recording-file', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2012 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

	rtpe_req('start recording', 'start recording with explicit path',
			{ 'recording-file' => $explicit_pcap });

	snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
	rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));

	rtpe_req('stop recording', 'stop recording', {});

	ok(-e $explicit_pcap, 'pcap file exists at explicit recording-file path');
	ok(!grep({ -f $_ } glob("$spooldir/pcaps/*.pcap")),
			'no pcap written to auto-generated spooldir/pcaps/ path');

	rtpe_req('delete', 'delete call');
}


# Test: auto-generated path is used when recording-file is not specified
{
	($sock_a, $sock_b) = new_call([qw(198.51.100.1 2010)], [qw(198.51.100.3 2012)]);

	($port_a) = offer('auto-generated recording path', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2010 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

	($port_b) = answer('auto-generated recording path', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2012 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

	rtpe_req('start recording', 'start recording without explicit path', {});

	snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
	rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));

	rtpe_req('stop recording', 'stop recording', {});

	my @auto_pcaps = grep({ -f $_ } glob("$spooldir/pcaps/*.pcap"));
	ok(scalar(@auto_pcaps) > 0, 'pcap file created in auto-generated spooldir/pcaps/');

	rtpe_req('delete', 'delete call');
}


# Test: recording_file is cleared after stop recording so a subsequent start
# recording (without recording-file) uses an auto-generated path, not the
# previously specified one.
{
	my $first_explicit_pcap = "$spooldir/stale-path-test.pcap";

	($sock_a, $sock_b) = new_call([qw(198.51.100.1 2010)], [qw(198.51.100.3 2012)]);

	($port_a) = offer('stale recording-file cleared after stop', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2010 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

	($port_b) = answer('stale recording-file cleared after stop', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2012 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

	# First recording: explicit path
	rtpe_req('start recording', 'start first recording with explicit path',
			{ 'recording-file' => $first_explicit_pcap });

	snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
	rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));

	rtpe_req('stop recording', 'stop first recording', {});
	my $size_after_first = -s $first_explicit_pcap;
	ok(defined($size_after_first) && $size_after_first > 0,
			'first pcap file written to explicit path');

	# Second recording on the same call: no recording-file specified.
	# recording_file must have been cleared by recording_finish() so the
	# second recording goes to the auto-generated path, not $first_explicit_pcap.
	rtpe_req('start recording', 'start second recording without explicit path', {});

	snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
	rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 160));

	rtpe_req('stop recording', 'stop second recording', {});

	# The first explicit pcap must not have been extended by the second recording
	my $size_after_second = -s $first_explicit_pcap;
	is($size_after_second, $size_after_first,
			'first pcap not extended by second recording (stale path was cleared)');

	# A new auto-generated pcap must exist in spooldir/pcaps/
	my @auto_pcaps = grep({ -f $_ } glob("$spooldir/pcaps/*.pcap"));
	ok(scalar(@auto_pcaps) > 0,
			'second recording created a new auto-generated pcap in spooldir/pcaps/');

	rtpe_req('delete', 'delete call');
}


done_testing();
