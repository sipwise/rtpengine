#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E --endpoint-learning=heuristic))
		or die;


my ($sock_a, $sock_b, $sock_c, $sock_d, $sock_e, $port_a, $port_b);




($sock_a, $sock_b, $sock_c, $sock_d, $sock_e) = new_call(
	[qw(198.51.100.1 2010)], # caller
	[qw(198.51.100.3 2012)], # callee - from SDP
	[qw(198.51.100.3 2032)], # callee - different port
	[qw(198.51.100.6 2012)], # callee - different address
	[qw(198.51.100.6 2032)], # callee - all different
);

($port_a) = offer('basic, forward', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2010 RTP/AVP 0 8
c=IN IP4 198.51.100.1
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

($port_b) = answer('basic, forward', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2012 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
# callee send from expected
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 160));
# callee send from different port
snd($sock_c, $port_a, rtp(0, 2001, 4160, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2002, 4320, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2002, 4320, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3480, 0x1234, "\x00" x 160));
# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2003, 4480, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2003, 4480, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1004, 3640, 0x1234, "\x00" x 160));

# callee send from expected
snd($sock_b, $port_a, rtp(0, 2004, 4640, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2004, 4640, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1005, 3800, 0x1234, "\x00" x 160));
# callee send from different port
snd($sock_c, $port_a, rtp(0, 2005, 4800, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2005, 4800, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3960, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2006, 4960, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2006, 4960, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1007, 4120, 0x1234, "\x00" x 160));
# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2007, 5120, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2007, 5120, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1008, 4280, 0x1234, "\x00" x 160));

# wait for fix
sleep(4);

# callee send from expected
snd($sock_b, $port_a, rtp(0, 2008, 5280, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2008, 5280, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1009, 4440, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1009, 4440, 0x1234, "\x00" x 160));
# callee send from different port
snd($sock_c, $port_a, rtp(0, 2009, 5440, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2009, 5440, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2010, 5600, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2010, 5600, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1011, 4760, 0x1234, "\x00" x 160));
# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2011, 5760, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2011, 5760, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1012, 4920, 0x1234, "\x00" x 160));

rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);
rcv_no($sock_e);


($sock_a, $sock_b, $sock_c, $sock_d, $sock_e) = new_call(
	[qw(198.51.100.1 2050)], # caller
	[qw(198.51.100.3 2052)], # callee - from SDP
	[qw(198.51.100.3 2072)], # callee - different port
	[qw(198.51.100.6 2052)], # callee - different address
	[qw(198.51.100.6 2072)], # callee - all different
);

($port_a) = offer('basic, reverse', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2050 RTP/AVP 0 8
c=IN IP4 198.51.100.1
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

($port_b) = answer('basic, reverse', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2052 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2000, 4000, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x1234, "\x00" x 160));
# caller send, forward to worst candidate
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_e, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 160));
# callee send from different port
snd($sock_c, $port_a, rtp(0, 2001, 4160, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x1234, "\x00" x 160));
# caller send, forward to almost good candidate
snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_c, $port_a, rtpm(0, 1002, 3320, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2002, 4320, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2002, 4320, 0x1234, "\x00" x 160));
# caller send, forward to almost good candidate (different address ignored)
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_c, $port_a, rtpm(0, 1003, 3480, 0x1234, "\x00" x 160));
# callee send from expected
snd($sock_b, $port_a, rtp(0, 2003, 4480, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2003, 4480, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1004, 3640, 0x1234, "\x00" x 160));

# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2004, 4640, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2004, 4640, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1005, 3800, 0x1234, "\x00" x 160));
# callee send from different port
snd($sock_c, $port_a, rtp(0, 2005, 4800, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2005, 4800, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3960, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2006, 4960, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2006, 4960, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1007, 4120, 0x1234, "\x00" x 160));
# callee send from expected
snd($sock_b, $port_a, rtp(0, 2007, 5120, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2007, 5120, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1008, 4280, 0x1234, "\x00" x 160));

# wait for fix
sleep(4);

# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2008, 5280, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2008, 5280, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1009, 4440, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1009, 4440, 0x1234, "\x00" x 160));
# callee send from different port
snd($sock_c, $port_a, rtp(0, 2009, 5440, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2009, 5440, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2010, 5600, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2010, 5600, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1011, 4760, 0x1234, "\x00" x 160));
# callee send from expected
snd($sock_b, $port_a, rtp(0, 2011, 5760, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2011, 5760, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1012, 4920, 0x1234, "\x00" x 160));

rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);
rcv_no($sock_e);






($sock_a, $sock_b, $sock_c, $sock_d, $sock_e) = new_call(
	[qw(198.51.100.1 2080)], # caller
	[qw(198.51.100.3 2082)], # callee - from SDP
	[qw(198.51.100.3 2102)], # callee - different port
	[qw(198.51.100.6 2082)], # callee - different address
	[qw(198.51.100.6 2102)], # callee - all different
);

($port_a) = offer('strict source, forward', { flags => ['strict source'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2080 RTP/AVP 0 8
c=IN IP4 198.51.100.1
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

($port_b) = answer('strict source, forward', { flags => ['strict source'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2082 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
# callee send from expected
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 160));
# callee send from different port
snd($sock_c, $port_a, rtp(0, 2001, 4160, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2002, 4320, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3480, 0x1234, "\x00" x 160));
# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2003, 4480, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1004, 3640, 0x1234, "\x00" x 160));

# callee send from expected
snd($sock_b, $port_a, rtp(0, 2004, 4640, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2004, 4640, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1005, 3800, 0x1234, "\x00" x 160));
# callee send from different port
snd($sock_c, $port_a, rtp(0, 2005, 4800, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3960, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2006, 4960, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1007, 4120, 0x1234, "\x00" x 160));
# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2007, 5120, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1008, 4280, 0x1234, "\x00" x 160));

# wait for fix
sleep(4);

# callee send from expected
snd($sock_b, $port_a, rtp(0, 2008, 5280, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2008, 5280, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1009, 4440, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1009, 4440, 0x1234, "\x00" x 160));
# callee send from different port
snd($sock_c, $port_a, rtp(0, 2009, 5440, 0x1234, "\x00" x 160));
rcv_no($sock_a); # dropped
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2010, 5600, 0x1234, "\x00" x 160));
rcv_no($sock_a); # dropped
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1011, 4760, 0x1234, "\x00" x 160));
# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2011, 5760, 0x1234, "\x00" x 160));
rcv_no($sock_a); # dropped
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1012, 4920, 0x1234, "\x00" x 160));

rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);
rcv_no($sock_e);





($sock_a, $sock_b, $sock_c, $sock_d, $sock_e) = new_call(
	[qw(198.51.100.1 2140)], # caller
	[qw(198.51.100.3 2142)], # callee - from SDP
	[qw(198.51.100.3 2162)], # callee - different port
	[qw(198.51.100.6 2142)], # callee - different address
	[qw(198.51.100.6 2162)], # callee - all different
);

($port_a) = offer('strict source, reverse', { flags => ['strict source'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2140 RTP/AVP 0 8
c=IN IP4 198.51.100.1
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

($port_b) = answer('strict source, reverse', { flags => ['strict source'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2142 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2000, 4000, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x1234, "\x00" x 160));
# caller send, forward to worst candidate
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_e, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 160));
# callee send from different port
snd($sock_c, $port_a, rtp(0, 2001, 4160, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x1234, "\x00" x 160));
# caller send, forward to almost good candidate
snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_c, $port_a, rtpm(0, 1002, 3320, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2002, 4320, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to almost good candidate (different address ignored)
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_c, $port_a, rtpm(0, 1003, 3480, 0x1234, "\x00" x 160));
# callee send from expected
snd($sock_b, $port_a, rtp(0, 2003, 4480, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2003, 4480, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1004, 3640, 0x1234, "\x00" x 160));

# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2004, 4640, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1005, 3800, 0x1234, "\x00" x 160));
# callee send from different port
snd($sock_c, $port_a, rtp(0, 2005, 4800, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3960, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2006, 4960, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1007, 4120, 0x1234, "\x00" x 160));
# callee send from expected
snd($sock_b, $port_a, rtp(0, 2007, 5120, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2007, 5120, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1008, 4280, 0x1234, "\x00" x 160));

# wait for fix
sleep(4);

# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2008, 5280, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1009, 4440, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1009, 4440, 0x1234, "\x00" x 160));
# callee send from different port
snd($sock_c, $port_a, rtp(0, 2009, 5440, 0x1234, "\x00" x 160));
rcv_no($sock_a); # dropped
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2010, 5600, 0x1234, "\x00" x 160));
rcv_no($sock_a); # dropped
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1011, 4760, 0x1234, "\x00" x 160));
# callee send from expected
snd($sock_b, $port_a, rtp(0, 2011, 5760, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2011, 5760, 0x1234, "\x00" x 160));
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1012, 4920, 0x1234, "\x00" x 160));

rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);
rcv_no($sock_e);





($sock_a, $sock_b, $sock_c) = new_call(
	[qw(198.51.100.1 2188)], # caller
	[qw(198.51.100.3 2190)], # callee - from SDP
	[qw(198.51.100.3 2210)], # hijack
);

($port_a) = offer('offer only', { flags => ['strict source'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2188 RTP/AVP 0 8
c=IN IP4 198.51.100.1
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

# callee send
snd($sock_b, $port_a,         rtp(0, 2000, 4000, 0x1234, "\x00" x 160));
($port_b) = rcv($sock_a, -1, rtpm(0, 2000, 4000, 0x1234, "\x00" x 160));
rcv_no($sock_b);
rcv_no($sock_c);
# hijack send
snd($sock_c, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
# callee send, forward, hijack ignored
snd($sock_b, $port_a,  rtp(0, 2001, 4160, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x1234, "\x00" x 160));
rcv_no($sock_b);
rcv_no($sock_c);

rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);





#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
