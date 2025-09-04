#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1
			-n 2223 -f -L 7 -E --endpoint-learning=delayed))
		or die;


my ($sock_a, $sock_b, $sock_c, $sock_d, $sock_e, $port_a, $port_b);




($sock_a, $sock_b, $sock_c, $sock_d, $sock_e) = new_call(
	[qw(198.51.100.1 2010)], # caller
	[qw(198.51.100.3 2012)], # callee - from SDP
	[qw(198.51.100.3 2032)], # callee - different port
	[qw(198.51.100.6 2012)], # callee - different address
	[qw(198.51.100.6 2032)], # callee - all different
);

($port_a) = offer('default, forward', { flags => ['asymmetric'] }, <<SDP);
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

($port_b) = answer('default, forward', { flags => ['asymmetric'] }, <<SDP);
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

($port_a) = offer('default, reverse', { flags => ['asymmetric'] }, <<SDP);
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

($port_b) = answer('default, reverse', { flags => ['asymmetric'] }, <<SDP);
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
	[qw(198.51.100.1 2030)], # caller
	[qw(198.51.100.3 2032)], # callee - from SDP
	[qw(198.51.100.3 2052)], # callee - different port
	[qw(198.51.100.6 2032)], # callee - different address
	[qw(198.51.100.6 2052)], # callee - all different
);

($port_a) = offer('default, forward, strict source', { flags => ['asymmetric', 'strict source'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2030 RTP/AVP 0 8
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

($port_b) = answer('default, forward, strict source', { flags => ['asymmetric', 'strict source'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2032 RTP/AVP 0 8
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
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2010, 5600, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1011, 4760, 0x1234, "\x00" x 160));
# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2011, 5760, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1012, 4920, 0x1234, "\x00" x 160));

rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);
rcv_no($sock_e);



($sock_a, $sock_b, $sock_c, $sock_d, $sock_e) = new_call(
	[qw(198.51.100.1 2070)], # caller
	[qw(198.51.100.3 2072)], # callee - from SDP
	[qw(198.51.100.3 2092)], # callee - different port
	[qw(198.51.100.6 2072)], # callee - different address
	[qw(198.51.100.6 2092)], # callee - all different
);

($port_a) = offer('default, reverse, strict source', { flags => ['asymmetric', 'strict source'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2070 RTP/AVP 0 8
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

($port_b) = answer('default, reverse, strict source', { flags => ['asymmetric', 'strict source'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2072 RTP/AVP 0 8
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
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2010, 5600, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1011, 4760, 0x1234, "\x00" x 160));
# callee send from expected
snd($sock_b, $port_a, rtp(0, 2011, 5760, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1012, 4920, 0x1234, "\x00" x 160));

rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);
rcv_no($sock_e);





($sock_a, $sock_b, $sock_c, $sock_d, $sock_e) = new_call(
	[qw(198.51.100.1 2106)], # caller
	[qw(198.51.100.3 2108)], # callee - from SDP
	[qw(198.51.100.3 2128)], # callee - different port
	[qw(198.51.100.6 2108)], # callee - different address
	[qw(198.51.100.6 2128)], # callee - all different
);

($port_a) = offer('forward, el=off', { flags => ['asymmetric'], 'endpoint learning' => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2106 RTP/AVP 0 8
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

($port_b) = answer('forward, el=off', { flags => ['asymmetric'], 'endpoint learning' => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2108 RTP/AVP 0 8
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
	[qw(198.51.100.1 2146)], # caller
	[qw(198.51.100.3 2148)], # callee - from SDP
	[qw(198.51.100.3 2168)], # callee - different port
	[qw(198.51.100.6 2148)], # callee - different address
	[qw(198.51.100.6 2168)], # callee - all different
);

($port_a) = offer('reverse, el=off', { flags => ['asymmetric'], 'endpoint learning' => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2146 RTP/AVP 0 8
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

($port_b) = answer('reverse, el=off', { flags => ['asymmetric'], 'endpoint learning' => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2148 RTP/AVP 0 8
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
	[qw(198.51.100.1 2126)], # caller
	[qw(198.51.100.3 2128)], # callee - from SDP
	[qw(198.51.100.3 2148)], # callee - different port
	[qw(198.51.100.6 2128)], # callee - different address
	[qw(198.51.100.6 2148)], # callee - all different
);

($port_a) = offer('forward, strict source, el=off', { flags => ['asymmetric', 'strict source'], 'endpoint learning' => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2126 RTP/AVP 0 8
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

($port_b) = answer('forward, strict source, el=off', { flags => ['asymmetric', 'strict source'], 'endpoint learning' => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2128 RTP/AVP 0 8
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
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2010, 5600, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1011, 4760, 0x1234, "\x00" x 160));
# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2011, 5760, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1012, 4920, 0x1234, "\x00" x 160));

rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);
rcv_no($sock_e);



($sock_a, $sock_b, $sock_c, $sock_d, $sock_e) = new_call(
	[qw(198.51.100.1 2166)], # caller
	[qw(198.51.100.3 2168)], # callee - from SDP
	[qw(198.51.100.3 2188)], # callee - different port
	[qw(198.51.100.6 2168)], # callee - different address
	[qw(198.51.100.6 2188)], # callee - all different
);

($port_a) = offer('reverse, strict source, el=off', { flags => ['asymmetric', 'strict source'], 'endpoint learning' => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2166 RTP/AVP 0 8
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

($port_b) = answer('reverse, strict source, el=off', { flags => ['asymmetric', 'strict source'], 'endpoint learning' => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2168 RTP/AVP 0 8
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
rcv_no($sock_a);
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
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2010, 5600, 0x1234, "\x00" x 160));
rcv_no($sock_a);
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
	[qw(198.51.100.1 2168)], # caller
	[qw(198.51.100.3 2170)], # callee - from SDP
	[qw(198.51.100.3 2190)], # callee - different port
	[qw(198.51.100.6 2170)], # callee - different address
	[qw(198.51.100.6 2190)], # callee - all different
);

($port_a) = offer('forward, el=heuristic', { flags => ['asymmetric'], 'endpoint learning' => 'heuristic' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2168 RTP/AVP 0 8
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

($port_b) = answer('forward, el=heuristic', { flags => ['asymmetric'], 'endpoint learning' => 'heuristic' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2170 RTP/AVP 0 8
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
	[qw(198.51.100.1 2208)], # caller
	[qw(198.51.100.3 2210)], # callee - from SDP
	[qw(198.51.100.3 2230)], # callee - different port
	[qw(198.51.100.6 2210)], # callee - different address
	[qw(198.51.100.6 2230)], # callee - all different
);

($port_a) = offer('reverse, el=heuristic', { flags => ['asymmetric'], 'endpoint learning' => 'heuristic' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2208 RTP/AVP 0 8
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

($port_b) = answer('reverse, el=heuristic', { flags => ['asymmetric'], 'endpoint learning' => 'heuristic' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2210 RTP/AVP 0 8
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
	[qw(198.51.100.1 2188)], # caller
	[qw(198.51.100.3 2190)], # callee - from SDP
	[qw(198.51.100.3 2210)], # callee - different port
	[qw(198.51.100.6 2190)], # callee - different address
	[qw(198.51.100.6 2210)], # callee - all different
);

($port_a) = offer('forward, strict source, el=heuristic', { flags => ['asymmetric', 'strict source'], 'endpoint learning' => 'heuristic' }, <<SDP);
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

($port_b) = answer('forward, strict source, el=heuristic', { flags => ['asymmetric', 'strict source'], 'endpoint learning' => 'heuristic' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2190 RTP/AVP 0 8
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
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2010, 5600, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1011, 4760, 0x1234, "\x00" x 160));
# callee send from different everything
snd($sock_e, $port_a, rtp(0, 2011, 5760, 0x1234, "\x00" x 160));
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1012, 4920, 0x1234, "\x00" x 160));

rcv_no($sock_a);
rcv_no($sock_b);
rcv_no($sock_c);
rcv_no($sock_d);
rcv_no($sock_e);



($sock_a, $sock_b, $sock_c, $sock_d, $sock_e) = new_call(
	[qw(198.51.100.1 2228)], # caller
	[qw(198.51.100.3 2230)], # callee - from SDP
	[qw(198.51.100.3 2250)], # callee - different port
	[qw(198.51.100.6 2230)], # callee - different address
	[qw(198.51.100.6 2250)], # callee - all different
);

($port_a) = offer('reverse, strict source, el=heuristic', { flags => ['asymmetric', 'strict source'], 'endpoint learning' => 'heuristic' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2228 RTP/AVP 0 8
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

($port_b) = answer('reverse, strict source, el=heuristic', { flags => ['asymmetric', 'strict source'], 'endpoint learning' => 'heuristic' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2230 RTP/AVP 0 8
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
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3480, 0x1234, "\x00" x 160));
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
rcv_no($sock_a);
# caller send, forward to expected
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));
# callee send from different address
snd($sock_d, $port_a, rtp(0, 2010, 5600, 0x1234, "\x00" x 160));
rcv_no($sock_a);
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


#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
