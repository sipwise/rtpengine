#!/usr/bin/perl

use strict;
use warnings;
use Socket;
use Socket6;

my %cmds = (noop => 1, add => 2, delete => 3, update => 4, add_call => 5, del_call => 6, add_stream => 7, del_stream => 8, packet => 9);
my %ciphers = ('null' => 1, 'aes-cm' => 2, 'aes-f8' => 3);
my %hmacs = ('null' => 1, 'hmac-sha1' => 2);
STDOUT->autoflush(1);

open(my $fh, '+>', '/proc/rtpengine/0/control') or die;
$fh->autoflush(1);

sub re_address {
	my ($fam, $addr, $port) = @_;

	$fam //= '';
	$addr //= '';
	$port //= 0;

	if ($fam eq 'inet' || $fam eq 'inet4') {
		return pack('V a4 a12 v v', 2, inet_aton($addr), '', $port, 0);
	}
	if ($fam eq 'inet6') {
		return pack('V a16 v v', 10, inet_pton(AF_INET6, $addr), $port, 0);
	}
	if ($fam eq '') {
		return pack('V a16 v v', 0, '', 0, 0);
	}

	die;
}
sub re_srtp {
	my ($h) = @_;
	my %opts = %{$h};

	# Explicitly initialize the hash entries.
	$opts{$_} //= q{} foreach (qw(master_key master_salt mki));
	$opts{$_} //= 0 foreach (qw(last_index auth_tag_len mki_len));

	return pack('VV a16 a16 a256 Q VV', $ciphers{$opts{cipher}}, $hmacs{$opts{hmac}},
		@opts{qw(master_key master_salt mki last_index auth_tag_len mki_len)});
}
sub rtpengine_message {
	my ($cmd, %args) = @_;

	my $ret = '';

	# amd64 alignment
	$ret .= pack('VV', $cmds{$cmd}, 0);
	#print(length($ret) . "\n");
	$ret .= re_address(@{$args{local_addr}}, $args{local_port});
	#print(length($ret) . "\n");
	$ret .= re_address(@{$args{expected_addr}}, $args{expected_port});
	#print(length($ret) . "\n");
	$ret .= pack('V', $args{mismatch} // 0);
	#print(length($ret) . "\n");
	$ret .= re_address(@{$args{src_addr}}, $args{src_port});
	#print(length($ret) . "\n");
	$ret .= re_address(@{$args{dst_addr}}, $args{dst_port});
	#print(length($ret) . "\n");
	$ret .= re_address(@{$args{mirror_addr}}, $args{mirror_port});
	#print(length($ret) . "\n");
	$ret .= pack('V', $args{stream_idx} // 0);
	#print(length($ret) . "\n");
	$ret .= re_srtp($args{decrypt});
	#print(length($ret) . "\n");
	$ret .= re_srtp($args{encrypt});
	#print(length($ret) . "\n");
	$ret .= pack('V', $args{ssrc} // 0);
	#print(length($ret) . "\n");
	$ret .= pack('CCCCCCCCCCCCCCCC V', 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0);
	#print(length($ret) . "\n");
	$ret .= pack('C CvV', $args{tos} // 0, $args{flags} // 0, 0, 0);
	#print(length($ret) . "\n");

	return $ret;
}

sub rtpengine_message_call {
	my ($cmd, $idx, $callid) = @_;

	my $ret = '';

	# amd64 alignment
	$ret .= pack('VV V a256', $cmds{$cmd}, 0, $idx, $callid // '');

	while (length($ret) < 792) {
		$ret .= pack('v', 0);
	}

	return $ret;
}

sub rtpengine_message_stream {
	my ($cmd, $call_idx, $stream_idx, $stream_name, $max_packets) = @_;

	my $ret = '';

	# amd64 alignment
	$ret .= pack('VV VVV a256', $cmds{$cmd}, 0, $call_idx, $stream_idx, $max_packets // 0, $stream_name // '');

	while (length($ret) < 792) {
		$ret .= pack('v', 0);
	}

	return $ret;
}

sub rtpengine_message_packet {
	my ($cmd, $call_idx, $stream_idx, $data) = @_;

	my $ret = '';

	# amd64 alignment
	$ret .= pack('VV VV', $cmds{$cmd}, 0, $call_idx, $stream_idx);

	while (length($ret) < 792) {
		$ret .= pack('v', 0);
	}

	$ret .= $data;

	return $ret;
}

my $sleep = 2;

my @local = qw(inet4 192.168.1.194);
my @src = qw(inet 192.168.1.194);
my @dst = qw(inet 192.168.1.90);
#my @src = qw(inet6 2a00:4600:1:0:a00:27ff:feb0:f7fe);
#my @dst = qw(inet6 2a00:4600:1:0:6884:adff:fe98:6ac5);
my $dec = {cipher => 'null', hmac => 'null'};
my $enc = {cipher => 'null', hmac => 'null'};

my $ret;
my $msg;

# print("add 9876 -> 1234/6543\n");
# $ret = syswrite($fh, rtpengine_message('add', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 1234, dst_addr => \@dst, dst_port => 6543, tos => 184, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("add fail\n");
# $ret = syswrite($fh, rtpengine_message('add', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 1234, dst_addr => \@dst, dst_port => 6543, mirror_addr => \@dst, mirror_port => 6789, tos => 184, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("update 9876 -> 1234/6543 & 6789\n");
# $ret = syswrite($fh, rtpengine_message('update', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 1234, dst_addr => \@dst, dst_port => 6543, mirror_addr => \@dst, mirror_port => 6789, tos => 184, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("update 9876 -> 2345/7890 & 4321\n");
# $ret = syswrite($fh, rtpengine_message('update', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 2345, dst_addr => \@dst, dst_port => 7890, mirror_addr => \@dst, mirror_port => 4321, tos => 184, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("add fail\n");
# $ret = syswrite($fh, rtpengine_message('add', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 1234, dst_addr => \@dst, dst_port => 6543, mirror_addr => \@dst, mirror_port => 6789, tos => 184, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("update 9876 -> 1234/6543\n");
# $ret = syswrite($fh, rtpengine_message('update', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 1234, dst_addr => \@dst, dst_port => 6543, tos => 184, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("delete\n");
# $ret = syswrite($fh, rtpengine_message('delete', local_addr => \@local, local_port => 9876, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("delete fail\n");
# $ret = syswrite($fh, rtpengine_message('delete', local_addr => \@local, local_port => 9876, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("update fail\n");
# $ret = syswrite($fh, rtpengine_message('update', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 1234, dst_addr => \@dst, dst_port => 6543, tos => 184, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);





if (0) {
	my (@calls, @streams);
	my $runs = 100;
	while ($runs >= 0 || @calls || @streams) {
		print("$runs to go...\n");

		my $op = rand() > .3 ? 'add' : 'del';
		$runs < 0 and $op = 'del';
		my $which = rand() > .6 ? 'call' : 'stream';
		if ($op eq 'add' && $which eq 'stream' && !@calls) {
			# can't add stream without call
			$which = 'call';
		}
		if ($op eq 'del' && $which eq 'stream' && !@streams) {
			# can't del stream if there aren't any
			$which = 'call';
		}
		if ($op eq 'del' && $which eq 'call' && !@calls) {
			# can't del call if there aren't any
			$op = 'add';
		}

		if ($op eq 'add' && $which eq 'call') {
			my $name = rand();
			print("creating call $name\n");

			$msg = rtpengine_message_call('add_call', 0, $name);
			$ret = sysread($fh, $msg, length($msg)) // '-';
			#print("reply: " . unpack("H*", $msg) . "\n");
			print("ret = $ret, code = $!\n");

			my (undef, undef, $idx) = unpack("VV V a256", $msg);
			print("index is $idx\n");

			push(@calls, $idx);

			sleep($sleep);
		}
		if ($op eq 'add' && $which eq 'stream') {
			my $call = $calls[rand(@calls)];
			my $name = rand();
			print("creating stream $name under call idx $call\n");

			$msg = rtpengine_message_stream('add_stream', $call, 0, $name);
			$ret = sysread($fh, $msg, length($msg)) // '-';
			#print("reply: " . unpack("H*", $msg) . "\n");
			print("ret = $ret, code = $!\n");

			my (undef, undef, undef, $idx) = unpack("VV VV a256", $msg);
			print("index is $idx\n");

			push(@streams, [$call, $idx]);

			sleep($sleep);
		}
		if ($op eq 'del' && $which eq 'call') {
			my $arridx = int(rand(@calls));
			my $call = $calls[$arridx];
			print("deleting call idx $call\n");

			$msg = rtpengine_message_call('del_call', $call);
			$ret = syswrite($fh, $msg) // '-';
			#print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
			print("ret = $ret, code = $!\n");

			splice(@calls, $arridx, 1);

			# kill streams linked to call
			my @to_del;
			for my $sidx (0 .. $#streams) {
				my $s = $streams[$sidx];
				$s->[0] == $call or next;
				print("stream idx $s->[1] got nuked\n");
				push(@to_del, $sidx);
			}
			my $offset = 0;
			while (@to_del) {
				my $i = shift(@to_del);
				splice(@streams, $i - $offset, 1);
				$offset++;
			}

			sleep($sleep);
		}
		if ($op eq 'del' && $which eq 'stream') {
			my $arridx = int(rand(@streams));
			my $stream = $streams[$arridx];
			print("deleting stream idx $stream->[1] (call $stream->[0])\n");

			$msg = rtpengine_message_stream('del_stream', $stream->[0], $stream->[1]);
			$ret = syswrite($fh, $msg) // '-';
			#print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
			print("ret = $ret, code = $!\n");

			splice(@streams, $arridx, 1);

			sleep($sleep);
		}

		for (1 .. rand(30)) {
			@streams or last;

			my $idx = $streams[rand(@streams)];
			$idx = $idx->[1];
			print("delivering a packet to $idx\n");

			$msg = rtpengine_message_packet('packet', 0, $idx, 'packet data bla bla ' . rand() . "\n");
			$ret = syswrite($fh, $msg) // '-';
			print("ret = $ret, code = $!\n");

			sleep($sleep);
		}

		$runs--;
	}
}









print("creating call\n");

$msg = rtpengine_message_call('add_call', 0, 'test call');
$ret = sysread($fh, $msg, length($msg)) // '-';
#print("reply: " . unpack("H*", $msg) . "\n");
print("ret = $ret, code = $!\n");

my (undef, undef, $idx1) = unpack("VV V a256", $msg);
print("index is $idx1\n");

sleep($sleep);



# print("creating identical call\n");
# 
# $msg = rtpengine_message_call('add_call', 0, 'test call');
# $ret = sysread($fh, $msg, length($msg)) // '-';
# #print("reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# my (undef, undef, $idx2) = unpack("VV V a256", $msg);
# print("index is $idx2\n");
# 
# sleep($sleep);



# print("creating other call\n");
# 
# $msg = rtpengine_message_call('add_call', 0, 'another test call');
# $ret = sysread($fh, $msg, length($msg)) // '-';
# #print("reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# my (undef, undef, $idx3) = unpack("VV V a256", $msg);
# print("index is $idx3\n");
# 
# sleep($sleep);



for my $exp (0 .. 1000) {
	print("creating a stream\n");

	$msg = rtpengine_message_stream('add_stream', $idx1, 0, 'test stream ' . rand());
	$ret = sysread($fh, $msg, length($msg)) // '-';
	#print("reply: " . unpack("H*", $msg) . "\n");
	print("ret = $ret, code = $!\n");

	my (undef, undef, undef, $sidx1) = unpack("VV VV a256", $msg);
	print("index is $sidx1\n");
	$sidx1 == $exp or die;
}



# print("creating a stream\n");
# 
# $msg = rtpengine_message_stream('add_stream', $idx1, 0, 'test stream');
# $ret = sysread($fh, $msg, length($msg)) // '-';
# #print("reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# my (undef, undef, undef, $sidx1) = unpack("VV VV a256", $msg);
# print("index is $sidx1\n");
# 
# sleep($sleep);



# print("creating identical stream\n");
# 
# $msg = rtpengine_message_stream('add_stream', $idx1, 0, 'test stream');
# $ret = sysread($fh, $msg, length($msg)) // '-';
# #print("reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# my (undef, undef, undef, $sidx2) = unpack("VV VV a256", $msg);
# print("index is $sidx2\n");
# 
# sleep($sleep);



# print("creating different stream\n");
# 
# $msg = rtpengine_message_stream('add_stream', $idx3, 0, 'test stream');
# $ret = sysread($fh, $msg, length($msg)) // '-';
# #print("reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# my (undef, undef, undef, $sidx3) = unpack("VV VV a256", $msg);
# print("index is $sidx3\n");

# sleep($sleep);



# print("add 9876 -> 1234/6543\n");
# $ret = syswrite($fh, rtpengine_message('add', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 1234, dst_addr => \@dst, dst_port => 6543, tos => 184, decrypt => $dec, encrypt => $enc, stream_idx => $sidx1, flags => 0x20)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);



# for (1 .. 50) {
# 	print("delivering a packet\n");
# 
# 	$msg = rtpengine_message_packet('packet', $idx1, $sidx1, 'packet data bla bla ' . rand() . "\n");
# 	$ret = syswrite($fh, $msg) // '-';
# 	#print("reply: " . unpack("H*", $msg) . "\n");
# 	print("ret = $ret, code = $!\n");
# 
# 	sleep($sleep);
# }




# print("deleting stream\n");
# 
# $msg = rtpengine_message_stream('del_stream', $idx1, $sidx1, '');
# $ret = syswrite($fh, $msg) // '-';
# #print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# sleep($sleep);



# print("deleting call\n");
# 
# $msg = rtpengine_message_call('del_call', $idx1, '');
# $ret = syswrite($fh, $msg) // '-';
# #print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# sleep($sleep);




close($fh);
