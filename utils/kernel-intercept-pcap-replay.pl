#!/usr/bin/perl

use strict;
use warnings;
use Net::Pcap;
use Data::Dumper;
use Time::HiRes qw(usleep);

my $spool_dir = '/var/spool/rtpengine';
my $table = 0;

my $kfd;
open($kfd, '+>', "/proc/rtpengine/$table/control") or die $!;

my $err;
my $p = pcap_open_offline($ARGV[0], \$err) or die $err;

my @packets;
my %src_ips;
my $tags = 0;
my $streams = 0;

print("reading pcap\n");
my $ret = pcap_loop($p, -1, \&loop_cb, '');
$ret == 0 or die $ret;

my $meta_file = "$spool_dir/" . rand() . '.meta';

my $parent = rand();

print("adding kernel call\n");
my (undef, $cid) = msg_ret(5, '', 'I I', 'I a256', 0, $parent);
print("kernel cid $cid\n");

print("starting metafile\n");
put_meta('CALL-ID', rand());
put_meta('PARENT', $parent);

print("creating kernel streams\n");
my @sids;
my @tag_keys = keys(%src_ips);
for my $key (@tag_keys) {
	my $tag = $src_ips{$key};
	my $tag_id = $tag->{id};
	put_meta("TAG $tag_id", rand());
	my @port_keys = keys(%{$tag->{ports}});
	for my $port (@port_keys) {
		my $stream = $tag->{ports}->{$port};
		my $sname = "tag-$tag_id-media-$stream->{media_id}-".
			"component-$stream->{component}-xxx-id-$stream->{stream_id}";
		put_meta("STREAM $stream->{stream_id} details",
			"TAG $tag_id MEDIA $stream->{media_id} COMPONENT $stream->{component} ".
			"FLAGS 0");
		my @ret = msg_ret(7, '', 'I I I I',
			'I I I a256', $cid, 0, 0, $sname);
		my $sid = $ret[3];
		$stream->{sid} = $sid;
		print("kernel sid $sid\n");
		put_meta("STREAM $stream->{stream_id} interface", $sname);
		push(@sids, $sid);
	}
}

print("sending packets\n");
foreach my $pack (@packets) {
	msg_ret(9, $pack->{eth}->{rest}, '', 'I I', $cid, $pack->{media}->{sid});
	usleep(5000);
}

print("deleting call and metafile\n");
msg_ret(6, '', '', 'I', $cid);
unlink($meta_file);

print("done\n");
exit;

sub loop_cb {
	my ($user_data, $header, $packet) = @_;
	my %eth;
	@eth{qw(src dst type rest)} = unpack('a6 a6 n a*', $packet);
	if ($eth{type} == 0x0800) {
		my $ip = ip($eth{rest});
		my $rtp = rtp($ip->{udp}->{payload});

		my %pkt = ( eth => \%eth, ip => $ip, rtp => $rtp );

		my $src_ip = $ip->{src};
		my $tag = ($src_ips{$src_ip} //= {
				id => $tags++,
				ports => { },
				medias => 0,
			});
		$pkt{tag} = $tag;

		my $component = $ip->{udp}->{src} & 1;
		my $base_port = $ip->{udp}->{src} - $component;
		my $base_media = ($tag->{ports}->{$base_port} //= {
				media_id => $tag->{medias}++,
				component => 0,
				stream_id => $streams++,
			});

		my $media = ($tag->{ports}->{$ip->{udp}->{src}} //= {
				media_id => $base_media->{media_id},
				component => $component,
				stream_id => $streams++,
			});
		$pkt{media} =  $media;

		push(@packets, \%pkt);
	}
	else {
		die($eth{type});
	}
}

sub ip {
	my ($p) = @_;
	my %ret;
	@ret{qw(hv diffserv totlen id flags_foff ttl proto csum src dst rest)} = unpack('C C n n n C C n N N a*', $p);
	if ($ret{proto} == 17) {
		$ret{udp} = udp($ret{rest});
	}
	else {
		die $ret{proto};
	}
	return \%ret;
}

sub udp {
	my ($p) = @_;
	my %ret;
	@ret{qw(src dst len csum payload)} = unpack('nnnn a*', $p);
	return \%ret;
}

sub rtp {
	my ($p) = @_;
	my %ret;
	@ret{qw(vpx pt seq ts ssrc payload)} = unpack('CC n N N', $p);
	return \%ret;
}

sub put_meta {
	my ($label, $content) = @_;
	my $fd;
	open($fd, '>>', $meta_file) or die $!;
	print $fd "$label\n" . length($content) . ":\n$content\n\n";
	close($fd);
}

sub msg_ret {
	my ($cmd, $extra, $unpacker, $packer, @rest) = @_;
	my $msg = pack('II' . $packer, $cmd, 0, @rest);
	# for 32-bit:
	# my $msg = pack('I' . $packer, $cmd, @rest);
	$msg .= ("\0" x (840 - length($msg))); # packet length also needs adjusting for 32-bit
	$msg .= ($extra // '');
	sysread($kfd, $msg, length($msg)) or die $!;
	return unpack($unpacker, $msg);
}
