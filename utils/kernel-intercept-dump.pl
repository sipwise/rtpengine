#!/usr/bin/perl

use strict;
use warnings;
use Linux::Inotify2;
use AnyEvent::Loop;
use AnyEvent;
use Fcntl;
use Errno qw(EINTR EIO EAGAIN EWOULDBLOCK :POSIX);
use Net::Pcap;
use Time::HiRes;

my $COMBINE = 1;
# possible values:
# 0: don't combine any streams. each stream gets written to its own pcap file
# 1: combine all streams of one call into one pcap file

my $i = Linux::Inotify2->new or die;
$i->blocking(0);

$i->watch('/var/spool/rtpengine', IN_CLOSE_WRITE | IN_DELETE, \&handle_inotify) or die;
my $i_w = AnyEvent->io(fh => $i->fileno, poll => 'r', cb => sub { $i->poll });

setup();

AnyEvent::Loop::run();

exit;

my %metafiles;
my %callbacks;

sub handle_inotify {
	my ($e) = @_;
	my $fn = $e->{w}->{name} . '/' . $e->{name};
	my $mf = ($metafiles{$fn} //= { name => $fn });
	if ($e->IN_DELETE) {
		handle_delete($e, $fn, $mf);
	}
	elsif ($e->IN_CLOSE_WRITE) {
		handle_change($e, $fn, $mf);
	}
	else {
		print("unhandled inotify event on $fn\n");
	}
}

sub handle_change {
	my ($e, $fn, $mf) = @_;

	print("handling change on $fn\n");

	my $fd;
	open($fd, '<', $fn) or return;

	# resume from where we left of
	my $pos = $mf->{pos} // 0;
	seek($fd, $pos, 0);

	# read as much as we can
	my $buf;
	read($fd, $buf, 100000) or return;
	$mf->{pos} = tell($fd);
	close($fd);

	# read contents section by section
	while ($buf =~ s/^(.*?)\n//s) {
		my $key = $1;
		$buf =~ s/^(\d+):\n//s or die $buf;
		my $len = $1;
		my $val = substr($buf, 0, $len, '');
		$buf =~ s/^\n\n//s or die;

		if ($key =~ /^(CALL-ID|PARENT)$/) {
			$mf->{$key} = $val;
		}
		elsif ($key =~ /^STREAM (\d+) interface$/) {
			open_stream($mf, $val, $1);
		}
		elsif ($key =~ /^STREAM (\d+) details$/) {
			stream_details($mf, $val, $1);
		}
	}

	cb('call_setup', $mf);
}

sub handle_delete {
	my ($e, $fn, $mf) = @_;

	print("handling delete on $fn\n");

	cb('call_close', $mf);

	for my $sn (keys(%{$mf->{streams}})) {
		my $ref = $mf->{streams}->{$sn};
		close_stream($ref);
	}

	delete($mf->{streams});
	delete($mf->{streams_id});
	delete($metafiles{$fn});
}


sub get_stream_by_id {
	my ($mf, $id) = @_;
	my $ref = ($mf->{streams_id}->[$id] //= { metafile => $mf, id => $id });
	return $ref;
}

sub open_stream {
	my ($mf, $stream, $id) = @_;
	print("opening $stream for $mf->{'CALL-ID'}\n");
	my $fd;
	sysopen($fd, '/proc/rtpengine/0/calls/' . $mf->{PARENT} . '/' . $stream, O_RDONLY | O_NONBLOCK) or return;
	my $ref = get_stream_by_id($mf, $id);
	$ref->{name} = $stream;
	$ref->{fh} = $fd;
	$ref->{watcher} = AnyEvent->io(fh => $fd, poll => 'r', cb => sub { stream_read($mf, $ref) });
	cb('stream_setup', $ref, $mf);
	$mf->{streams}->{$stream} = $ref;
	$mf->{streams_id}->[$id] = $ref;
	print("opened for reading $stream for $mf->{'CALL-ID'}\n");
}

sub stream_details {
	my ($mf, $val, $id) = @_;
	my $ref = get_stream_by_id($mf, $id);
	my @details = $val =~ /(\w+) (\d+)/g;
	while (@details) {
		my $k = shift(@details);
		my $v = shift(@details);
		$ref->{$k} = $v;
	}
}

sub close_stream {
	my ($ref) = @_;
	# this needs to be done explicitly, otherwise the closure would keep
	# the object from being freed
	delete($ref->{watcher});
	my $mf = $ref->{metafile};
	delete($mf->{streams}->{$ref->{name}});
	cb('stream_close', $ref);
	print("closed $ref->{name}\n");
}

sub stream_read {
	my ($mf, $ref) = @_;
	#print("handling read event for $mf->{name} / $ref->{name}\n");
	while (1) {
		my $buf;
		my $ret = sysread($ref->{fh}, $buf, 65535);
		if (!defined($ret)) {
			if ($!{EAGAIN} || $!{EWOULDBLOCK}) {
				return;
			}
			print("read error on $ref->{name} for $mf->{'CALL-ID'}: $!\n");
			# fall through
		}
		elsif ($ret == 0) {
			print("eof on $ref->{name} for $mf->{'CALL-ID'}\n");
			# fall through
		}
		else {
			# $ret > 0
			#print("$ret bytes read from $ref->{name} for $mf->{'CALL-ID'}\n");
			cb('packet', $ref, $mf, $buf, $ret);
			next;
		}

		# some kind of error
		close_stream($ref);
		return;
	}
}

sub tvsec_now {
	my ($h) = @_;
	my @now = Time::HiRes::gettimeofday();
	$h->{tv_sec} = $now[0];
	$h->{tv_usec} = $now[1];
}

sub setup {
	if ($COMBINE == 0) {
		$callbacks{stream_setup} = \&stream_pcap;
		$callbacks{stream_close} = \&stream_pcap_close;
		$callbacks{packet} = \&stream_packet;
	}
	elsif ($COMBINE == 1) {
		$callbacks{call_setup} = \&call_pcap;
		$callbacks{call_close} = \&call_pcap_close;
		$callbacks{packet} = \&call_packet;
	}
}
sub cb {
	my ($name, @args) = @_;
	my $fn = $callbacks{$name};
	$fn or return;
	return $fn->(@args);
}


sub dump_open {
	my ($hash, $name) = @_;
	$hash->{pcap} = pcap_open_dead(DLT_RAW, 65535);
	$hash->{dumper} = pcap_dump_open($hash->{pcap}, $name);
}
sub dump_close {
	my ($hash) = @_;
	pcap_dump_close($hash->{dumper});
	pcap_close($hash->{pcap});
	delete($hash->{dumper});
	delete($hash->{pcap});
}
sub dump_packet {
	my ($hash, $buf, $len) = @_;
	if (!$hash->{dumper}) {
		print("discarding packet (dumper not open) - $hash->{name}\n");
		return;
	}
	my $hdr = { len => $len, caplen => $len };
	tvsec_now($hdr);
	pcap_dump($hash->{dumper}, $hdr, $buf);
}

# COMBINE 0 functions
sub stream_pcap {
	my ($ref, $mf) = @_;
	dump_open($ref, $mf->{PARENT} . '-' . $ref->{name} . '.pcap');
}
sub stream_pcap_close {
	my ($ref) = @_;
	dump_close($ref);
}
sub stream_packet {
	my ($ref, $mf, $buf, $ret) = @_;
	dump_packet($ref, $buf, $ret);
}

# COMBINE 1 functions
sub call_pcap {
	my ($mf) = @_;

	$mf->{pcap} and return;
	$mf->{PARENT} or return;

	print("opening pcap for $mf->{PARENT}\n");
	dump_open($mf, $mf->{PARENT} . '.pcap');
}
sub call_pcap_close {
	my ($mf) = @_;
	dump_close($mf);
}
sub call_packet {
	my ($ref, $mf, $buf, $ret) = @_;
	dump_packet($mf, $buf, $ret);
}
