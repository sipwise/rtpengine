#!/usr/bin/perl

use strict;
use warnings;
use IPC::Open2;
use POSIX ":sys_wait_h";

my ($send_src, $send_sink);
my $send_pid = open2($send_src, $send_sink, './spandsp_send_fax_pcm test.tif') or die;

unlink('out.tif');

my ($recv_src, $recv_sink);
my $recv_pid = open2($recv_src, $recv_sink, './spandsp_recv_fax_pcm out.tif') or die;

while ($send_pid && $recv_pid) {

	my $buf;

	if (sysread($send_src, $buf = '', 160)) {
		syswrite($recv_sink, $buf) or die;
	}

	if (sysread($recv_src, $buf = '', 160)) {
		syswrite($send_sink, $buf) or die;
	}

	undef($send_pid) if waitpid($send_pid, WNOHANG);
	undef($recv_pid) if waitpid($recv_pid, WNOHANG);
}

sleep(5);
