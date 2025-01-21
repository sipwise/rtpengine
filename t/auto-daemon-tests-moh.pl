#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use NGCP::Rtpclient::ICE;
use POSIX;

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-i foo/203.0.113.7 -i bar/203.0.113.8
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --silence-detect=1 --log-level-internals=7))
		or die;

my ($sock_a, $sock_b, $seq, $ts, $ssrc);

my $pcma_1 = "\xd5\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\x55\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c";
my $pcma_2 = "\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\xd5\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\xd5\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09";
my $pcma_3 = "\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\x55\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0";
my $pcma_4 = "\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\x55\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\x55\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1";
my $pcma_5 = "\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\xd5\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34";

my $wav_file = "\x52\x49\x46\x46\x64\x06\x00\x00\x57\x41\x56\x45\x66\x6d\x74\x20\x10\x00\x00\x00\x01\x00\x01\x00\x40\x1f\x00\x00\x80\x3e\x00\x00\x02\x00\x10\x00\x64\x61\x74\x61\x40\x06\x00\x00\x00\x00\xb0\x22\x45\x41\x25\x58\x95\x64\x24\x65\xbd\x59\xb6\x43\xb4\x25\x35\x03\x5e\xe0\x3b\xc1\x8c\xa9\x0f\x9c\x6a\x9a\xc2\xa4\xe7\xb9\x55\xd7\x92\xf9\x92\x1c\x30\x3c\xb2\x54\x2e\x63\xf3\x65\xa7\x5c\x68\x48\x9b\x2b\xa1\x09\x8a\xe6\x71\xc6\x28\xad\xab\x9d\xcc\x99\x06\xa2\x5c\xb5\x81\xd1\x2d\xf3\x53\x16\xe1\x36\xe8\x50\x64\x61\x59\x66\x36\x5f\xcf\x4c\x56\x31\x04\x10\xd0\xec\xe0\xcb\x19\xb1\xa9\x9f\x98\x99\xa8\x9f\x1a\xb1\xdf\xcb\xd1\xec\x04\x10\x54\x31\xd2\x4c\x33\x5f\x5c\x66\x61\x61\xeb\x50\xde\x36\x56\x16\x2b\xf3\x83\xd1\x59\xb5\x08\xa2\xcb\x99\xac\x9d\x28\xad\x70\xc6\x8a\xe6\xa3\x09\x98\x2b\x6a\x48\xa6\x5c\xf4\x65\x2d\x63\xb3\x54\x2e\x3c\x93\x1c\x93\xf9\x53\xd7\xe9\xb9\xc1\xa4\x69\x9a\x11\x9c\x8b\xa9\x3b\xc1\x5e\xe0\x36\x03\xb2\x25\xba\x43\xb7\x59\x2a\x65\x90\x64\x29\x58\x42\x41\xb2\x22\xff\xff\x50\xdd\xbb\xbe\xdb\xa7\x6b\x9b\xdd\x9a\x42\xa6\x4b\xbc\x4b\xda\xca\xfc\xa5\x1f\xc2\x3e\x77\x56\xed\x63\x9a\x65\x3b\x5b\x1b\x46\xa9\x28\x70\x06\x6c\xe3\xd2\xc3\x4d\xab\xd1\x9c\x10\x9a\x56\xa3\x99\xb7\x67\xd4\x5b\xf6\x79\x19\x8e\x39\xd7\x52\x58\x62\x30\x66\xfd\x5d\xa2\x4a\x81\x2e\xd1\x0c\xae\xe9\x1f\xc9\x17\xaf\x9e\x9e\xa4\x99\xce\xa0\x2c\xb3\xaf\xce\xf8\xef\x33\x13\x1e\x34\xe8\x4e\x57\x60\x68\x66\x57\x60\xe9\x4e\x1c\x34\x35\x13\xf6\xef\xb0\xce\x2d\xb3\xcc\xa0\xa6\x99\x9c\x9e\x17\xaf\x22\xc9\xa9\xe9\xd6\x0c\x7c\x2e\xa7\x4a\xf8\x5d\x36\x66\x52\x62\xdb\x52\x8c\x39\x79\x19\x5c\xf6\x67\xd4\x97\xb7\x59\xa3\x0e\x9a\xd1\x9c\x4e\xab\xd0\xc3\x6e\xe3\x6e\x06\xac\x28\x18\x46\x3d\x5b\x98\x65\xef\x63\x76\x56\xc3\x3e\xa4\x1f\xc9\xfc\x4e\xda\x49\xbc\x43\xa6\xdd\x9a\x69\x9b\xdd\xa7\xbb\xbe\x4f\xdd\x01\x00\xaf\x22\x47\x41\x23\x58\x96\x64\x24\x65\xbb\x59\xba\x43\xb0\x25\x39\x03\x59\xe0\x40\xc1\x87\xa9\x15\x9c\x65\x9a\xc4\xa4\xe7\xb9\x56\xd7\x90\xf9\x94\x1c\x2e\x3c\xb3\x54\x2f\x63\xf1\x65\xa8\x5c\x68\x48\x9a\x2b\xa2\x09\x8a\xe6\x71\xc6\x27\xad\xac\x9d\xcb\x99\x08\xa2\x59\xb5\x84\xd1\x2a\xf3\x56\x16\xe0\x36\xe7\x50\x65\x61\x59\x66\x35\x5f\xd1\x4c\x54\x31\x04\x10\xd2\xec\xdd\xcb\x1c\xb1\xa5\x9f\x9b\x99\xa8\x9f\x18\xb1\xe2\xcb\xcd\xec\x07\x10\x54\x31\xd1\x4c\x33\x5f\x5d\x66\x60\x61\xec\x50\xdd\x36\x57\x16\x29\xf3\x86\xd1\x57\xb5\x09\xa2\xcb\x99\xab\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9a\x2b\x69\x48\xa7\x5c\xf2\x65\x2e\x63\xb2\x54\x31\x3c\x91\x1c\x93\xf9\x53\xd7\xe9\xb9\xc1\xa4\x6a\x9a\x10\x9c\x8a\xa9\x3f\xc1\x59\xe0\x3a\x03\xb0\x25\xb8\x43\xbd\x59\x24\x65\x95\x64\x24\x58\x46\x41\xaf\x22\x02\x00\x4e\xdd\xbb\xbe\xdd\xa7\x68\x9b\xdf\x9a\x42\xa6\x48\xbc\x50\xda\xc6\xfc\xa7\x1f\xc2\x3e\x75\x56\xef\x63\x99\x65\x3c\x5b\x1a\x46\xaa\x28\x6e\x06\x6e\xe3\xd1\xc3\x4e\xab\xd1\x9c\x0e\x9a\x57\xa3\x9a\xb7\x64\xd4\x60\xf6\x75\x19\x90\x39\xd7\x52\x55\x62\x34\x66\xf9\x5d\xa8\x4a\x7a\x2e\xd8\x0c\xa7\xe9\x23\xc9\x16\xaf\x9d\x9e\xa6\x99\xcb\xa0\x2f\xb3\xad\xce\xfa\xef\x30\x13\x21\x34\xe6\x4e\x59\x60\x66\x66\x5a\x60\xe4\x4e\x23\x34\x2e\x13\xfc\xef\xab\xce\x30\xb3\xcb\xa0\xa5\x99\x9f\x9e\x14\xaf\x24\xc9\xa7\xe9\xd8\x0c\x7b\x2e\xa8\x4a\xf7\x5d\x36\x66\x53\x62\xda\x52\x8d\x39\x78\x19\x5d\xf6\x67\xd4\x97\xb7\x59\xa3\x0d\x9a\xd2\x9c\x4e\xab\xd1\xc3\x6d\xe3\x6f\x06\xaa\x28\x19\x46\x3f\x5b\x95\x65\xf2\x63\x74\x56\xc2\x3e\xa8\x1f\xc4\xfc\x52\xda\x45\xbc\x46\xa6\xdc\x9a\x6a\x9b\xdc\xa7\xba\xbe\x51\xdd\xff\xff\xb1\x22\x45\x41\x24\x58\x97\x64\x22\x65\xbd\x59\xb7\x43\xb3\x25\x37\x03\x5b\xe0\x3e\xc1\x89\xa9\x11\x9c\x6a\x9a\xc0\xa4\xeb\xb9\x51\xd7\x94\xf9\x91\x1c\x31\x3c\xb1\x54\x2f\x63\xf3\x65\xa5\x5c\x6c\x48\x95\x2b\xa7\x09\x86\xe6\x73\xc6\x28\xad\xa9\x9d\xcf\x99\x04\xa2\x5b\xb5\x84\xd1\x29\xf3\x57\x16\xde\x36\xe9\x50\x65\x61\x57\x66\x38\x5f\xcd\x4c\x57\x31\x04\x10\xd0\xec\xe1\xcb\x17\xb1\xaa\x9f\x97\x99\xaa\x9f\x18\xb1\xe1\xcb\xce\xec\x07\x10\x53\x31\xd0\x4c\x38\x5f\x55\x66\x68\x61\xe6\x50\xe0\x36\x56\x16\x2b\xf3\x81\xd1\x5d\xb5\x04\xa2\xce\x99\xaa\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9b\x2b\x67\x48\xa9\x5c\xf1\x65\x2e\x63\xb4\x54\x2e\x3c\x93\x1c\x92\xf9\x54\xd7\xe8\xb9\xc2\xa4\x69\x9a\x10\x9c\x8c\xa9\x3c\xc1\x5c\xe0\x37\x03\xb2\x25\xb8\x43\xbc\x59\x24\x65\x95\x64\x26\x58\x43\x41\xb2\x22\xff\xff\x50\xdd\xba\xbe\xde\xa7\x68\x9b\xdd\x9a\x45\xa6\x45\xbc\x52\xda\xc5\xfc\xa8\x1f\xbf\x3e\x79\x56\xec\x63\x9b\x65\x3b\x5b\x1a\x46\xaa\x28\x6f\x06\x6e\xe3\xd0\xc3\x4f\xab\xd0\x9c\x0f\x9a\x58\xa3\x97\xb7\x68\xd4\x5c\xf6\x78\x19\x8f\x39\xd6\x52\x57\x62\x32\x66\xfb\x5d\xa6\x4a\x7b\x2e\xd8\x0c\xa6\xe9\x25\xc9\x15\xaf\x9c\x9e\xa9\x99\xc7\xa0\x33\xb3\xa9\xce\xfd\xef\x2f\x13\x21\x34\xe6\x4e\x58\x60\x67\x66\x59\x60\xe5\x4e\x23\x34\x2c\x13\x00\xf0\xa6\xce\x35\xb3\xc7\xa0\xa8\x99\x9d\x9e\x15\xaf\x24\xc9\xa8\xe9\xd5\x0c\x7e\x2e\xa5\x4a\xfa\x5d\x35\x66\x52\x62\xdb\x52\x8d\x39\x77\x19\x5e\xf6\x66\xd4\x98\xb7\x59\xa3\x0c\x9a\xd3\x9c\x4d\xab\xd1\xc3\x6e\xe3\x6e\x06\xaa\x28\x1b\x46\x3b\x5b\x9a\x65\xed\x63\x76\x56\xc4\x3e\xa3\x1f\xcb\xfc\x4b\xda\x4a\xbc\x43\xa6\xdd\x9a\x6a\x9b\xdc\xa7\xba\xbe\x51\xdd\xff\xff\xb1\x22\x44\x41\x25\x58\x96\x64\x23\x65\xbd\x59\xb6\x43\xb4\x25\x36\x03\x5c\xe0\x3d\xc1\x8a\xa9\x12\x9c\x67\x9a\xc4\xa4\xe6\xb9\x55\xd7\x93\xf9\x91\x1c\x31\x3c\xb0\x54\x31\x63\xef\x65\xab\x5c\x66\x48\x9a\x2b\xa4\x09\x87\xe6\x73\xc6\x26\xad\xad\x9d\xcb\x99\x07\xa2\x5b\xb5\x81\xd1\x2c\xf3\x56\x16\xde\x36\xeb\x50\x62\x61\x59\x66\x38\x5f\xcc\x4c\x59\x31\x01\x10\xd3\xec\xdd\xcb\x1b\xb1\xa8\x9f\x98\x99\xa9\x9f\x18\xb1\xe0\xcb\xd1\xec\x03\x10\x57\x31\xce\x4c\x37\x5f\x58\x66\x63\x61\xec\x50\xdb\x36\x5a\x16\x27\xf3\x85\xd1\x5a\xb5\x05\xa2\xce\x99\xaa\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9a\x2b\x69\x48\xa6\x5c\xf4\x65\x2e\x63\xb1\x54\x32\x3c\x8e\x1c\x96\xf9\x52\xd7\xea\xb9\xc1\xa4\x67\x9a\x13\x9c\x8a\xa9\x3c\xc1\x5e\xe0\x33\x03\xb7\x25\xb4\x43\xbf\x59\x21\x65\x99\x64\x21\x58\x48\x41\xad\x22\x03\x00\x4f\xdd\xbb\xbe\xdb\xa7\x6a\x9b\xdd\x9a\x43\xa6\x4b\xbc\x4a\xda\xcb\xfc\xa4\x1f\xc3\x3e\x76\x56\xef\x63\x96\x65\x40\x5b\x17\x46\xac\x28\x6e\x06\x6d\xe3\xd2\xc3\x4d\xab\xd2\x9c\x0d\x9a\x59\xa3\x97\xb7\x68\xd4\x5c\xf6\x77\x19\x8f\x39\xd8\x52\x55\x62\x33\x66\xfb\x5d\xa4\x4a\x7f\x2e\xd4\x0c\xab\xe9\x20\xc9\x17\xaf\x9d\x9e\xa7\x99\xc9\xa0\x32\xb3\xa9\xce\xfd\xef\x2f\x13\x20\x34\xe8\x4e\x56\x60\x6a\x66\x55\x60\xe9\x4e\x1f\x34\x31\x13\xfa\xef\xad\xce\x2e\xb3\xcc\xa0\xa7\x99\x9b\x9e\x18\xaf\x20\xc9\xac\xe9\xd2\x0c\x81\x2e\xa1\x4a\xff\x5d\x30\x66\x56\x62\xd7\x52\x90\x39\x77\x19\x5d\xf6\x67\xd4\x96\xb7\x5a\xa3\x0e\x9a\xd0\x9c\x50\xab\xcf\xc3\x6e\xe3\x6f\x06\xaa\x28\x1a\x46\x3d\x5b\x98\x65\xee\x63\x77\x56\xc1\x3e\xa7\x1f\xc8\xfc\x4c\xda\x4b\xbc\x41\xa6\xdf\x9a\x68\x9b\xdd\xa7\xba\xbe\x51\xdd";
is length($wav_file), 1644, 'embedded binary wav file';

# test MoH

($sock_a, $sock_b) = new_call([qw(198.51.100.1 33041)], [qw(198.51.100.3 33042)]);

# declare that offerer is capable of moh
offer('Music on hold - sendrecv', { ICE => 'remove', DTLS => 'off', moh => { blob => $wav_file } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# declare that answerer is capable of moh (fake db-id)
answer('Music on hold - sendrecv', { ICE => 'remove', moh => { 'db-id' => '123' } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# offerer puts on hold
offer('Music on hold - MoH set by offerer', { ICE => 'remove', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997028 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendonly
----------------------------------
v=0
o=- 1545997028 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

# test received packets on the recepient side
(undef, $seq, $ts, $ssrc) = rcv($sock_b, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_b, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_b, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_b, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_b, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));

answer('Music on hold - MoH set by offerer', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997028 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.3
a=recvonly
--------------------------------------
v=0
o=- 1545997028 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=recvonly
a=rtcp:PORT
SDP

# offerer puts off hold
offer('Music on hold - MoH put off by offerer', { ICE => 'remove', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997029 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997029 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('Music on hold - MoH put off by offerer', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997029 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997029 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# test MoH zero-connection

($sock_a, $sock_b) = new_call([qw(198.51.100.1 33041)], [qw(198.51.100.3 33042)]);

# declare that offerer is capable of moh
offer('Music on hold - sendrecv and declared zero-connection', { ICE => 'remove', DTLS => 'off', moh => { blob => $wav_file, connection => 'zero' } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# declare that answerer is capable of moh (fake db-id)
answer('Music on hold - sendrecv and declared zero-connection', { ICE => 'remove', moh => { 'db-id' => '123', connection => 'zero' } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# offerer puts on hold
offer('Music on hold - MoH set by offerer and declared zero-connection', { ICE => 'remove', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997028 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendonly
----------------------------------
v=0
o=- 1545997028 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 0.0.0.0
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

# test received packets on the recepient side
(undef, $seq, $ts, $ssrc) = rcv($sock_b, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_b, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_b, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_b, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_b, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));

answer('Music on hold - MoH set by offerer and declared zero-connection', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997028 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.3
a=recvonly
--------------------------------------
v=0
o=- 1545997028 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=recvonly
a=rtcp:PORT
SDP

# offerer puts off hold
offer('Music on hold - MoH put off by offerer and declared zero-connection', { ICE => 'remove', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997029 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997029 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('Music on hold - MoH put off by offerer and declared zero-connection', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997029 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997029 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# test MoH sendrecv mode

($sock_a, $sock_b) = new_call([qw(198.51.100.1 33041)], [qw(198.51.100.3 33042)]);

# declare that offerer is capable of moh
offer('Music on hold - sendrecv and declared sendrecv mode', { ICE => 'remove', DTLS => 'off', moh => { blob => $wav_file, mode => 'sendrecv' } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# declare that answerer is capable of moh (fake db-id)
answer('Music on hold - sendrecv and declared sendrecv mode', { ICE => 'remove', moh => { 'db-id' => '123', mode => 'sendrecv' } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# offerer puts on hold
offer('Music on hold - MoH set by offerer and declared sendrecv mode', { ICE => 'remove', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997028 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendonly
----------------------------------
v=0
o=- 1545997028 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# test received packets on the recepient side
(undef, $seq, $ts, $ssrc) = rcv($sock_b, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_b, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_b, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_b, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_b, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));

answer('Music on hold - MoH set by offerer and declared sendrecv mode', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997028 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997028 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# offerer puts off hold
offer('Music on hold - MoH put off by offerer and declared sendrecv mode', { ICE => 'remove', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997029 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997029 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('Music on hold - MoH put off by offerer and declared sendrecv mode', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997029 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997029 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# test MoH zero-connection + mode sendrecv

($sock_a, $sock_b) = new_call([qw(198.51.100.1 33041)], [qw(198.51.100.3 33042)]);

# declare that offerer is capable of moh
offer('Music on hold - sendrecv and declared zero-connection + mode sendrecv', { ICE => 'remove', DTLS => 'off', moh => { blob => $wav_file, connection => 'zero', mode => 'sendrecv' } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# declare that answerer is capable of moh (fake db-id)
answer('Music on hold - sendrecv and declared zero-connection + mode sendrecv', { ICE => 'remove', moh => { 'db-id' => '123', connection => 'zero', mode => 'sendrecv' } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# offerer puts on hold
offer('Music on hold - MoH set by offerer and declared zero-connection + mode sendrecv', { ICE => 'remove', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997028 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendonly
----------------------------------
v=0
o=- 1545997028 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 0.0.0.0
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# test received packets on the recepient side
(undef, $seq, $ts, $ssrc) = rcv($sock_b, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_b, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_b, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_b, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_b, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));

answer('Music on hold - MoH set by offerer and declared zero-connection + mode sendrecv', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997028 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997028 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# offerer puts off hold
offer('Music on hold - MoH put off by offerer and declared zero-connection + mode sendrecv', { ICE => 'remove', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997029 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997029 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('Music on hold - MoH put off by offerer and declared zero-connection + mode sendrecv', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997029 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997029 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# test MoH for answerer

($sock_a, $sock_b) = new_call([qw(198.51.100.1 33041)], [qw(198.51.100.3 33042)]);

# declare that offerer is capable of moh (fake db-id)
offer('Music on hold - answerer test, sendrecv', { ICE => 'remove', DTLS => 'off', moh => { 'db-id' => '123' } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# declare that answerer is capable of moh
answer('Music on hold - answerer test, sendrecv', { ICE => 'remove', moh => { blob => $wav_file } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

reverse_tags();

# answerer puts on hold
offer('Music on hold - answerer test, MoH set by answerer', { ICE => 'remove', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997028 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendonly
----------------------------------
v=0
o=- 1545997028 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

# test received packets on the originator's side
(undef, $seq, $ts, $ssrc) = rcv($sock_a, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_a, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_a, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_a, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_a, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));

answer('Music on hold - answerer test, MoH set by answerer', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997028 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.3
a=recvonly
--------------------------------------
v=0
o=- 1545997028 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=recvonly
a=rtcp:PORT
SDP

# answerer puts off hold
offer('Music on hold - answerer test, MoH put off by answerer', { ICE => 'remove', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997029 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 33042 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997029 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('Music on hold - answerer test, MoH put off by answerer', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997029 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 33041 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997029 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
