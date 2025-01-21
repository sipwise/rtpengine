#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use Test2::Tools::Compare qw();
use NGCP::Rtpclient::ICE;
use POSIX;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --silence-detect=1 --log-level-internals=7))
		or die;


my $extended_tests = $ENV{RTPENGINE_EXTENDED_TESTS};


# 100 ms sine wave

my $wav_file = "\x52\x49\x46\x46\x64\x06\x00\x00\x57\x41\x56\x45\x66\x6d\x74\x20\x10\x00\x00\x00\x01\x00\x01\x00\x40\x1f\x00\x00\x80\x3e\x00\x00\x02\x00\x10\x00\x64\x61\x74\x61\x40\x06\x00\x00\x00\x00\xb0\x22\x45\x41\x25\x58\x95\x64\x24\x65\xbd\x59\xb6\x43\xb4\x25\x35\x03\x5e\xe0\x3b\xc1\x8c\xa9\x0f\x9c\x6a\x9a\xc2\xa4\xe7\xb9\x55\xd7\x92\xf9\x92\x1c\x30\x3c\xb2\x54\x2e\x63\xf3\x65\xa7\x5c\x68\x48\x9b\x2b\xa1\x09\x8a\xe6\x71\xc6\x28\xad\xab\x9d\xcc\x99\x06\xa2\x5c\xb5\x81\xd1\x2d\xf3\x53\x16\xe1\x36\xe8\x50\x64\x61\x59\x66\x36\x5f\xcf\x4c\x56\x31\x04\x10\xd0\xec\xe0\xcb\x19\xb1\xa9\x9f\x98\x99\xa8\x9f\x1a\xb1\xdf\xcb\xd1\xec\x04\x10\x54\x31\xd2\x4c\x33\x5f\x5c\x66\x61\x61\xeb\x50\xde\x36\x56\x16\x2b\xf3\x83\xd1\x59\xb5\x08\xa2\xcb\x99\xac\x9d\x28\xad\x70\xc6\x8a\xe6\xa3\x09\x98\x2b\x6a\x48\xa6\x5c\xf4\x65\x2d\x63\xb3\x54\x2e\x3c\x93\x1c\x93\xf9\x53\xd7\xe9\xb9\xc1\xa4\x69\x9a\x11\x9c\x8b\xa9\x3b\xc1\x5e\xe0\x36\x03\xb2\x25\xba\x43\xb7\x59\x2a\x65\x90\x64\x29\x58\x42\x41\xb2\x22\xff\xff\x50\xdd\xbb\xbe\xdb\xa7\x6b\x9b\xdd\x9a\x42\xa6\x4b\xbc\x4b\xda\xca\xfc\xa5\x1f\xc2\x3e\x77\x56\xed\x63\x9a\x65\x3b\x5b\x1b\x46\xa9\x28\x70\x06\x6c\xe3\xd2\xc3\x4d\xab\xd1\x9c\x10\x9a\x56\xa3\x99\xb7\x67\xd4\x5b\xf6\x79\x19\x8e\x39\xd7\x52\x58\x62\x30\x66\xfd\x5d\xa2\x4a\x81\x2e\xd1\x0c\xae\xe9\x1f\xc9\x17\xaf\x9e\x9e\xa4\x99\xce\xa0\x2c\xb3\xaf\xce\xf8\xef\x33\x13\x1e\x34\xe8\x4e\x57\x60\x68\x66\x57\x60\xe9\x4e\x1c\x34\x35\x13\xf6\xef\xb0\xce\x2d\xb3\xcc\xa0\xa6\x99\x9c\x9e\x17\xaf\x22\xc9\xa9\xe9\xd6\x0c\x7c\x2e\xa7\x4a\xf8\x5d\x36\x66\x52\x62\xdb\x52\x8c\x39\x79\x19\x5c\xf6\x67\xd4\x97\xb7\x59\xa3\x0e\x9a\xd1\x9c\x4e\xab\xd0\xc3\x6e\xe3\x6e\x06\xac\x28\x18\x46\x3d\x5b\x98\x65\xef\x63\x76\x56\xc3\x3e\xa4\x1f\xc9\xfc\x4e\xda\x49\xbc\x43\xa6\xdd\x9a\x69\x9b\xdd\xa7\xbb\xbe\x4f\xdd\x01\x00\xaf\x22\x47\x41\x23\x58\x96\x64\x24\x65\xbb\x59\xba\x43\xb0\x25\x39\x03\x59\xe0\x40\xc1\x87\xa9\x15\x9c\x65\x9a\xc4\xa4\xe7\xb9\x56\xd7\x90\xf9\x94\x1c\x2e\x3c\xb3\x54\x2f\x63\xf1\x65\xa8\x5c\x68\x48\x9a\x2b\xa2\x09\x8a\xe6\x71\xc6\x27\xad\xac\x9d\xcb\x99\x08\xa2\x59\xb5\x84\xd1\x2a\xf3\x56\x16\xe0\x36\xe7\x50\x65\x61\x59\x66\x35\x5f\xd1\x4c\x54\x31\x04\x10\xd2\xec\xdd\xcb\x1c\xb1\xa5\x9f\x9b\x99\xa8\x9f\x18\xb1\xe2\xcb\xcd\xec\x07\x10\x54\x31\xd1\x4c\x33\x5f\x5d\x66\x60\x61\xec\x50\xdd\x36\x57\x16\x29\xf3\x86\xd1\x57\xb5\x09\xa2\xcb\x99\xab\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9a\x2b\x69\x48\xa7\x5c\xf2\x65\x2e\x63\xb2\x54\x31\x3c\x91\x1c\x93\xf9\x53\xd7\xe9\xb9\xc1\xa4\x6a\x9a\x10\x9c\x8a\xa9\x3f\xc1\x59\xe0\x3a\x03\xb0\x25\xb8\x43\xbd\x59\x24\x65\x95\x64\x24\x58\x46\x41\xaf\x22\x02\x00\x4e\xdd\xbb\xbe\xdd\xa7\x68\x9b\xdf\x9a\x42\xa6\x48\xbc\x50\xda\xc6\xfc\xa7\x1f\xc2\x3e\x75\x56\xef\x63\x99\x65\x3c\x5b\x1a\x46\xaa\x28\x6e\x06\x6e\xe3\xd1\xc3\x4e\xab\xd1\x9c\x0e\x9a\x57\xa3\x9a\xb7\x64\xd4\x60\xf6\x75\x19\x90\x39\xd7\x52\x55\x62\x34\x66\xf9\x5d\xa8\x4a\x7a\x2e\xd8\x0c\xa7\xe9\x23\xc9\x16\xaf\x9d\x9e\xa6\x99\xcb\xa0\x2f\xb3\xad\xce\xfa\xef\x30\x13\x21\x34\xe6\x4e\x59\x60\x66\x66\x5a\x60\xe4\x4e\x23\x34\x2e\x13\xfc\xef\xab\xce\x30\xb3\xcb\xa0\xa5\x99\x9f\x9e\x14\xaf\x24\xc9\xa7\xe9\xd8\x0c\x7b\x2e\xa8\x4a\xf7\x5d\x36\x66\x53\x62\xda\x52\x8d\x39\x78\x19\x5d\xf6\x67\xd4\x97\xb7\x59\xa3\x0d\x9a\xd2\x9c\x4e\xab\xd1\xc3\x6d\xe3\x6f\x06\xaa\x28\x19\x46\x3f\x5b\x95\x65\xf2\x63\x74\x56\xc2\x3e\xa8\x1f\xc4\xfc\x52\xda\x45\xbc\x46\xa6\xdc\x9a\x6a\x9b\xdc\xa7\xba\xbe\x51\xdd\xff\xff\xb1\x22\x45\x41\x24\x58\x97\x64\x22\x65\xbd\x59\xb7\x43\xb3\x25\x37\x03\x5b\xe0\x3e\xc1\x89\xa9\x11\x9c\x6a\x9a\xc0\xa4\xeb\xb9\x51\xd7\x94\xf9\x91\x1c\x31\x3c\xb1\x54\x2f\x63\xf3\x65\xa5\x5c\x6c\x48\x95\x2b\xa7\x09\x86\xe6\x73\xc6\x28\xad\xa9\x9d\xcf\x99\x04\xa2\x5b\xb5\x84\xd1\x29\xf3\x57\x16\xde\x36\xe9\x50\x65\x61\x57\x66\x38\x5f\xcd\x4c\x57\x31\x04\x10\xd0\xec\xe1\xcb\x17\xb1\xaa\x9f\x97\x99\xaa\x9f\x18\xb1\xe1\xcb\xce\xec\x07\x10\x53\x31\xd0\x4c\x38\x5f\x55\x66\x68\x61\xe6\x50\xe0\x36\x56\x16\x2b\xf3\x81\xd1\x5d\xb5\x04\xa2\xce\x99\xaa\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9b\x2b\x67\x48\xa9\x5c\xf1\x65\x2e\x63\xb4\x54\x2e\x3c\x93\x1c\x92\xf9\x54\xd7\xe8\xb9\xc2\xa4\x69\x9a\x10\x9c\x8c\xa9\x3c\xc1\x5c\xe0\x37\x03\xb2\x25\xb8\x43\xbc\x59\x24\x65\x95\x64\x26\x58\x43\x41\xb2\x22\xff\xff\x50\xdd\xba\xbe\xde\xa7\x68\x9b\xdd\x9a\x45\xa6\x45\xbc\x52\xda\xc5\xfc\xa8\x1f\xbf\x3e\x79\x56\xec\x63\x9b\x65\x3b\x5b\x1a\x46\xaa\x28\x6f\x06\x6e\xe3\xd0\xc3\x4f\xab\xd0\x9c\x0f\x9a\x58\xa3\x97\xb7\x68\xd4\x5c\xf6\x78\x19\x8f\x39\xd6\x52\x57\x62\x32\x66\xfb\x5d\xa6\x4a\x7b\x2e\xd8\x0c\xa6\xe9\x25\xc9\x15\xaf\x9c\x9e\xa9\x99\xc7\xa0\x33\xb3\xa9\xce\xfd\xef\x2f\x13\x21\x34\xe6\x4e\x58\x60\x67\x66\x59\x60\xe5\x4e\x23\x34\x2c\x13\x00\xf0\xa6\xce\x35\xb3\xc7\xa0\xa8\x99\x9d\x9e\x15\xaf\x24\xc9\xa8\xe9\xd5\x0c\x7e\x2e\xa5\x4a\xfa\x5d\x35\x66\x52\x62\xdb\x52\x8d\x39\x77\x19\x5e\xf6\x66\xd4\x98\xb7\x59\xa3\x0c\x9a\xd3\x9c\x4d\xab\xd1\xc3\x6e\xe3\x6e\x06\xaa\x28\x1b\x46\x3b\x5b\x9a\x65\xed\x63\x76\x56\xc4\x3e\xa3\x1f\xcb\xfc\x4b\xda\x4a\xbc\x43\xa6\xdd\x9a\x6a\x9b\xdc\xa7\xba\xbe\x51\xdd\xff\xff\xb1\x22\x44\x41\x25\x58\x96\x64\x23\x65\xbd\x59\xb6\x43\xb4\x25\x36\x03\x5c\xe0\x3d\xc1\x8a\xa9\x12\x9c\x67\x9a\xc4\xa4\xe6\xb9\x55\xd7\x93\xf9\x91\x1c\x31\x3c\xb0\x54\x31\x63\xef\x65\xab\x5c\x66\x48\x9a\x2b\xa4\x09\x87\xe6\x73\xc6\x26\xad\xad\x9d\xcb\x99\x07\xa2\x5b\xb5\x81\xd1\x2c\xf3\x56\x16\xde\x36\xeb\x50\x62\x61\x59\x66\x38\x5f\xcc\x4c\x59\x31\x01\x10\xd3\xec\xdd\xcb\x1b\xb1\xa8\x9f\x98\x99\xa9\x9f\x18\xb1\xe0\xcb\xd1\xec\x03\x10\x57\x31\xce\x4c\x37\x5f\x58\x66\x63\x61\xec\x50\xdb\x36\x5a\x16\x27\xf3\x85\xd1\x5a\xb5\x05\xa2\xce\x99\xaa\x9d\x29\xad\x70\xc6\x8a\xe6\xa2\x09\x9a\x2b\x69\x48\xa6\x5c\xf4\x65\x2e\x63\xb1\x54\x32\x3c\x8e\x1c\x96\xf9\x52\xd7\xea\xb9\xc1\xa4\x67\x9a\x13\x9c\x8a\xa9\x3c\xc1\x5e\xe0\x33\x03\xb7\x25\xb4\x43\xbf\x59\x21\x65\x99\x64\x21\x58\x48\x41\xad\x22\x03\x00\x4f\xdd\xbb\xbe\xdb\xa7\x6a\x9b\xdd\x9a\x43\xa6\x4b\xbc\x4a\xda\xcb\xfc\xa4\x1f\xc3\x3e\x76\x56\xef\x63\x96\x65\x40\x5b\x17\x46\xac\x28\x6e\x06\x6d\xe3\xd2\xc3\x4d\xab\xd2\x9c\x0d\x9a\x59\xa3\x97\xb7\x68\xd4\x5c\xf6\x77\x19\x8f\x39\xd8\x52\x55\x62\x33\x66\xfb\x5d\xa4\x4a\x7f\x2e\xd4\x0c\xab\xe9\x20\xc9\x17\xaf\x9d\x9e\xa7\x99\xc9\xa0\x32\xb3\xa9\xce\xfd\xef\x2f\x13\x20\x34\xe8\x4e\x56\x60\x6a\x66\x55\x60\xe9\x4e\x1f\x34\x31\x13\xfa\xef\xad\xce\x2e\xb3\xcc\xa0\xa7\x99\x9b\x9e\x18\xaf\x20\xc9\xac\xe9\xd2\x0c\x81\x2e\xa1\x4a\xff\x5d\x30\x66\x56\x62\xd7\x52\x90\x39\x77\x19\x5d\xf6\x67\xd4\x96\xb7\x5a\xa3\x0e\x9a\xd0\x9c\x50\xab\xcf\xc3\x6e\xe3\x6f\x06\xaa\x28\x1a\x46\x3d\x5b\x98\x65\xee\x63\x77\x56\xc1\x3e\xa7\x1f\xc8\xfc\x4c\xda\x4b\xbc\x41\xa6\xdf\x9a\x68\x9b\xdd\xa7\xba\xbe\x51\xdd";
is length($wav_file), 1644, 'embedded binary wav file';

my $pcma_1 = "\xd5\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\x55\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c";
my $pcma_2 = "\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\xd5\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\xd5\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09";
my $pcma_3 = "\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\x55\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0";
my $pcma_4 = "\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\x55\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34\x55\xb4\xa5\xa3\xac\xac\xa3\xa5\xb7\xfc\x0a\x3a\x20\x2d\x2c\x23\x24\x31\x6c\x89\xbb\xa0\xad\xac\xa2\xa7\xb0\x96\x0c\x39\x21\x2d\x2c\x22\x27\x32\x1c\x83\xbe\xa1";
my $pcma_5 = "\xad\xac\xa2\xa6\xbd\x9a\x06\x3f\x26\x2d\x2c\x2d\x26\x3f\x06\x9a\xbd\xa6\xa2\xac\xad\xa1\xbe\x83\x1c\x32\x27\x22\x2c\x2d\x21\x39\x0c\x96\xb0\xa7\xa2\xac\xad\xa0\xbb\x89\x6c\x31\x24\x23\x2c\x2d\x20\x3a\x0a\xfc\xb7\xa5\xa3\xac\xac\xa3\xa5\xb4\xd5\x34\x25\x23\x2c\x2c\x23\x25\x37\x7c\x8a\xba\xa0\xad\xac\xa3\xa4\xb1\xec\x09\x3b\x20\x2d\x2c\x22\x27\x30\x16\x8c\xb9\xa1\xad\xac\xa2\xa7\xb2\x9c\x03\x3e\x21\x2d\x2c\x22\x26\x3d\x1a\x86\xbf\xa6\xad\xac\xad\xa6\xbf\x86\x1a\x3d\x26\x22\x2c\x2d\x21\x3e\x03\x9c\xb2\xa7\xa2\xac\xad\xa1\xb9\x8c\x16\x30\x27\x22\x2c\x2d\x20\x3b\x09\xec\xb1\xa4\xa3\xac\xad\xa0\xba\x8a\x7c\x37\x25\x23\x2c\x2c\x23\x25\x34";



my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $ssrc, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx,
	$sock_cx, $sock_dx, $port_c, $port_d, $port_cx, $port_dx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $has_recv, $tmp_blob);





sub stun_req {
	my ($controlling, $pref, $comp, $my_ufrag, $other_ufrag, $other_pwd) = @_;

	my $tid = NGCP::Rtpclient::ICE::random_string(12);

	my @attrs;
	unshift(@attrs, NGCP::Rtpclient::ICE::attr(0x8022, 'perltester'));

	unshift(@attrs, NGCP::Rtpclient::ICE::attr($controlling ? 0x802a : 0x8029, NGCP::Rtpclient::ICE::random_string(8)));

	unshift(@attrs, NGCP::Rtpclient::ICE::attr(0x0024, pack('N', NGCP::Rtpclient::ICE::calc_priority('prflx',
				$pref, $comp))));
	unshift(@attrs, NGCP::Rtpclient::ICE::attr(0x0006, "$other_ufrag:$my_ufrag"));
	# nominate

	NGCP::Rtpclient::ICE::integrity(\@attrs, 1, $tid, $other_pwd);
	NGCP::Rtpclient::ICE::fingerprint(\@attrs, 1, $tid);

	my $packet = join('', @attrs);
	$packet = pack('nnNa12', 1, length($packet), 0x2112A442, $tid) . $packet;

	return ($packet, $tid);
}

sub stun_succ {
	my ($port, $tid, $my_pwd) = @_;
	my $sw = NGCP::Rtpclient::ICE::attr(0x8022, 'perltester');
	my $xor_addr = NGCP::Rtpclient::ICE::attr(0x0020, pack('nna4', 1, $port ^ 0x2112, pack('CCCC', 203,0,113,1) ^ "\x21\x12\xa4\x42"));
	my $attrs = [$sw, $xor_addr];
	NGCP::Rtpclient::ICE::integrity($attrs, 257, $tid, $my_pwd);
	NGCP::Rtpclient::ICE::fingerprint($attrs, 257, $tid);
	my $pack = join('', @{$attrs});
	my $packet = pack('nnNa12', 257, length($pack), 0x2112A442, $tid) . $pack;
	#print(unpack('H*', $packet)."\n");
	return $packet;
};






if ($extended_tests) {
new_call;

offer('mismatched G.729 annexb', { }, <<SDP);
v=0
o=- 13111259 1 IN IP4 1.2.3.4
s=-
c=IN IP4 1.2.3.4
t=0 0
m=audio 23874 RTP/AVP 9 8 0 18 100
a=rtpmap:100 telephone-event/8000
a=ptime:20
----------------------------
v=0
o=- 13111259 1 IN IP4 1.2.3.4
s=-
t=0 0
m=audio PORT RTP/AVP 9 8 0 18 100
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:18 G729/8000
a=rtpmap:100 telephone-event/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

answer('mismatched G.729 annexb', { }, <<SDP);
v=0
o=- 1737116508926565 1737116508926565 IN IP4 5.6.7.7
s=SIP call
c=IN IP4 5.6.7.7
t=0 0
m=audio 49696 RTP/AVP 8 0 18 100
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:100 telephone-event/8000
a=fmtp:100 0-11
a=ptime:20
a=maxptime:30
a=sendrecv
----------------------------
v=0
o=- 1737116508926565 1737116508926565 IN IP4 5.6.7.7
s=SIP call
t=0 0
m=audio PORT RTP/AVP 8 0 18 100
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:100 telephone-event/8000
a=fmtp:100 0-11
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:30
SDP

new_call;

offer('actually mismatched G.729 annexb', { }, <<SDP);
v=0
o=- 13111259 1 IN IP4 1.2.3.4
s=-
c=IN IP4 1.2.3.4
t=0 0
m=audio 23874 RTP/AVP 9 8 0 18 100
a=rtpmap:100 telephone-event/8000
a=ptime:20
----------------------------
v=0
o=- 13111259 1 IN IP4 1.2.3.4
s=-
t=0 0
m=audio PORT RTP/AVP 9 8 0 18 100
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:18 G729/8000
a=rtpmap:100 telephone-event/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

answer('actually mismatched G.729 annexb', { }, <<SDP);
v=0
o=- 1737116508926565 1737116508926565 IN IP4 5.6.7.7
s=SIP call
c=IN IP4 5.6.7.7
t=0 0
m=audio 49696 RTP/AVP 8 0 18 100
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=yes
a=rtpmap:100 telephone-event/8000
a=fmtp:100 0-11
a=ptime:20
a=maxptime:30
a=sendrecv
----------------------------
v=0
o=- 1737116508926565 1737116508926565 IN IP4 5.6.7.7
s=SIP call
t=0 0
m=audio PORT RTP/AVP 8 0 100
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:100 telephone-event/8000
a=fmtp:100 0-11
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:30
SDP

}

new_call;

offer('original sendrecv control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
c=IN IP4 198.51.100.50
t=0 0
m=audio 3000 RTP/AVP 8
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('original sendrecv control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
c=IN IP4 198.51.100.50
t=0 0
m=audio 3000 RTP/AVP 8
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('original sendrecv control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
c=IN IP4 0.0.0.0
t=0 0
m=audio 3000 RTP/AVP 8
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 0.0.0.0
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

answer('original sendrecv control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
c=IN IP4 0.0.0.0
t=0 0
m=audio 3000 RTP/AVP 8
a=recvonly
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 0.0.0.0
a=rtpmap:8 PCMA/8000
a=inactive
a=rtcp:PORT
SDP

new_call;

offer('original sendrecv', { flags => ['original sendrecv'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
c=IN IP4 0.0.0.0
t=0 0
m=audio 3000 RTP/AVP 8
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 0.0.0.0
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('original sendrecv', { flags => ['original sendrecv'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
c=IN IP4 0.0.0.0
t=0 0
m=audio 3000 RTP/AVP 8
a=recvonly
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 0.0.0.0
a=rtpmap:8 PCMA/8000
a=recvonly
a=rtcp:PORT
SDP


new_call;

offer('double answer codec change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3000 RTP/AVP 0 8 9
---------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 9
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('double answer codec change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3000 RTP/AVP 0
---------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('double answer codec change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3000 RTP/AVP 8
---------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('double answer codec change with new to-tag', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3000 RTP/AVP 0 8 9
---------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 9
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('double answer codec change with new to-tag', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3000 RTP/AVP 0
---------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_tt;

answer('double answer codec change with new to-tag', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3000 RTP/AVP 8
---------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP




($sock_a, $sock_b) = new_call([qw(198.51.100.65 3000)], [qw(198.51.100.65 3002)]);

($port_a) = offer('opus<>opus+DTMF', { }, <<SDP);
v=0
o=root 620038904 620038904 IN IP4 192.168.199.83
s=call
c=IN IP4 198.51.100.65
t=0 0
m=audio 3000 RTP/AVP 119 9 8 101
a=rtpmap:119 opus/48000/2
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=ptime:20
a=sendrecv
----------------------------------------------------------
v=0
o=root 620038904 620038904 IN IP4 192.168.199.83
s=call
t=0 0
m=audio PORT RTP/AVP 119 9 8 101
c=IN IP4 203.0.113.1
a=rtpmap:119 opus/48000/2
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

snd($sock_b, $port_a, rtp(119, 2000, 4000, 0x123494f, "\x08\x09\x97\x2a\x18\x8d\xbb\x4d\x93\xfb\x73\x40\x4c\xcd\x84\xb8\x27\xb1\x11\x71\xdd\x3a\xd7\x93\x2b\xa9\x11\xeb\x5f\xc6\x42\x9d\xc9\xa0\x84\x44\x3c\x60\xfc\xb8"));

($port_b) = answer('opus<>opus+DTMF', { flags => [qw,allow-asymmetric-codecs,] }, <<SDP);
v=0
o=- 620038904 620038906 IN IP4 10.27.45.45
s=Asterisk
c=IN IP4 198.51.100.65
t=0 0
m=audio 3002 RTP/AVP 119 101
a=rtpmap:119 opus/48000/2
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:60
a=sendrecv
---------------------------------------------------------
v=0
o=- 620038904 620038906 IN IP4 10.27.45.45
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 119 101
c=IN IP4 203.0.113.1
a=rtpmap:119 opus/48000/2
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:60
SDP

rcv($sock_a, $port_b, rtpm(119, 2000, 4000, 0x123494f, "\x08\x09\x97\x2a\x18\x8d\xbb\x4d\x93\xfb\x73\x40\x4c\xcd\x84\xb8\x27\xb1\x11\x71\xdd\x3a\xd7\x93\x2b\xa9\x11\xeb\x5f\xc6\x42\x9d\xc9\xa0\x84\x44\x3c\x60\xfc\xb8"));

snd($sock_b, $port_a, rtp(119, 2001, 4960, 0x123494f, "\x08\x09\x92\x4c\x09\x80\xf5\x6a\xd8\xe1\x0e\x57\x55\x0d\xb0\xf4\x9f\x5f\xaf\xe4\xdc\xa7\x2d\x74\x99\xb8\x10\xaa\x3a\xa8\xe5\x18\x6e\x8f\x87\xe4\xc9\x33\xbb"));
rcv($sock_a, $port_b, rtpm(119, 2001, 4960, 0x123494f, "\x08\x09\x92\x4c\x09\x80\xf5\x6a\xd8\xe1\x0e\x57\x55\x0d\xb0\xf4\x9f\x5f\xaf\xe4\xdc\xa7\x2d\x74\x99\xb8\x10\xaa\x3a\xa8\xe5\x18\x6e\x8f\x87\xe4\xc9\x33\xbb"));

snd($sock_a, $port_b, rtp(119, 3000, 5000, 0x1234d37, "\x08\x09\x97\x2a\x18\x8d\xbb\x4d\x93\xfb\x73\x40\x4c\xcd\x84\xb8\x27\xb1\x11\x71\xdd\x3a\xd7\x93\x2b\xa9\x11\xeb\x5f\xc6\x42\x9d\xc9\xa0\x84\x44\x3c\x60\xfc\xb8"));
rcv($sock_b, $port_a, rtpm(119, 3000, 5000, 0x1234d37, "\x08\x09\x97\x2a\x18\x8d\xbb\x4d\x93\xfb\x73\x40\x4c\xcd\x84\xb8\x27\xb1\x11\x71\xdd\x3a\xd7\x93\x2b\xa9\x11\xeb\x5f\xc6\x42\x9d\xc9\xa0\x84\x44\x3c\x60\xfc\xb8"));

snd($sock_b, $port_a, rtp(119, 4001, 6960, 0x123511f, "\x08\x09\x92\x4c\x09\x80\xf5\x6a\xd8\xe1\x0e\x57\x55\x0d\xb0\xf4\x9f\x5f\xaf\xe4\xdc\xa7\x2d\x74\x99\xb8\x10\xaa\x3a\xa8\xe5\x18\x6e\x8f\x87\xe4\xc9\x33\xbb"));
rcv($sock_a, $port_b, rtpm(119, 4001, 6960, 0x123511f, "\x08\x09\x92\x4c\x09\x80\xf5\x6a\xd8\xe1\x0e\x57\x55\x0d\xb0\xf4\x9f\x5f\xaf\xe4\xdc\xa7\x2d\x74\x99\xb8\x10\xaa\x3a\xa8\xe5\x18\x6e\x8f\x87\xe4\xc9\x33\xbb"));

reverse_tags();

offer('opus<>opus+DTMF', { codec => { accept => ['all'], transcode => [qw,G722 PCMA,] } }, <<SDP);
v=0
o=- 620038904 620038906 IN IP4 10.27.45.45
s=Asterisk
c=IN IP4 198.51.100.65
t=0 0
m=audio 3002 RTP/AVP 119 113 101
a=rtpmap:119 opus/48000/2
a=rtpmap:113 telephone-event/48000
a=fmtp:113 0-16
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:60
a=sendrecv
---------------------------------------------------------
v=0
o=- 620038904 620038906 IN IP4 10.27.45.45
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 119 9 8 113 101
c=IN IP4 203.0.113.1
a=rtpmap:119 opus/48000/2
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:113 telephone-event/48000
a=fmtp:113 0-16
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:60
SDP

snd($sock_a, $port_b, rtp(119, 3001, 5960, 0x1234d37, "\x08\x09\x97\x2a\x18\x8d\xbb\x4d\x93\xfb\x73\x40\x4c\xcd\x84\xb8\x27\xb1\x11\x71\xdd\x3a\xd7\x93\x2b\xa9\x11\xeb\x5f\xc6\x42\x9d\xc9\xa0\x84\x44\x3c\x60\xfc\xb8"));
rcv($sock_b, $port_a, rtpm(119, 3001, 5960, 0x1234d37, "\x08\x09\x97\x2a\x18\x8d\xbb\x4d\x93\xfb\x73\x40\x4c\xcd\x84\xb8\x27\xb1\x11\x71\xdd\x3a\xd7\x93\x2b\xa9\x11\xeb\x5f\xc6\x42\x9d\xc9\xa0\x84\x44\x3c\x60\xfc\xb8"));

snd($sock_b, $port_a, rtp(119, 4002, 7920, 0x123511f, "\x08\x09\x92\x4c\x09\x80\xf5\x6a\xd8\xe1\x0e\x57\x55\x0d\xb0\xf4\x9f\x5f\xaf\xe4\xdc\xa7\x2d\x74\x99\xb8\x10\xaa\x3a\xa8\xe5\x18\x6e\x8f\x87\xe4\xc9\x33\xbb"));
rcv($sock_a, $port_b, rtpm(119, 4002, 7920, 0x123511f, "\x08\x09\x92\x4c\x09\x80\xf5\x6a\xd8\xe1\x0e\x57\x55\x0d\xb0\xf4\x9f\x5f\xaf\xe4\xdc\xa7\x2d\x74\x99\xb8\x10\xaa\x3a\xa8\xe5\x18\x6e\x8f\x87\xe4\xc9\x33\xbb"));

answer('opus<>opus+DTMF', { }, <<SDP);
v=0
o=root 620038904 620038904 IN IP4 192.168.199.83
s=call
c=IN IP4 198.51.100.65
t=0 0
m=audio 3000 RTP/AVP 119 9 8 101
a=rtpmap:119 opus/48000/2
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=ptime:20
a=sendrecv
----------------------------------------------------------
v=0
o=root 620038904 620038904 IN IP4 192.168.199.83
s=call
t=0 0
m=audio PORT RTP/AVP 119 113
c=IN IP4 203.0.113.1
a=rtpmap:119 opus/48000/2
a=fmtp:119 stereo=1; useinbandfec=1
a=rtpmap:113 telephone-event/48000
a=fmtp:113 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

snd($sock_a, $port_b, rtp(119, 3002, 6920, 0x1234d37, "\x08\x09\x97\x2a\x18\x8d\xbb\x4d\x93\xfb\x73\x40\x4c\xcd\x84\xb8\x27\xb1\x11\x71\xdd\x3a\xd7\x93\x2b\xa9\x11\xeb\x5f\xc6\x42\x9d\xc9\xa0\x84\x44\x3c\x60\xfc\xb8"));
rcv($sock_b, $port_a, rtpm(119, 3002, 6920, 0x1234d37, "\x7c\x07\xfd\x8f\xd8\x72\x17\x27\x5a\x44\x8f\x61\x33\x88\xfd\x28\x0b\xeb\x95\x47\xb8\xb7\x5e\xcf\x51\xfa\x5a\x6e\x48\xd9\xc4\xd9\x83\x75\xcf\xaf\x1b\x35\x07\x4a\x1e\x5f\x91\x6c\x67\xbd\xba"));

snd($sock_b, $port_a, rtp(113, 5001, 7960, 0x123494f, "\x08\x09\x92\x4c\x09\x80\xf5\x6a\xd8\xe1\x0e\x57\x55\x0d\xb0\xf4\x9f\x5f\xaf\xe4\xdc\xa7\x2d\x74\x99\xb8\x10\xaa\x3a\xa8\xe5\x18\x6e\x8f\x87\xe4\xc9\x33\xbb"));
rcv($sock_a, $port_b, rtpm(119, 5001, 7960, 0x123494f, "\x7c\x87\xfc\xe0\x9a\x50\x9a\x79\x65\xb9\x03\x78\xff\x0a\xcb\x3a\x4d\xa4\x24\x7c\x7d\xde\x9d\x4c\xed\x7d\xab\xbd\x3b\x80\x34\x55\x91\x50\x5e\x97\x38\x8e\x4b\xc8\x5c\x5a\x92\xa2\xce\x43\x49\xbd\x7e\xef\xa7\x0f\x63\x95\x20\x39\x69\x7a\xb3\x6f"));





($sock_a, $sock_ax, $sock_b, $sock_bx,
$sock_c, $sock_cx, $sock_d, $sock_dx) = new_call([qw(198.51.100.35 3000)], [qw(198.51.100.35 3001)],
							[qw(198.51.100.35 3002)], [qw(198.51.100.35 3003)],
							[qw(198.51.100.35 3004)], [qw(198.51.100.35 3005)],
							[qw(198.51.100.35 3006)], [qw(198.51.100.35 3007)],
							);

($port_a, $port_ax) = offer('simple connect', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('simple connect', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3002 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x7654321, "\x00" x 160));

my $t_a = ft();
my $t_b = tt();

new_ft();
new_tt();

($port_c, $port_cx) = offer('simple connect', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3004 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_d, $port_dx) = answer('simple connect', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3006 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_c, $port_d, rtp(0, 3000, 5000, 0x7532346, "\x00" x 160));
rcv($sock_d, $port_c, rtpm(0, 3000, 5000, 0x7532346, "\x00" x 160));
snd($sock_d, $port_c, rtp(0, 4000, 6000, 0x5432345, "\x00" x 160));
rcv($sock_c, $port_d, rtpm(0, 4000, 6000, 0x5432345, "\x00" x 160));

snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x7654321, "\x00" x 160));

my $t_c = ft();
my $t_d = tt();

rtpe_req('connect', 'connect', { 'from-tag' => $t_a, 'to-tag' => $t_c });

snd($sock_c, $port_d, rtp(0, 3001, 5160, 0x7532346, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 3001, 5160, 0x7532346, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x5432345, "\x00" x 160));
rcv($sock_c, $port_d, rtpm(0, 1002, 3320, 0x5432345, "\x00" x 160));





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.35 3008)], [qw(198.51.100.35 3009)],
							[qw(198.51.100.35 3010)], [qw(198.51.100.35 3011)],
							);

($port_a, $port_ax) = offer('cross call connect', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3008 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('cross call connect', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3010 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x7654321, "\x00" x 160));

my $cid1 = cid();
$t_a = ft();
$t_b = tt();

($sock_c, $sock_cx, $sock_d, $sock_dx) = new_call_nc([qw(198.51.100.35 3012)], [qw(198.51.100.35 3013)],
							[qw(198.51.100.35 3014)], [qw(198.51.100.35 3015)],
							);

($port_c, $port_cx) = offer('cross call connect', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3012 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_d, $port_dx) = answer('cross call connect', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3014 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_c, $port_d, rtp(0, 3000, 5000, 0x7532346, "\x00" x 160));
rcv($sock_d, $port_c, rtpm(0, 3000, 5000, 0x7532346, "\x00" x 160));
snd($sock_d, $port_c, rtp(0, 4000, 6000, 0x5432345, "\x00" x 160));
rcv($sock_c, $port_d, rtpm(0, 4000, 6000, 0x5432345, "\x00" x 160));

snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x7654321, "\x00" x 160));

$t_c = ft();
$t_d = tt();

rtpe_req('connect', 'connect', { 'from-tag' => $t_c, 'to-tag' => $t_a, 'to-call-id' => $cid1 });

snd($sock_c, $port_d, rtp(0, 3001, 5160, 0x7532346, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 3001, 5160, 0x7532346, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x5432345, "\x00" x 160));
rcv($sock_c, $port_d, rtpm(0, 1002, 3320, 0x5432345, "\x00" x 160));

rtpe_req('delete', 'delete');




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.35 3024)], [qw(198.51.100.35 3025)],
							[qw(198.51.100.35 3026)], [qw(198.51.100.35 3027)],
							);

($port_a, $port_ax) = offer('cross call connect with proper delete', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3024 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('cross call connect with proper delete', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3026 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x7654321, "\x00" x 160));

$cid1 = cid();
$t_a = ft();
$t_b = tt();

($sock_c, $sock_cx, $sock_d, $sock_dx) = new_call_nc([qw(198.51.100.35 3028)], [qw(198.51.100.35 3029)],
							[qw(198.51.100.35 3030)], [qw(198.51.100.35 3031)],
							);

($port_c, $port_cx) = offer('cross call connect with proper delete', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3028 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_d, $port_dx) = answer('cross call connect with proper delete', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3030 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_c, $port_d, rtp(0, 3000, 5000, 0x7532346, "\x00" x 160));
rcv($sock_d, $port_c, rtpm(0, 3000, 5000, 0x7532346, "\x00" x 160));
snd($sock_d, $port_c, rtp(0, 4000, 6000, 0x5432345, "\x00" x 160));
rcv($sock_c, $port_d, rtpm(0, 4000, 6000, 0x5432345, "\x00" x 160));

snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x7654321, "\x00" x 160));

$t_c = ft();
$t_d = tt();

rtpe_req('connect', 'connect', { 'from-tag' => $t_c, 'to-tag' => $t_a, 'to-call-id' => $cid1 });

snd($sock_c, $port_d, rtp(0, 3001, 5160, 0x7532346, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 3001, 5160, 0x7532346, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x5432345, "\x00" x 160));
rcv($sock_c, $port_d, rtpm(0, 1002, 3320, 0x5432345, "\x00" x 160));

rtpe_req('delete', 'delete');
rtpe_req('delete', 'delete', { 'call-id' => $cid1 } );





($sock_a, $sock_ax, $sock_b, $sock_bx,
$sock_c, $sock_cx, $sock_d, $sock_dx) = new_call([qw(198.51.100.35 3032)], [qw(198.51.100.35 3033)],
							[qw(198.51.100.35 3034)], [qw(198.51.100.35 3035)],
							[qw(198.51.100.35 3036)], [qw(198.51.100.35 3037)],
							[qw(198.51.100.35 3038)], [qw(198.51.100.35 3039)],
							);

($port_a, $port_ax) = offer('connect with mismatched media types', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3032 RTP/AVP 0
m=video 3932 RTP/AVP 96
a=rtpmap:96 foobar/90000
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 foobar/90000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('connect with mismatched media types', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3034 RTP/AVP 0
m=video 3934 RTP/AVP 96
a=rtpmap:96 foobar/90000
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 foobar/90000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x7654321, "\x00" x 160));

$t_a = ft();
$t_b = tt();

new_ft();
new_tt();

(undef, undef, $port_c, $port_cx) = offer('connect with mismatched media types', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=video 3934 RTP/AVP 96
a=rtpmap:96 foobar/90000
m=audio 3036 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=video PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 foobar/90000
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

(undef, undef, $port_d, $port_dx) = answer('connect with mismatched media types', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=video 3934 RTP/AVP 96
a=rtpmap:96 foobar/90000
m=audio 3038 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=video PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 foobar/90000
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_c, $port_d, rtp(0, 3000, 5000, 0x7532346, "\x00" x 160));
rcv($sock_d, $port_c, rtpm(0, 3000, 5000, 0x7532346, "\x00" x 160));
snd($sock_d, $port_c, rtp(0, 4000, 6000, 0x5432345, "\x00" x 160));
rcv($sock_c, $port_d, rtpm(0, 4000, 6000, 0x5432345, "\x00" x 160));

snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x7654321, "\x00" x 160));

$t_c = ft();
$t_d = tt();

rtpe_req('connect', 'connect', { 'from-tag' => $t_a, 'to-tag' => $t_c });

snd($sock_c, $port_d, rtp(0, 3001, 5160, 0x7532346, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 3001, 5160, 0x7532346, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x5432345, "\x00" x 160));
rcv($sock_c, $port_d, rtpm(0, 1002, 3320, 0x5432345, "\x00" x 160));

offer('connect with mismatched media types', { 'from-tag' => $t_a, 'to-tag' => $t_c }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3032 RTP/AVP 0
m=video 3932 RTP/AVP 96
a=rtpmap:96 foobar/90000
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=video PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 foobar/90000
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('connect with mismatched media types', { 'from-tag' => $t_a, 'to-tag' => $t_c }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=video 3934 RTP/AVP 96
a=rtpmap:96 foobar/90000
m=audio 3038 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 foobar/90000
a=sendrecv
a=rtcp:PORT
SDP






($sock_a, $sock_ax, $sock_b, $sock_bx,
$sock_c, $sock_cx, $sock_d, $sock_dx) = new_call([qw(198.51.100.35 3040)], [qw(198.51.100.35 3041)],
							[qw(198.51.100.35 3042)], [qw(198.51.100.35 3043)],
							[qw(198.51.100.35 3044)], [qw(198.51.100.35 3045)],
							[qw(198.51.100.35 3046)], [qw(198.51.100.35 3047)],
							);

($port_a, $port_ax) = offer('connect with different codecs', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3040 RTP/AVP 8
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('connect with different codecs', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3042 RTP/AVP 8
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(8, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 2000, 4000, 0x7654321, "\x00" x 160));

$t_a = ft();
$t_b = tt();

new_ft();
new_tt();

($port_c, $port_cx) = offer('connect with different codecs', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3044 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_d, $port_dx) = answer('connect with different codecs', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.35
t=0 0
m=audio 3046 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_c, $port_d, rtp(0, 3000, 5000, 0x7532346, "\x00" x 160));
rcv($sock_d, $port_c, rtpm(0, 3000, 5000, 0x7532346, "\x00" x 160));
snd($sock_d, $port_c, rtp(0, 4000, 6000, 0x5432345, "\x00" x 160));
rcv($sock_c, $port_d, rtpm(0, 4000, 6000, 0x5432345, "\x00" x 160));

snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x7654321, "\x00" x 160));

$t_c = ft();
$t_d = tt();

rtpe_req('connect', 'connect', { 'from-tag' => $t_a, 'to-tag' => $t_c });

snd($sock_c, $port_d, rtp(0, 3001, 5160, 0x7532346, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 3001, 5160, 0x7532346, "\x2a" x 160));
snd($sock_a, $port_b, rtp(8, 1002, 3320, 0x5432345, "\x00" x 160));
rcv($sock_c, $port_d, rtpm(0, 1002, 3320, 0x5432345, "\x29" x 160));






new_call;

offer('unsolicited to-tag', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('unsolicited to-tag', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 4000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

my $old_tt = tt();
new_tt;

answer('unsolicited to-tag', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 4000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

$resp = rtpe_req('query', 'unsolicited to-tag w/ via-branch', { });
Test2::Tools::Compare::like($resp, {
          'result' => 'ok',
          'last redis update' => '0',
          'SSRC' => {},
          'last signal' => qr//,
          'tags' => {
                      ft() => {
                                                              'tag' => ft(),
                                                              'subscriptions' => [
                                                                                   {
                                                                                     'type' => 'offer/answer',
                                                                                     'tag' => tt()
                                                                                   }
                                                                                 ],
                                                              'medias' => [
                                                                            {
                                                                              'index' => '1',
                                                                              'streams' => [
                                                                                             {
                                                                                               'last user packet' => qr//,
                                                                                               'egress SSRCs' => [],
                                                                                               'advertised endpoint' => {
                                                                                                                          'address' => '198.51.100.1',
                                                                                                                          'family' => 'IPv4',
                                                                                                                          'port' => '3000'
                                                                                                                        },
                                                                                               'ingress SSRCs' => [],
                                                                                               'flags' => [
                                                                                                            'RTP',
                                                                                                            'filled'
                                                                                                          ],
                                                                                               'stats_out' => {
                                                                                                                'packets' => '0',
                                                                                                                'errors' => '0',
                                                                                                                'bytes' => '0'
                                                                                                              },
                                                                                               'last kernel packet' => '0',
                                                                                               'stats' => {
                                                                                                            'packets' => '0',
                                                                                                            'errors' => '0',
                                                                                                            'bytes' => '0'
                                                                                                          },
                                                                                               'family' => 'IPv4',
                                                                                               'local address' => '203.0.113.1',
                                                                                               'local port' => qr/^\d*$/,
                                                                                               'endpoint' => {
                                                                                                               'port' => '3000',
                                                                                                               'family' => 'IPv4',
                                                                                                               'address' => '198.51.100.1'
                                                                                                             },
                                                                                               'last packet' => qr//
                                                                                             },
                                                                                             {
                                                                                               'egress SSRCs' => [],
                                                                                               'advertised endpoint' => {
                                                                                                                          'address' => '198.51.100.1',
                                                                                                                          'family' => 'IPv4',
                                                                                                                          'port' => '3001'
                                                                                                                        },
                                                                                               'ingress SSRCs' => [],
                                                                                               'flags' => [
                                                                                                            'RTCP',
                                                                                                            'filled'
                                                                                                          ],
                                                                                               'last user packet' => qr//,
                                                                                               'stats_out' => {
                                                                                                                'packets' => '0',
                                                                                                                'errors' => '0',
                                                                                                                'bytes' => '0'
                                                                                                              },
                                                                                               'last kernel packet' => '0',
                                                                                               'stats' => {
                                                                                                            'errors' => '0',
                                                                                                            'packets' => '0',
                                                                                                            'bytes' => '0'
                                                                                                          },
                                                                                               'local address' => '203.0.113.1',
                                                                                               'family' => 'IPv4',
                                                                                               'endpoint' => {
                                                                                                               'address' => '198.51.100.1',
                                                                                                               'family' => 'IPv4',
                                                                                                               'port' => '3001'
                                                                                                             },
                                                                                               'last packet' => qr//,
                                                                                               'local port' => qr/^\d*$/
                                                                                             }
                                                                                           ],
                                                                              'protocol' => 'RTP/AVP',
                                                                              'type' => 'audio',
                                                                              'flags' => [
                                                                                           'initialized',
                                                                                           'send',
                                                                                           'recv'
                                                                                         ]
                                                                            }
                                                                          ],
                                                              'VSC' => [],
                                                              'subscribers' => [
                                                                                 {
                                                                                   'tag' => tt(),
                                                                                   'type' => 'offer/answer'
                                                                                 }
                                                                               ],
                                                              'created' => qr//
                                                            },
                      tt() => {
                                                            'tag' => tt(),
                                                            'medias' => [
                                                                          {
                                                                            'streams' => [
                                                                                           {
                                                                                             'stats_out' => {
                                                                                                              'bytes' => '0',
                                                                                                              'packets' => '0',
                                                                                                              'errors' => '0'
                                                                                                            },
                                                                                             'egress SSRCs' => [],
                                                                                             'ingress SSRCs' => [],
                                                                                             'advertised endpoint' => {
                                                                                                                        'port' => '4000',
                                                                                                                        'family' => 'IPv4',
                                                                                                                        'address' => '198.51.100.1'
                                                                                                                      },
                                                                                             'flags' => [
                                                                                                          'RTP',
                                                                                                          'filled'
                                                                                                        ],
                                                                                             'last user packet' => qr//,
                                                                                             'endpoint' => {
                                                                                                             'port' => '4000',
                                                                                                             'address' => '198.51.100.1',
                                                                                                             'family' => 'IPv4'
                                                                                                           },
                                                                                             'last packet' => qr//,
                                                                                             'local port' => qr/^\d*$/,
                                                                                             'stats' => {
                                                                                                          'bytes' => '0',
                                                                                                          'packets' => '0',
                                                                                                          'errors' => '0'
                                                                                                        },
                                                                                             'last kernel packet' => '0',
                                                                                             'family' => 'IPv4',
                                                                                             'local address' => '203.0.113.1'
                                                                                           },
                                                                                           {
                                                                                             'family' => 'IPv4',
                                                                                             'local address' => '203.0.113.1',
                                                                                             'last kernel packet' => '0',
                                                                                             'stats' => {
                                                                                                          'bytes' => '0',
                                                                                                          'packets' => '0',
                                                                                                          'errors' => '0'
                                                                                                        },
                                                                                             'last packet' => qr//,
                                                                                             'endpoint' => {
                                                                                                             'port' => '4001',
                                                                                                             'family' => 'IPv4',
                                                                                                             'address' => '198.51.100.1'
                                                                                                           },
                                                                                             'local port' => qr/^\d*$/,
                                                                                             'flags' => [
                                                                                                          'RTCP',
                                                                                                          'filled'
                                                                                                        ],
                                                                                             'ingress SSRCs' => [],
                                                                                             'advertised endpoint' => {
                                                                                                                        'port' => '4001',
                                                                                                                        'address' => '198.51.100.1',
                                                                                                                        'family' => 'IPv4'
                                                                                                                      },
                                                                                             'egress SSRCs' => [],
                                                                                             'last user packet' => qr//,
                                                                                             'stats_out' => {
                                                                                                              'bytes' => '0',
                                                                                                              'packets' => '0',
                                                                                                              'errors' => '0'
                                                                                                            }
                                                                                           }
                                                                                         ],
                                                                            'protocol' => 'RTP/AVP',
                                                                            'index' => '1',
                                                                            'flags' => [
                                                                                         'initialized',
                                                                                         'send',
                                                                                         'recv',
                                                                                         'ICE controlling'
                                                                                       ],
                                                                            'type' => 'audio'
                                                                          }
                                                                        ],
                                                            'created' => qr//,
                                                            'tag-aliases' => [
                                                                           $old_tt,
                                                                         ],
                                                            'VSC' => [],
                                                            'subscriptions' => [
                                                                                 {
                                                                                   'type' => 'offer/answer',
                                                                                   'tag' => ft()
                                                                                 }
                                                                               ],
                                                            'subscribers' => [
                                                                               {
                                                                                 'tag' => ft(),
                                                                                 'type' => 'offer/answer'
                                                                               }
                                                                             ]
                                                          }
                    },
          'totals' => {
                        'RTCP' => {
                                    'errors' => '0',
                                    'packets' => '0',
                                    'bytes' => '0'
                                  },
                        'RTP' => {
                                   'bytes' => '0',
                                   'errors' => '0',
                                   'packets' => '0'
                                 }
                      },
          'created_us' => qr//,
          'created' => qr//
        }, "query result matches");



new_call;

offer('unsolicited to-tag w/ via-branch', { 'via-branch' => 'foobar' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('unsolicited to-tag w/ via-branch', { 'via-branch' => 'foobar' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 4000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

$old_tt = tt();
new_tt;

answer('unsolicited to-tag w/ via-branch', { 'via-branch' => 'foobar' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 4000 RTP/AVP 0
-----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

$resp = rtpe_req('query', 'unsolicited to-tag w/ via-branch', { });
Test2::Tools::Compare::like($resp, {
          'result' => 'ok',
          'last redis update' => '0',
          'SSRC' => {},
          'last signal' => qr//,
          'tags' => {
                      ft() => {
                                                              'tag' => ft(),
                                                              'subscriptions' => [
                                                                                   {
                                                                                     'type' => 'offer/answer',
                                                                                     'tag' => tt()
                                                                                   }
                                                                                 ],
                                                              'medias' => [
                                                                            {
                                                                              'index' => '1',
                                                                              'streams' => [
                                                                                             {
                                                                                               'last user packet' => qr//,
                                                                                               'egress SSRCs' => [],
                                                                                               'advertised endpoint' => {
                                                                                                                          'address' => '198.51.100.1',
                                                                                                                          'family' => 'IPv4',
                                                                                                                          'port' => '3000'
                                                                                                                        },
                                                                                               'ingress SSRCs' => [],
                                                                                               'flags' => [
                                                                                                            'RTP',
                                                                                                            'filled'
                                                                                                          ],
                                                                                               'stats_out' => {
                                                                                                                'packets' => '0',
                                                                                                                'errors' => '0',
                                                                                                                'bytes' => '0'
                                                                                                              },
                                                                                               'last kernel packet' => '0',
                                                                                               'stats' => {
                                                                                                            'packets' => '0',
                                                                                                            'errors' => '0',
                                                                                                            'bytes' => '0'
                                                                                                          },
                                                                                               'family' => 'IPv4',
                                                                                               'local address' => '203.0.113.1',
                                                                                               'local port' => qr/^\d*$/,
                                                                                               'endpoint' => {
                                                                                                               'port' => '3000',
                                                                                                               'family' => 'IPv4',
                                                                                                               'address' => '198.51.100.1'
                                                                                                             },
                                                                                               'last packet' => qr//
                                                                                             },
                                                                                             {
                                                                                               'egress SSRCs' => [],
                                                                                               'advertised endpoint' => {
                                                                                                                          'address' => '198.51.100.1',
                                                                                                                          'family' => 'IPv4',
                                                                                                                          'port' => '3001'
                                                                                                                        },
                                                                                               'ingress SSRCs' => [],
                                                                                               'flags' => [
                                                                                                            'RTCP',
                                                                                                            'filled'
                                                                                                          ],
                                                                                               'last user packet' => qr//,
                                                                                               'stats_out' => {
                                                                                                                'packets' => '0',
                                                                                                                'errors' => '0',
                                                                                                                'bytes' => '0'
                                                                                                              },
                                                                                               'last kernel packet' => '0',
                                                                                               'stats' => {
                                                                                                            'errors' => '0',
                                                                                                            'packets' => '0',
                                                                                                            'bytes' => '0'
                                                                                                          },
                                                                                               'local address' => '203.0.113.1',
                                                                                               'family' => 'IPv4',
                                                                                               'endpoint' => {
                                                                                                               'address' => '198.51.100.1',
                                                                                                               'family' => 'IPv4',
                                                                                                               'port' => '3001'
                                                                                                             },
                                                                                               'last packet' => qr//,
                                                                                               'local port' => qr/^\d*$/
                                                                                             }
                                                                                           ],
                                                                              'protocol' => 'RTP/AVP',
                                                                              'type' => 'audio',
                                                                              'flags' => [
                                                                                           'initialized',
                                                                                           'send',
                                                                                           'recv'
                                                                                         ]
                                                                            }
                                                                          ],
                                                              'VSC' => [],
                                                              'subscribers' => [
                                                                                 {
                                                                                   'tag' => tt(),
                                                                                   'type' => 'offer/answer'
                                                                                 }
                                                                               ],
                                                              'created' => qr//
                                                            },
                      tt() => {
                                                            'tag' => tt(),
                                                            'medias' => [
                                                                          {
                                                                            'streams' => [
                                                                                           {
                                                                                             'stats_out' => {
                                                                                                              'bytes' => '0',
                                                                                                              'packets' => '0',
                                                                                                              'errors' => '0'
                                                                                                            },
                                                                                             'egress SSRCs' => [],
                                                                                             'ingress SSRCs' => [],
                                                                                             'advertised endpoint' => {
                                                                                                                        'port' => '4000',
                                                                                                                        'family' => 'IPv4',
                                                                                                                        'address' => '198.51.100.1'
                                                                                                                      },
                                                                                             'flags' => [
                                                                                                          'RTP',
                                                                                                          'filled'
                                                                                                        ],
                                                                                             'last user packet' => qr//,
                                                                                             'endpoint' => {
                                                                                                             'port' => '4000',
                                                                                                             'address' => '198.51.100.1',
                                                                                                             'family' => 'IPv4'
                                                                                                           },
                                                                                             'last packet' => qr//,
                                                                                             'local port' => qr/^\d*$/,
                                                                                             'stats' => {
                                                                                                          'bytes' => '0',
                                                                                                          'packets' => '0',
                                                                                                          'errors' => '0'
                                                                                                        },
                                                                                             'last kernel packet' => '0',
                                                                                             'family' => 'IPv4',
                                                                                             'local address' => '203.0.113.1'
                                                                                           },
                                                                                           {
                                                                                             'family' => 'IPv4',
                                                                                             'local address' => '203.0.113.1',
                                                                                             'last kernel packet' => '0',
                                                                                             'stats' => {
                                                                                                          'bytes' => '0',
                                                                                                          'packets' => '0',
                                                                                                          'errors' => '0'
                                                                                                        },
                                                                                             'last packet' => qr//,
                                                                                             'endpoint' => {
                                                                                                             'port' => '4001',
                                                                                                             'family' => 'IPv4',
                                                                                                             'address' => '198.51.100.1'
                                                                                                           },
                                                                                             'local port' => qr/^\d*$/,
                                                                                             'flags' => [
                                                                                                          'RTCP',
                                                                                                          'filled'
                                                                                                        ],
                                                                                             'ingress SSRCs' => [],
                                                                                             'advertised endpoint' => {
                                                                                                                        'port' => '4001',
                                                                                                                        'address' => '198.51.100.1',
                                                                                                                        'family' => 'IPv4'
                                                                                                                      },
                                                                                             'egress SSRCs' => [],
                                                                                             'last user packet' => qr//,
                                                                                             'stats_out' => {
                                                                                                              'bytes' => '0',
                                                                                                              'packets' => '0',
                                                                                                              'errors' => '0'
                                                                                                            }
                                                                                           }
                                                                                         ],
                                                                            'protocol' => 'RTP/AVP',
                                                                            'index' => '1',
                                                                            'flags' => [
                                                                                         'initialized',
                                                                                         'send',
                                                                                         'recv',
                                                                                         'ICE controlling'
                                                                                       ],
                                                                            'type' => 'audio'
                                                                          }
                                                                        ],
                                                            'created' => qr//,
                                                            'tag-aliases' => [
                                                                           $old_tt,
                                                                         ],
                                                            'VSC' => [],
                                                            'subscriptions' => [
                                                                                 {
                                                                                   'type' => 'offer/answer',
                                                                                   'tag' => ft()
                                                                                 }
                                                                               ],
                                                            'subscribers' => [
                                                                               {
                                                                                 'tag' => ft(),
                                                                                 'type' => 'offer/answer'
                                                                               }
                                                                             ]
                                                          }
                    },
          'totals' => {
                        'RTCP' => {
                                    'errors' => '0',
                                    'packets' => '0',
                                    'bytes' => '0'
                                  },
                        'RTP' => {
                                   'bytes' => '0',
                                   'errors' => '0',
                                   'packets' => '0'
                                 }
                      },
          'created_us' => qr//,
          'created' => qr//
        }, "query result matches");



if ($ENV{RTPENGINE_MOS_TESTS}) {

($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3000)], [qw(198.51.100.23 3001)],
							[qw(198.51.100.23 3002)], [qw(198.51.100.23 3003)]);

($port_a, $port_ax) = offer('MOS basic', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('MOS basic', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3002 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


# populate known payload type
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x7654321, "\x00" x 160));

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100001,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	0 << 24      # fraction lost
	| 0,         # number of packets lost
	2000,        # extended highest sequence number received
	0,           # jitter
	0x00000000,  # last SR
	0 / 65536,   # delay since last SR
));

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100004,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	0 << 24      # fraction lost
	| 0,         # number of packets lost
	1010,        # extended highest sequence number received
	0,           # jitter
	0x00010020,  # last SR
	3 * 65536,   # delay since last SR
));
# no MOS calculated here as we don't have an opposite side RTT yet ^

Time::HiRes::usleep(2 * 1000000);

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100006,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	0 << 24      # fraction lost
	| 0,         # number of packets lost
	2020,        # extended highest sequence number received
	0,           # jitter
	0x00040020,  # last SR
	2 * 65536,   # delay since last SR
));
# CQ MOS for 0x1234567 calculated here ^

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100007,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	0 << 24      # fraction lost
	| 0,         # number of packets lost
	1030,        # extended highest sequence number received
	0,           # jitter
	0x00060020,  # last SR
	3 * 65536,   # delay since last SR
));
# CQ MOS for 0x7654321 calculated here ^

$resp = rtpe_req('delete', 'MOS basic', { });


my $processing_us = 10000; # allow for 10 ms processing time


is $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, 1, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, 43, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, 0, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '<', $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '<', $processing_us, 'metric matches';

is $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, 1, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, 43, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, 0, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '<', $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '<', $processing_us, 'metric matches';





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3004)], [qw(198.51.100.23 3005)],
							[qw(198.51.100.23 3006)], [qw(198.51.100.23 3007)]);

($port_a, $port_ax) = offer('MOS degraded', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3004 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('MOS degraded', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3006 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


# populate known payload type
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x7654321, "\x00" x 160));

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100001,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	2000,        # extended highest sequence number received
	15 * 8000 / 1000, # jitter
	0x00000000,  # last SR
	0 / 65536,   # delay since last SR
));

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100004,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	1010,        # extended highest sequence number received
	15 * 8000 / 1000, # jitter
	0x00010020,  # last SR
	2.88 * 65536,# delay since last SR
));
# no MOS calculated here as we don't have an opposite side RTT yet ^

Time::HiRes::usleep(2 * 1000000);

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100006,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	2020,        # extended highest sequence number received
	15 * 8000 / 1000, # jitter
	0x00040020,  # last SR
	1.87 * 65536,#delay since last SR
));
# CQ MOS for 0x1234567 calculated here ^

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100007,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	1030,        # extended highest sequence number received
	15 * 8000 / 1000, # jitter
	0x00060020,  # last SR
	2.88 * 65536,# delay since last SR
));
# CQ MOS for 0x7654321 calculated here ^

$resp = rtpe_req('delete', 'MOS degraded', { });

is $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, '>=', 35, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, '<=', 36, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, 15, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, 3, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '>=', 250000, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '<', 250000 + $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '>=', 130000, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '<', 130000 + $processing_us, 'metric matches';

is $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, '>=', 35, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, '<=', 36, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, 15, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, 3, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '>=', 250000, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '<', 250000 + $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '>=', 120000, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '<', 120000 + $processing_us, 'metric matches';




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3008)], [qw(198.51.100.23 3009)],
							[qw(198.51.100.23 3010)], [qw(198.51.100.23 3011)]);

($port_a, $port_ax) = offer('MOS very degraded', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3008 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('MOS very degraded', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3010 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


# populate known payload type
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x7654321, "\x00" x 160));

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100001,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	2000,        # extended highest sequence number received
	20 * 8000 / 1000, # jitter
	0x00000000,  # last SR
	0 / 65536,   # delay since last SR
));

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100004,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	(0.06*256) << 24 # fraction lost
	| 0,         # number of packets lost
	1010,        # extended highest sequence number received
	20 * 8000 / 1000, # jitter
	0x00010020,  # last SR
	2.80 * 65536,# delay since last SR
));
# no MOS calculated here as we don't have an opposite side RTT yet ^

Time::HiRes::usleep(2 * 1000000);

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100006,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	(0.06*256) << 24 # fraction lost
	| 0,         # number of packets lost
	2020,        # extended highest sequence number received
	20 * 8000 / 1000, # jitter
	0x00040020,  # last SR
	1.80 * 65536,#delay since last SR
));
# CQ MOS for 0x1234567 calculated here ^

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100007,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	(0.06*256) << 24 # fraction lost
	| 0,         # number of packets lost
	1030,        # extended highest sequence number received
	20 * 8000 / 1000, # jitter
	0x00060020,  # last SR
	2.80 * 65536,# delay since last SR
));
# CQ MOS for 0x7654321 calculated here ^

$resp = rtpe_req('delete', 'MOS very degraded', { });

is $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, 1, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, 29, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, 20, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, 5, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '>=', 400000, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '<', 400000 + $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '>=', 200000, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '<', 200000 + $processing_us, 'metric matches';

is $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, 1, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, 29, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, 20, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, 5, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '>=', 400000, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '<', 400000 + $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '>=', 200000, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '<', 200000 + $processing_us, 'metric matches';





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3016)], [qw(198.51.100.23 3017)],
							[qw(198.51.100.23 3018)], [qw(198.51.100.23 3019)]);

($port_a, $port_ax) = offer('Opus MOS basic', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3016 RTP/AVP 96
a=rtpmap:96 opus/48000/2
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('Opus MOS basic', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3018 RTP/AVP 96
a=rtpmap:96 opus/48000/2
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=sendrecv
a=rtcp:PORT
SDP


# populate known payload type
snd($sock_a, $port_b, rtp(96, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(96, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 2000, 4000, 0x7654321, "\x00" x 160));

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100001,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	0 << 24      # fraction lost
	| 0,         # number of packets lost
	2000,        # extended highest sequence number received
	0,           # jitter
	0x00000000,  # last SR
	0 / 65536,   # delay since last SR
));

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100004,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	0 << 24      # fraction lost
	| 0,         # number of packets lost
	1010,        # extended highest sequence number received
	0,           # jitter
	0x00010020,  # last SR
	3 * 65536,   # delay since last SR
));
# no MOS calculated here as we don't have an opposite side RTT yet ^

Time::HiRes::usleep(2 * 1000000);

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100006,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	0 << 24      # fraction lost
	| 0,         # number of packets lost
	2020,        # extended highest sequence number received
	0,           # jitter
	0x00040020,  # last SR
	2 * 65536,   # delay since last SR
));
# CQ MOS for 0x1234567 calculated here ^

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100007,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	0 << 24      # fraction lost
	| 0,         # number of packets lost
	1030,        # extended highest sequence number received
	0,           # jitter
	0x00060020,  # last SR
	3 * 65536,   # delay since last SR
));
# CQ MOS for 0x7654321 calculated here ^

$resp = rtpe_req('delete', 'Opus MOS basic', { });

is $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, 1, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, 43, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, 0, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '<', $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '<', $processing_us, 'metric matches';

is $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, 1, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, 43, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, 0, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '<', $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '<', $processing_us, 'metric matches';





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3020)], [qw(198.51.100.23 3021)],
							[qw(198.51.100.23 3022)], [qw(198.51.100.23 3023)]);

($port_a, $port_ax) = offer('Opus MOS degraded', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3020 RTP/AVP 96
a=rtpmap:96 opus/48000/2
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('Opus MOS degraded', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3022 RTP/AVP 96
a=rtpmap:96 opus/48000/2
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=sendrecv
a=rtcp:PORT
SDP


# populate known payload type
snd($sock_a, $port_b, rtp(96, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(96, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 2000, 4000, 0x7654321, "\x00" x 160));

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100001,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	2000,        # extended highest sequence number received
	15 * 48000 / 1000, # jitter
	0x00000000,  # last SR
	0 / 65536,   # delay since last SR
));

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100004,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	1010,        # extended highest sequence number received
	15 * 48000 / 1000, # jitter
	0x00010020,  # last SR
	2.88 * 65536,# delay since last SR
));
# no MOS calculated here as we don't have an opposite side RTT yet ^

Time::HiRes::usleep(2 * 1000000);

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100006,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	2020,        # extended highest sequence number received
	15 * 48000 / 1000, # jitter
	0x00040020,  # last SR
	1.87 * 65536,#delay since last SR
));
# CQ MOS for 0x1234567 calculated here ^

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100007,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	1030,        # extended highest sequence number received
	15 * 48000 / 1000, # jitter
	0x00060020,  # last SR
	2.88 * 65536,# delay since last SR
));
# CQ MOS for 0x7654321 calculated here ^

$resp = rtpe_req('delete', 'Opus MOS degraded', { });

is $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, 1, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, 36, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, 15, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, 3, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '>=', 250000, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '<', 250000 + $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '>=', 130000, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '<', 130000 + $processing_us, 'metric matches';

is $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, 1, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, 36, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, 15, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, 3, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '>=', 250000, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '<', 250000 + $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '>=', 120000, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '<', 120000 + $processing_us, 'metric matches';




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3024)], [qw(198.51.100.23 3025)],
							[qw(198.51.100.23 3026)], [qw(198.51.100.23 3027)]);

($port_a, $port_ax) = offer('Opus MOS very degraded', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3024 RTP/AVP 96
a=rtpmap:96 opus/48000/2
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('Opus MOS very degraded', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3026 RTP/AVP 96
a=rtpmap:96 opus/48000/2
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=sendrecv
a=rtcp:PORT
SDP


# populate known payload type
snd($sock_a, $port_b, rtp(96, 1000, 3000, 0x1234567, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1000, 3000, 0x1234567, "\x00" x 160));
snd($sock_b, $port_a, rtp(96, 2000, 4000, 0x7654321, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 2000, 4000, 0x7654321, "\x00" x 160));

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100001,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	(0.04*256) << 24 # fraction lost
	| 0,         # number of packets lost
	2000,        # extended highest sequence number received
	20 * 48000 / 1000, # jitter
	0x00000000,  # last SR
	0 / 65536,   # delay since last SR
));

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100004,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	(0.06*256) << 24 # fraction lost
	| 0,         # number of packets lost
	1010,        # extended highest sequence number received
	20 * 48000 / 1000, # jitter
	0x00010020,  # last SR
	2.80 * 65536,# delay since last SR
));
# no MOS calculated here as we don't have an opposite side RTT yet ^

Time::HiRes::usleep(2 * 1000000);

snd($sock_ax, $port_bx, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x1234567,   # sender SSRC
	0x00100006,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x7654321,   # received SSRC
	(0.06*256) << 24 # fraction lost
	| 0,         # number of packets lost
	2020,        # extended highest sequence number received
	20 * 48000 / 1000, # jitter
	0x00040020,  # last SR
	1.80 * 65536,#delay since last SR
));
# CQ MOS for 0x1234567 calculated here ^

Time::HiRes::usleep(3 * 1000000);

snd($sock_bx, $port_ax, pack("CC n N NN N N N  N N N N N N",
	0x81,        # version, one reception report
	200,         # sender report
	52 / 4 - 1,  # length
	0x7654321,   # sender SSRC
	0x00100007,  # NTP MSB
	0x00200000,  # NTP LSB
	4000,        # RTP TS
	100,         # sender packet count
	16000,       # sender octet count

	0x1234567,   # received SSRC
	(0.06*256) << 24 # fraction lost
	| 0,         # number of packets lost
	1030,        # extended highest sequence number received
	20 * 48000 / 1000, # jitter
	0x00060020,  # last SR
	2.80 * 65536,# delay since last SR
));
# CQ MOS for 0x7654321 calculated here ^

$resp = rtpe_req('delete', 'Opus MOS very degraded', { });

is $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, 1, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, 29, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, 20, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, 5, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '>=', 400000, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time'}, '<', 400000 + $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '>=', 200000, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'round-trip time leg'}, '<', 200000 + $processing_us, 'metric matches';

is $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, 1, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, 29, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, 20, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, 5, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '>=', 400000, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time'}, '<', 400000 + $processing_us * 2, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '>=', 200000, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'round-trip time leg'}, '<', 200000 + $processing_us, 'metric matches';


}





new_call;

offer('a=mid mixup', { 'address family' => 'IP6' }, <<SDP);
v=0
o=CiscoSystemsCCM-SIP 133090092 1 IN IP4 22.22.220.163
s=SIP Call
c=IN IP4 33.33.41.40
b=TIAS:5952000
b=AS:5952
t=0 0
a=cisco-mari-rate
a=cisco-mari:v1
m=audio 18860 RTP/AVP 108 114 9 104 105 0 8 18 123 101
b=TIAS:64000
a=extmap:4 http://protocols.cisco.com/timestamp#100us
a=rtpmap:108 MP4A-LATM/90000
a=fmtp:108 bitrate=64000;profile-level-id=24;object=23
a=rtpmap:114 opus/48000/2
a=fmtp:114  maxaveragebitrate=128000;stereo=1
a=rtpmap:9 G722/8000
a=rtpmap:104 G7221/16000
a=fmtp:104 bitrate=32000
a=rtpmap:105 G7221/16000
a=fmtp:105 bitrate=24000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:123 X-ULPFECUC/8000
a=fmtp:123  multi_ssrc=1;feedback=0;max_esel=1450;m=8;max_n=42;FEC_ORDER=FEC_SRTP;non_seq=1
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=mid:1
a=trafficclass:conversational.audio.immersive.aq:admitted
m=video 19952 RTP/AVP 99 97 126 123
b=TIAS:5952000
a=label:11
a=answer:full
a=extmap:4 http://protocols.cisco.com/timestamp#100us
a=rtcp-fb:* ccm pan
a=cisco-mari-psre:97 ltrf=3
a=cisco-mari-psre:126 ltrf=3
a=rtpmap:99 H265/90000
a=fmtp:99  level-id=90;max-lsr=125337600;max-lps=2088960;max-tr=22;max-tc=20;max-fps=6000;x-cisco-hevc=529
a=rtpmap:97 H264/90000
a=fmtp:97 profile-level-id=428016;packetization-mode=0;max-mbps=490000;max-fs=8160;max-cpb=200;max-dpb=16320;max-br=5000;max-smbps=490000;max-fps=6000
a=rtpmap:126 H264/90000
a=fmtp:126 profile-level-id=428016;packetization-mode=1;max-mbps=490000;max-fs=8160;max-cpb=200;max-dpb=16320;max-br=5000;max-smbps=490000;max-fps=6000
a=rtpmap:123 X-ULPFECUC/90000
a=fmtp:123  multi_ssrc=1;feedback=0;max_esel=1450;m=8;max_n=42;FEC_ORDER=FEC_SRTP;non_seq=1
a=content:main
a=mid:2
a=rtcp-fb:* nack pli
a=rtcp-fb:* ccm fir
a=rtcp-fb:* ccm tmmbr
a=trafficclass:conversational.video.immersive.aq:admitted
m=application 27814 RTP/AVP 100
a=rtpmap:100 H224/4800
a=mid:5
-----------------------------------
v=0
o=CiscoSystemsCCM-SIP 133090092 1 IN IP4 22.22.220.163
s=SIP Call
b=AS:5952
b=TIAS:5952000
t=0 0
a=cisco-mari-rate
a=cisco-mari:v1
m=audio PORT RTP/AVP 108 114 9 104 105 0 8 18 123 101
c=IN IP6 2001:db8:4321::1
b=TIAS:64000
a=mid:1
a=rtpmap:108 MP4A-LATM/90000
a=fmtp:108 bitrate=64000;profile-level-id=24;object=23
a=rtpmap:114 opus/48000/2
a=fmtp:114 stereo=1; maxaveragebitrate=128000
a=rtpmap:9 G722/8000
a=rtpmap:104 G7221/16000
a=fmtp:104 bitrate=32000
a=rtpmap:105 G7221/16000
a=fmtp:105 bitrate=24000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:123 X-ULPFECUC/8000
a=fmtp:123  multi_ssrc=1;feedback=0;max_esel=1450;m=8;max_n=42;FEC_ORDER=FEC_SRTP;non_seq=1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=extmap:4 http://protocols.cisco.com/timestamp#100us
a=trafficclass:conversational.audio.immersive.aq:admitted
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 99 97 126 123
c=IN IP6 2001:db8:4321::1
b=TIAS:5952000
a=mid:2
a=rtpmap:99 H265/90000
a=fmtp:99  level-id=90;max-lsr=125337600;max-lps=2088960;max-tr=22;max-tc=20;max-fps=6000;x-cisco-hevc=529
a=rtpmap:97 H264/90000
a=fmtp:97 profile-level-id=428016;packetization-mode=0;max-mbps=490000;max-fs=8160;max-cpb=200;max-dpb=16320;max-br=5000;max-smbps=490000;max-fps=6000
a=rtpmap:126 H264/90000
a=fmtp:126 profile-level-id=428016;packetization-mode=1;max-mbps=490000;max-fs=8160;max-cpb=200;max-dpb=16320;max-br=5000;max-smbps=490000;max-fps=6000
a=rtpmap:123 X-ULPFECUC/90000
a=fmtp:123  multi_ssrc=1;feedback=0;max_esel=1450;m=8;max_n=42;FEC_ORDER=FEC_SRTP;non_seq=1
a=rtcp-fb:* ccm pan
a=rtcp-fb:* nack pli
a=rtcp-fb:* ccm fir
a=rtcp-fb:* ccm tmmbr
a=label:11
a=answer:full
a=extmap:4 http://protocols.cisco.com/timestamp#100us
a=cisco-mari-psre:97 ltrf=3
a=cisco-mari-psre:126 ltrf=3
a=content:main
a=trafficclass:conversational.video.immersive.aq:admitted
a=sendrecv
a=rtcp:PORT
m=application PORT RTP/AVP 100
c=IN IP6 2001:db8:4321::1
a=mid:5
a=rtpmap:100 H224/4800
a=sendrecv
a=rtcp:PORT
SDP

answer('a=mid mixup', { }, <<SDP);
v=0
o=- 6072555788964436425 2 IN IP4 127.0.0.1
s=-
t=0 0
a=msid-semantic:  WMS
m=audio 62445 RTP/AVP 114 9 0 8 101
c=IN IP6 3333:3333:3333:99d:0:4daf:a7d2:0
b=AS:64
a=rtpmap:114 opus/48000/2
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:114 minptime=10;useinbandfec=1
a=rtcp:9 IN IP4 0.0.0.0
a=setup:active
a=mid:1
a=msid:- e8befb98-6b80-4c4e-b525-bb28b0d1d43a
a=sendrecv
a=ssrc:3018685568 cname:Kk01/qU0PWi9Cacd
a=rtcp-mux
m=video 45817 RTP/AVP 97 126
c=IN IP6 3333:3333:3333:99d:0:4daf:a7d2:0
b=AS:2496
a=rtpmap:97 H264/90000
a=rtpmap:126 H264/90000
a=fmtp:97 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
a=fmtp:126 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f
a=rtcp:9 IN IP4 0.0.0.0
a=rtcp-fb:97 ccm fir
a=rtcp-fb:97 nack pli
a=rtcp-fb:126 ccm fir
a=rtcp-fb:126 nack pli
a=setup:active
a=mid:2
a=msid:- bfc26333-b744-4775-aebf-d43a42ffa1cb
a=sendrecv
a=ssrc:1948313614 cname:Kk01/qU0PWi9Cacd
a=rtcp-mux
a=content:main
m=application 0 RTP/SAVP 0
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=extmap-allow-mixed
a=setup:active
a=mid:5
a=sendrecv
a=ice-ufrag:UXPd
a=ice-pwd:02K77oy8PHQ2tmz6RjF4gyWB
a=fingerprint:sha-256 44:5F:4A:32:D6:AF:7A:BA:74:7C:DD:8B:07:5C:E3:75:46:9F:53:55:2B:46:AC:B9:C1:03:78:82:F3:29:EA:42
a=ice-options:trickle
-------------------------------------------
v=0
o=- 6072555788964436425 2 IN IP4 127.0.0.1
s=-
t=0 0
a=msid-semantic:  WMS
m=audio PORT RTP/AVP 114 9 0 8 101
c=IN IP4 203.0.113.1
b=AS:64
a=mid:1
a=rtpmap:114 opus/48000/2
a=fmtp:114 useinbandfec=1; minptime=10
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=msid:- e8befb98-6b80-4c4e-b525-bb28b0d1d43a
a=ssrc:3018685568 cname:Kk01/qU0PWi9Cacd
a=sendrecv
a=rtcp:PORT
m=video PORT RTP/AVP 97 126
c=IN IP4 203.0.113.1
b=AS:2496
a=mid:2
a=rtpmap:97 H264/90000
a=fmtp:97 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
a=rtcp-fb:97 ccm fir
a=rtcp-fb:97 nack pli
a=rtpmap:126 H264/90000
a=fmtp:126 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f
a=rtcp-fb:126 ccm fir
a=rtcp-fb:126 nack pli
a=msid:- bfc26333-b744-4775-aebf-d43a42ffa1cb
a=ssrc:1948313614 cname:Kk01/qU0PWi9Cacd
a=content:main
a=sendrecv
a=rtcp:PORT
m=application 0 RTP/AVP 0
c=IN IP4 0.0.0.0
a=mid:5
SDP

reverse_tags;

offer('a=mid mixup', { }, <<SDP);
v=0
o=- 6072555788964436425 3 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic:  WMS
a=group:BUNDLE 1 2
m=audio 62445 RTP/AVP 114 9 0 8 101 63 13 110
c=IN IP6 3333:3333:3333:99d:0:4daf:a7d2:0
b=AS:64
a=rtpmap:114 opus/48000/2
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=rtpmap:63 red/48000/2
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=fmtp:114 minptime=10;useinbandfec=1
a=fmtp:63 114/114
a=rtcp:9 IN IP4 0.0.0.0
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid
a=setup:actpass
a=mid:1
a=msid:- e8befb98-6b80-4c4e-b525-bb28b0d1d43a
a=sendrecv
a=ssrc:3018685568 cname:Kk01/qU0PWi9Cacd
a=ssrc:3018685568 msid:- e8befb98-6b80-4c4e-b525-bb28b0d1d43a
a=rtcp-mux
m=video 45817 RTP/AVP 97 126 96 124 103 105 106 107 108 109 127 111 39 40 45 46 98 99 100 123 112 113 125
c=IN IP6 3333:3333:3333:99d:0:4daf:a7d2:0
b=AS:2496
a=rtpmap:97 H264/90000
a=rtpmap:126 H264/90000
a=rtpmap:96 VP8/90000
a=rtpmap:124 rtx/90000
a=rtpmap:103 rtx/90000
a=rtpmap:105 rtx/90000
a=rtpmap:106 H264/90000
a=rtpmap:107 rtx/90000
a=rtpmap:108 H264/90000
a=rtpmap:109 rtx/90000
a=rtpmap:127 H264/90000
a=rtpmap:111 rtx/90000
a=rtpmap:39 H264/90000
a=rtpmap:40 rtx/90000
a=rtpmap:45 AV1/90000
a=rtpmap:46 rtx/90000
a=rtpmap:98 VP9/90000
a=rtpmap:99 rtx/90000
a=rtpmap:100 VP9/90000
a=rtpmap:123 rtx/90000
a=rtpmap:112 red/90000
a=rtpmap:113 rtx/90000
a=rtpmap:125 ulpfec/90000
a=fmtp:97 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
a=fmtp:126 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f
a=fmtp:124 apt=96
a=fmtp:103 apt=126
a=fmtp:105 apt=97
a=fmtp:106 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f
a=fmtp:107 apt=106
a=fmtp:108 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
a=fmtp:109 apt=108
a=fmtp:127 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f
a=fmtp:111 apt=127
a=fmtp:39 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
a=fmtp:40 apt=39
a=fmtp:45 level-idx=5;profile=0;tier=0
a=fmtp:46 apt=45
a=fmtp:98 profile-id=0
a=fmtp:99 apt=98
a=fmtp:100 profile-id=2
a=fmtp:123 apt=100
a=fmtp:113 apt=112
a=rtcp:9 IN IP4 0.0.0.0
a=rtcp-fb:97 ccm fir
a=rtcp-fb:97 nack pli
a=rtcp-fb:126 ccm fir
a=rtcp-fb:126 nack pli
a=rtcp-fb:96 goog-remb
a=rtcp-fb:96 transport-cc
a=rtcp-fb:96 ccm fir
a=rtcp-fb:96 nack
a=rtcp-fb:96 nack pli
a=rtcp-fb:106 goog-remb
a=rtcp-fb:106 transport-cc
a=rtcp-fb:106 ccm fir
a=rtcp-fb:106 nack
a=rtcp-fb:106 nack pli
a=rtcp-fb:108 goog-remb
a=rtcp-fb:108 transport-cc
a=rtcp-fb:108 ccm fir
a=rtcp-fb:108 nack
a=rtcp-fb:108 nack pli
a=rtcp-fb:127 goog-remb
a=rtcp-fb:127 transport-cc
a=rtcp-fb:127 ccm fir
a=rtcp-fb:127 nack
a=rtcp-fb:127 nack pli
a=rtcp-fb:39 goog-remb
a=rtcp-fb:39 transport-cc
a=rtcp-fb:39 ccm fir
a=rtcp-fb:39 nack
a=rtcp-fb:39 nack pli
a=rtcp-fb:45 goog-remb
a=rtcp-fb:45 transport-cc
a=rtcp-fb:45 ccm fir
a=rtcp-fb:45 nack
a=rtcp-fb:45 nack pli
a=rtcp-fb:98 goog-remb
a=rtcp-fb:98 transport-cc
a=rtcp-fb:98 ccm fir
a=rtcp-fb:98 nack
a=rtcp-fb:98 nack pli
a=rtcp-fb:100 goog-remb
a=rtcp-fb:100 transport-cc
a=rtcp-fb:100 ccm fir
a=rtcp-fb:100 nack
a=rtcp-fb:100 nack pli
a=extmap:14 urn:ietf:params:rtp-hdrext:toffset
a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:13 urn:3gpp:video-orientation
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay
a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type
a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing
a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:11 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=setup:actpass
a=mid:2
a=msid:- bfc26333-b744-4775-aebf-d43a42ffa1cb
a=sendrecv
a=ssrc:1948313614 cname:Kk01/qU0PWi9Cacd
a=ssrc:1948313614 msid:- bfc26333-b744-4775-aebf-d43a42ffa1cb
a=rtcp-mux
a=rtcp-rsize
a=content:main
m=application 0 RTP/SAVP 0
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=setup:actpass
a=mid:5
a=sendrecv
------------------------------------------
v=0
o=- 6072555788964436425 3 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic:  WMS
m=audio PORT RTP/AVP 114 9 0 8 101 63 13 110
c=IN IP4 203.0.113.1
b=AS:64
a=mid:1
a=rtpmap:114 opus/48000/2
a=fmtp:114 useinbandfec=1; minptime=10
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=rtpmap:63 red/48000/2
a=fmtp:63 114/114
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid
a=msid:- e8befb98-6b80-4c4e-b525-bb28b0d1d43a
a=ssrc:3018685568 cname:Kk01/qU0PWi9Cacd
a=ssrc:3018685568 msid:- e8befb98-6b80-4c4e-b525-bb28b0d1d43a
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
m=video PORT RTP/AVP 97 126 96 124 103 105 106 107 108 109 127 111 39 40 45 46 98 99 100 123 112 113 125
c=IN IP4 203.0.113.1
b=AS:2496
a=mid:2
a=rtpmap:97 H264/90000
a=fmtp:97 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
a=rtcp-fb:97 ccm fir
a=rtcp-fb:97 nack pli
a=rtpmap:126 H264/90000
a=fmtp:126 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f
a=rtcp-fb:126 ccm fir
a=rtcp-fb:126 nack pli
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 goog-remb
a=rtcp-fb:96 transport-cc
a=rtcp-fb:96 ccm fir
a=rtcp-fb:96 nack
a=rtcp-fb:96 nack pli
a=rtpmap:124 rtx/90000
a=fmtp:124 apt=96
a=rtpmap:103 rtx/90000
a=fmtp:103 apt=126
a=rtpmap:105 rtx/90000
a=fmtp:105 apt=97
a=rtpmap:106 H264/90000
a=fmtp:106 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f
a=rtcp-fb:106 goog-remb
a=rtcp-fb:106 transport-cc
a=rtcp-fb:106 ccm fir
a=rtcp-fb:106 nack
a=rtcp-fb:106 nack pli
a=rtpmap:107 rtx/90000
a=fmtp:107 apt=106
a=rtpmap:108 H264/90000
a=fmtp:108 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
a=rtcp-fb:108 goog-remb
a=rtcp-fb:108 transport-cc
a=rtcp-fb:108 ccm fir
a=rtcp-fb:108 nack
a=rtcp-fb:108 nack pli
a=rtpmap:109 rtx/90000
a=fmtp:109 apt=108
a=rtpmap:127 H264/90000
a=fmtp:127 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f
a=rtcp-fb:127 goog-remb
a=rtcp-fb:127 transport-cc
a=rtcp-fb:127 ccm fir
a=rtcp-fb:127 nack
a=rtcp-fb:127 nack pli
a=rtpmap:111 rtx/90000
a=fmtp:111 apt=127
a=rtpmap:39 H264/90000
a=fmtp:39 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
a=rtcp-fb:39 goog-remb
a=rtcp-fb:39 transport-cc
a=rtcp-fb:39 ccm fir
a=rtcp-fb:39 nack
a=rtcp-fb:39 nack pli
a=rtpmap:40 rtx/90000
a=fmtp:40 apt=39
a=rtpmap:45 AV1/90000
a=fmtp:45 level-idx=5;profile=0;tier=0
a=rtcp-fb:45 goog-remb
a=rtcp-fb:45 transport-cc
a=rtcp-fb:45 ccm fir
a=rtcp-fb:45 nack
a=rtcp-fb:45 nack pli
a=rtpmap:46 rtx/90000
a=fmtp:46 apt=45
a=rtpmap:98 VP9/90000
a=fmtp:98 profile-id=0
a=rtcp-fb:98 goog-remb
a=rtcp-fb:98 transport-cc
a=rtcp-fb:98 ccm fir
a=rtcp-fb:98 nack
a=rtcp-fb:98 nack pli
a=rtpmap:99 rtx/90000
a=fmtp:99 apt=98
a=rtpmap:100 VP9/90000
a=fmtp:100 profile-id=2
a=rtcp-fb:100 goog-remb
a=rtcp-fb:100 transport-cc
a=rtcp-fb:100 ccm fir
a=rtcp-fb:100 nack
a=rtcp-fb:100 nack pli
a=rtpmap:123 rtx/90000
a=fmtp:123 apt=100
a=rtpmap:112 red/90000
a=rtpmap:113 rtx/90000
a=fmtp:113 apt=112
a=rtpmap:125 ulpfec/90000
a=extmap:14 urn:ietf:params:rtp-hdrext:toffset
a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:13 urn:3gpp:video-orientation
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay
a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type
a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing
a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:11 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=msid:- bfc26333-b744-4775-aebf-d43a42ffa1cb
a=ssrc:1948313614 cname:Kk01/qU0PWi9Cacd
a=ssrc:1948313614 msid:- bfc26333-b744-4775-aebf-d43a42ffa1cb
a=rtcp-rsize
a=content:main
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
m=application 0 RTP/AVP 0
c=IN IP4 0.0.0.0
a=mid:5
SDP

answer('a=mid mixup', { }, <<SDP);
v=0
o=CiscoSystemsCCM-SIP 133090092 2 IN IP4 22.22.220.163
s=SIP Call
t=0 0
m=audio 27248 RTP/AVP 0
c=IN IP4 95.108.178.230
b=AS:80
a=X-cisco-media:umoh
a=ptime:20
a=rtpmap:0 PCMU/8000
a=mid:1
m=video 0 RTP/AVP 99 97 126 123
c=IN IP4 33.33.41.40
b=TIAS:5952000
a=label:11
a=rtpmap:99 H265/90000
a=fmtp:99  level-id=90;max-lsr=125337600;max-lps=2088960;max-tr=22;max-tc=20;max-fps=6000;x-cisco-hevc=529
a=rtpmap:97 H264/90000
a=fmtp:97 profile-level-id=428016;packetization-mode=0;max-mbps=490000;max-fs=8160;max-cpb=200;max-dpb=16320;max-br=5000;max-smbps=490000;max-fps=6000
a=rtpmap:126 H264/90000
a=fmtp:126 profile-level-id=428016;packetization-mode=1;max-mbps=490000;max-fs=8160;max-cpb=200;max-dpb=16320;max-br=5000;max-smbps=490000;max-fps=6000
a=rtpmap:123 X-ULPFECUC/90000
a=fmtp:123  multi_ssrc=1;feedback=0;max_esel=1450;m=8;max_n=42;FEC_ORDER=FEC_SRTP;non_seq=1
a=content:main
a=inactive
a=mid:2
m=application 0 RTP/AVP 96
c=IN IP4 95.108.178.230
a=rtpmap:96 H224/0
a=inactive
a=mid:5
------------------------------------
v=0
o=CiscoSystemsCCM-SIP 133090092 2 IN IP4 22.22.220.163
s=SIP Call
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP6 2001:db8:4321::1
b=AS:80
a=mid:1
a=rtpmap:0 PCMU/8000
a=X-cisco-media:umoh
a=sendrecv
a=rtcp:PORT
a=ptime:20
m=video 0 RTP/AVP 99 97 126 123
c=IN IP6 ::
b=TIAS:5952000
a=mid:2
m=application 0 RTP/SAVP 96
c=IN IP4 0.0.0.0
a=mid:5
SDP

offer('a=mid mixup', { }, <<SDP);
v=0
o=- 1853902600970192916 2 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic:  WMS
a=group:BUNDLE 0 1
m=audio 50642 RTP/AVP 111 63 9 0 8 13 110 126
c=IN IP6 3333:3333:3333:99d:0:4daf:a7d2:0
b=AS:64
a=rtpmap:111 opus/48000/2
a=rtpmap:63 red/48000/2
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:126 telephone-event/8000
a=fmtp:111 minptime=10;useinbandfec=1
a=fmtp:63 111/111
a=rtcp:9 IN IP4 0.0.0.0
a=rtcp-fb:111 transport-cc
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid
a=ssrc:2265387584 cname:O+/zt1Rc13nsML+e
a=rtcp-mux
a=mid:0
m=video 46494 RTP/AVP 96 97 102 103 104 105 106 107 108 109 127 125 39 40 45 46 98 99 100 101 112 113 114
c=IN IP6 3333:3333:3333:99d:0:4daf:a7d2:0
b=AS:2496
a=rtpmap:97 rtx/90000
a=rtpmap:102 H264/90000
a=rtpmap:104 H264/90000
a=rtpmap:105 rtx/90000
a=rtpmap:106 H264/90000
a=rtpmap:108 H264/90000
a=rtpmap:109 rtx/90000
a=rtpmap:125 rtx/90000
a=rtpmap:39 H264/90000
a=rtpmap:40 rtx/90000
a=rtpmap:46 rtx/90000
a=rtpmap:99 rtx/90000
a=rtpmap:100 VP9/90000
a=rtpmap:101 rtx/90000
a=rtpmap:113 rtx/90000
a=rtpmap:114 ulpfec/90000
a=fmtp:97 apt=96
a=fmtp:103 apt=102
a=fmtp:107 apt=106
a=fmtp:108 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
a=fmtp:109 apt=108
a=fmtp:125 apt=127
a=fmtp:39 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
a=fmtp:40 apt=39
a=fmtp:45 level-idx=5;profile=0;tier=0
a=fmtp:99 apt=98
a=fmtp:100 profile-id=2
a=fmtp:101 apt=100
a=rtcp:9 IN IP4 0.0.0.0
a=rtcp-fb:96 goog-remb
a=rtcp-fb:96 ccm fir
a=rtcp-fb:96 nack
a=rtcp-fb:96 nack pli
a=rtcp-fb:102 transport-cc
a=rtcp-fb:102 ccm fir
a=rtcp-fb:102 nack
a=rtcp-fb:104 goog-remb
a=rtcp-fb:104 transport-cc
a=rtcp-fb:104 nack
a=rtcp-fb:104 nack pli
a=rtcp-fb:106 goog-remb
a=rtcp-fb:106 ccm fir
a=rtcp-fb:106 nack pli
a=rtcp-fb:108 goog-remb
a=rtcp-fb:108 transport-cc
a=rtcp-fb:108 nack
a=rtcp-fb:108 nack pli
a=rtcp-fb:127 goog-remb
a=rtcp-fb:127 ccm fir
a=rtcp-fb:127 nack
a=rtcp-fb:39 goog-remb
a=rtcp-fb:39 transport-cc
a=rtcp-fb:39 ccm fir
a=rtcp-fb:39 nack pli
a=rtcp-fb:45 goog-remb
a=rtcp-fb:45 transport-cc
a=rtcp-fb:45 nack
a=rtcp-fb:45 nack pli
a=rtcp-fb:98 goog-remb
a=rtcp-fb:98 ccm fir
a=rtcp-fb:98 nack
a=rtcp-fb:100 goog-remb
a=rtcp-fb:100 transport-cc
a=rtcp-fb:100 ccm fir
a=rtcp-fb:100 nack pli
a=extmap:13 urn:3gpp:video-orientation
a=extmap:5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay
a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type
a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing
a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space
a=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:11 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=setup:actpass
a=msid:- bfc26333-b744-4775-aebf-d43a42ffa1cb
a=sendrecv
a=ssrc:3133813647 cname:O+/zt1Rc13nsML+e
a=ssrc:1356931172 cname:O+/zt1Rc13nsML+e
a=ssrc:1356931172 msid:- bfc26333-b744-4775-aebf-d43a42ffa1cb
a=ssrc-group:FID 3133813647 1356931172
a=rtcp-rsize
a=content:main
a=mid:1
m=application 0 RTP/AVP 0
c=IN IP4 0.0.0.0
a=mid:5
------------------------------------------
v=0
o=- 1853902600970192916 2 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic:  WMS
m=audio PORT RTP/AVP 111 63 9 0 8 13 110 126
c=IN IP4 203.0.113.1
b=AS:64
a=mid:1
a=rtpmap:111 opus/48000/2
a=fmtp:111 useinbandfec=1; minptime=10
a=rtcp-fb:111 transport-cc
a=rtpmap:63 red/48000/2
a=fmtp:63 111/111
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:126 telephone-event/8000
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid
a=ssrc:2265387584 cname:O+/zt1Rc13nsML+e
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=ptime:20
m=video PORT RTP/AVP 96 97 102 103 104 105 106 107 108 109 127 125 39 40 45 46 98 99 100 101 112 113 114
c=IN IP4 203.0.113.1
b=AS:2496
a=mid:2
a=rtpmap:96 /0
a=rtcp-fb:96 goog-remb
a=rtcp-fb:96 ccm fir
a=rtcp-fb:96 nack
a=rtcp-fb:96 nack pli
a=rtpmap:97 rtx/90000
a=fmtp:97 apt=96
a=rtpmap:102 H264/90000
a=rtcp-fb:102 transport-cc
a=rtcp-fb:102 ccm fir
a=rtcp-fb:102 nack
a=rtpmap:103 /0
a=fmtp:103 apt=102
a=rtpmap:104 H264/90000
a=rtcp-fb:104 goog-remb
a=rtcp-fb:104 transport-cc
a=rtcp-fb:104 nack
a=rtcp-fb:104 nack pli
a=rtpmap:105 rtx/90000
a=rtpmap:106 H264/90000
a=rtcp-fb:106 goog-remb
a=rtcp-fb:106 ccm fir
a=rtcp-fb:106 nack pli
a=rtpmap:107 /0
a=fmtp:107 apt=106
a=rtpmap:108 H264/90000
a=fmtp:108 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
a=rtcp-fb:108 goog-remb
a=rtcp-fb:108 transport-cc
a=rtcp-fb:108 nack
a=rtcp-fb:108 nack pli
a=rtpmap:109 rtx/90000
a=fmtp:109 apt=108
a=rtpmap:127 /0
a=rtcp-fb:127 goog-remb
a=rtcp-fb:127 ccm fir
a=rtcp-fb:127 nack
a=rtpmap:125 rtx/90000
a=fmtp:125 apt=127
a=rtpmap:39 H264/90000
a=fmtp:39 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
a=rtcp-fb:39 goog-remb
a=rtcp-fb:39 transport-cc
a=rtcp-fb:39 ccm fir
a=rtcp-fb:39 nack pli
a=rtpmap:40 rtx/90000
a=fmtp:40 apt=39
a=rtpmap:45 /0
a=fmtp:45 level-idx=5;profile=0;tier=0
a=rtcp-fb:45 goog-remb
a=rtcp-fb:45 transport-cc
a=rtcp-fb:45 nack
a=rtcp-fb:45 nack pli
a=rtpmap:46 rtx/90000
a=rtpmap:98 /0
a=rtcp-fb:98 goog-remb
a=rtcp-fb:98 ccm fir
a=rtcp-fb:98 nack
a=rtpmap:99 rtx/90000
a=fmtp:99 apt=98
a=rtpmap:100 VP9/90000
a=fmtp:100 profile-id=2
a=rtcp-fb:100 goog-remb
a=rtcp-fb:100 transport-cc
a=rtcp-fb:100 ccm fir
a=rtcp-fb:100 nack pli
a=rtpmap:101 rtx/90000
a=fmtp:101 apt=100
a=rtpmap:112 /0
a=rtpmap:113 rtx/90000
a=rtpmap:114 ulpfec/90000
a=extmap:13 urn:3gpp:video-orientation
a=extmap:5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay
a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type
a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing
a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space
a=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:11 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=msid:- bfc26333-b744-4775-aebf-d43a42ffa1cb
a=ssrc:3133813647 cname:O+/zt1Rc13nsML+e
a=ssrc:1356931172 cname:O+/zt1Rc13nsML+e
a=ssrc:1356931172 msid:- bfc26333-b744-4775-aebf-d43a42ffa1cb
a=ssrc-group:FID 3133813647 1356931172
a=rtcp-rsize
a=content:main
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
m=application 0 RTP/AVP 0
c=IN IP4 0.0.0.0
a=mid:5
SDP




new_call;

offer('reject first stream, session c=', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
c=IN IP4 198.51.100.50
t=0 0
m=audio 3000 RTP/AVP 8
a=sendrecv
m=audio 4000 RTP/AVP 8
a=sendrecv
----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('reject first stream, session c=', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
c=IN IP4 198.51.100.50
t=0 0
m=audio 0 RTP/AVP 8
a=sendrecv
m=audio 5000 RTP/AVP 8
a=sendrecv
----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 0 RTP/AVP 8
c=IN IP4 0.0.0.0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('reject first stream, media c=', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8
c=IN IP4 198.51.100.50
a=sendrecv
m=audio 4000 RTP/AVP 8
c=IN IP4 198.51.100.50
a=sendrecv
----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('reject first stream, media c=', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 0 RTP/AVP 8
c=IN IP4 198.51.100.50
a=sendrecv
m=audio 5000 RTP/AVP 8
c=IN IP4 198.51.100.50
a=sendrecv
----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 0 RTP/AVP 8
c=IN IP4 0.0.0.0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP



if ($extended_tests) {

($sock_a, $sock_b) = new_call([qw(198.51.100.45 6060)], [qw(198.51.100.45 6062)]);

($port_a) = offer('AMR play media bit rate control',
	{ codec => { } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 6060 RTP/AVP 96
c=IN IP4 198.51.100.45
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,3,4,8; mode-change-period=2; mode-change-neighbor=1; max-red=0; octet-align=1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,3,4,8; mode-change-period=2; mode-change-neighbor=1; max-red=0; octet-align=1
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('AMR play media bit rate control',
	{ codec => { } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 6062 RTP/AVP 96
c=IN IP4 198.51.100.45
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,3,4,8; mode-change-period=2; mode-change-neighbor=1; max-red=0; octet-align=1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,3,4,8; mode-change-period=2; mode-change-neighbor=1; max-red=0; octet-align=1
a=sendrecv
a=rtcp:PORT
SDP


# no CMR, mode 8
snd($sock_a, $port_b, rtp(96, 1000, 3000, 0x1234, "\xf0\x44\x11\x06\x30\x33\xbe\xce\xb3\xa0\xd3\x00\x00\xeb\x50\x87\xb4\xff\xd6\x42\x40\x18\x08\x1a\xe5\x02\x2a\x96\x91\x29\x48\x49\xcb\x52\x22\x89\x06\x78\xc0\x28\x00\xb1\x18\x8b\x93\x24\xc6\x58\x74\xac\x19\x0d\xd7\xb0\x5b\x08\x88\xcb\xba\xaf\xf2\x58"));
rcv($sock_b, $port_a, rtpm(96, 1000, 3000, 0x1234, "\xf0\x44\x11\x06\x30\x33\xbe\xce\xb3\xa0\xd3\x00\x00\xeb\x50\x87\xb4\xff\xd6\x42\x40\x18\x08\x1a\xe5\x02\x2a\x96\x91\x29\x48\x49\xcb\x52\x22\x89\x06\x78\xc0\x28\x00\xb1\x18\x8b\x93\x24\xc6\x58\x74\xac\x19\x0d\xd7\xb0\x5b\x08\x88\xcb\xba\xaf\xf2\x58"));

# no CMR, mode 3
snd($sock_b, $port_a, rtp(96, 2000, 4000, 0x9876, "\xf0\x1c\x5b\x06\x25\x73\xb2\xca\xd9\xe7\x92\x0f\x15\x41\xe6\x71\x50\x3b\x83\xb9\x34\x27\x93\x29\x02\x02\x99\xe3\xd4\xc0\xb7\xe0\xbf\xf5\xda\xdd\x55\x40"));
rcv($sock_a, $port_b, rtpm(96, 2000, 4000, 0x9876, "\xf0\x1c\x5b\x06\x25\x73\xb2\xca\xd9\xe7\x92\x0f\x15\x41\xe6\x71\x50\x3b\x83\xb9\x34\x27\x93\x29\x02\x02\x99\xe3\xd4\xc0\xb7\xe0\xbf\xf5\xda\xdd\x55\x40"));

$resp = rtpe_req('play media', 'media player', { 'from-tag' => ft(), blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

# receive mode 3
($seq, $ts, $ssrc) = rcv($sock_a, $port_b, rtpm(96 | 0x80, -1, -1, -1, "\xf0\x1c\xfc\xce\x67\x32\x83\x15\x62\xbe\x89\x42\xed\xdd\x82\xd4\xb5\x63\x35\x34\x44\x44\x76\x86\xb5\x76\x4c\xd4\x54\x44\x8c\xcd\xce\xc5\x74\x47\x2f\xe8"));




($sock_a, $sock_b) = new_call([qw(198.51.100.45 6064)], [qw(198.51.100.45 6066)]);

($port_a) = offer('AMR play media bit rate highest mode',
	{ codec => { } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 6064 RTP/AVP 96
c=IN IP4 198.51.100.45
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,3,4,8; mode-change-period=2; mode-change-neighbor=1; max-red=0; octet-align=1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,3,4,8; mode-change-period=2; mode-change-neighbor=1; max-red=0; octet-align=1
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('AMR play media bit rate highest mode',
	{ codec => { } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 6066 RTP/AVP 96
c=IN IP4 198.51.100.45
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,3,4,8; mode-change-period=2; mode-change-neighbor=1; max-red=0; octet-align=1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,3,4,8; mode-change-period=2; mode-change-neighbor=1; max-red=0; octet-align=1
a=sendrecv
a=rtcp:PORT
SDP


# no CMR, mode 8
snd($sock_a, $port_b, rtp(96, 1000, 3000, 0x1234, "\xf0\x44\x11\x06\x30\x33\xbe\xce\xb3\xa0\xd3\x00\x00\xeb\x50\x87\xb4\xff\xd6\x42\x40\x18\x08\x1a\xe5\x02\x2a\x96\x91\x29\x48\x49\xcb\x52\x22\x89\x06\x78\xc0\x28\x00\xb1\x18\x8b\x93\x24\xc6\x58\x74\xac\x19\x0d\xd7\xb0\x5b\x08\x88\xcb\xba\xaf\xf2\x58"));
rcv($sock_b, $port_a, rtpm(96, 1000, 3000, 0x1234, "\xf0\x44\x11\x06\x30\x33\xbe\xce\xb3\xa0\xd3\x00\x00\xeb\x50\x87\xb4\xff\xd6\x42\x40\x18\x08\x1a\xe5\x02\x2a\x96\x91\x29\x48\x49\xcb\x52\x22\x89\x06\x78\xc0\x28\x00\xb1\x18\x8b\x93\x24\xc6\x58\x74\xac\x19\x0d\xd7\xb0\x5b\x08\x88\xcb\xba\xaf\xf2\x58"));

# no CMR, mode 3
snd($sock_b, $port_a, rtp(96, 2000, 4000, 0x9876, "\xf0\x1c\x5b\x06\x25\x73\xb2\xca\xd9\xe7\x92\x0f\x15\x41\xe6\x71\x50\x3b\x83\xb9\x34\x27\x93\x29\x02\x02\x99\xe3\xd4\xc0\xb7\xe0\xbf\xf5\xda\xdd\x55\x40"));
rcv($sock_a, $port_b, rtpm(96, 2000, 4000, 0x9876, "\xf0\x1c\x5b\x06\x25\x73\xb2\xca\xd9\xe7\x92\x0f\x15\x41\xe6\x71\x50\x3b\x83\xb9\x34\x27\x93\x29\x02\x02\x99\xe3\xd4\xc0\xb7\xe0\xbf\xf5\xda\xdd\x55\x40"));

$resp = rtpe_req('play media', 'media player', {
		'from-tag' => ft(), blob => $wav_file,
		codec => { set => [qw,AMR/8000/1/12200 AMR-WB/16000/1/23850,] },
	});
is $resp->{duration}, 100, 'media duration';

# receive mode 8
($seq, $ts, $ssrc) = rcv($sock_a, $port_b, rtpm(96 | 0x80, -1, -1, -1, "\xf0\x44\xfa\xce\x55\xb2\x8f\x39\x12\xbe\x89\xf0\x00\x44\x6d\xdd\xa2\xf0\x03\x18\x61\x10\x19\xd0\x18\x0a\x0c\x21\xba\x06\xc2\x24\x00\x24\xcc\x10\x8c\xfb\x43\xcf\x01\x39\x5b\x65\x04\x01\x73\x14\x1c\xbc\xd1\x9c\x70\xe5\x6e\x16\x16\x17\xd4\x71\xff\xc0"));





($sock_a, $sock_b) = new_call([qw(198.51.100.45 6068)], [qw(198.51.100.45 6066)]);

($port_a) = offer('AMR play media bit rate lower mode',
	{ codec => { } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 6064 RTP/AVP 96
c=IN IP4 198.51.100.45
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,3,4,7; mode-change-period=2; mode-change-neighbor=1; max-red=0; octet-align=1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,3,4,7; mode-change-period=2; mode-change-neighbor=1; max-red=0; octet-align=1
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('AMR play media bit rate lower mode',
	{ codec => { } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 6066 RTP/AVP 96
c=IN IP4 198.51.100.45
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,3,4,7; mode-change-period=2; mode-change-neighbor=1; max-red=0; octet-align=1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,3,4,7; mode-change-period=2; mode-change-neighbor=1; max-red=0; octet-align=1
a=sendrecv
a=rtcp:PORT
SDP


# no CMR, mode 8 (not actually allowed)
snd($sock_a, $port_b, rtp(96, 1000, 3000, 0x1234, "\xf0\x44\x11\x06\x30\x33\xbe\xce\xb3\xa0\xd3\x00\x00\xeb\x50\x87\xb4\xff\xd6\x42\x40\x18\x08\x1a\xe5\x02\x2a\x96\x91\x29\x48\x49\xcb\x52\x22\x89\x06\x78\xc0\x28\x00\xb1\x18\x8b\x93\x24\xc6\x58\x74\xac\x19\x0d\xd7\xb0\x5b\x08\x88\xcb\xba\xaf\xf2\x58"));
rcv($sock_b, $port_a, rtpm(96, 1000, 3000, 0x1234, "\xf0\x44\x11\x06\x30\x33\xbe\xce\xb3\xa0\xd3\x00\x00\xeb\x50\x87\xb4\xff\xd6\x42\x40\x18\x08\x1a\xe5\x02\x2a\x96\x91\x29\x48\x49\xcb\x52\x22\x89\x06\x78\xc0\x28\x00\xb1\x18\x8b\x93\x24\xc6\x58\x74\xac\x19\x0d\xd7\xb0\x5b\x08\x88\xcb\xba\xaf\xf2\x58"));

# no CMR, mode 3
snd($sock_b, $port_a, rtp(96, 2000, 4000, 0x9876, "\xf0\x1c\x5b\x06\x25\x73\xb2\xca\xd9\xe7\x92\x0f\x15\x41\xe6\x71\x50\x3b\x83\xb9\x34\x27\x93\x29\x02\x02\x99\xe3\xd4\xc0\xb7\xe0\xbf\xf5\xda\xdd\x55\x40"));
rcv($sock_a, $port_b, rtpm(96, 2000, 4000, 0x9876, "\xf0\x1c\x5b\x06\x25\x73\xb2\xca\xd9\xe7\x92\x0f\x15\x41\xe6\x71\x50\x3b\x83\xb9\x34\x27\x93\x29\x02\x02\x99\xe3\xd4\xc0\xb7\xe0\xbf\xf5\xda\xdd\x55\x40"));

$resp = rtpe_req('play media', 'media player', {
		'from-tag' => ft(), blob => $wav_file,
		codec => { set => [qw,AMR/8000/1/12200 AMR-WB/16000/1/23850,] },
	});
is $resp->{duration}, 100, 'media duration';

# receive mode 7
($seq, $ts, $ssrc) = rcv($sock_a, $port_b, rtpm(96 | 0x80, -1, -1, -1, "\xf0\x3c\xfa\xce\x55\xb2\x8f\x39\x12\xbe\x89\x44\x6d\xdd\xa2\xf0\x03\x18\x61\x10\x19\xd0\x18\x0a\x0c\x21\xba\x06\xc2\x24\x00\x24\xcc\x10\x8c\xfb\x43\xcf\x01\x39\x5b\x65\x04\x01\x73\x14\x1c\xbc\xd1\x9c\x70\xe5\x6e\x16\x16\x17\xd4\x71\xff\xc0"));


}



new_call;

offer('mismatched t-e control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8 101
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:101 telephone-event/8000
-------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('mismatched t-e control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8 97
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:97 telephone-event/8000
-------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('mismatched t-e', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8 101
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:101 telephone-event/8000
-------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('mismatched t-e', { flags => ['allow asymmetric codecs'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8 97
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:97 telephone-event/8000
-------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 97
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:97 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('mismatched t/c t-e control', { codec => {transcode => ['telephone-event'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8
c=IN IP4 198.51.100.50
a=sendrecv
-------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
a=rtcp:PORT
SDP

answer('mismatched t/c t-e control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8 97
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:97 telephone-event/8000
-------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('mismatched t/c t-e', { codec => {transcode => ['telephone-event'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8
c=IN IP4 198.51.100.50
a=sendrecv
-------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
a=rtcp:PORT
SDP

answer('mismatched t/c t-e', { flags => ['allow asymmetric codecs'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8 97
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:97 telephone-event/8000
-------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 97
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:97 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('mismatched accept t-e control', { codec => {accept => ['telephone-event'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8 101
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:101 telephone-event/8000
-------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('mismatched accept t-e control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8 97
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:97 telephone-event/8000
-------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('mismatched accept t-e', { codec => {accept => ['telephone-event'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8 101
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:101 telephone-event/8000
-------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('mismatched accept t-e', { flags => ['allow asymmetric codecs'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8 97
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:97 telephone-event/8000
-------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 97
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:97 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('duplicate t-e', { codec => {
		strip => ['all'],
		except => [qw/opus G722 PCMA telephone-event/],
		transcode => ['telephone-event'],
	} }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 127 98 97 9 8 101 102
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:127 EVS/16000/1
a=fmtp:127 evs-mode-switch=0;br=5.9-24.4;bw=nb-wb;cmr=-1;ch-aw-recv=0;max-red=0
a=rtpmap:98 AMR-WB/16000/1
a=fmtp:98 octet-align=0;mode-change-capability=2;max-red=0
a=rtpmap:97 AMR/8000/1
a=fmtp:97 octet-align=0;mode-change-capability=2;max-red=0
a=rtpmap:101 telephone-event/16000
a=rtpmap:102 telephone-event/8000
-------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 9 8 102
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:102 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('duplicate t-e', { flags => ['allow asymmetric codecs'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8 101
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
-------------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('t-e fmtp', { flags => [qw(codec-strip-all codec-transcode-PCMA codec-transcode-telephone-event)],
		ICE => 'remove' }, <<SDP);
v=0
o=SBC01N2TB 9880719 9880719 IN IP4 91.236.83.218
s=sip call
c=IN IP4 91.236.83.250
t=0 0
m=audio 7918 RTP/AVP 8 96
b=RS:0
b=RR:0
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
a=maxptime:40
---------------------------------
v=0
o=SBC01N2TB 9880719 9880719 IN IP4 91.236.83.218
s=sip call
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
b=RR:0
b=RS:0
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
a=rtcp:PORT
a=maxptime:40
SDP

answer('t-e fmtp', { flags => [qw(codec-strip-all codec-transcode-PCMA codec-transcode-telephone-event)],
		ICE => 'remove' }, <<SDP);
v=0
o=FreeSWITCH 1699011004 1699011005 IN IP4 178.238.96.232
s=FreeSWITCH
c=IN IP4 178.238.96.232
t=0 0
m=audio 10096 RTP/AVP 8 96
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-16
a=silenceSupp:off - - - -
a=ptime:20
a=rtcp:10097 IN IP4 178.238.96.232
---------------------------------
v=0
o=FreeSWITCH 1699011004 1699011005 IN IP4 178.238.96.232
s=FreeSWITCH
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=silenceSupp:off - - - -
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

answer('t-e fmtp', { flags => [qw(codec-strip-all codec-transcode-PCMA codec-transcode-telephone-event)],
		ICE => 'remove' }, <<SDP);
v=0
o=FreeSWITCH 1699011004 1699011005 IN IP4 178.238.96.232
s=FreeSWITCH
c=IN IP4 178.238.96.232
t=0 0
m=audio 10096 RTP/AVP 8 96
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-16
a=silenceSupp:off - - - -
a=ptime:20
a=rtcp:10097 IN IP4 178.238.96.232
---------------------------------
v=0
o=FreeSWITCH 1699011004 1699011005 IN IP4 178.238.96.232
s=FreeSWITCH
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=silenceSupp:off - - - -
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP




new_call;

offer('static codecs control', { codec => { transcode =>
			['opus/48000/2///useinbandfec--1;stereo--0;sprop-stereo--0'],
		}}, <<SDP);
v=0
o=- 0 0 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
m=audio 3110 RTP/AVP 8 0 101
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
--------------------------------
v=0
o=- 0 0 IN IP4 127.0.0.1
s=-
t=0 0
m=audio PORT RTP/AVP 8 0 96 97 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=0; useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=fmtp:97 0-15
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('static codecs control', {}, <<SDP);
v=0
o=- 2405046764736097547 2405046764736097548 IN IP4 192.168.178.99
s=SDP data
c=IN IP4 192.168.178.99
t=0 0
m=audio 6002 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=silenceSupp:off - - - -
a=fmtp:101 0-15
a=ptime:20
a=mptime:20 20 -
a=sendrecv
--------------------------------
v=0
o=- 2405046764736097547 2405046764736097548 IN IP4 192.168.178.99
s=SDP data
t=0 0
m=audio PORT RTP/AVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=silenceSupp:off - - - -
a=mptime:20 20 -
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

offer('static codecs control', { codec => { transcode =>
			['opus/48000/2///useinbandfec--1;stereo--0;sprop-stereo--0'],
		}}, <<SDP);
v=0
o=- 2405046764736097547 2405046764736097550 IN IP4 192.168.178.104
s=SDP data
c=IN IP4 192.168.178.104
t=0 0
m=audio 15028 RTP/AVP 0 8 97 98 96
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:97 opus/48000/2
a=fmtp:97 stereo=0; sprop-stereo=0; useinbandfec=1
a=rtpmap:98 telephone-event/48000
a=fmtp:98 0-15
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
a=rtcp:39279
a=mid:0
a=silenceSupp:off - - - -
a=mptime:20 20 -
a=ptime:20
--------------------------------
v=0
o=- 2405046764736097547 2405046764736097550 IN IP4 192.168.178.104
s=SDP data
t=0 0
m=audio PORT RTP/AVP 0 8 97 98 96
c=IN IP4 203.0.113.1
a=mid:0
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:97 opus/48000/2
a=fmtp:97 stereo=0; sprop-stereo=0; useinbandfec=1
a=rtpmap:98 telephone-event/48000
a=fmtp:98 0-15
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=silenceSupp:off - - - -
a=mptime:20 20 -
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP




new_call;

offer('static codecs (reuse control)', { codec => { transcode =>
			['opus/48000/2///useinbandfec--1;stereo--0;sprop-stereo--0'],
		}, flags => ['no codec renegotiation'] }, <<SDP);
v=0
o=- 0 0 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
m=audio 3110 RTP/AVP 8 0 101
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
--------------------------------
v=0
o=- 0 0 IN IP4 127.0.0.1
s=-
t=0 0
m=audio PORT RTP/AVP 8 0 96 97 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=0; useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=fmtp:97 0-15
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('static codecs (reuse control)', {flags => ['no codec renegotiation'] }, <<SDP);
v=0
o=- 2405046764736097547 2405046764736097548 IN IP4 192.168.178.99
s=SDP data
c=IN IP4 192.168.178.99
t=0 0
m=audio 6002 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=silenceSupp:off - - - -
a=fmtp:101 0-15
a=ptime:20
a=mptime:20 20 -
a=sendrecv
--------------------------------
v=0
o=- 2405046764736097547 2405046764736097548 IN IP4 192.168.178.99
s=SDP data
t=0 0
m=audio PORT RTP/AVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=silenceSupp:off - - - -
a=mptime:20 20 -
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

offer('static codecs (reuse control)', { codec => { transcode =>
			['opus/48000/2///useinbandfec--1;stereo--0;sprop-stereo--0'],
		}, flags => ['no codec renegotiation'] }, <<SDP);
v=0
o=- 2405046764736097547 2405046764736097550 IN IP4 192.168.178.104
s=SDP data
c=IN IP4 192.168.178.104
t=0 0
m=audio 15028 RTP/AVP 0 8 97 98 96
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:97 opus/48000/2
a=fmtp:97 stereo=0; sprop-stereo=0; useinbandfec=1
a=rtpmap:98 telephone-event/48000
a=fmtp:98 0-15
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
a=rtcp:39279
a=mid:0
a=silenceSupp:off - - - -
a=mptime:20 20 -
a=ptime:20
--------------------------------
v=0
o=- 2405046764736097547 2405046764736097550 IN IP4 192.168.178.104
s=SDP data
t=0 0
m=audio PORT RTP/AVP 8 0 97 98 96
c=IN IP4 203.0.113.1
a=mid:0
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:97 opus/48000/2
a=fmtp:97 stereo=0; sprop-stereo=0; useinbandfec=1
a=rtpmap:98 telephone-event/48000
a=fmtp:98 0-15
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=silenceSupp:off - - - -
a=mptime:20 20 -
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP



new_call;

offer('static codecs', { codec => { transcode =>
			['opus/48000/2///useinbandfec--1;stereo--0;sprop-stereo--0'],
		}, flags => ['static codecs'] }, <<SDP);
v=0
o=- 0 0 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
m=audio 3110 RTP/AVP 8 0 101
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
--------------------------------
v=0
o=- 0 0 IN IP4 127.0.0.1
s=-
t=0 0
m=audio PORT RTP/AVP 8 0 96 97 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=0; useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=fmtp:97 0-15
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('static codecs', {flags => ['static codecs'] }, <<SDP);
v=0
o=- 2405046764736097547 2405046764736097548 IN IP4 192.168.178.99
s=SDP data
c=IN IP4 192.168.178.99
t=0 0
m=audio 6002 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=silenceSupp:off - - - -
a=ptime:20
a=mptime:20 20 -
a=sendrecv
--------------------------------
v=0
o=- 2405046764736097547 2405046764736097548 IN IP4 192.168.178.99
s=SDP data
t=0 0
m=audio PORT RTP/AVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=silenceSupp:off - - - -
a=mptime:20 20 -
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

offer('static codecs', { codec => { transcode =>
			['opus/48000/2///useinbandfec--1;stereo--0;sprop-stereo--0'],
		}, flags => ['static codecs'] }, <<SDP);
v=0
o=- 2405046764736097547 2405046764736097550 IN IP4 192.168.178.104
s=SDP data
c=IN IP4 192.168.178.104
t=0 0
m=audio 15028 RTP/AVP 0 8 97 98 96
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:97 opus/48000/2
a=fmtp:97 stereo=0; sprop-stereo=0; useinbandfec=1
a=rtpmap:98 telephone-event/48000
a=fmtp:98 0-15
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
a=rtcp:39279
a=mid:0
a=silenceSupp:off - - - -
a=mptime:20 20 -
a=ptime:20
--------------------------------
v=0
o=- 2405046764736097547 2405046764736097550 IN IP4 192.168.178.104
s=SDP data
t=0 0
m=audio PORT RTP/AVP 8 99 98 101
c=IN IP4 203.0.113.1
a=mid:0
a=rtpmap:8 PCMA/8000
a=rtpmap:99 opus/48000/2
a=fmtp:99 stereo=0; sprop-stereo=0; useinbandfec=1
a=rtpmap:98 telephone-event/48000
a=fmtp:98 0-15
a=rtpmap:101 telephone-event/8000
a=silenceSupp:off - - - -
a=mptime:20 20 -
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP



new_call;

offer('codec reneg control', {
	ptime => 20, 'ptime-reverse' => 20, ICE => 'force', flags => [qw(
		generate-mid generate-rtcp port-latching SDES-off codec-strip-telephone-event
		codec-strip-opus codec-strip-G729 codec-strip-G729a codec-strip-speex
		codec-strip-G723 codec-strip-GSM codec-strip-iLBC codec-mask-G722 codec-mask-PCMA
		codec-mask-PCMU transcode-opus codec-offer-telephone-event)],
	replace => ['origin'], 'transport-protocol' => 'RTP/SAVPF',
	'rtcp-mux' => ['require']}, <<SDP);
v=0
o=Sonus_UAC 945064 419036 IN IP4 207.242.181.114
s=SIP Media Capabilities
c=IN IP4 207.242.181.114
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 61cc3524-d456-4497-b92e-2babd3d83d84
m=audio 28348 RTP/AVP 126 0 8 9
a=msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=ssrc:889323910 cname:OCP1KqOq/lFpZRp0
a=ssrc:889323910 msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=ptime:20
a=rtcp-xr:voip-metrics
a=rtpmap:126 telephone-event/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=sendonly
-------------------------------------
v=0
o=Sonus_UAC 945064 419036 IN IP4 203.0.113.1
s=SIP Media Capabilities
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 61cc3524-d456-4497-b92e-2babd3d83d84
m=audio PORT RTP/SAVPF 96 97
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=fmtp:97 0-15
a=msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=ssrc:889323910 cname:OCP1KqOq/lFpZRp0
a=ssrc:889323910 msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=rtcp-xr:voip-metrics
a=sendonly
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
a=ptime:20
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
SDP

answer('codec reneg control', { ICE => 'remove', flags => [qw(port-latching always-transcode SDES-off
		no-rtcp-attribute strip-extmap)],
	'transport-protocol' => 'RTP/AVP', replace => ['origin'],
	'rtcp-mux' => ['demux']}, <<SDP);
v=0
o=- 4209499349425057536 2 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio 45907 RTP/SAVPF 96 97
c=IN IP4 92.239.152.221
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:4024033178 1 udp 2122260223 192.168.0.54 45907 typ host generation 0 network-id 1 network-cost 10
a=candidate:2434153730 1 tcp 1518280447 192.168.0.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:886767579 1 udp 1686052607 92.239.152.221 45907 typ srflx raddr 192.168.0.54 rport 45907 generation 0 network-id 1 network-cost 10
a=ice-ufrag:W7Oq
a=ice-pwd:lle8qiYox8AhGf+/SOUMVaYy
a=ice-options:trickle
a=fingerprint:sha-256 D1:10:D3:33:45:C5:9A:5E:4E:49:A1:BC:24:04:84:77:B0:A3:4C:95:3B:0D:C4:9C:3B:AB:55:33:10:B6:32:06
a=setup:active
a=mid:1
a=recvonly
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=rtcp-mux
a=rtpmap:96 opus/48000/2
a=fmtp:96 minptime=10;usedtx=1;useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
-------------------------------------
v=0
o=- 4209499349425057536 2 IN IP4 203.0.113.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio PORT RTP/AVP 0 126
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:126 telephone-event/8000
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
a=recvonly
a=ptime:20
SDP

reverse_tags();

offer('codec reneg control', {
	ptime => 20, 'ptime-reverse' => 20, ICE => 'remove', flags => [qw(
		generate-rtcp port-latching SDES-off codec-strip-telephone-event
		codec-strip-G722 codec-strip-PCMU codec-strip-PCMA codec-strip-CN codec-strip-red
		codec-mask-opus transcode-PCMU transcode-PCMA transcode-G722 codec-offer-telephone-event
		always-transcode no-rtcp-attribute strip-extmap)],
	replace => ['origin'], 'transport-protocol' => 'RTP/AVP',
	'rtcp-mux' => ['demux']}, <<SDP);
v=0
o=- 4209499349425057536 3 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio 45907 RTP/SAVPF 96 97
c=IN IP4 92.239.152.221
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:4024033178 1 udp 2122260223 192.168.0.54 45907 typ host generation 0 network-id 1 network-cost 10
a=candidate:2434153730 1 tcp 1518280447 192.168.0.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:886767579 1 udp 1686052607 92.239.152.221 45907 typ srflx raddr 192.168.0.54 rport 45907 generation 0 network-id 1 network-cost 10
a=ice-ufrag:W7Oq
a=ice-pwd:lle8qiYox8AhGf+/SOUMVaYy
a=ice-options:trickle
a=fingerprint:sha-256 D1:10:D3:33:45:C5:9A:5E:4E:49:A1:BC:24:04:84:77:B0:A3:4C:95:3B:0D:C4:9C:3B:AB:55:33:10:B6:32:06
a=setup:active
a=mid:1
a=sendrecv
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=rtcp-mux
a=rtpmap:96 opus/48000/2
a=fmtp:96 minptime=10;usedtx=1;useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
------------------------------------------
v=0
o=- 4209499349425057536 3 IN IP4 203.0.113.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio PORT RTP/AVP 126 0 8 9
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:126 telephone-event/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
a=sendrecv
a=ptime:20
SDP

offer('codec reneg control', {
	ptime => 20, 'ptime-reverse' => 20, ICE => 'remove', flags => [qw(
		generate-rtcp port-latching SDES-off codec-strip-telephone-event
		codec-strip-G722 codec-strip-PCMU codec-strip-PCMA codec-strip-CN codec-strip-red
		codec-mask-opus transcode-PCMU transcode-PCMA transcode-G722 codec-offer-telephone-event
		always-transcode no-rtcp-attribute strip-extmap)],
	replace => ['origin'], 'transport-protocol' => 'RTP/AVP',
	'rtcp-mux' => ['demux']}, <<SDP);
v=0
o=- 4209499349425057536 3 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio 45907 RTP/SAVPF 96 97
c=IN IP4 92.239.152.221
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:4024033178 1 udp 2122260223 192.168.0.54 45907 typ host generation 0 network-id 1 network-cost 10
a=candidate:2434153730 1 tcp 1518280447 192.168.0.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:886767579 1 udp 1686052607 92.239.152.221 45907 typ srflx raddr 192.168.0.54 rport 45907 generation 0 network-id 1 network-cost 10
a=ice-ufrag:W7Oq
a=ice-pwd:lle8qiYox8AhGf+/SOUMVaYy
a=ice-options:trickle
a=fingerprint:sha-256 D1:10:D3:33:45:C5:9A:5E:4E:49:A1:BC:24:04:84:77:B0:A3:4C:95:3B:0D:C4:9C:3B:AB:55:33:10:B6:32:06
a=setup:active
a=mid:1
a=sendrecv
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=rtcp-mux
a=rtpmap:96 opus/48000/2
a=fmtp:96 minptime=10;usedtx=1;useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
------------------------------------------
v=0
o=- 4209499349425057536 3 IN IP4 203.0.113.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio PORT RTP/AVP 126 0 8 9
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:126 telephone-event/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
a=sendrecv
a=ptime:20
SDP




new_call;

offer('codec reneg ntp', {
	ptime => 20, 'ptime-reverse' => 20, ICE => 'force', flags => [qw(
		generate-mid generate-rtcp port-latching SDES-off
		codec-strip-opus codec-strip-G729 codec-strip-G729a codec-strip-speex
		codec-strip-G723 codec-strip-GSM codec-strip-iLBC codec-mask-G722 codec-mask-PCMA
		codec-mask-PCMU transcode-opus)],
	replace => ['origin'], 'transport-protocol' => 'RTP/SAVPF',
	'rtcp-mux' => ['require']}, <<SDP);
v=0
o=Sonus_UAC 945064 419036 IN IP4 207.242.181.114
s=SIP Media Capabilities
c=IN IP4 207.242.181.114
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 61cc3524-d456-4497-b92e-2babd3d83d84
m=audio 28348 RTP/AVP 126 0 8 9
a=msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=ssrc:889323910 cname:OCP1KqOq/lFpZRp0
a=ssrc:889323910 msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=ptime:20
a=rtcp-xr:voip-metrics
a=rtpmap:126 telephone-event/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=sendonly
-------------------------------------
v=0
o=Sonus_UAC 945064 419036 IN IP4 203.0.113.1
s=SIP Media Capabilities
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 61cc3524-d456-4497-b92e-2babd3d83d84
m=audio PORT RTP/SAVPF 96 97
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=fmtp:97 0-15
a=msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=ssrc:889323910 cname:OCP1KqOq/lFpZRp0
a=ssrc:889323910 msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=rtcp-xr:voip-metrics
a=sendonly
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
a=ptime:20
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
SDP

answer('codec reneg ntp', { ICE => 'remove', flags => [qw(port-latching always-transcode SDES-off
		no-rtcp-attribute strip-extmap)],
	'transport-protocol' => 'RTP/AVP', replace => ['origin'],
	'rtcp-mux' => ['demux']}, <<SDP);
v=0
o=- 4209499349425057536 2 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio 45907 RTP/SAVPF 96 97
c=IN IP4 92.239.152.221
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:4024033178 1 udp 2122260223 192.168.0.54 45907 typ host generation 0 network-id 1 network-cost 10
a=candidate:2434153730 1 tcp 1518280447 192.168.0.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:886767579 1 udp 1686052607 92.239.152.221 45907 typ srflx raddr 192.168.0.54 rport 45907 generation 0 network-id 1 network-cost 10
a=ice-ufrag:W7Oq
a=ice-pwd:lle8qiYox8AhGf+/SOUMVaYy
a=ice-options:trickle
a=fingerprint:sha-256 D1:10:D3:33:45:C5:9A:5E:4E:49:A1:BC:24:04:84:77:B0:A3:4C:95:3B:0D:C4:9C:3B:AB:55:33:10:B6:32:06
a=setup:active
a=mid:1
a=recvonly
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=rtcp-mux
a=rtpmap:96 opus/48000/2
a=fmtp:96 minptime=10;usedtx=1;useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
-------------------------------------
v=0
o=- 4209499349425057536 2 IN IP4 203.0.113.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio PORT RTP/AVP 0 126
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:126 telephone-event/8000
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
a=recvonly
a=ptime:20
SDP

reverse_tags();

offer('codec reneg ntp', {
	ptime => 20, 'ptime-reverse' => 20, ICE => 'remove', flags => [qw(
		generate-rtcp port-latching SDES-off
		codec-strip-G722 codec-strip-PCMU codec-strip-PCMA codec-strip-CN codec-strip-red
		codec-mask-opus transcode-PCMU transcode-PCMA transcode-G722
		always-transcode no-rtcp-attribute strip-extmap)],
	replace => ['origin'], 'transport-protocol' => 'RTP/AVP',
	'rtcp-mux' => ['demux']}, <<SDP);
v=0
o=- 4209499349425057536 3 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio 45907 RTP/SAVPF 96 97
c=IN IP4 92.239.152.221
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:4024033178 1 udp 2122260223 192.168.0.54 45907 typ host generation 0 network-id 1 network-cost 10
a=candidate:2434153730 1 tcp 1518280447 192.168.0.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:886767579 1 udp 1686052607 92.239.152.221 45907 typ srflx raddr 192.168.0.54 rport 45907 generation 0 network-id 1 network-cost 10
a=ice-ufrag:W7Oq
a=ice-pwd:lle8qiYox8AhGf+/SOUMVaYy
a=ice-options:trickle
a=fingerprint:sha-256 D1:10:D3:33:45:C5:9A:5E:4E:49:A1:BC:24:04:84:77:B0:A3:4C:95:3B:0D:C4:9C:3B:AB:55:33:10:B6:32:06
a=setup:active
a=mid:1
a=sendrecv
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=rtcp-mux
a=rtpmap:96 opus/48000/2
a=fmtp:96 minptime=10;usedtx=1;useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
------------------------------------------
v=0
o=- 4209499349425057536 3 IN IP4 203.0.113.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio PORT RTP/AVP 0 8 9 126
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:126 telephone-event/8000
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
a=sendrecv
a=ptime:20
SDP

offer('codec reneg ntp', {
	ptime => 20, 'ptime-reverse' => 20, ICE => 'remove', flags => [qw(
		generate-rtcp port-latching SDES-off
		codec-strip-G722 codec-strip-PCMU codec-strip-PCMA codec-strip-CN codec-strip-red
		codec-mask-opus transcode-PCMU transcode-PCMA transcode-G722
		always-transcode no-rtcp-attribute strip-extmap)],
	replace => ['origin'], 'transport-protocol' => 'RTP/AVP',
	'rtcp-mux' => ['demux']}, <<SDP);
v=0
o=- 4209499349425057536 3 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio 45907 RTP/SAVPF 96 97
c=IN IP4 92.239.152.221
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:4024033178 1 udp 2122260223 192.168.0.54 45907 typ host generation 0 network-id 1 network-cost 10
a=candidate:2434153730 1 tcp 1518280447 192.168.0.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:886767579 1 udp 1686052607 92.239.152.221 45907 typ srflx raddr 192.168.0.54 rport 45907 generation 0 network-id 1 network-cost 10
a=ice-ufrag:W7Oq
a=ice-pwd:lle8qiYox8AhGf+/SOUMVaYy
a=ice-options:trickle
a=fingerprint:sha-256 D1:10:D3:33:45:C5:9A:5E:4E:49:A1:BC:24:04:84:77:B0:A3:4C:95:3B:0D:C4:9C:3B:AB:55:33:10:B6:32:06
a=setup:active
a=mid:1
a=sendrecv
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=rtcp-mux
a=rtpmap:96 opus/48000/2
a=fmtp:96 minptime=10;usedtx=1;useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
------------------------------------------
v=0
o=- 4209499349425057536 3 IN IP4 203.0.113.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio PORT RTP/AVP 0 8 9 126
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:126 telephone-event/8000
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
a=sendrecv
a=ptime:20
SDP




new_call;

offer('codec reneg reuse', {
	ptime => 20, 'ptime-reverse' => 20, ICE => 'force', flags => [qw(no-codec-renegotiation
		generate-mid generate-rtcp port-latching SDES-off codec-strip-telephone-event
		codec-strip-opus codec-strip-G729 codec-strip-G729a codec-strip-speex
		codec-strip-G723 codec-strip-GSM codec-strip-iLBC codec-mask-G722 codec-mask-PCMA
		codec-mask-PCMU transcode-opus codec-offer-telephone-event)],
	replace => ['origin'], 'transport-protocol' => 'RTP/SAVPF',
	'rtcp-mux' => ['require']}, <<SDP);
v=0
o=Sonus_UAC 945064 419036 IN IP4 207.242.181.114
s=SIP Media Capabilities
c=IN IP4 207.242.181.114
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 61cc3524-d456-4497-b92e-2babd3d83d84
m=audio 28348 RTP/AVP 126 0 8 9
a=msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=ssrc:889323910 cname:OCP1KqOq/lFpZRp0
a=ssrc:889323910 msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=ptime:20
a=rtcp-xr:voip-metrics
a=rtpmap:126 telephone-event/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=sendonly
-------------------------------------
v=0
o=Sonus_UAC 945064 419036 IN IP4 203.0.113.1
s=SIP Media Capabilities
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 61cc3524-d456-4497-b92e-2babd3d83d84
m=audio PORT RTP/SAVPF 96 97
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=fmtp:97 0-15
a=msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=ssrc:889323910 cname:OCP1KqOq/lFpZRp0
a=ssrc:889323910 msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=rtcp-xr:voip-metrics
a=sendonly
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
a=ptime:20
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
SDP

answer('codec reneg reuse', { ICE => 'remove', flags => [qw(port-latching always-transcode SDES-off
		no-rtcp-attribute strip-extmap)],
	'transport-protocol' => 'RTP/AVP', replace => ['origin'],
	'rtcp-mux' => ['demux']}, <<SDP);
v=0
o=- 4209499349425057536 2 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio 45907 RTP/SAVPF 96 97
c=IN IP4 92.239.152.221
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:4024033178 1 udp 2122260223 192.168.0.54 45907 typ host generation 0 network-id 1 network-cost 10
a=candidate:2434153730 1 tcp 1518280447 192.168.0.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:886767579 1 udp 1686052607 92.239.152.221 45907 typ srflx raddr 192.168.0.54 rport 45907 generation 0 network-id 1 network-cost 10
a=ice-ufrag:W7Oq
a=ice-pwd:lle8qiYox8AhGf+/SOUMVaYy
a=ice-options:trickle
a=fingerprint:sha-256 D1:10:D3:33:45:C5:9A:5E:4E:49:A1:BC:24:04:84:77:B0:A3:4C:95:3B:0D:C4:9C:3B:AB:55:33:10:B6:32:06
a=setup:active
a=mid:1
a=recvonly
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=rtcp-mux
a=rtpmap:96 opus/48000/2
a=fmtp:96 minptime=10;usedtx=1;useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
-------------------------------------
v=0
o=- 4209499349425057536 2 IN IP4 203.0.113.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio PORT RTP/AVP 0 126
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:126 telephone-event/8000
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
a=recvonly
a=ptime:20
SDP

reverse_tags();

offer('codec reneg reuse', {
	ptime => 20, 'ptime-reverse' => 20, ICE => 'remove', flags => [qw(no-codec-renegotiation
		generate-rtcp port-latching SDES-off codec-strip-telephone-event
		codec-strip-G722 codec-strip-PCMU codec-strip-PCMA codec-strip-CN codec-strip-red
		codec-mask-opus transcode-PCMU transcode-PCMA transcode-G722 codec-offer-telephone-event
		always-transcode no-rtcp-attribute strip-extmap)],
	replace => ['origin'], 'transport-protocol' => 'RTP/AVP',
	'rtcp-mux' => ['demux']}, <<SDP);
v=0
o=- 4209499349425057536 3 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio 45907 RTP/SAVPF 96 97
c=IN IP4 92.239.152.221
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:4024033178 1 udp 2122260223 192.168.0.54 45907 typ host generation 0 network-id 1 network-cost 10
a=candidate:2434153730 1 tcp 1518280447 192.168.0.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:886767579 1 udp 1686052607 92.239.152.221 45907 typ srflx raddr 192.168.0.54 rport 45907 generation 0 network-id 1 network-cost 10
a=ice-ufrag:W7Oq
a=ice-pwd:lle8qiYox8AhGf+/SOUMVaYy
a=ice-options:trickle
a=fingerprint:sha-256 D1:10:D3:33:45:C5:9A:5E:4E:49:A1:BC:24:04:84:77:B0:A3:4C:95:3B:0D:C4:9C:3B:AB:55:33:10:B6:32:06
a=setup:active
a=mid:1
a=sendrecv
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=rtcp-mux
a=rtpmap:96 opus/48000/2
a=fmtp:96 minptime=10;usedtx=1;useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
------------------------------------------
v=0
o=- 4209499349425057536 3 IN IP4 203.0.113.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio PORT RTP/AVP 126 0 8 9
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:126 telephone-event/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
a=sendrecv
a=ptime:20
SDP

offer('codec reneg reuse', {
	ptime => 20, 'ptime-reverse' => 20, ICE => 'remove', flags => [qw(no-codec-renegotiation
		generate-rtcp port-latching SDES-off codec-strip-telephone-event
		codec-strip-G722 codec-strip-PCMU codec-strip-PCMA codec-strip-CN codec-strip-red
		codec-mask-opus transcode-PCMU transcode-PCMA transcode-G722 codec-offer-telephone-event
		always-transcode no-rtcp-attribute strip-extmap)],
	replace => ['origin'], 'transport-protocol' => 'RTP/AVP',
	'rtcp-mux' => ['demux']}, <<SDP);
v=0
o=- 4209499349425057536 3 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio 45907 RTP/SAVPF 96 97
c=IN IP4 92.239.152.221
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:4024033178 1 udp 2122260223 192.168.0.54 45907 typ host generation 0 network-id 1 network-cost 10
a=candidate:2434153730 1 tcp 1518280447 192.168.0.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:886767579 1 udp 1686052607 92.239.152.221 45907 typ srflx raddr 192.168.0.54 rport 45907 generation 0 network-id 1 network-cost 10
a=ice-ufrag:W7Oq
a=ice-pwd:lle8qiYox8AhGf+/SOUMVaYy
a=ice-options:trickle
a=fingerprint:sha-256 D1:10:D3:33:45:C5:9A:5E:4E:49:A1:BC:24:04:84:77:B0:A3:4C:95:3B:0D:C4:9C:3B:AB:55:33:10:B6:32:06
a=setup:active
a=mid:1
a=sendrecv
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=rtcp-mux
a=rtpmap:96 opus/48000/2
a=fmtp:96 minptime=10;usedtx=1;useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
------------------------------------------
v=0
o=- 4209499349425057536 3 IN IP4 203.0.113.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio PORT RTP/AVP 126 0 8 9
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:126 telephone-event/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
a=sendrecv
a=ptime:20
SDP




new_call;

offer('codec reneg simpler', {
	ptime => 20, 'ptime-reverse' => 20, ICE => 'force', flags => [qw(no-codec-renegotiation
		generate-mid generate-rtcp port-latching SDES-off codec-strip-telephone-event
		codec-strip-opus codec-strip-G729 codec-strip-G729a codec-strip-speex
		codec-strip-G723 codec-strip-GSM codec-strip-iLBC codec-mask-G722 codec-mask-PCMA
		codec-mask-PCMU transcode-opus codec-offer-telephone-event)],
	replace => ['origin'], 'transport-protocol' => 'RTP/SAVPF',
	'rtcp-mux' => ['require']}, <<SDP);
v=0
o=Sonus_UAC 945064 419036 IN IP4 207.242.181.114
s=SIP Media Capabilities
c=IN IP4 207.242.181.114
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 61cc3524-d456-4497-b92e-2babd3d83d84
m=audio 28348 RTP/AVP 126 0 8 9
a=msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=ssrc:889323910 cname:OCP1KqOq/lFpZRp0
a=ssrc:889323910 msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=ptime:20
a=rtcp-xr:voip-metrics
a=rtpmap:126 telephone-event/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=sendonly
-------------------------------------
v=0
o=Sonus_UAC 945064 419036 IN IP4 203.0.113.1
s=SIP Media Capabilities
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 61cc3524-d456-4497-b92e-2babd3d83d84
m=audio PORT RTP/SAVPF 96 97
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=fmtp:97 0-15
a=msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=ssrc:889323910 cname:OCP1KqOq/lFpZRp0
a=ssrc:889323910 msid:61cc3524-d456-4497-b92e-2babd3d83d84 02c5b74b-b03e-44a6-b175-6639fa009f2d
a=rtcp-xr:voip-metrics
a=sendonly
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
a=ptime:20
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
SDP

answer('codec reneg simpler', { ICE => 'remove', flags => [qw(port-latching SDES-off
		no-rtcp-attribute strip-extmap)],
	'transport-protocol' => 'RTP/AVP', replace => ['origin'],
	'rtcp-mux' => ['demux']}, <<SDP);
v=0
o=- 4209499349425057536 2 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio 45907 RTP/SAVPF 96 97
c=IN IP4 92.239.152.221
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:4024033178 1 udp 2122260223 192.168.0.54 45907 typ host generation 0 network-id 1 network-cost 10
a=candidate:2434153730 1 tcp 1518280447 192.168.0.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:886767579 1 udp 1686052607 92.239.152.221 45907 typ srflx raddr 192.168.0.54 rport 45907 generation 0 network-id 1 network-cost 10
a=ice-ufrag:W7Oq
a=ice-pwd:lle8qiYox8AhGf+/SOUMVaYy
a=ice-options:trickle
a=fingerprint:sha-256 D1:10:D3:33:45:C5:9A:5E:4E:49:A1:BC:24:04:84:77:B0:A3:4C:95:3B:0D:C4:9C:3B:AB:55:33:10:B6:32:06
a=setup:active
a=mid:1
a=recvonly
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=rtcp-mux
a=rtpmap:96 opus/48000/2
a=fmtp:96 minptime=10;usedtx=1;useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
-------------------------------------
v=0
o=- 4209499349425057536 2 IN IP4 203.0.113.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio PORT RTP/AVP 0 126
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:126 telephone-event/8000
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
a=recvonly
a=ptime:20
SDP

reverse_tags();

offer('codec reneg simpler', {
	ptime => 20, 'ptime-reverse' => 20, ICE => 'remove', flags => [qw(no-codec-renegotiation
		generate-rtcp port-latching SDES-off
		transcode-PCMU transcode-PCMA transcode-G722
		codec-mask-opus
		no-rtcp-attribute strip-extmap)],
	replace => ['origin'], 'transport-protocol' => 'RTP/AVP',
	'rtcp-mux' => ['demux']}, <<SDP);
v=0
o=- 4209499349425057536 3 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio 45907 RTP/SAVPF 96 97
c=IN IP4 92.239.152.221
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:4024033178 1 udp 2122260223 192.168.0.54 45907 typ host generation 0 network-id 1 network-cost 10
a=candidate:2434153730 1 tcp 1518280447 192.168.0.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:886767579 1 udp 1686052607 92.239.152.221 45907 typ srflx raddr 192.168.0.54 rport 45907 generation 0 network-id 1 network-cost 10
a=ice-ufrag:W7Oq
a=ice-pwd:lle8qiYox8AhGf+/SOUMVaYy
a=ice-options:trickle
a=fingerprint:sha-256 D1:10:D3:33:45:C5:9A:5E:4E:49:A1:BC:24:04:84:77:B0:A3:4C:95:3B:0D:C4:9C:3B:AB:55:33:10:B6:32:06
a=setup:active
a=mid:1
a=sendrecv
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=rtcp-mux
a=rtpmap:96 opus/48000/2
a=fmtp:96 minptime=10;usedtx=1;useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
------------------------------------------
v=0
o=- 4209499349425057536 3 IN IP4 203.0.113.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio PORT RTP/AVP 0 8 9 126
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:126 telephone-event/8000
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
a=sendrecv
a=ptime:20
SDP

offer('codec reneg simpler', {
	ptime => 20, 'ptime-reverse' => 20, ICE => 'remove', flags => [qw(no-codec-renegotiation
		generate-rtcp port-latching SDES-off
		transcode-PCMU transcode-PCMA transcode-G722
		codec-mask-opus
		no-rtcp-attribute strip-extmap)],
	replace => ['origin'], 'transport-protocol' => 'RTP/AVP',
	'rtcp-mux' => ['demux']}, <<SDP);
v=0
o=- 4209499349425057536 3 IN IP4 127.0.0.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio 45907 RTP/SAVPF 96 97
c=IN IP4 92.239.152.221
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:4024033178 1 udp 2122260223 192.168.0.54 45907 typ host generation 0 network-id 1 network-cost 10
a=candidate:2434153730 1 tcp 1518280447 192.168.0.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:886767579 1 udp 1686052607 92.239.152.221 45907 typ srflx raddr 192.168.0.54 rport 45907 generation 0 network-id 1 network-cost 10
a=ice-ufrag:W7Oq
a=ice-pwd:lle8qiYox8AhGf+/SOUMVaYy
a=ice-options:trickle
a=fingerprint:sha-256 D1:10:D3:33:45:C5:9A:5E:4E:49:A1:BC:24:04:84:77:B0:A3:4C:95:3B:0D:C4:9C:3B:AB:55:33:10:B6:32:06
a=setup:active
a=mid:1
a=sendrecv
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=rtcp-mux
a=rtpmap:96 opus/48000/2
a=fmtp:96 minptime=10;usedtx=1;useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
------------------------------------------
v=0
o=- 4209499349425057536 3 IN IP4 203.0.113.1
s=-
t=0 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4d091157-8680-47a2-b124-36b52fefea19
m=audio PORT RTP/AVP 0 8 9 126
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:126 telephone-event/8000
a=msid:4d091157-8680-47a2-b124-36b52fefea19 ed2eaf3a-926c-4c1a-a315-e02458e05292
a=ssrc:572293880 cname:pHBBuw7Qa5BaQ36a
a=sendrecv
a=ptime:20
SDP


new_call;

offer('AMR asymmetric, control', {}, <<SDP);
v=0
o=ccs-0-615-7 61271729250917 1201132646 IN IP4 10.104.1.81
s=-
c=IN IP4 10.104.1.144
b=AS:80
b=RS:1000
b=RR:3000
t=0 0
a=sendrecv
m=audio 18918 RTP/AVP 96 97 8 98
b=AS:80
b=RS:362
b=RR:1087
a=ptime:20
a=maxptime:40
a=msi:mavodi-0-15b-6c6-2-ffffffff-d3c00000-6005c95738e64-171f-ffffffffffffffff-@127.0.0.1-127.0.0.1;UAG-ELL-45-108
a=rtpmap:96 AMR/8000
a=fmtp:96 mode-set=0,2,4,7;mode-change-period=2;mode-change-neighbor=1;mode-change-capability=2;max-red=0
a=rtpmap:97 AMR/8000
a=fmtp:97 mode-set=7;max-red=0
a=rtpmap:8 PCMA/8000
a=rtpmap:98 telephone-event/8000
a=fmtp:98 0-15
-----------------------------------------
v=0
o=ccs-0-615-7 61271729250917 1201132646 IN IP4 10.104.1.81
s=-
b=AS:80
b=RR:3000
b=RS:1000
t=0 0
m=audio PORT RTP/AVP 96 97 8 98
c=IN IP4 203.0.113.1
b=AS:80
b=RR:1087
b=RS:362
a=rtpmap:96 AMR/8000
a=fmtp:96 mode-set=0,2,4,7;mode-change-period=2;mode-change-neighbor=1;mode-change-capability=2;max-red=0
a=rtpmap:97 AMR/8000
a=fmtp:97 mode-set=7;max-red=0
a=rtpmap:8 PCMA/8000
a=rtpmap:98 telephone-event/8000
a=fmtp:98 0-15
a=msi:mavodi-0-15b-6c6-2-ffffffff-d3c00000-6005c95738e64-171f-ffffffffffffffff-.0.0.1-127.0.0.1;UAG-ELL-45-108
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:40
SDP

answer('AMR asymmetric, control', {}, <<SDP);
v=0
o=- 4694032 4694033 IN IP4 10.104.1.81
s=-
c=IN IP4 10.104.1.141
t=0 0
a=sendrecv
m=audio 18914 RTP/AVP 118 98
c=IN IP4 10.104.1.141
b=RR:1087
b=RS:362
a=rtpmap:118 AMR/8000
a=fmtp:118 mode-set=0,2,4,7;mode-change-period=2;mode-change-capability=2;mode-change-neighbor=1;max-red=0
a=rtpmap:98 telephone-event/8000
a=fmtp:98 0-15
a=ptime:20
a=maxptime:40
-----------------------------------------
v=0
o=- 4694032 4694033 IN IP4 10.104.1.81
s=-
t=0 0
m=audio PORT RTP/AVP 98
c=IN IP4 203.0.113.1
b=RR:1087
b=RS:362
a=rtpmap:98 telephone-event/8000
a=fmtp:98 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:40
SDP


new_call;

offer('AMR asymmetric', {}, <<SDP);
v=0
o=ccs-0-615-7 61271729250917 1201132646 IN IP4 10.104.1.81
s=-
c=IN IP4 10.104.1.144
b=AS:80
b=RS:1000
b=RR:3000
t=0 0
a=sendrecv
m=audio 18918 RTP/AVP 96 97 8 98
b=AS:80
b=RS:362
b=RR:1087
a=ptime:20
a=maxptime:40
a=msi:mavodi-0-15b-6c6-2-ffffffff-d3c00000-6005c95738e64-171f-ffffffffffffffff-@127.0.0.1-127.0.0.1;UAG-ELL-45-108
a=rtpmap:96 AMR/8000
a=fmtp:96 mode-set=0,2,4,7;mode-change-period=2;mode-change-neighbor=1;mode-change-capability=2;max-red=0
a=rtpmap:97 AMR/8000
a=fmtp:97 mode-set=7;max-red=0
a=rtpmap:8 PCMA/8000
a=rtpmap:98 telephone-event/8000
a=fmtp:98 0-15
-----------------------------------------
v=0
o=ccs-0-615-7 61271729250917 1201132646 IN IP4 10.104.1.81
s=-
b=AS:80
b=RR:3000
b=RS:1000
t=0 0
m=audio PORT RTP/AVP 96 97 8 98
c=IN IP4 203.0.113.1
b=AS:80
b=RR:1087
b=RS:362
a=rtpmap:96 AMR/8000
a=fmtp:96 mode-set=0,2,4,7;mode-change-period=2;mode-change-neighbor=1;mode-change-capability=2;max-red=0
a=rtpmap:97 AMR/8000
a=fmtp:97 mode-set=7;max-red=0
a=rtpmap:8 PCMA/8000
a=rtpmap:98 telephone-event/8000
a=fmtp:98 0-15
a=msi:mavodi-0-15b-6c6-2-ffffffff-d3c00000-6005c95738e64-171f-ffffffffffffffff-.0.0.1-127.0.0.1;UAG-ELL-45-108
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:40
SDP

answer('AMR asymmetric', {flags => ['allow asymmetric codecs']}, <<SDP);
v=0
o=test 4694032 4694033 IN IP4 10.104.1.81
s=-
c=IN IP4 10.104.1.141
t=0 0
a=sendrecv
m=audio 18914 RTP/AVP 118 98
c=IN IP4 10.104.1.141
b=RR:1087
b=RS:362
a=rtpmap:118 AMR/8000
a=fmtp:118 mode-set=0,2,4,7;mode-change-period=2;mode-change-capability=2;mode-change-neighbor=1;max-red=0
a=rtpmap:98 telephone-event/8000
a=fmtp:98 0-15
a=ptime:20
a=maxptime:40
-----------------------------------------
v=0
o=test 4694032 4694033 IN IP4 10.104.1.81
s=-
t=0 0
m=audio PORT RTP/AVP 118 98
c=IN IP4 203.0.113.1
b=RR:1087
b=RS:362
a=rtpmap:118 AMR/8000
a=fmtp:118 mode-set=0,2,4,7;mode-change-period=2;mode-change-capability=2;mode-change-neighbor=1;max-red=0
a=rtpmap:98 telephone-event/8000
a=fmtp:98 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:40
SDP

subscribe_request('AMR asymmetric', {flags => [qw/SIPREC all/]}, <<SDP);
v=0
o=ccs-0-615-7 SDP_VERSION IN IP4 10.104.1.81
s=-
t=0 0
m=audio PORT RTP/AVP 118 98
c=IN IP4 203.0.113.1
b=AS:80
b=RR:1087
b=RS:362
a=label:0
a=rtpmap:118 AMR/8000
a=fmtp:118 mode-set=0,2,4,7;mode-change-period=2;mode-change-capability=2;mode-change-neighbor=1;max-red=0
a=rtpmap:98 telephone-event/8000
a=fmtp:98 0-15
a=msi:mavodi-0-15b-6c6-2-ffffffff-d3c00000-6005c95738e64-171f-ffffffffffffffff-@127.0.0.1-127.0.0.1;UAG-ELL-45-108
a=sendonly
a=rtcp:PORT
a=ptime:20
a=maxptime:40
m=audio PORT RTP/AVP 96 98
c=IN IP4 203.0.113.1
b=RR:1087
b=RS:362
a=label:1
a=rtpmap:96 AMR/8000
a=fmtp:96 mode-set=0,2,4,7;mode-change-period=2;mode-change-capability=2;mode-change-neighbor=1;max-red=0
a=rtpmap:98 telephone-event/8000
a=fmtp:98 0-15
a=sendonly
a=rtcp:PORT
a=ptime:20
a=maxptime:40
SDP



# inject DTMF with passthrough

($sock_a, $sock_b) = new_call([qw(198.51.100.50 3000)], [qw(198.51.100.50 3002)]);

($port_a) = offer('inject passthrough',
       { flags => [qw(inject-DTMF)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 8 101
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:101 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('inject passthrough',
       { flags => [qw(inject-DTMF)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3002 RTP/AVP 8 101
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:101 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1001, 3160, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1002, 3320, 0x1234, "\x00" x 160));

snd($sock_b, $port_a, rtp(8, 5000, 7000, 0x5432, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 5000, 7000, 0x5432, "\x00" x 160));
snd($sock_b, $port_a, rtp(8, 5001, 7160, 0x5432, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 5001, 7160, 0x5432, "\x00" x 160));
snd($sock_b, $port_a, rtp(8, 5002, 7320, 0x5432, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 5002, 7320, 0x5432, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
       { 'from-tag' => ft(), code => '0', volume => 10, duration => 100 });

snd($sock_a, $port_b, rtp(8, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(101 | 0x80, 1003, 3480, 0x1234, "\x00\x0a\x00\xa0"));
snd($sock_a, $port_b, rtp(8, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(101, 1004, 3480, 0x1234, "\x00\x0a\x01\x40"));
snd($sock_a, $port_b, rtp(8, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(101, 1005, 3480, 0x1234, "\x00\x0a\x01\xe0"));
snd($sock_a, $port_b, rtp(8, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(101, 1006, 3480, 0x1234, "\x00\x0a\x02\x80"));
snd($sock_a, $port_b, rtp(8, 1007, 4120, 0x1234, "\x00" x 160));
# end event
rcv($sock_b, $port_a, rtpm(101, 1007, 3480, 0x1234, "\x00\x8a\x03\x20"));
rcv($sock_b, $port_a, rtpm(101, 1008, 3480, 0x1234, "\x00\x8a\x03\x20"));
rcv($sock_b, $port_a, rtpm(101, 1009, 3480, 0x1234, "\x00\x8a\x03\x20"));

snd($sock_a, $port_b, rtp(8, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1010, 4280, 0x1234, "\x00" x 160));




# inject DTMF to SRTP with passthrough

($sock_a, $sock_b) = new_call([qw(198.51.100.50 3056)], [qw(198.51.100.50 3058)]);

($port_a) = offer('inject passthrough',
       { flags => [qw(inject-DTMF)], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3056 RTP/SAVP 8 101
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:101 telephone-event/8000
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/SAVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b) = answer('inject passthrough',
       { flags => [qw(inject-DTMF)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3058 RTP/SAVP 8 101
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:101 telephone-event/8000
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Opr7g+J9VgQnRkCFNmL/0LP/dcF1Exu43qwiE0So
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/SAVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Opr7g+J9VgQnRkCFNmL/0LP/dcF1Exu43qwiE0So
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'Opr7g+J9VgQnRkCFNmL/0LP/dcF1Exu43qwiE0So',
};

srtp_snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_a, $port_b, rtp(8, 1001, 3160, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(8, 1001, 3160, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_a, $port_b, rtp(8, 1002, 3320, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(8, 1002, 3320, 0x1234, "\x00" x 160), $srtp_ctx_a);

srtp_snd($sock_b, $port_a, rtp(8, 5000, 7000, 0x5432, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_a, $port_b, rtpm(8, 5000, 7000, 0x5432, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp(8, 5001, 7160, 0x5432, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_a, $port_b, rtpm(8, 5001, 7160, 0x5432, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp(8, 5002, 7320, 0x5432, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_a, $port_b, rtpm(8, 5002, 7320, 0x5432, "\x00" x 160), $srtp_ctx_b);

$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
       { 'from-tag' => ft(), code => '0', volume => 10, duration => 100 });

srtp_snd($sock_a, $port_b, rtp(8, 1003, 3480, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(101 | 0x80, 1003, 3480, 0x1234, "\x00\x0a\x00\xa0"), $srtp_ctx_a);
srtp_snd($sock_a, $port_b, rtp(8, 1004, 3640, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(101, 1004, 3480, 0x1234, "\x00\x0a\x01\x40"), $srtp_ctx_a);
srtp_snd($sock_a, $port_b, rtp(8, 1005, 3800, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(101, 1005, 3480, 0x1234, "\x00\x0a\x01\xe0"), $srtp_ctx_a);
srtp_snd($sock_a, $port_b, rtp(8, 1006, 3960, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(101, 1006, 3480, 0x1234, "\x00\x0a\x02\x80"), $srtp_ctx_a);
srtp_snd($sock_a, $port_b, rtp(8, 1007, 4120, 0x1234, "\x00" x 160), $srtp_ctx_a);
# end event
srtp_rcv($sock_b, $port_a, rtpm(101, 1007, 3480, 0x1234, "\x00\x8a\x03\x20"), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(101, 1008, 3480, 0x1234, "\x00\x8a\x03\x20"), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(101, 1009, 3480, 0x1234, "\x00\x8a\x03\x20"), $srtp_ctx_a);

srtp_snd($sock_a, $port_b, rtp(8, 1008, 4280, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(8, 1010, 4280, 0x1234, "\x00" x 160), $srtp_ctx_a);




# inject DTMF with passthrough and blocking

($sock_a, $sock_b) = new_call([qw(198.51.100.50 3002)], [qw(198.51.100.50 3004)]);

($port_a) = offer('inject passthrough',
       { flags => [qw(inject-DTMF)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3002 RTP/AVP 8 101
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:101 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('inject passthrough',
       { flags => [qw(inject-DTMF)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3004 RTP/AVP 8 101
c=IN IP4 198.51.100.50
a=sendrecv
a=rtpmap:101 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio PORT RTP/AVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

$resp = rtpe_req('block DTMF', 'block DTMF', { 'from-tag' => ft() });

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1001, 3160, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1002, 3320, 0x1234, "\x00" x 160));

snd($sock_a, $port_b, rtp(101 | 0x80, 1003, 3480, 0x1234, "\x02\x14\x00\xa0"));
rcv_no($sock_b);
snd($sock_a, $port_b, rtp(101, 1004, 3480, 0x1234, "\x02\x14\x01\x40"));
rcv_no($sock_b);
snd($sock_a, $port_b, rtp(101, 1005, 3480, 0x1234, "\x02\x14\x01\xe0"));
rcv_no($sock_b);
snd($sock_a, $port_b, rtp(101, 1006, 3480, 0x1234, "\x02\x14\x02\x80"));
rcv_no($sock_b);
snd($sock_a, $port_b, rtp(101, 1007, 3480, 0x1234, "\x02\x14\x03\x20"));
rcv_no($sock_b);
snd($sock_a, $port_b, rtp(101, 1008, 3480, 0x1234, "\x02\x94\x03\xc0"));
rcv_no($sock_b);
snd($sock_a, $port_b, rtp(101, 1009, 3480, 0x1234, "\x02\x94\x03\xc0"));
rcv_no($sock_b);
snd($sock_a, $port_b, rtp(101, 1010, 3480, 0x1234, "\x02\x94\x03\xc0"));
rcv_no($sock_b);

snd($sock_b, $port_a, rtp(8, 5000, 7000, 0x5432, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 5000, 7000, 0x5432, "\x00" x 160));
snd($sock_b, $port_a, rtp(8, 5001, 7160, 0x5432, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 5001, 7160, 0x5432, "\x00" x 160));
snd($sock_b, $port_a, rtp(8, 5002, 7320, 0x5432, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 5002, 7320, 0x5432, "\x00" x 160));

snd($sock_a, $port_b, rtp(8, 1011, 4440, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1011, 4440, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1012, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1012, 4600, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1013, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1013, 4760, 0x1234, "\x00" x 160));


$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
       { 'from-tag' => ft(), code => '0', volume => 10, duration => 100 });

snd($sock_a, $port_b, rtp(8, 1014, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(101 | 0x80, 1014, 4920, 0x1234, "\x00\x0a\x00\xa0"));
snd($sock_a, $port_b, rtp(8, 1015, 5080, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(101, 1015, 4920, 0x1234, "\x00\x0a\x01\x40"));
snd($sock_a, $port_b, rtp(8, 1016, 5240, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(101, 1016, 4920, 0x1234, "\x00\x0a\x01\xe0"));
snd($sock_a, $port_b, rtp(8, 1017, 5400, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(101, 1017, 4920, 0x1234, "\x00\x0a\x02\x80"));
snd($sock_a, $port_b, rtp(8, 1018, 5560, 0x1234, "\x00" x 160));
# end event
rcv($sock_b, $port_a, rtpm(101, 1018, 4920, 0x1234, "\x00\x8a\x03\x20"));
rcv($sock_b, $port_a, rtpm(101, 1019, 4920, 0x1234, "\x00\x8a\x03\x20"));
rcv($sock_b, $port_a, rtpm(101, 1020, 4920, 0x1234, "\x00\x8a\x03\x20"));

snd($sock_a, $port_b, rtp(8, 1019, 5720, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1021, 5720, 0x1234, "\x00" x 160));

snd($sock_a, $port_b, rtp(101 | 0x80, 1021, 6040, 0x1234, "\x03\x26\x00\xa0"));
rcv_no($sock_b);

$resp = rtpe_req('play DTMF', 'inject DTMF towards B over received DTMF',
       { 'from-tag' => ft(), code => '1', volume => 12, duration => 100 });

snd($sock_a, $port_b, rtp(101, 1022, 6040, 0x1234, "\x03\x26\x01\x40"));
rcv_no($sock_b);
snd($sock_a, $port_b, rtp(101, 1023, 6040, 0x1234, "\x03\x26\x01\xe0"));
rcv_no($sock_b);
snd($sock_a, $port_b, rtp(101, 1024, 6040, 0x1234, "\x03\x26\x02\x80"));
rcv($sock_b, $port_a, rtpm(101 | 0x80, 1026, 6520, 0x1234, "\x01\x0c\x00\xa0"));
snd($sock_a, $port_b, rtp(101, 1025, 6040, 0x1234, "\x03\x26\x03\x20"));
rcv($sock_b, $port_a, rtpm(101, 1027, 6520, 0x1234, "\x01\x0c\x01\x40"));
# send end event
snd($sock_a, $port_b, rtp(101, 1026, 6040, 0x1234, "\x03\xa6\x03\xc0"));
snd($sock_a, $port_b, rtp(101, 1027, 6040, 0x1234, "\x03\xa6\x03\xc0"));
snd($sock_a, $port_b, rtp(101, 1028, 6040, 0x1234, "\x03\xa6\x03\xc0"));
rcv($sock_b, $port_a, rtpm(101, 1028, 6520, 0x1234, "\x01\x0c\x01\xe0"));
rcv_no($sock_b);
# send audio, receive end event
snd($sock_a, $port_b, rtp(8, 1029, 7000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(101, 1029, 6520, 0x1234, "\x01\x0c\x02\x80"));
snd($sock_a, $port_b, rtp(8, 1030, 7160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(101, 1030, 6520, 0x1234, "\x01\x8c\x03\x20"));
rcv($sock_b, $port_a, rtpm(101, 1031, 6520, 0x1234, "\x01\x8c\x03\x20"));
rcv($sock_b, $port_a, rtpm(101, 1032, 6520, 0x1234, "\x01\x8c\x03\x20"));

snd($sock_a, $port_b, rtp(8, 1031, 7320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1033, 7320, 0x1234, "\x00" x 160));





if ($extended_tests) {

($sock_a, $sock_b) = new_call([qw(198.51.100.43 6060)], [qw(198.51.100.43 6062)]);

($port_a) = offer('opus fmtp options, full offer list',
	{ codec => { transcode =>
		['opus/48000/2///maxaveragebitrate--40000;maxplaybackrate--32000;sprop-stereo--0;stereo--0;cbr--0;useinbandfec--0;usedtx--0;sprop-maxcapturerate--16000',
		'PCMU'],
	mask => ['all'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6060 RTP/AVP 0 8 101 13
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=rtpmap:13 CN/8000
a=ptime:20
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96 0
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=0; useinbandfec=0; cbr=0; maxplaybackrate=32000; maxaveragebitrate=40000; sprop-maxcapturerate=16000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

($port_b) = answer('opus fmtp options, full offer list',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6062 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 maxaveragebitrate=40000;maxplaybackrate=32000;stereo=0;cbr=0;useinbandfec=0;usedtx=0;sprop-maxcapturerate=16000;sprop-stereo=0
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

snd($sock_a, $port_b, rtp(0, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 8000, 5000, -1, "\x08\x83\xf9\x97\xc1\x5b\x98\x5f\xdf\x55\x5d\x26\xd7\xf9\x54\xf6\xef\xd7\x11\x03\x1e\xab\x07\xdc\x29\x89\x95\x3d\x2b\x5a\x6f\xfd\xb0\x5a\xb8\xce\x6d\xe8\x61\x9d\x30\xcd\x3a\xba\xb8\x40\xae\x03\xab\xbf\x4d\xb7\x4b\x48\x74\xaa\x66\xfa\xcd\x63\x6d\x15\xa4\x8d\x66\x7f\x9d\xa6\x1c"));



($sock_a, $sock_b) = new_call([qw(198.51.100.43 6024)], [qw(198.51.100.43 6026)]);

($port_a) = offer('opus fmtp options, accept stereo',
	{ codec => { transcode => ['PCMA'], mask => ['opus'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6024 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus fmtp options, accept stereo',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6026 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=1; useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(8, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 8000, 5000, -1, "\x0c\x87\xfc\xe4\x56\x3b\x03\xec\x1f\xa8\xa2\x3f\xda\xc0\xca\x15\xec\x3e\xd6\x05\x1d\xc1\xf3\x38\x93\x63\xe5\x28\x64\xbf\x21\x34\x71\x69\xd6\xe3\x22\x5a\x2c\x7c\xbc\x8b\x59\x6e\x40", "\x0c\x87\xfc\xe4\x56\x22\x83\xab\x48\x98\xd0\x47\xeb\xd2\x1c\xa9\x4d\xaa\x15\x4f\xee\x02\xaa\x36\x72\xf1\x17\x3f\x28\xd4\xea\x08\x71\x29\xf2\xf1\xf7\x6a\xa3\xcd\x93\x8d\xed\x23\x00\x9c"));




($sock_a, $sock_b) = new_call([qw(198.51.100.43 6000)], [qw(198.51.100.43 6002)]);

($port_a) = offer('opus fmtp options, default',
	{ codec => { transcode => ['opus'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6000 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus fmtp options, default',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6002 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 8000, 5000, -1, "\x08\x83\x10\x27\x01\x21\xc5\xb4\x16\x83\xf2\x83\x8f\x30\xa2\x91\xbf\x58\x81\xa2\xcc\x6d\x4c\xfa\x89\xd9\xa8\xef\x68\xaf\x8d\x91\x1d\x81\xf4\x1d\x62\x40\x64\x86\xaa\xa2\xc3\x8f\xa2\x62\x58\xc4\xfd\x9d\x98\x7b\xe2\x6f\xc4\x33\x5c\x27\x21\x86\xd7\x11\x2c\x49\xc5\xa7\x40"));




($sock_a, $sock_b) = new_call([qw(198.51.100.43 6004)], [qw(198.51.100.43 6006)]);

($port_a) = offer('opus fmtp options, force stereo',
	{ codec => { transcode => ['opus/48000/2///useinbandfec=1;stereo=1;sprop-stereo=1'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6004 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=1; sprop-stereo=1; useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus fmtp options, force stereo',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6006 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=1; sprop-stereo=1; useinbandfec=1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 8000, 5000, -1, "\x0c\x87\xfc\xe4\x56\x3b\x03\xec\x1f\xa8\xa2\x3f\xda\xc0\xca\x15\xec\x3e\xd6\x05\x1d\xc1\xf3\x38\x93\x63\xe5\x28\x64\xbf\x21\x34\x71\x69\xd6\xe3\x22\x5a\x2c\x7c\xbc\x8b\x59\x6e\x40", "\x0c\x87\xfc\xe4\x56\x22\x83\xab\x48\x98\xd0\x47\xeb\xd2\x1c\xa9\x4d\xaa\x15\x4f\xee\x02\xaa\x36\x72\xf1\x17\x3f\x28\xd4\xea\x08\x71\x29\xf2\xf1\xf7\x6a\xa3\xcd\x93\x8d\xed\x23\x00\x9c"));




($sock_a, $sock_b) = new_call([qw(198.51.100.43 6008)], [qw(198.51.100.43 6010)]);

($port_a) = offer('opus fmtp options, force mono',
	{ codec => { transcode => ['opus/48000/2///useinbandfec=1;stereo=0;sprop-stereo=0'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6008 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=0; useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus fmtp options, force mono',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6010 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=0; useinbandfec=1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 8000, 5000, -1, "\x08\x83\x10\x27\x01\x21\xc5\xb4\x16\x83\xf2\x83\x8f\x30\xa2\x91\xbf\x58\x81\xa2\xcc\x6d\x4c\xfa\x89\xd9\xa8\xef\x68\xaf\x8d\x91\x1d\x81\xf4\x1d\x62\x40\x64\x86\xaa\xa2\xc3\x8f\xa2\x62\x58\xc4\xfd\x9d\x98\x7b\xe2\x6f\xc4\x33\x5c\x27\x21\x86\xd7\x11\x2c\x49\xc5\xa7\x40"));




($sock_a, $sock_b) = new_call([qw(198.51.100.43 6012)], [qw(198.51.100.43 6014)]);

($port_a) = offer('opus fmtp options, stereo 1/0',
	{ codec => { transcode => ['opus/48000/2///stereo=1;sprop-stereo=0'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6012 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=1; sprop-stereo=0
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus fmtp options, stereo 1/0',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6014 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=1; useinbandfec=0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 8000, 5000, -1, "\x08\x83\x10\x27\x01\x21\xc5\xb4\x16\x83\xf2\x83\x8f\x30\xa2\x91\xbf\x58\x81\xa2\xcc\x6d\x4c\xfa\x89\xd9\xa8\xef\x68\xaf\x8d\x91\x1d\x81\xf4\x1d\x62\x40\x64\x86\xaa\xa2\xc3\x8f\xa2\x62\x58\xc4\xfd\x9d\x98\x7b\xe2\x6f\xc4\x33\x5c\x27\x21\x86\xd7\x11\x2c\x49\xc5\xa7\x40"));



($sock_a, $sock_b) = new_call([qw(198.51.100.43 6016)], [qw(198.51.100.43 6018)]);

($port_a) = offer('opus fmtp options, stereo 0/1 (mono)',
	{ codec => { transcode => ['opus/48000/2///stereo=0;sprop-stereo=1'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6016 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; sprop-stereo=1
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus fmtp options, stereo 0/1 (mono)',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6018 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=1; sprop-stereo=0; useinbandfec=0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 8000, 5000, -1, "\x0c\x87\xfc\xe4\x56\x3b\x03\xec\x1f\xa8\xa2\x3f\xda\xc0\xca\x15\xec\x3e\xd6\x05\x1d\xc1\xf3\x38\x93\x63\xe5\x28\x64\xbf\x21\x34\x71\x69\xd6\xe3\x22\x5a\x2c\x7c\xbc\x8b\x59\x6e\x40", "\x0c\x87\xfc\xe4\x56\x22\x83\xab\x48\x98\xd0\x47\xeb\xd2\x1c\xa9\x4d\xaa\x15\x4f\xee\x02\xaa\x36\x72\xf1\x17\x3f\x28\xd4\xea\x08\x71\x29\xf2\xf1\xf7\x6a\xa3\xcd\x93\x8d\xed\x23\x00\x9c"));




($sock_a, $sock_b) = new_call([qw(198.51.100.43 6020)], [qw(198.51.100.43 6022)]);

($port_a) = offer('opus fmtp options, accept default',
	{ codec => { transcode => ['PCMA'], mask => ['opus'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6020 RTP/AVP 96
a=rtpmap:96 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus fmtp options, accept default',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 6022 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(8, 8000, 5000, 0x1234, $pcma_1 . $pcma_2));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 8000, 5000, -1, "\x08\x83\x10\x27\x01\x21\xc5\xb4\x16\x83\xf2\x83\x8f\x30\xa2\x91\xbf\x58\x81\xa2\xcc\x6d\x4c\xfa\x89\xd9\xa8\xef\x68\xaf\x8d\x91\x1d\x81\xf4\x1d\x62\x40\x64\x86\xaa\xa2\xc3\x8f\xa2\x62\x58\xc4\xfd\x9d\x98\x7b\xe2\x6f\xc4\x33\x5c\x27\x21\x86\xd7\x11\x2c\x49\xc5\xa7\x40"));

}



new_call;

offer('legacy OSRTP offer, control',
       { flags  => [ ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6000 RTP/AVP 8
m=audio 6002 RTP/SAVP 8
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

answer('legacy OSRTP offer, control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6038 RTP/AVP 8
m=audio 0 RTP/SAVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
m=audio 0 RTP/SAVP 8
c=IN IP4 0.0.0.0
SDP


new_call;

offer('legacy reverse OSRTP offer, control',
       { flags  => [ ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6002 RTP/SAVP 8
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
m=audio 6000 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('legacy OSRTP offer, control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6038 RTP/SAVP 8
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
m=audio 0 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
m=audio 0 RTP/AVP 8
c=IN IP4 0.0.0.0
SDP


new_call;

offer('legacy reversed OSRTP offer, accept',
       { flags  => [ 'OSRTP-accept' ], 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6032 RTP/SAVP 8
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
m=audio 6030 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('legacy reversed OSRTP offer, accept', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6038 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
m=audio 0 RTP/AVP 8
SDP

offer('legacy reversed OSRTP offer, re-invite',
       { flags  => [ 'OSRTP-accept' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6032 RTP/SAVP 8
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
m=audio 0 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('legacy reversed OSRTP offer, re-invite', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6038 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
m=audio 0 RTP/AVP 8
SDP

reverse_tags();

offer('legacy reversed OSRTP offer, reverse re-invite', { SDES => 'nonew' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6038 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
m=audio 0 RTP/AVP 8
SDP

answer('legacy reversed OSRTP offer, reverse re-invite',
       { flags  => [ 'OSRTP-accept' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6032 RTP/SAVP 8
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
m=audio 0 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('legacy OSRTP offer, accept',
       { flags  => [ 'OSRTP-accept' ], 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6004 RTP/AVP 8
m=audio 6006 RTP/SAVP 8
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('legacy OSRTP offer, accept', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6012 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio 0 RTP/AVP 8
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

offer('legacy OSRTP offer, re-invite',
       { flags  => [ 'OSRTP-accept' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 0 RTP/AVP 8
c=IN IP4 0.0.0.0
m=audio 6006 RTP/SAVP 8
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('legacy OSRTP offer, re-invite', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6012 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio 0 RTP/AVP 8
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

reverse_tags();

offer('legacy OSRTP offer, reverse re-invite', { SDES => 'nonew' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6012 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio 0 RTP/AVP 8
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

answer('legacy OSRTP offer, reverse re-invite',
       { flags  => [ 'OSRTP-accept' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 0 RTP/AVP 8
c=IN IP4 0.0.0.0
m=audio 6006 RTP/SAVP 8
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('add legacy OSRTP offer, reject',
       { flags  => [ 'OSRTP-offer-legacy' ], 'transport-protocol' => 'RTP/SAVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6012 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

answer('add legacy OSRTP offer, reject', { flags  => [ 'OSRTP-accept-legacy' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6014 RTP/AVP 8
m=audio 0 RTP/SAVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


new_call;

offer('add legacy OSRTP offer, accept',
       { flags  => [ 'OSRTP-offer-legacy' ], 'transport-protocol' => 'RTP/SAVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 6020 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

answer('add legacy OSRTP offer, accept', { flags  => [ 'OSRTP-accept-legacy' ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.24
t=0 0
m=audio 0 RTP/AVP 8
m=audio 6016 RTP/SAVP 8
a=crypto:1 AEAD_AES_256_GCM inline:53P5CsePy3hFUcuqsizkCnTE+4OKa1cOGa2WXHjoN19ifpweerTLaj+9vxc
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP





if ($extended_tests) {

new_call;

offer('AMR options test, exact match',
	{ codec => { transcode => ['AMR/8000/1///octet-align=1;mode-change-capability=2'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 96
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1;mode-change-capability=2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1;mode-change-capability=2
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('AMR options test, default', { codec => { transcode => ['AMR'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 96
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1;mode-change-capability=2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1;mode-change-capability=2
a=sendrecv
a=rtcp:PORT
SDP


new_call;

offer('AMR options test, default w/ spacing', { codec => { transcode => ['AMR'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 96
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-change-capability=2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-change-capability=2
a=sendrecv
a=rtcp:PORT
SDP


new_call;

offer('AMR options test, exact match with spacing',
	{ codec => { transcode => ['AMR/8000/1///octet-align=1;mode-change-capability=2'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 96
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-change-capability=2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-change-capability=2
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('AMR options test, partial option',
	{ codec => { transcode => ['AMR/8000/1///octet-align=1'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 96
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-change-capability=2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-change-capability=2
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('AMR options test, incompat',
	{ codec => { transcode => ['AMR/8000/1///octet-align=0'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 96
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-change-capability=2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96 97
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-change-capability=2
a=rtpmap:97 AMR/8000
a=fmtp:97 octet-align=0
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('AMR options test, extra option',
	{ codec => { transcode => ['AMR/8000/1///octet-align=1;mode-set=1,2,3'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 96
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-change-capability=2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96 97
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-change-capability=2
a=rtpmap:97 AMR/8000
a=fmtp:97 octet-align=1;mode-set=1,2,3
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('AMR options test, redundant extra option',
	{ codec => { transcode => ['AMR/8000/1///octet-align=1;mode-set=1,2,3'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 96
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-change-capability=2; mode-set=1,2,3
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-change-capability=2; mode-set=1,2,3
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('AMR options test, exact match with spacing',
	{ codec => { transcode => ['AMR/8000/1///octet-align=1;mode-set=1,2,3'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 96
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-set=1,2,3
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-set=1,2,3
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('AMR options test, partial option',
	{ codec => { transcode => ['AMR/8000/1///octet-align=1'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 96
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-set=1,2,3
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96 97
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-set=1,2,3
a=rtpmap:97 AMR/8000
a=fmtp:97 octet-align=1
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('AMR options test, incompat',
	{ codec => { transcode => ['AMR/8000/1///octet-align=0'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 96
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-set=1,2,3
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96 97
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-set=1,2,3
a=rtpmap:97 AMR/8000
a=fmtp:97 octet-align=0
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('AMR options test, extra option',
	{ codec => { transcode => ['AMR/8000/1///octet-align=1;mode-set=1,2,3,4,5'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 96
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-set=1,2,3
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96 97
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-set=1,2,3
a=rtpmap:97 AMR/8000
a=fmtp:97 octet-align=1;mode-set=1,2,3,4,5
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('AMR options test, redundant extra option',
	{ codec => { transcode => ['AMR/8000/1///octet-align=1;mode-set=1,2,3'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.19
t=0 0
m=audio 6000 RTP/AVP 96
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-set=1,2,3; mode-change-period=2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96 97
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR/8000
a=fmtp:96 octet-align=1; mode-set=1,2,3; mode-change-period=2
a=rtpmap:97 AMR/8000
a=fmtp:97 octet-align=1;mode-set=1,2,3
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('AMR codec accept basic', { codec => { accept => ['AMR-WB'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4020 RTP/AVP 96 8 0
c=IN IP4 198.51.100.4
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=3,4,5; octet-align=1
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8 0
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=3,4,5; octet-align=1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('AMR codec accept basic', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4022 RTP/AVP 8
c=IN IP4 198.51.100.4
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=3,4,5; octet-align=1
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('AMR codec accept basic def option not given', { codec => { accept => ['AMR-WB'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4020 RTP/AVP 96 8 0
c=IN IP4 198.51.100.4
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=3,4,5
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8 0
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=3,4,5
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('AMR codec accept basic def option not given', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4022 RTP/AVP 8
c=IN IP4 198.51.100.4
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=3,4,5
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('AMR codec accept multi', { codec => { accept => ['AMR-WB'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4020 RTP/AVP 96 97 8 0
c=IN IP4 198.51.100.4
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=0
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96 97 8 0
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=0
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('AMR codec accept multi', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4022 RTP/AVP 8
c=IN IP4 198.51.100.4
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('AMR codec accept multi select', { codec => { accept => ['AMR-WB/16000/1///octet-align=0'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4020 RTP/AVP 96 97 8 0
c=IN IP4 198.51.100.4
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=0
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96 97 8 0
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=0
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('AMR codec accept multi select', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4022 RTP/AVP 8
c=IN IP4 198.51.100.4
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 97
c=IN IP4 203.0.113.1
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=0
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('AMR codec accept select compat control', { codec => { accept => ['AMR-WB/16000/1///octet-align=1'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4020 RTP/AVP 96 97 8 0
c=IN IP4 198.51.100.4
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=1; mode-set=2,3,4,5,6
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96 97 8 0
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=1; mode-set=2,3,4,5,6
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('AMR codec accept select compat control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4022 RTP/AVP 8
c=IN IP4 198.51.100.4
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('AMR codec accept select compat 1', { codec => { accept => ['AMR-WB/16000/1///octet-align=1'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4020 RTP/AVP 96 97 8 0
c=IN IP4 198.51.100.4
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=2,3,4,5,6
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=1
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96 97 8 0
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=2,3,4,5,6
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('AMR codec accept select compat 1', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4022 RTP/AVP 8
c=IN IP4 198.51.100.4
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=2,3,4,5,6
a=sendrecv
a=rtcp:PORT
SDP





new_call;

offer('AMR codec accept select compat 2', { codec => { accept => ['AMR-WB/16000/1///octet-align=1'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4020 RTP/AVP 96 97 8 0
c=IN IP4 198.51.100.4
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=2,3,4,5,6
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=1; mode-set=0,1,2,3
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96 97 8 0
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=2,3,4,5,6
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=1; mode-set=0,1,2,3
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('AMR codec accept select compat 2', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4022 RTP/AVP 8
c=IN IP4 198.51.100.4
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=2,3,4,5,6
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('AMR codec accept select compat 3', { codec => { accept => ['AMR-WB/16000/1///octet-align=1;mode-set=2,3,4'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4020 RTP/AVP 96 97 8 0
c=IN IP4 198.51.100.4
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=4,5,6
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=1; mode-set=2,3,4
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96 97 8 0
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=4,5,6
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=1; mode-set=2,3,4
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('AMR codec accept select compat 3', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4022 RTP/AVP 8
c=IN IP4 198.51.100.4
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 97
c=IN IP4 203.0.113.1
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=1; mode-set=2,3,4
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('AMR codec accept select compat 4', { codec => { accept => ['AMR-WB/16000/1///octet-align=1;mode-set=3,4,5,6'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4020 RTP/AVP 96 97 8 0
c=IN IP4 198.51.100.4
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=5,6,7
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=1; mode-set=4,5
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96 97 8 0
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=5,6,7
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=1; mode-set=4,5
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('AMR codec accept select compat 4', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4022 RTP/AVP 8
c=IN IP4 198.51.100.4
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 97
c=IN IP4 203.0.113.1
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=1; mode-set=4,5
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('AMR codec accept select compat 5', { codec => { accept => ['AMR-WB/16000/1///mode-set=3,4,5,6'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4020 RTP/AVP 96 97 98 99 8 0
c=IN IP4 198.51.100.4
a=sendrecv
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=5,6,7
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=1; mode-set=1,2,3
a=rtpmap:98 AMR-WB/16000
a=fmtp:98 mode-set=5,6,7
a=rtpmap:99 AMR-WB/16000
a=fmtp:99 mode-set=4,5
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 96 97 98 99 8 0
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=5,6,7
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=1; mode-set=1,2,3
a=rtpmap:98 AMR-WB/16000
a=fmtp:98 mode-set=5,6,7
a=rtpmap:99 AMR-WB/16000
a=fmtp:99 mode-set=4,5
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('AMR codec accept select compat 5', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio 4022 RTP/AVP 8
c=IN IP4 198.51.100.4
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 99
c=IN IP4 203.0.113.1
a=rtpmap:99 AMR-WB/16000
a=fmtp:99 mode-set=4,5
a=sendrecv
a=rtcp:PORT
SDP




}




new_call;

offer('stray ICE reset after hold',
	{ ICE => 'remove', 'ICE-lite' => 'backward', 'rtcp-mux' => ['demux'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.5
s=tester
t=0 0
c=IN IP4 172.17.0.5
m=audio 4024 RTP/AVP 0
a=ice-pwd:bd5dfhdfddd8e1bc6
a=ice-ufrag:q25293
a=candidate:1 1 UDP 2130706303 172.17.0.5 4024 typ host
a=candidate:1 2 UDP 2130706302 172.17.0.5 4025 typ host
a=rtcp-mux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.5
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_a, undef, $ufrag_a) = answer('stray ICE reset after hold',
	{ ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.5
s=tester
t=0 0
c=IN IP4 172.17.0.5
m=audio 4026 RTP/AVP 0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.5
s=tester
t=0 0
a=ice-lite
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
SDP



offer('stray ICE reset after hold',
	{ ICE => 'remove', 'ICE-lite' => 'backward', 'rtcp-mux' => ['demux'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.5
s=tester
t=0 0
c=IN IP4 172.17.0.5
m=audio 4024 RTP/AVP 0
a=ice-pwd:bd5dfhdfddd8e1bc6
a=ice-ufrag:q25293
a=candidate:1 1 UDP 2130706303 172.17.0.5 4024 typ host
a=rtcp-mux
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.5
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_a, undef, $ufrag_a) = answer('stray ICE reset after hold',
	{ ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.5
s=tester
t=0 0
c=IN IP4 172.17.0.5
m=audio 4026 RTP/AVP 0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.5
s=tester
t=0 0
a=ice-lite
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
SDP



offer('stray ICE reset after hold',
	{ ICE => 'remove', 'ICE-lite' => 'backward', 'rtcp-mux' => ['demux'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.5
s=tester
t=0 0
c=IN IP4 172.17.0.5
m=audio 4024 RTP/AVP 0
a=ice-pwd:bd5dfhdfddd8e1bc6
a=ice-ufrag:q25293
a=candidate:1 1 UDP 2130706303 172.17.0.5 4024 typ host
a=rtcp-mux
a=inactive
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.5
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=inactive
a=rtcp:PORT
SDP

($port_b, undef, $ufrag_b) = answer('stray ICE reset after hold',
	{ replace => ['zero address'], ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.5
s=tester
t=0 0
c=IN IP4 0.0.0.0
m=audio 4026 RTP/AVP 0
a=inactive
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.5
s=tester
t=0 0
a=ice-lite
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=inactive
a=rtcp:PORT
a=rtcp-mux
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
SDP

is($port_a, $port_b, 'port unchanged');
is($ufrag_a, $ufrag_b, 'ufrag unchanged');

reverse_tags();

($port_b, undef, $ufrag_b) = offer('stray ICE reset after hold',
	{ 'ICE-lite' => 'forward', ICE => 'force', 'to-tag' => tt(), 'rtcp-mux' => ['offer'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.5
s=tester
t=0 0
c=IN IP4 172.17.0.5
m=audio 4026 RTP/AVP 0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.5
s=tester
t=0 0
a=ice-lite
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
SDP

is($port_a, $port_b, 'port unchanged');
is($ufrag_a, $ufrag_b, 'ufrag unchanged');



if ($extended_tests) {

# opus encoder options tests

($sock_a, $sock_b) = new_call([qw(198.51.100.16 6000)], [qw(198.51.100.16 6002)]);

($port_a) = offer('opus encoder control, forward tc',
	{ codec => { transcode => ['opus/48000/2'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6000 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus encoder control, forward tc',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6002 RTP/AVP 96
a=rtpmap:96 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(8, 1000, 3000, 0x1234, $pcma_1));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 1000, 3000, -1, "\x08\x83\x10\x27\x01\x21\xc5\xb4\x16\x83\xf2\x83\x8f\x30\xa2\x91\xbf\x58\x81\xa2\xcc\x6d\x4c\xfa\x89\xd9\xa8\xef\x68\xaf\x8d\x91\x1d\x81\xf4\x1d\x62\x40\x64\x86\xaa\xa2\xc3\x8f\xa2\x62\x58\xc4\xfd\x9d\x98\x7b\xe2\x6f\xc4\x33\x5c\x27\x21\x86\xd7\x11\x2c\x49\xc5\xa7\x40"));
snd($sock_a, $port_b,  rtp(8, 1001, 3160, 0x1234, $pcma_1));
rcv($sock_b, $port_a, rtpm(96, 1001, 3960, $ssrc, "\x08\xb1\x0e\x10\x08\xb3\xa6\xc5\xe6\x04\xc7\x72\x8e\x72\xe8\x4c\x21\xf8\x1c\x5b\x74\x28\x40\x5d\xef\x39\xfb\xa0\xbc\x29\x74\x81\x9c\xd7\x45\x76\x56\x39\xb5\xcf\xa4\x25\xee\x89\xd4\x43\x19\x5a\x5c\xdb\x26\x9b\xec\x24\xcd\xc0"));



($sock_a, $sock_b) = new_call([qw(198.51.100.16 6032)], [qw(198.51.100.16 6034)]);

($port_a) = offer('opus encoder control, application audio',
	{ codec => { transcode => ['opus/48000/2////application=audio'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6032 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus encoder control, application audio',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6034 RTP/AVP 96
a=rtpmap:96 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(8, 1000, 3000, 0x1234, $pcma_1));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 1000, 3000, -1, "\x98\xb5\x0e\x7d\x91\xb5\x16\xd8\xd8\x10\x27\xd1\xe5\x77\xdb\xe5\x86\x37\x13\x5e\x3e\xae\xd1\xa4\xf3\x88\xd9\x3c\x7f\x6e\xdf\x47\xe4\x05\x35\xaa\xda\xd4\xb7\xcc\xc3\x14\x06\x64\x37\x91\xca\xb1\x53\x93\x7b\x75\x21\xcf\x17\x72\x2a\xae\xbd\xfc\x62\x03\x8e\x64\x18\x5f\xd2\x88\xbb\x13\xb0\xac\x7b\x84\xa4\x8a\x24\xdf\x2e\x45\x9d\x65\x17\xd4\x47\x3f\x78\xd6\xce\x8e\x06\xc7\x88\xe0\x6a\x5e\x6d\x74\x1c\xca\x86\xe9\x7c\xa1\x01\xbc\x1c\xc1\xaa\x5c\x55\xb9\x98\x64\x79\x49\x27\x41\xbb\x22\xea\x1a\x9c\x6f\x95\xc5\xc0\xdd\xfd\xad"));
snd($sock_a, $port_b,  rtp(8, 1001, 3160, 0x1234, $pcma_1));
rcv($sock_b, $port_a, rtpm(96, 1001, 3960, $ssrc, "\x98\xab\xb2\x67\x01\x72\x4c\xdf\xd0\xf4\x3c\xb8\x3d\x53\x00\x48\x82\x55\xfd\x46\xd9\xb8\x2b\x41\xf5\x0d\x0d\x86\x9d\xcc\x40\xa0\x81\xb6\xfa\x39\x44\x21\x3f\x40\x9b\xef\xc1\x04\xb4\x0e\x3c\x98\xdb\x77\xe0\x1d\xbc\x70\x8a\xc5\xc2\x0d\x3d\x35\x12\x8b\xe2\x92\x78\xb1\x32\xfe\xc6\x62\x5a\x4e\x77\x3a\x67\xd4\x30\x9a\xaf\x2f\x4a\x20\x34\x8e\xa1\xaf\xdd\x90\x5e\x66\x12\x7d\xad"));



($sock_a, $sock_b) = new_call([qw(198.51.100.16 6004)], [qw(198.51.100.16 6006)]);

($port_a) = offer('opus encoder lower bitrate, forward tc',
	{ codec => { transcode => ['opus/48000/2/16000'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6004 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus encoder lower bitrate, forward tc',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6006 RTP/AVP 96
a=rtpmap:96 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(8, 1000, 3000, 0x1234, $pcma_1));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 1000, 3000, -1, "\x08\x84\x55\xa7\x01\x21\xc5\xb4\x16\x83\xe3\x4e\xf1\x9d\xe4\x66\x50\xd8\x76\x62\x6f\xe2\xde\x26\x7a\x1e\xe4\xc6\xc8\x50\xdb\x27\x8d\x66\xfa\xe2\xb0\x0d\x70"));
snd($sock_a, $port_b,  rtp(8, 1001, 3160, 0x1234, $pcma_1));
rcv($sock_b, $port_a, rtpm(96, 1001, 3960, $ssrc, "\x08\xb9\x15\x70\xe6\xab\xd0\x63\xd0\x90\xc4\x93\x80\xa5\x1e\xd7\x39\x6c\x77\xb3\x85\xbb\x1b\x65\xe5\x8a\xc7\x68"));




($sock_a, $sock_b) = new_call([qw(198.51.100.16 6008)], [qw(198.51.100.16 6010)]);

($port_a) = offer('opus encoder lower complexity, forward tc',
	{ codec => { transcode => ['opus/48000/2////compression_level=2'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6008 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus encoder lower complexity, forward tc',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6010 RTP/AVP 96
a=rtpmap:96 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(8, 1000, 3000, 0x1234, $pcma_1));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 1000, 3000, -1, "\x08\x82\xe2\x33\x5a\x06\xe3\x74\xfa\x41\xdc\x7f\x11\xc5\x94\xd6\xb1\x7a\xee\xe8\xa3\x16\xc7\xb1\xea\x49\xc6\xaa\x18\x8b\x08\x7a\xba\x52\xe9\x8c\xf7\xa2\x74\x89\x74\x1f\xd9\x9f\x7c\x64\xa2\x29\xb1\x2d\xc2\x17\x5b\x33\xc1\x8a\xb8\x49\xa9\x31\xa0\x70\x08\xb5\x73\xd7"));
snd($sock_a, $port_b,  rtp(8, 1001, 3160, 0x1234, $pcma_1));
rcv($sock_b, $port_a, rtpm(96, 1001, 3960, $ssrc, "\x08\xaf\x62\x1a\xdf\x03\xd5\xd8\x45\xbe\xf9\x28\x7c\x38\x44\xbd\x5a\x3f\x68\x93\x41\xbb\x52\x05\x73\xc5\x2e\x9e\x63\x99\x19\xd0\xf8\xa7\xac\xc8\x7b\xc0\x06\x25\x2e\xac\xa7\xb2\xbb\x1b\xb8\xe4\x50\x68\x68\xd1\x24\xc7\x2a\xc0"));


($sock_a, $sock_b) = new_call([qw(198.51.100.16 6012)], [qw(198.51.100.16 6014)]);

($port_a) = offer('opus encoder lower bitrate lower complexity, forward tc',
	{ codec => { transcode => ['opus/48000/2/16000///compression_level=2'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6012 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus encoder lower bitrate lower complexity, forward tc',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6014 RTP/AVP 96
a=rtpmap:96 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(8, 1000, 3000, 0x1234, $pcma_1));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 1000, 3000, -1, "\x08\x83\xf9\x5e\xdd\x07\x1e\x3c\xdf\xb8\xc4\x87\x5c\x22\x08\xd0\x2d\x33\x7b\xdc\xee\xbe\x79\x1c\x3e\x47\x2c\x49\x24\xda\x4d\xfc\xc3\xa7\x17"));
snd($sock_a, $port_b,  rtp(8, 1001, 3160, 0x1234, $pcma_1));
rcv($sock_b, $port_a, rtpm(96, 1001, 3960, $ssrc, "\x08\xb8\x2f\xff\x50\x7f\x50\xd1\xf3\x37\x7d\x66\xb7\x48\x21\xb8\x02\x72\x52\x5b\xb7\xdb\x4e\x72\x41\xe6\xc6\xdb\xba\x97\x6f\xc0"));



($sock_a, $sock_b) = new_call([qw(198.51.100.16 6016)], [qw(198.51.100.16 6018)]);

($port_a) = offer('opus encoder control, reverse tc',
	{ codec => { transcode => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6016 RTP/AVP 96
a=rtpmap:96 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus encoder control, reverse tc',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6018 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a,  rtp(8, 1000, 3000, 0x1234, $pcma_1));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\x08\x83\x10\x27\x01\x21\xc5\xb4\x16\x83\xf2\x83\x8f\x30\xa2\x91\xbf\x58\x81\xa2\xcc\x6d\x4c\xfa\x89\xd9\xa8\xef\x68\xaf\x8d\x91\x1d\x81\xf4\x1d\x62\x40\x64\x86\xaa\xa2\xc3\x8f\xa2\x62\x58\xc4\xfd\x9d\x98\x7b\xe2\x6f\xc4\x33\x5c\x27\x21\x86\xd7\x11\x2c\x49\xc5\xa7\x40"));
snd($sock_b, $port_a,  rtp(8, 1001, 3160, 0x1234, $pcma_1));
rcv($sock_a, $port_b, rtpm(96, 1001, 3960, $ssrc, "\x08\xb1\x0e\x10\x08\xb3\xa6\xc5\xe6\x04\xc7\x72\x8e\x72\xe8\x4c\x21\xf8\x1c\x5b\x74\x28\x40\x5d\xef\x39\xfb\xa0\xbc\x29\x74\x81\x9c\xd7\x45\x76\x56\x39\xb5\xcf\xa4\x25\xee\x89\xd4\x43\x19\x5a\x5c\xdb\x26\x9b\xec\x24\xcd\xc0"));




($sock_a, $sock_b) = new_call([qw(198.51.100.16 6048)], [qw(198.51.100.16 6050)]);

($port_a) = offer('opus encoder control, reverse tc, application audio',
	{ codec => { transcode => ['PCMA'], set => ['opus/48000/2////application=audio'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6048 RTP/AVP 96
a=rtpmap:96 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus encoder control, reverse tc, application audio',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6050 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a,  rtp(8, 1000, 3000, 0x1234, $pcma_1));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\x98\xb5\x0e\x7d\x91\xb5\x16\xd8\xd8\x10\x27\xd1\xe5\x77\xdb\xe5\x86\x37\x13\x5e\x3e\xae\xd1\xa4\xf3\x88\xd9\x3c\x7f\x6e\xdf\x47\xe4\x05\x35\xaa\xda\xd4\xb7\xcc\xc3\x14\x06\x64\x37\x91\xca\xb1\x53\x93\x7b\x75\x21\xcf\x17\x72\x2a\xae\xbd\xfc\x62\x03\x8e\x64\x18\x5f\xd2\x88\xbb\x13\xb0\xac\x7b\x84\xa4\x8a\x24\xdf\x2e\x45\x9d\x65\x17\xd4\x47\x3f\x78\xd6\xce\x8e\x06\xc7\x88\xe0\x6a\x5e\x6d\x74\x1c\xca\x86\xe9\x7c\xa1\x01\xbc\x1c\xc1\xaa\x5c\x55\xb9\x98\x64\x79\x49\x27\x41\xbb\x22\xea\x1a\x9c\x6f\x95\xc5\xc0\xdd\xfd\xad"));
snd($sock_b, $port_a,  rtp(8, 1001, 3160, 0x1234, $pcma_1));
rcv($sock_a, $port_b, rtpm(96, 1001, 3960, $ssrc, "\x98\xab\xb2\x67\x01\x72\x4c\xdf\xd0\xf4\x3c\xb8\x3d\x53\x00\x48\x82\x55\xfd\x46\xd9\xb8\x2b\x41\xf5\x0d\x0d\x86\x9d\xcc\x40\xa0\x81\xb6\xfa\x39\x44\x21\x3f\x40\x9b\xef\xc1\x04\xb4\x0e\x3c\x98\xdb\x77\xe0\x1d\xbc\x70\x8a\xc5\xc2\x0d\x3d\x35\x12\x8b\xe2\x92\x78\xb1\x32\xfe\xc6\x62\x5a\x4e\x77\x3a\x67\xd4\x30\x9a\xaf\x2f\x4a\x20\x34\x8e\xa1\xaf\xdd\x90\x5e\x66\x12\x7d\xad"));




($sock_a, $sock_b) = new_call([qw(198.51.100.16 6020)], [qw(198.51.100.16 6022)]);

($port_a) = offer('opus encoder lower bitrate, reverse tc',
	{ codec => { transcode => ['PCMA'], set => ['opus/48000/2/16000'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6020 RTP/AVP 96
a=rtpmap:96 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus encoder lower bitrate, reverse tc',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6022 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a,  rtp(8, 1000, 3000, 0x1234, $pcma_1));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\x08\x84\x55\xa7\x01\x21\xc5\xb4\x16\x83\xe3\x4e\xf1\x9d\xe4\x66\x50\xd8\x76\x62\x6f\xe2\xde\x26\x7a\x1e\xe4\xc6\xc8\x50\xdb\x27\x8d\x66\xfa\xe2\xb0\x0d\x70"));
snd($sock_b, $port_a,  rtp(8, 1001, 3160, 0x1234, $pcma_1));
rcv($sock_a, $port_b, rtpm(96, 1001, 3960, $ssrc, "\x08\xb9\x15\x70\xe6\xab\xd0\x63\xd0\x90\xc4\x93\x80\xa5\x1e\xd7\x39\x6c\x77\xb3\x85\xbb\x1b\x65\xe5\x8a\xc7\x68"));



($sock_a, $sock_b) = new_call([qw(198.51.100.16 6024)], [qw(198.51.100.16 6026)]);

($port_a) = offer('opus encoder lower complexity, reverse tc',
	{ codec => { transcode => ['PCMA'], set => ['opus/48000/2////compression_level=2'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6024 RTP/AVP 96
a=rtpmap:96 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus encoder lower complexity, reverse tc',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6026 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a,  rtp(8, 1000, 3000, 0x1234, $pcma_1));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\x08\x82\xe2\x33\x5a\x06\xe3\x74\xfa\x41\xdc\x7f\x11\xc5\x94\xd6\xb1\x7a\xee\xe8\xa3\x16\xc7\xb1\xea\x49\xc6\xaa\x18\x8b\x08\x7a\xba\x52\xe9\x8c\xf7\xa2\x74\x89\x74\x1f\xd9\x9f\x7c\x64\xa2\x29\xb1\x2d\xc2\x17\x5b\x33\xc1\x8a\xb8\x49\xa9\x31\xa0\x70\x08\xb5\x73\xd7"));
snd($sock_b, $port_a,  rtp(8, 1001, 3160, 0x1234, $pcma_1));
rcv($sock_a, $port_b, rtpm(96, 1001, 3960, $ssrc, "\x08\xaf\x62\x1a\xdf\x03\xd5\xd8\x45\xbe\xf9\x28\x7c\x38\x44\xbd\x5a\x3f\x68\x93\x41\xbb\x52\x05\x73\xc5\x2e\x9e\x63\x99\x19\xd0\xf8\xa7\xac\xc8\x7b\xc0\x06\x25\x2e\xac\xa7\xb2\xbb\x1b\xb8\xe4\x50\x68\x68\xd1\x24\xc7\x2a\xc0"));



($sock_a, $sock_b) = new_call([qw(198.51.100.16 6028)], [qw(198.51.100.16 6030)]);

($port_a) = offer('opus encoder lower bitrate lower complexity, reverse tc',
	{ codec => { transcode => ['PCMA'], set => ['opus/48000/2/16000///compression_level=2'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6028 RTP/AVP 96
a=rtpmap:96 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('opus encoder lower complexity, reverse tc',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 198.51.100.16
t=0 0
m=audio 6030 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a,  rtp(8, 1000, 3000, 0x1234, $pcma_1));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\x08\x83\xf9\x5e\xdd\x07\x1e\x3c\xdf\xb8\xc4\x87\x5c\x22\x08\xd0\x2d\x33\x7b\xdc\xee\xbe\x79\x1c\x3e\x47\x2c\x49\x24\xda\x4d\xfc\xc3\xa7\x17"));
snd($sock_b, $port_a,  rtp(8, 1001, 3160, 0x1234, $pcma_1));
rcv($sock_a, $port_b, rtpm(96, 1001, 3960, $ssrc, "\x08\xb8\x2f\xff\x50\x7f\x50\xd1\xf3\x37\x7d\x66\xb7\x48\x21\xb8\x02\x72\x52\x5b\xb7\xdb\x4e\x72\x41\xe6\xc6\xdb\xba\x97\x6f\xc0"));


}


new_call;

offer('DTMF PT reduction',
	{ codec => { transcode => ['PCMA', 'PCMU'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 172.17.0.2
t=0 0
m=audio 4024 RTP/AVP 109 104 110 102 108 105 100
a=rtpmap:109 EVS/16000
a=fmtp:109 br=5.9-24.4; bw=nb-swb; max-red=220; cmr=1; ch-aw-recv=3
a=rtpmap:104 speex/16000
a=fmtp:104 max-red=0; mode-change-capability=2
a=rtpmap:110 speex/16000
a=fmtp:110 octet-align=1; max-red=0; mode-change-capability=2
a=rtpmap:102 G722/8000
a=fmtp:102 max-red=0; mode-change-capability=2
a=rtpmap:108 G722/8000
a=fmtp:108 octet-align=1; max-red=0; mode-change-capability=2
a=rtpmap:105 telephone-event/16000
a=fmtp:105 0-15
a=rtpmap:100 telephone-event/8000
a=fmtp:100 0-15
a=ptime:20
a=maxptime:240
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 104 110 102 108 8 0 105 100
c=IN IP4 203.0.113.1
a=rtpmap:104 speex/16000
a=fmtp:104 max-red=0; mode-change-capability=2
a=rtpmap:110 speex/16000
a=fmtp:110 octet-align=1; max-red=0; mode-change-capability=2
a=rtpmap:102 G722/8000
a=fmtp:102 max-red=0; mode-change-capability=2
a=rtpmap:108 G722/8000
a=fmtp:108 octet-align=1; max-red=0; mode-change-capability=2
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:105 telephone-event/16000
a=fmtp:105 0-15
a=rtpmap:100 telephone-event/8000
a=fmtp:100 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:240
SDP

answer('DTMF PT reduction',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
c=IN IP4 172.17.0.2
t=0 0
m=audio 33548 RTP/AVP 8 100
a=direction:both
a=rtpmap:8 PCMA/8000
a=rtpmap:100 telephone-event/8000
a=fmtp:100 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 104 105
c=IN IP4 203.0.113.1
a=rtpmap:104 speex/16000
a=fmtp:104 max-red=0; mode-change-capability=2
a=rtpmap:105 telephone-event/16000
a=fmtp:105 0-15
a=direction:both
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP




new_call;

offer('GH 1499',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
c=IN IP4 172.17.0.2
m=audio 4024 RTP/AVP 0 9 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0 9 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('GH 1499',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
c=IN IP4 172.17.0.2
m=audio 4026 RTP/AVP 8 101
a=rtpmap:101 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


new_call;

offer('GH 1499 corollary',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
c=IN IP4 172.17.0.2
m=audio 4024 RTP/AVP 0 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('GH 1499 corollary',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
c=IN IP4 172.17.0.2
m=audio 4026 RTP/AVP 8 9
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


new_call;

offer('GH 1499 control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
c=IN IP4 172.17.0.2
m=audio 4024 RTP/AVP 0 8
m=audio 4026 RTP/AVP 8 9
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/AVP 8 9
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('GH 1499 control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
c=IN IP4 172.17.0.2
m=audio 4026 RTP/AVP 8 9
m=audio 0 RTP/AVP 0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 172.17.0.2
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
m=audio 0 RTP/AVP 8
c=IN IP4 0.0.0.0
SDP
# ^ technically fishy - rejected stream should not do offer/answer and should just
# pass through 0 instead




($sock_a, $sock_b, $sock_c, $sock_d) = new_call([qw(198.51.100.4 2412)], [qw(198.51.100.4 2413)], [qw(198.51.100.8 3412)], [qw(198.51.100.8 3413)]);

offer('ICE with just peer reflexive',
	{ ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
c=IN IP4 198.51.100.4
t=0 0
a=sendrecv
m=audio 2412 RTP/AVP 0
a=ice-pwd:bd5e8b8d6dd8e1bc6
a=ice-ufrag:q27e93
a=candidate:1 1 UDP 2130706303 198.51.100.4 2412 typ host
a=candidate:1 2 UDP 2130706302 198.51.100.4 2413 typ host
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_a, $port_ax, $ufrag_a, $ufrag_b, undef, $port_b, undef, undef, undef, $port_bx)
		= answer('ICE with just peer reflexive',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
c=IN IP4 198.51.100.4
t=0 0
a=sendrecv
m=audio 2422 RTP/AVP 0
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

is($port_a, $port_b, 'ICE port matches');
is($port_ax, $port_bx, 'ICE port matches');

# consume STUN checks, but don't respond
rcv($sock_a, -1, qr/^\x00\x01\x00.\x21\x12\xa4\x42/s);
rcv($sock_b, -1, qr/^\x00\x01\x00.\x21\x12\xa4\x42/s);

# send our own STUN checks from different port, resulting in learned prflx candidates
my ($packet, $tid) = stun_req(1, 65527, 1, 'q27e93', $ufrag_a, $ufrag_b);
snd($sock_c, $port_a, $packet);

$has_recv = 0;

while ($has_recv != 3) {
	# receive STUN packet, either triggered check or success
	@ret2 = rcv($sock_c, $port_a, qr/^\x01(\x01)\x00.\x21\x12\xa4\x42\Q$tid\E|^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine/s);
	if ($ret2[0]) {
		# STUN success
		$has_recv |= 1;
	}
	elsif ($ret2[1]) {
		# triggered check
		@ret1 = @ret2;
		$has_recv |= 2;
	}
}

# respond with success
snd($sock_c, $port_a, stun_succ($port_a, $ret1[1], 'bd5e8b8d6dd8e1bc6'));

# repeat for RTCP
($packet, $tid) = stun_req(1, 65527, 2, 'q27e93', $ufrag_a, $ufrag_b);
snd($sock_d, $port_ax, $packet);
$has_recv = 0;
while ($has_recv != 3) {
	@ret2 = rcv($sock_d, $port_ax, qr/^\x01(\x01)\x00.\x21\x12\xa4\x42\Q$tid\E|^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine/s);
	if ($ret2[0]) {
		$has_recv |= 1;
	}
	elsif ($ret2[1]) {
		@ret1 = @ret2;
		$has_recv |= 2;
	}
}
snd($sock_d, $port_ax, stun_succ($port_b, $ret1[1], 'bd5e8b8d6dd8e1bc6'));





($sock_a, $sock_b, $sock_c, $sock_d) = new_call([qw(198.51.100.4 2436)], [qw(198.51.100.4 2437)], [qw(198.51.100.8 3436)], [qw(198.51.100.8 3437)]);

($port_a, $port_ax, $ufrag_a, $ufrag_b, undef, $port_b, undef, undef, undef, $port_bx)
		= offer('ICE with just peer reflexive, controlled',
	{ ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
c=IN IP4 198.51.100.4
t=0 0
a=sendrecv
m=audio 2428 RTP/AVP 0
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('ICE with just peer reflexive, controlled',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
c=IN IP4 198.51.100.4
t=0 0
a=sendrecv
m=audio 2436 RTP/AVP 0
a=ice-pwd:bd5e8b8d6dd8e1bc6
a=ice-ufrag:q27e93
a=candidate:1 1 UDP 2130706303 198.51.100.4 2436 typ host
a=candidate:1 2 UDP 2130706302 198.51.100.4 2437 typ host
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.4
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

is($port_a, $port_b, 'ICE port matches');
is($port_ax, $port_bx, 'ICE port matches');

# consume STUN checks, but don't respond
rcv($sock_a, -1, qr/^\x00\x01\x00.\x21\x12\xa4\x42/s);
rcv($sock_b, -1, qr/^\x00\x01\x00.\x21\x12\xa4\x42/s);

# send our own STUN checks from different port, resulting in learned prflx candidates
($packet, $tid) = stun_req(0, 65527, 1, 'q27e93', $ufrag_a, $ufrag_b);
snd($sock_c, $port_a, $packet);

$has_recv = 0;

while ($has_recv != 3) {
	# receive STUN packet, either triggered check or success
	@ret2 = rcv($sock_c, $port_a, qr/^\x01(\x01)\x00.\x21\x12\xa4\x42\Q$tid\E|^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine/s);
	if ($ret2[0]) {
		# STUN success
		$has_recv |= 1;
	}
	elsif ($ret2[1]) {
		# triggered check
		@ret1 = @ret2;
		$has_recv |= 2;
	}
}

# respond with success
snd($sock_c, $port_a, stun_succ($port_a, $ret1[1], 'bd5e8b8d6dd8e1bc6'));

# repeat for RTCP
($packet, $tid) = stun_req(0, 65527, 2, 'q27e93', $ufrag_a, $ufrag_b);
snd($sock_d, $port_ax, $packet);
$has_recv = 0;
while ($has_recv != 3) {
	@ret2 = rcv($sock_d, $port_ax, qr/^\x01(\x01)\x00.\x21\x12\xa4\x42\Q$tid\E|^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine/s);
	if ($ret2[0]) {
		$has_recv |= 1;
	}
	elsif ($ret2[1]) {
		@ret1 = @ret2;
		$has_recv |= 2;
	}
}
snd($sock_d, $port_ax, stun_succ($port_b, $ret1[1], 'bd5e8b8d6dd8e1bc6'));

# wait for nominations
@ret1 = rcv($sock_c, $port_a, qr/^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine.*\x00\x25/s);
@ret1 = rcv($sock_d, $port_ax, qr/^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine.*\x00\x25/s);





($sock_a, $sock_b) = new_call([qw(198.51.100.1 4370)], [qw(198.51.100.3 4372)]);

($port_a) = offer('ROC reset after re-invite',
	{ 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
a=sendrecv
m=audio 4370 RTP/SAVP 0
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
a=crypto:2 AEAD_AES_128_GCM inline:8wyZzreYaVyPCO6svztEPaFxzrytDfEBdzE++w
a=fingerprint:sha-256 F8:31:36:7B:ED:6D:12:CC:E8:A8:BF:C3:07:6F:FB:C4:EC:02:BE:70:12:B6:87:B6:C3:F8:47:11:49:30:E0:22
a=setup:actpass
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

($port_b, undef, $srtp_key_a) = answer('ROC reset after re-invite', { DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.3
t=0 0
a=sendrecv
m=audio 4372 RTP/AVP 0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_a,
};

# consume DTLS
rcv($sock_a, -1, qr/^\x16\xfe\xff\x00\x00\x00\x00\x00\x00\x00/);

snd($sock_b, $port_a, rtp(0, 65534, 4000, 0x6543, "\x00" x 160));
srtp_rcv($sock_a, $port_b, rtpm(0, 65534, 4000, -1, "\x00" x 160), $srtp_ctx_a);
is($srtp_ctx_a->{roc}, 0, "initial zero ROC");
snd($sock_b, $port_a, rtp(0, 65535, 4160, 0x6543, "\x00" x 160));
srtp_rcv($sock_a, $port_b, rtpm(0, 65535, 4160, -1, "\x00" x 160), $srtp_ctx_a);
is($srtp_ctx_a->{roc}, 0, "initial zero ROC");
snd($sock_b, $port_a, rtp(0, 0, 4320, 0x6543, "\x00" x 160));
srtp_rcv($sock_a, $port_b, rtpm(0, 0, 4320, -1, "\x00" x 160), $srtp_ctx_a);
is($srtp_ctx_a->{roc}, 1, "ROC increase");

($port_ax) = offer('ROC reset after re-invite',
	{ 'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
a=sendrecv
m=audio 4370 RTP/SAVP 0
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
a=crypto:2 AEAD_AES_128_GCM inline:Dvjk5xrZDgGNFX+Xv2D5bV3Em+IXiRzX5U6F6A
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
is($port_a, $port_ax, "port match");

($port_bx, undef, $srtp_key_b) = answer('ROC reset after re-invite', { DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.3
t=0 0
a=sendrecv
m=audio 4372 RTP/AVP 0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP
is($port_b, $port_bx, "port match");
is($srtp_key_a, $srtp_key_b, 'key match');

snd($sock_b, $port_a, rtp(0, 1, 4480, 0x6543, "\x00" x 160));
srtp_rcv($sock_a, $port_b, rtpm(0, 1, 4480, -1, "\x00" x 160), $srtp_ctx_a);
is($srtp_ctx_a->{roc}, 1, "ROC unchanged");



new_call;

offer('ICE restart',
	{ ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 198.51.100.1
a=ice-pwd:bd5e845657ecb8d6dd8e1bc6
a=ice-ufrag:q2758e93
a=candidate:1 1 UDP 2130706303 198.51.100.4 6126 typ host
a=candidate:1 2 UDP 2130706302 198.51.100.4 6127 typ host
a=candidate:2 1 UDP 2130706301 198.51.100.8 7126 typ host
a=candidate:2 2 UDP 2130706300 198.51.100.8 7127 typ host
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_a, undef, $ufrag_a) = answer('ICE restart',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

offer('ICE restart',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 198.51.100.1
a=ice-pwd:bd5e8gssdfecb8d6dd8e1bc6
a=ice-ufrag:qdgsdfs3
a=candidate:1 1 UDP 2130706303 198.51.100.7 6126 typ host
a=candidate:1 2 UDP 2130706302 198.51.100.7 6127 typ host
a=candidate:2 1 UDP 2130706301 198.51.100.9 7126 typ host
a=candidate:2 2 UDP 2130706300 198.51.100.9 7127 typ host
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, undef, $ufrag_b) = answer('ICE restart',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

is($port_a, $port_b, 'port match');
isnt($ufrag_a, $ufrag_b, 'ufrag mismatch');



new_call;

offer('re-invite with unsupported primary codec', {
	codec => { transcode => [qw(PCMA G722 PCMU)] }
}, <<SDP);
v=0
o=- 36581458169058 3658145816 IN IP4 192.168.1.1
s=TELES-SBC
c=IN IP4 192.168.1.1
t=0 0
m=audio 20832 RTP/AVP 8 102 101
a=rtpmap:8 PCMA/8000
a=rtpmap:102 telephone-event/8000
a=fmtp:102 0-15
a=rtpmap:101 telephone-event/16000
a=fmtp:101 0-15
a=maxptime:240
a=sendrecv
a=ptime:20
----------------------------------
v=0
o=- 36581458169058 3658145816 IN IP4 192.168.1.1
s=TELES-SBC
t=0 0
m=audio PORT RTP/AVP 8 9 0 102 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:102 telephone-event/8000
a=fmtp:102 0-15
a=rtpmap:101 telephone-event/16000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:240
SDP

answer('re-invite with unsupported primary codec', { }, <<SDP);
v=0
o=user 14175398 14175398 IN IP4 192.168.1.1
s=TELES-SBC
c=IN IP4 192.168.1.1
t=0 0
m=audio 7078 RTP/AVP 8 0 102
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:102 telephone-event/8000
a=fmtp:102 0-15
a=sendrecv
a=rtcp:7079
a=ptime:20
----------------------------------
v=0
o=user 14175398 14175398 IN IP4 192.168.1.1
s=TELES-SBC
t=0 0
m=audio PORT RTP/AVP 8 102
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:102 telephone-event/8000
a=fmtp:102 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

reverse_tags();

offer('re-invite with unsupported primary codec', {
	codec => { transcode => [qw(PCMA G722 PCMU)] }
}, <<SDP);
v=0
o=user 14175398 14175399 IN IP4 192.168.1.1
s=call
c=IN IP4 192.168.1.1
t=0 0
m=audio 7078 RTP/AVP 2 102 100 99 97 8 0 101
a=rtpmap:2 G726-32/8000
a=rtpmap:102 G726-32/8000
a=rtpmap:100 G726-40/8000
a=rtpmap:99 G726-24/8000
a=rtpmap:97 G722/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendonly
a=rtcp:7079
a=ptime:20
----------------------------------
v=0
o=user 14175398 14175399 IN IP4 192.168.1.1
s=call
t=0 0
m=audio PORT RTP/AVP 2 102 100 99 97 8 0 101
c=IN IP4 203.0.113.1
a=rtpmap:2 G726-32/8000
a=rtpmap:102 G726-32/8000
a=rtpmap:100 G726-40/8000
a=rtpmap:99 G726-24/8000
a=rtpmap:97 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendonly
a=rtcp:PORT
a=ptime:20
SDP



new_call;

offer('GH 1373 offer', { codec => { strip => ['all'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.14
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

new_call;

offer('GH 1373', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.14
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

answer('GH 1373', { codec => { strip => ['all'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.14
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

new_call;

offer('a=mid on zero streams', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:0
m=audio 0 RTP/AVP 0
c=IN IP4 198.51.100.14
a=sendrecv
a=mid:1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=mid:0
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=audio PORT RTP/AVP 0
c=IN IP4 0.0.0.0
a=mid:1
SDP

new_call;
my $ft1 = ft();

offer('re-invite re-tag w/ via-branch', { 'via-branch' => 'foo' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.14
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

new_ft;
my $ft2 = ft();

offer('re-invite re-tag w/ via-branch', { 'via-branch' => 'bar' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2100 RTP/AVP 0
c=IN IP4 198.51.100.14
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

# answer ft2
($port_a) = answer('re-invite re-tag w/ via-branch', { 'via-branch' => 'bar' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2200 RTP/AVP 0
c=IN IP4 198.51.100.14
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

# delete ft1
rtpe_req('delete', 'GH 1086', { 'from-tag' => $ft1 });

# reverse re-invite to new from-tag ft3
new_ft;
my $ft3 = ft();
reverse_tags;
# tt is the new tag ft3 now

($port_b) = offer('re-invite re-tag w/ via-branch', { 'via-branch' => 'blah', 'to-tag' => tt() }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2200 RTP/AVP 0
c=IN IP4 198.51.100.14
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

isnt($port_a, $port_b, "new port");

# restore to original ft2

($port_b) = offer('re-invite re-tag w/ via-branch', { 'via-branch' => 'baz', 'to-tag' => $ft2 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2200 RTP/AVP 0
c=IN IP4 198.51.100.14
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

is($port_a, $port_b, "new port");



new_call;

offer('unsupp codecs and dup encodings', { }, <<SDP);
v=0
o=- 24112892 24112892 IN IP4 198.51.100.1
s=SBC call
c=IN IP4 198.51.100.1
t=0 0
m=audio 34796 RTP/AVP 109 104 110 111 102 108 8 9 18 100
b=AS:80
b=RS:625
b=RR:1875
a=rtpmap:109 EVS/16000
a=fmtp:109 br=5.9-24.4; bw=nb-swb; max-red=0; cmr=1; ch-aw-recv=-1
a=rtpmap:104 AMR-WB/16000
a=fmtp:104 mode-set=0,1,2;max-red=0;mode-change-capability=2
a=rtpmap:110 AMR-WB/16000
a=fmtp:110 octet-align=1;mode-set=0,1,2;max-red=0;mode-change-capability=2
a=rtpmap:111 AMR-WB/16000
a=fmtp:111 mode-change-capability=2;max-red=0
a=rtpmap:102 AMR/8000
a=fmtp:102 max-red=0;mode-change-capability=2
a=rtpmap:108 AMR/8000
a=fmtp:108 octet-align=1;max-red=0;mode-change-capability=2
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:100 telephone-event/8000
a=fmtp:100 0-15
a=ptime:20
a=maxptime:240
a=sendrecv
--------------------
v=0
o=- 24112892 24112892 IN IP4 198.51.100.1
s=SBC call
t=0 0
m=audio PORT RTP/AVP 109 104 110 111 102 108 8 9 18 100
c=IN IP4 203.0.113.1
b=AS:80
b=RR:1875
b=RS:625
a=rtpmap:109 EVS/16000
a=fmtp:109 br=5.9-24.4; bw=nb-swb; max-red=0; cmr=1; ch-aw-recv=-1
a=rtpmap:104 AMR-WB/16000
a=fmtp:104 mode-set=0,1,2;max-red=0;mode-change-capability=2
a=rtpmap:110 AMR-WB/16000
a=fmtp:110 octet-align=1;mode-set=0,1,2;max-red=0;mode-change-capability=2
a=rtpmap:111 AMR-WB/16000
a=fmtp:111 mode-change-capability=2;max-red=0
a=rtpmap:102 AMR/8000
a=fmtp:102 max-red=0;mode-change-capability=2
a=rtpmap:108 AMR/8000
a=fmtp:108 octet-align=1;max-red=0;mode-change-capability=2
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:100 telephone-event/8000
a=fmtp:100 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:240
SDP

answer('unsupp codecs and dup encodings', { }, <<SDP);
v=0
o=root 599886518 599886518 IN IP4 198.51.100.1
s=modCOM v2 Media Gateway
c=IN IP4 198.51.100.1
t=0 0
m=audio 14382 RTP/AVP 9 8 18 100
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:100 telephone-event/8000
a=fmtp:100 0-16
a=ptime:20
a=maxptime:150
a=sendrecv
------------------------------
v=0
o=root 599886518 599886518 IN IP4 198.51.100.1
s=modCOM v2 Media Gateway
t=0 0
m=audio PORT RTP/AVP 9 8 18 100
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:100 telephone-event/8000
a=fmtp:100 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:150
SDP




new_call;

offer('t/c and implicit number of channels',
	{ codec => { transcode => ['opus','PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6000 RTP/AVP 0 102
c=IN IP4 198.51.100.20
a=rtpmap:102 opus/48000/1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 102 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:102 opus/48000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('t/c and implicit number of channels',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6002 RTP/AVP 102
c=IN IP4 198.51.100.20
a=rtpmap:102 opus/48000
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 102
c=IN IP4 203.0.113.1
a=rtpmap:102 opus/48000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP




($sock_a, $sock_b) = new_call([qw(198.51.100.14 6008)], [qw(198.51.100.14 6010)]);

($port_a, undef, $srtp_key_a) = offer('CN passthrough',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6008 RTP/AVP 0 13
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 13
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:13 CN/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('echo=fwd',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6010 RTP/AVP 0 13
c=IN IP4 198.51.100.14
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 13
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:13 CN/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(13, 2001, 4160, 0x3456, "12345"));
rcv($sock_a, $port_b, rtpm(13, 2001, 4160, $ssrc, "12345"));
snd($sock_a, $port_b, rtp(0, 3000, 5000, 0x3456, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 3000, 5000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(13, 3001, 5160, 0x3456, "654321"));
rcv($sock_b, $port_a, rtpm(13, 3001, 5160, $ssrc, "654321"));




($sock_a, $sock_b) = new_call([qw(198.51.100.14 6000)], [qw(198.51.100.14 6002)]);

($port_a) = offer('echo=fwd',
	{ 'media-echo' => 'fw' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6000 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('echo=fwd',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6002 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 2000, 4000, -1, "\x00" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.14 6004)], [qw(198.51.100.14 6006)]);

($port_a) = offer('echo=bkw',
	{ 'media-echo' => 'bk' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6004 RTP/AVP 0
c=IN IP4 198.51.100.14
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

($port_b) = answer('echo=bkw',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6006 RTP/AVP 0
c=IN IP4 198.51.100.14
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


snd($sock_a, $port_b, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));







new_call;

offer('SDES=static control',
	{ DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 10000 RTP/SAVP 8
c=IN IP4 198.51.100.1
a=crypto:1 AEAD_AES_256_GCM inline:53P5CsePy3hFUcuqsizkCnTE+4OKa1cOGa2WXHjoN19ifpweerTLaj+9vxc
a=crypto:2 AEAD_AES_128_GCM inline:QAXb41skvhZaVzQgiJH+y+P9HCUSTnQWXcuieA
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:Ylhu0C+EN+fjasQ730KXQn/t+5vpKmhzs9TgWD1mvRiLHpwABTovh/pwpjjajg
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:QmwGdHm6/VLHA2Et6NFw4i3g4Ely6SG8cWHHo+xTPREMRr0lfDMvr1p7CyXrog
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:K/C34oakA6ko9ZsWyc90W/M/EEx+YFLu3qzxL2IdWXLulkPqDNE
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:ig3qPKCMyU9aCG4YSysTxthgr3FkVdD1pXKVVOOEFeGHgnb7MBk
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:Opr7g+J9VgQnRkCFNmL/0LP/dcF1Exu43qwiE0So
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:LTwX81FUDIqkdr+g9ogW8T/HRoGmZF5snF97QAPF
a=crypto:9 F8_128_HMAC_SHA1_80 inline:sczm7mZYpQDbs5qGTMavRH89imN1tLcrJGJk+DG7
a=crypto:10 F8_128_HMAC_SHA1_32 inline:Gh+eY01+Uvw7gAbstjR0l91ZzuMn4h5JE9jaBYFq
a=crypto:11 NULL_HMAC_SHA1_80 inline:KPLgFC6jSYe7Xf7rVKi1zjm+CkfxLngL6L3o8kBu
a=crypto:12 NULL_HMAC_SHA1_32 inline:8ia0Ba4FPS/Dow99pIdt8BLIsq6xo7wn5pWR6zXB
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:53P5CsePy3hFUcuqsizkCnTE+4OKa1cOGa2WXHjoN19ifpweerTLaj+9vxc
a=crypto:2 AEAD_AES_128_GCM inline:QAXb41skvhZaVzQgiJH+y+P9HCUSTnQWXcuieA
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:Ylhu0C+EN+fjasQ730KXQn/t+5vpKmhzs9TgWD1mvRiLHpwABTovh/pwpjjaj?
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:QmwGdHm6/VLHA2Et6NFw4i3g4Ely6SG8cWHHo+xTPREMRr0lfDMvr1p7CyXro?
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:K/C34oakA6ko9ZsWyc90W/M/EEx+YFLu3qzxL2IdWXLulkPqDNE
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:ig3qPKCMyU9aCG4YSysTxthgr3FkVdD1pXKVVOOEFeGHgnb7MBk
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:Opr7g+J9VgQnRkCFNmL/0LP/dcF1Exu43qwiE0So
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:LTwX81FUDIqkdr+g9ogW8T/HRoGmZF5snF97QAPF
a=crypto:9 F8_128_HMAC_SHA1_80 inline:sczm7mZYpQDbs5qGTMavRH89imN1tLcrJGJk+DG7
a=crypto:10 F8_128_HMAC_SHA1_32 inline:Gh+eY01+Uvw7gAbstjR0l91ZzuMn4h5JE9jaBYFq
a=crypto:11 NULL_HMAC_SHA1_80 inline:KPLgFC6jSYe7Xf7rVKi1zjm+CkfxLngL6L3o8kBu
a=crypto:12 NULL_HMAC_SHA1_32 inline:8ia0Ba4FPS/Dow99pIdt8BLIsq6xo7wn5pWR6zXB
SDP

answer('SDES=static control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 20000 RTP/SAVP 8
c=IN IP4 198.51.100.1
a=crypto:1 AEAD_AES_256_GCM inline:555555ePy3hFUcuqsizkCnTE+4OKa1cOGa2WXHjoN19ifpweerTLaj+9vxc
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:555555ePy3hFUcuqsizkCnTE+4OKa1cOGa2WXHjoN19ifpweerTLaj+9vxc
SDP

offer('SDES=static control',
	{ DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 10000 RTP/SAVP 8
c=IN IP4 198.51.100.1
a=crypto:1 AEAD_AES_256_GCM inline:53P5CsePy3hFUcuqsizkCnTE+4OKa1cOGa2WXHjoN19ifpweerTLaj+9vxc
a=crypto:2 AEAD_AES_128_GCM inline:QAXb41skvhZaVzQgiJH+y+P9HCUSTnQWXcuieA
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:Ylhu0C+EN+fjasQ730KXQn/t+5vpKmhzs9TgWD1mvRiLHpwABTovh/pwpjjajg
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:QmwGdHm6/VLHA2Et6NFw4i3g4Ely6SG8cWHHo+xTPREMRr0lfDMvr1p7CyXrog
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:K/C34oakA6ko9ZsWyc90W/M/EEx+YFLu3qzxL2IdWXLulkPqDNE
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:ig3qPKCMyU9aCG4YSysTxthgr3FkVdD1pXKVVOOEFeGHgnb7MBk
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:Opr7g+J9VgQnRkCFNmL/0LP/dcF1Exu43qwiE0So
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:LTwX81FUDIqkdr+g9ogW8T/HRoGmZF5snF97QAPF
a=crypto:9 F8_128_HMAC_SHA1_80 inline:sczm7mZYpQDbs5qGTMavRH89imN1tLcrJGJk+DG7
a=crypto:10 F8_128_HMAC_SHA1_32 inline:Gh+eY01+Uvw7gAbstjR0l91ZzuMn4h5JE9jaBYFq
a=crypto:11 NULL_HMAC_SHA1_80 inline:KPLgFC6jSYe7Xf7rVKi1zjm+CkfxLngL6L3o8kBu
a=crypto:12 NULL_HMAC_SHA1_32 inline:8ia0Ba4FPS/Dow99pIdt8BLIsq6xo7wn5pWR6zXB
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:53P5CsePy3hFUcuqsizkCnTE+4OKa1cOGa2WXHjoN19ifpweerTLaj+9vxc
a=crypto:2 AEAD_AES_128_GCM inline:QAXb41skvhZaVzQgiJH+y+P9HCUSTnQWXcuieA
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:Ylhu0C+EN+fjasQ730KXQn/t+5vpKmhzs9TgWD1mvRiLHpwABTovh/pwpjjaj?
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:QmwGdHm6/VLHA2Et6NFw4i3g4Ely6SG8cWHHo+xTPREMRr0lfDMvr1p7CyXro?
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:K/C34oakA6ko9ZsWyc90W/M/EEx+YFLu3qzxL2IdWXLulkPqDNE
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:ig3qPKCMyU9aCG4YSysTxthgr3FkVdD1pXKVVOOEFeGHgnb7MBk
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:Opr7g+J9VgQnRkCFNmL/0LP/dcF1Exu43qwiE0So
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:LTwX81FUDIqkdr+g9ogW8T/HRoGmZF5snF97QAPF
a=crypto:9 F8_128_HMAC_SHA1_80 inline:sczm7mZYpQDbs5qGTMavRH89imN1tLcrJGJk+DG7
a=crypto:10 F8_128_HMAC_SHA1_32 inline:Gh+eY01+Uvw7gAbstjR0l91ZzuMn4h5JE9jaBYFq
a=crypto:11 NULL_HMAC_SHA1_80 inline:KPLgFC6jSYe7Xf7rVKi1zjm+CkfxLngL6L3o8kBu
a=crypto:12 NULL_HMAC_SHA1_32 inline:8ia0Ba4FPS/Dow99pIdt8BLIsq6xo7wn5pWR6zXB
SDP

answer('SDES=static control',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 20000 RTP/SAVP 8
c=IN IP4 198.51.100.1
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:O3333333333nRkCFNmL/0LP/dcF1Exu43qwiE0So
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:O3333333333nRkCFNmL/0LP/dcF1Exu43qwiE0So
SDP



offer('SDES=static',
	{ DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 10000 RTP/SAVP 8
c=IN IP4 198.51.100.1
a=crypto:1 AEAD_AES_256_GCM inline:53P5CsePy3hFUcuqsizkCnTE+4OKa1cOGa2WXHjoN19ifpweerTLaj+9vxc
a=crypto:2 AEAD_AES_128_GCM inline:QAXb41skvhZaVzQgiJH+y+P9HCUSTnQWXcuieA
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:Ylhu0C+EN+fjasQ730KXQn/t+5vpKmhzs9TgWD1mvRiLHpwABTovh/pwpjjajg
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:QmwGdHm6/VLHA2Et6NFw4i3g4Ely6SG8cWHHo+xTPREMRr0lfDMvr1p7CyXrog
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:K/C34oakA6ko9ZsWyc90W/M/EEx+YFLu3qzxL2IdWXLulkPqDNE
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:ig3qPKCMyU9aCG4YSysTxthgr3FkVdD1pXKVVOOEFeGHgnb7MBk
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:Opr7g+J9VgQnRkCFNmL/0LP/dcF1Exu43qwiE0So
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:LTwX81FUDIqkdr+g9ogW8T/HRoGmZF5snF97QAPF
a=crypto:9 F8_128_HMAC_SHA1_80 inline:sczm7mZYpQDbs5qGTMavRH89imN1tLcrJGJk+DG7
a=crypto:10 F8_128_HMAC_SHA1_32 inline:Gh+eY01+Uvw7gAbstjR0l91ZzuMn4h5JE9jaBYFq
a=crypto:11 NULL_HMAC_SHA1_80 inline:KPLgFC6jSYe7Xf7rVKi1zjm+CkfxLngL6L3o8kBu
a=crypto:12 NULL_HMAC_SHA1_32 inline:8ia0Ba4FPS/Dow99pIdt8BLIsq6xo7wn5pWR6zXB
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:53P5CsePy3hFUcuqsizkCnTE+4OKa1cOGa2WXHjoN19ifpweerTLaj+9vxc
a=crypto:2 AEAD_AES_128_GCM inline:QAXb41skvhZaVzQgiJH+y+P9HCUSTnQWXcuieA
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:Ylhu0C+EN+fjasQ730KXQn/t+5vpKmhzs9TgWD1mvRiLHpwABTovh/pwpjjaj?
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:QmwGdHm6/VLHA2Et6NFw4i3g4Ely6SG8cWHHo+xTPREMRr0lfDMvr1p7CyXro?
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:K/C34oakA6ko9ZsWyc90W/M/EEx+YFLu3qzxL2IdWXLulkPqDNE
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:ig3qPKCMyU9aCG4YSysTxthgr3FkVdD1pXKVVOOEFeGHgnb7MBk
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:Opr7g+J9VgQnRkCFNmL/0LP/dcF1Exu43qwiE0So
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:LTwX81FUDIqkdr+g9ogW8T/HRoGmZF5snF97QAPF
a=crypto:9 F8_128_HMAC_SHA1_80 inline:sczm7mZYpQDbs5qGTMavRH89imN1tLcrJGJk+DG7
a=crypto:10 F8_128_HMAC_SHA1_32 inline:Gh+eY01+Uvw7gAbstjR0l91ZzuMn4h5JE9jaBYFq
a=crypto:11 NULL_HMAC_SHA1_80 inline:KPLgFC6jSYe7Xf7rVKi1zjm+CkfxLngL6L3o8kBu
a=crypto:12 NULL_HMAC_SHA1_32 inline:8ia0Ba4FPS/Dow99pIdt8BLIsq6xo7wn5pWR6zXB
SDP

answer('SDES=static',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 20000 RTP/SAVP 8
c=IN IP4 198.51.100.1
a=crypto:1 AEAD_AES_256_GCM inline:555555ePy3hFUcuqsizkCnTE+4OKa1cOGa2WXHjoN19ifpweerTLaj+9vxc
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:555555ePy3hFUcuqsizkCnTE+4OKa1cOGa2WXHjoN19ifpweerTLaj+9vxc
SDP

offer('SDES=static',
	{ DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 10000 RTP/SAVP 8
c=IN IP4 198.51.100.1
a=crypto:1 AEAD_AES_256_GCM inline:53P5CsePy3hFUcuqsizkCnTE+4OKa1cOGa2WXHjoN19ifpweerTLaj+9vxc
a=crypto:2 AEAD_AES_128_GCM inline:QAXb41skvhZaVzQgiJH+y+P9HCUSTnQWXcuieA
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:Ylhu0C+EN+fjasQ730KXQn/t+5vpKmhzs9TgWD1mvRiLHpwABTovh/pwpjjajg
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:QmwGdHm6/VLHA2Et6NFw4i3g4Ely6SG8cWHHo+xTPREMRr0lfDMvr1p7CyXrog
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:K/C34oakA6ko9ZsWyc90W/M/EEx+YFLu3qzxL2IdWXLulkPqDNE
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:ig3qPKCMyU9aCG4YSysTxthgr3FkVdD1pXKVVOOEFeGHgnb7MBk
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:Opr7g+J9VgQnRkCFNmL/0LP/dcF1Exu43qwiE0So
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:LTwX81FUDIqkdr+g9ogW8T/HRoGmZF5snF97QAPF
a=crypto:9 F8_128_HMAC_SHA1_80 inline:sczm7mZYpQDbs5qGTMavRH89imN1tLcrJGJk+DG7
a=crypto:10 F8_128_HMAC_SHA1_32 inline:Gh+eY01+Uvw7gAbstjR0l91ZzuMn4h5JE9jaBYFq
a=crypto:11 NULL_HMAC_SHA1_80 inline:KPLgFC6jSYe7Xf7rVKi1zjm+CkfxLngL6L3o8kBu
a=crypto:12 NULL_HMAC_SHA1_32 inline:8ia0Ba4FPS/Dow99pIdt8BLIsq6xo7wn5pWR6zXB
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:53P5CsePy3hFUcuqsizkCnTE+4OKa1cOGa2WXHjoN19ifpweerTLaj+9vxc
a=crypto:2 AEAD_AES_128_GCM inline:QAXb41skvhZaVzQgiJH+y+P9HCUSTnQWXcuieA
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:Ylhu0C+EN+fjasQ730KXQn/t+5vpKmhzs9TgWD1mvRiLHpwABTovh/pwpjjaj?
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:QmwGdHm6/VLHA2Et6NFw4i3g4Ely6SG8cWHHo+xTPREMRr0lfDMvr1p7CyXro?
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:K/C34oakA6ko9ZsWyc90W/M/EEx+YFLu3qzxL2IdWXLulkPqDNE
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:ig3qPKCMyU9aCG4YSysTxthgr3FkVdD1pXKVVOOEFeGHgnb7MBk
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:Opr7g+J9VgQnRkCFNmL/0LP/dcF1Exu43qwiE0So
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:LTwX81FUDIqkdr+g9ogW8T/HRoGmZF5snF97QAPF
a=crypto:9 F8_128_HMAC_SHA1_80 inline:sczm7mZYpQDbs5qGTMavRH89imN1tLcrJGJk+DG7
a=crypto:10 F8_128_HMAC_SHA1_32 inline:Gh+eY01+Uvw7gAbstjR0l91ZzuMn4h5JE9jaBYFq
a=crypto:11 NULL_HMAC_SHA1_80 inline:KPLgFC6jSYe7Xf7rVKi1zjm+CkfxLngL6L3o8kBu
a=crypto:12 NULL_HMAC_SHA1_32 inline:8ia0Ba4FPS/Dow99pIdt8BLIsq6xo7wn5pWR6zXB
SDP

answer('SDES=static',
	{ SDES => ['static'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 20000 RTP/SAVP 8
c=IN IP4 198.51.100.1
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:O3333333333nRkCFNmL/0LP/dcF1Exu43qwiE0So
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:555555ePy3hFUcuqsizkCnTE+4OKa1cOGa2WXHjoN19ifpweerTLaj+9vxc
SDP

new_call;

($port_a, undef, $ufrag_a) = offer('ICE re-invite',
	{ ICE => 'force', }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

($port_b, undef, $ufrag_b) = offer('ICE re-invite',
	{ ICE => 'force', }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

is($port_a, $port_b, 'port match');
is($ufrag_a, $ufrag_b, 'ufrag match');

($port_a, undef, $ufrag_a) = offer('ICE re-invite port change',
	{ ICE => 'force', }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16480 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

is($port_a, $port_b, 'port match');
is($ufrag_a, $ufrag_b, 'ufrag match');

new_call;

($port_a, $port_ax, $ufrag_a) = offer('ICE re-invite w rtcp-mux',
	{ ICE => 'force', 'rtcp-mux' => ['require'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
SDP

is($port_a, $port_ax, 'port match');

($port_b, $port_bx, $ufrag_b) = offer('ICE re-invite w rtcp-mux',
	{ ICE => 'force', 'rtcp-mux' => ['require'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
SDP

is($port_b, $port_bx, 'port match');
is($port_a, $port_b, 'port match');
is($ufrag_a, $ufrag_b, 'ufrag match');

new_call;

($port_a, undef, $ufrag_a) = offer('ICE re-invite',
	{ ICE => 'force', flags => ['no port latching']}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

($port_b, undef, $ufrag_b) = offer('ICE re-invite',
	{ ICE => 'force', flags => ['no port latching']}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

is($port_a, $port_b, 'port match');
is($ufrag_a, $ufrag_b, 'ufrag match');

($port_a, undef, $ufrag_a) = offer('ICE re-invite port change no port latching',
	{ ICE => 'force', flags => ['no port latching']}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16480 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

isnt($port_a, $port_b, 'port match');
isnt($ufrag_a, $ufrag_b, 'ufrag match');

new_call;

offer('null address test A',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 0.0.0.0
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('null address test B',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP4 0.0.0.0
t=0 0
m=audio 16478 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 0.0.0.0
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('null address test A trickle',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 9 RTP/AVP 8
c=IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 0.0.0.0
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('null address test B trickle',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP4 0.0.0.0
t=0 0
m=audio 9 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 0.0.0.0
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('null address test A w replace option',
	{ replace => ['zero address'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('null address test B w replace option',
	{ replace => ['zero address'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP4 0.0.0.0
t=0 0
m=audio 16478 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('null address test A trickle w replace option',
	{ replace => ['zero address'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 9 RTP/AVP 8
c=IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('null address test B trickle w replace option',
	{ replace => ['zero address'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP4 0.0.0.0
t=0 0
m=audio 9 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('null address test C',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP6 ::
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP6 ::
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('null address test D',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP6 ::
t=0 0
m=audio 16478 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP6 ::
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('control E',
	{ 'address-family' => 'IP6' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 198.51.110.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP6 2001:db8:4321::1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('control F',
	{ 'address-family' => 'IP6' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP4 198.51.110.1
t=0 0
m=audio 16478 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP6 2001:db8:4321::1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('null address test E',
	{ 'address-family' => 'IP6' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP6 ::
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('null address test F',
	{ 'address-family' => 'IP6' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP4 0.0.0.0
t=0 0
m=audio 16478 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP6 ::
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('control G',
	{ 'address-family' => 'IP4' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP6 2001:db8:8765::1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('control H',
	{ 'address-family' => 'IP4' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP6 2001:db8:8765::1
t=0 0
m=audio 16478 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('null address test G',
	{ 'address-family' => 'IP4' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP6 ::
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 0.0.0.0
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('null address test H',
	{ 'address-family' => 'IP4' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP6 ::
t=0 0
m=audio 16478 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 0.0.0.0
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('trickle ICE test A',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP4 0.0.0.0
t=0 0
m=audio 9 RTP/AVP 8
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('trickle ICE test B',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP4 198.51.110.1
t=0 0
m=audio 6666 RTP/AVP 8
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
a=rtcp:9 IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('trickle ICE test A no ICE',
	{ ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP4 0.0.0.0
t=0 0
m=audio 9 RTP/AVP 8
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('trickle ICE test B no ICE',
	{ ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP4 198.51.110.1
t=0 0
m=audio 6666 RTP/AVP 8
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
a=rtcp:9 IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('trickle ICE test C',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP4 0.0.0.0
t=0 0
m=audio 9 RTP/AVP 8
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
a=rtcp:9 IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('trickle ICE test D',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 9 RTP/AVP 8
c=IN IP4 0.0.0.0
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('trickle ICE test E',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 6666 RTP/AVP 8
c=IN IP4 198.51.110.1
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
a=rtcp:9 IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('trickle ICE test F',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 9 RTP/AVP 8
c=IN IP4 0.0.0.0
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
a=rtcp:9 IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('trickle ICE test G',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP6 ::
t=0 0
m=audio 9 RTP/AVP 8
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP6 2001:db8:4321::1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 203.0.113.1 PORT typ host
SDP

new_call;

offer('trickle ICE test I',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP6 ::
t=0 0
m=audio 9 RTP/AVP 8
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
a=rtcp:9 IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP6 2001:db8:4321::1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 203.0.113.1 PORT typ host
SDP

new_call;

offer('trickle ICE test J',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 9 RTP/AVP 8
c=IN IP6 ::
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP6 2001:db8:4321::1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 203.0.113.1 PORT typ host
SDP

new_call;

offer('trickle ICE test L',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 9 RTP/AVP 8
c=IN IP6 ::
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
a=rtcp:9 IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP6 2001:db8:4321::1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 203.0.113.1 PORT typ host
SDP


new_call;

offer('gh#1136',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 102 9 0 110 18 127
c=IN IP4 198.51.100.1
a=rtpmap:102 G7221/16000
a=fmtp:102 bitrate=32000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:110 iLBC/8000
a=fmtp:110 mode=30
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:127 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 102 9 0 110 18 127
c=IN IP4 203.0.113.1
a=rtpmap:102 G7221/16000
a=fmtp:102 bitrate=32000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:110 iLBC/8000
a=fmtp:110 mode=30
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:127 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('gh#1136',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 102 127
c=IN IP4 198.51.100.1
a=rtpmap:102 G7221/16000
a=fmtp:102 bitrate=32000
a=rtpmap:127 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 102 127
c=IN IP4 203.0.113.1
a=rtpmap:102 G7221/16000
a=fmtp:102 bitrate=32000
a=rtpmap:127 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

# simple codec masking

new_call;

offer('simple codec neg',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('simple codec neg',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('codec-accept',
	{ codec => { accept => ['PCMU'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('codec-accept',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('codec-consume',
	{ codec => { consume => ['PCMU'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('codec-consume',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('simple codec neg',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('simple codec neg',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('simple codec masking',
	{ codec => { mask => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('simple codec masking',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('simple codec masking',
	{ codec => { mask => ['PCMU'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('simple codec masking',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

##

offer('simple codec neg w DTMF',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('simple codec neg w DTMF',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('simple codec neg w DTMF',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('simple codec neg w DTMF',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('simple codec masking w DTMF',
	{ codec => { mask => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('simple codec masking w DTMF',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('simple codec masking w DTMF',
	{ codec => { mask => ['PCMU'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('simple codec masking w DTMF',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

##

offer('simple codec neg w DTMF rej',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('simple codec neg w DTMF rej',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('simple codec neg w DTMF rej',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('simple codec neg w DTMF rej',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('simple codec masking w DTMF rej',
	{ codec => { mask => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('simple codec masking w DTMF rej',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('simple codec masking w DTMF rej',
	{ codec => { mask => ['PCMU'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('simple codec masking w DTMF rej',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

##

new_call;

offer('simple codec masking w DTMF masked',
	{ codec => { mask => ['telephone-event'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('simple codec masking w DTMF masked',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('simple codec masking w DTMF masked',
	{ codec => { mask => ['telephone-event'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('simple codec masking w DTMF masked',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

##

offer('strip-all w consume and offer',
	{ codec => {
		strip => ['all'],
		consume => ['CN'],
		offer => ['PCMA', 'PCMU', 'telephone-event'],
	} }, <<SDP);
v=0
o=testlab 949032 0 IN IP4 127.0.0.1
s=session
c=IN IP4 192.168.1.1
b=CT:10000000
t=0 0
m=audio 52152 RTP/AVP 104 9 103 111 18 0 8 97 101 13 118
c=IN IP4 192.168.1.1
a=rtcp:52153
a=mid:1
a=sendrecv
a=rtpmap:104 SILK/16000
a=rtpmap:9 G722/8000
a=rtpmap:103 SILK/8000
a=rtpmap:111 SIREN/16000
a=fmtp:111 bitrate=16000
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:97 RED/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:13 CN/8000
a=rtpmap:118 CN/16000
a=ptime:20
----------------------------------
v=0
o=testlab 949032 0 IN IP4 127.0.0.1
s=session
b=CT:10000000
t=0 0
m=audio PORT RTP/AVP 8 0 101
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

answer('strip-all w consume and offer',
	{ }, <<SDP);
v=0
o=testlab 3815920663 3815920664 IN IP4 192.168.1.1
s=pjmedia
c=IN IP4 192.168.1.1
t=0 0
m=audio 4002 RTP/AVP 8 101
c=IN IP4 192.168.1.1
a=rtcp:4003 IN IP4 172.31.250.201
a=sendrecv
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
----------------------------------
v=0
o=testlab 3815920663 3815920664 IN IP4 192.168.1.1
s=pjmedia
t=0 0
m=audio PORT RTP/AVP 8 13 101
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:8 PCMA/8000
a=rtpmap:13 CN/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP





# dup codec

new_call();

offer('dup codec 1',
	{ replace => ['origin'], codec => {
		transcode => ['opus/48000/1', 'opus/48000/2']
	} }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 97 98
c=IN IP4 198.51.101.1
a=rtpmap:97 opus/48000
a=rtpmap:98 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 97 98
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:97 opus/48000
a=rtpmap:98 opus/48000/2
a=sendrecv
a=rtcp:PORT
SDP

new_call();

offer('dup codec 2',
	{ replace => ['origin'], codec => {
		transcode => ['opus/48000', 'opus/48000/2']
	} }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 97 98
c=IN IP4 198.51.101.1
a=rtpmap:97 opus/48000
a=rtpmap:98 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 97 98
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:97 opus/48000
a=rtpmap:98 opus/48000/2
a=sendrecv
a=rtcp:PORT
SDP

new_call();

offer('dup codec 3',
	{ replace => ['origin'], codec => {
		transcode => ['opus', 'opus/48000/2']
	} }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 97 98
c=IN IP4 198.51.101.1
a=rtpmap:97 opus/48000
a=rtpmap:98 opus/48000/2
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 97 98
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:97 opus/48000
a=rtpmap:98 opus/48000/2
a=sendrecv
a=rtcp:PORT
SDP






# CN tests

($sock_a, $sock_b) = new_call([qw(198.51.101.1 3000)], [qw(198.51.101.3 4000)]);

($port_a) = offer('add CN',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['CN'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 3000 RTP/AVP 0
c=IN IP4 198.51.101.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 13
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:13 CN/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('add CN',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 4000 RTP/AVP 0 13
c=IN IP4 198.51.101.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(13, 2001, 4160, 0x3456, "\x12\x23\x23\x34\x56"));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc, "\xce\x56\x69\xcc\x61\xca\x63\xd2\x66\x57\xe2\x47\x65\x59\x6a\x74\x5d\x4a\x68\xe9\x60\x4a\x63\x4b\xf4\x43\x4b\x48\x48\x52\x39\x57\x37\x4c\x39\x4c\x48\x3b\x43\x47\x44\x57\x48\xf5\x3e\x59\x3e\x52\x3b\x53\x3d\x53\x3b\x41\x5b\x38\x4a\x4b\x35\x48\x4a\x3e\x52\x50\x4b\x46\xfd\x3e\xf1\x3a\xd6\x35\x54\x5d\x3a\x58\x45\x42\x3d\x3e\x4c\x42\x3a\x58\x3c\x50\x3b\x6e\x36\x60\x3e\x3d\x3b\x41\x3a\x47\x35\x48\x35\x4b\x3e\x3d\x47\x3a\x3d\x39\x4f\x40\x42\x4a\x47\x3d\x6b\x42\x5a\x75\x53\x45\x5a\x4b\x4f\x48\x59\x48\x78\x43\x77\x4c\x42\x59\x47\x46\x3e\x67\x44\x3a\x67\x4b\x3f\x51\x48\x44\x3e\x54\x37\x6c\x45\x45\x3f\x6e\x3a\x68\x49\x4e\x3f\x47\x4b\x3e\xf3\x39"));
snd($sock_b, $port_a, rtp(0, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2002, 4320, $ssrc, "\x00" x 160));
# test silence detection
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1001, 3160, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\xff" x 160));
rcv($sock_b, $port_a, rtpm(13, 1002, 3320, $ssrc, "\x20"));



# reverse of the above, sockets/ports swapped

($sock_b, $sock_a) = new_call([qw(198.51.101.1 6002)], [qw(198.51.101.3 7002)]);

($port_b) = offer('accept CN',
	{ ICE => 'remove', replace => ['origin'], flags => ['always transcode'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 6002 RTP/AVP 0 13
c=IN IP4 198.51.101.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 13
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:13 CN/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_a) = answer('accept CN',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7002 RTP/AVP 0
c=IN IP4 198.51.101.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 13
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:13 CN/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(13, 2001, 4160, 0x3456, "\x12\x23\x23\x34\x56"));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc, "\xce\x56\x69\xcc\x61\xca\x63\xd2\x66\x57\xe2\x47\x65\x59\x6a\x74\x5d\x4a\x68\xe9\x60\x4a\x63\x4b\xf4\x43\x4b\x48\x48\x52\x39\x57\x37\x4c\x39\x4c\x48\x3b\x43\x47\x44\x57\x48\xf5\x3e\x59\x3e\x52\x3b\x53\x3d\x53\x3b\x41\x5b\x38\x4a\x4b\x35\x48\x4a\x3e\x52\x50\x4b\x46\xfd\x3e\xf1\x3a\xd6\x35\x54\x5d\x3a\x58\x45\x42\x3d\x3e\x4c\x42\x3a\x58\x3c\x50\x3b\x6e\x36\x60\x3e\x3d\x3b\x41\x3a\x47\x35\x48\x35\x4b\x3e\x3d\x47\x3a\x3d\x39\x4f\x40\x42\x4a\x47\x3d\x6b\x42\x5a\x75\x53\x45\x5a\x4b\x4f\x48\x59\x48\x78\x43\x77\x4c\x42\x59\x47\x46\x3e\x67\x44\x3a\x67\x4b\x3f\x51\x48\x44\x3e\x54\x37\x6c\x45\x45\x3f\x6e\x3a\x68\x49\x4e\x3f\x47\x4b\x3e\xf3\x39"));
snd($sock_b, $port_a, rtp(0, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2002, 4320, $ssrc, "\x00" x 160));
# test silence detection
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1001, 3160, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\xff" x 160));
rcv($sock_b, $port_a, rtpm(13, 1002, 3320, $ssrc, "\x20"));

# consume CN

($sock_b, $sock_a) = new_call([qw(198.51.101.1 6006)], [qw(198.51.101.3 7006)]);

($port_b) = offer('consume CN',
	{ ICE => 'remove', replace => ['origin'],
	codec => {
		strip => ['all'],
		consume => ['CN'],
		offer => ['PCMA','PCMU','telephone-event'],
	} }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 6006 RTP/AVP 8 0 13 101
c=IN IP4 198.51.101.1
a=sendrecv
a=rtpmap:101 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_a) = answer('consume CN',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7006 RTP/AVP 8 101
c=IN IP4 198.51.101.3
a=sendrecv
a=rtpmap:101 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 13 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:13 CN/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(8, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(8, 2000, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(13, 2001, 4160, 0x3456, "\x12\x23\x23\x34\x56"));
rcv($sock_a, $port_b, rtpm(8, 2001, 4160, $ssrc, "\xfb\x70\x58\xe4\x43\xe6\x41\xfc\x44\x71\xc0\x63\x44\x77\x58\x50\x49\x66\x5a\xd8\x42\x66\x41\x67\xd0\x6f\x67\x60\x60\x7c\x10\x71\x12\x64\x10\x65\x60\x16\x6c\x63\x6c\x76\x60\xd1\x15\x74\x15\x7c\x16\x7d\x14\x7d\x16\x69\x4a\x13\x66\x67\x1c\x60\x66\x15\x7c\x7e\x67\x62\xd5\x15\xd2\x11\xf0\x1c\x72\x49\x11\x76\x6d\x6e\x14\x15\x64\x6e\x11\x76\x17\x7e\x16\x5c\x1d\x42\x15\x14\x16\x69\x11\x63\x1c\x60\x1d\x67\x6a\x15\x63\x11\x14\x10\x79\x68\x6e\x66\x60\x14\x59\x6e\x74\x50\x7d\x6d\x74\x67\x79\x60\x77\x60\x56\x6f\x56\x64\x6e\x77\x63\x62\x15\x45\x6c\x11\x45\x67\x6a\x7c\x60\x6c\x6a\x72\x12\x5f\x6d\x6d\x6a\x5d\x11\x5b\x61\x7b\x6a\x63\x67\x15\xd0\x10"));
snd($sock_b, $port_a, rtp(8, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 2002, 4320, $ssrc, "\x00" x 160));
# test silence detection
snd($sock_a, $port_b, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc_b) = rcv($sock_b, $port_a, rtpm(8, 1001, 3160, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1002, 3320, 0x1234, "\xd5" x 160));
rcv($sock_b, $port_a, rtpm(13, 1002, 3320, $ssrc_b, "\x20"));

# reverse re-invite

reverse_tags();

# XXX obsolete need for transcode=CN
offer('consume CN',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['CN'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 7006 RTP/AVP 8 0 101
c=IN IP4 198.51.101.3
a=sendrecv
a=rtpmap:101 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 13 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:13 CN/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(13, 2003, 4480, 0x3456, "\x12\x23\x23\x34\x56"));
rcv($sock_a, $port_b, rtpm(8, 2003, 4480, $ssrc, "\x57\x65\x6c\x6e\x6f\x11\x63\x17\x64\x15\x7b\x11\x6c\x13\x7d\x1f\x11\x16\x15\x69\x6d\x65\x15\x63\x16\x14\x65\x1e\x40\x6b\x6a\x11\x7d\x1a\x68\x6d\x16\x12\x6e\x13\x62\x63\x1f\x15\x61\x1f\x16\x1d\x6f\x18\x7b\x10\x1d\x7b\x14\x6e\x15\x6b\x11\x7c\x6b\x6d\x72\x11\x67\x7a\x14\x60\x73\x1d\x7d\x12\x51\x1a\xc6\x16\x17\x6e\x10\x65\x16\x10\x6e\x68\x17\x13\x7d\x15\x16\x45\x1f\x6b\x43\x12\x42\x7b\x77\x14\xe4\x11\x5d\x65\x6e\x46\x58\x10\x78\x51\x11\xf5\x6d\x6d\xd8\x16\x6f\xcf\x14\x63\x69\x68\x64\x6c\x6b\x17\x7a\x61\x11\x75\x79\x7a\x7f\x15\x5d\x12\x7c\x7d\x79\x60\x53\x60\x58\x15\xfe\x63\x45\xda\x7e\xe5\x68\xe0\x69\xf0\x6e\xe4\x58\x4d\x7e\x45\x69\xf7"));
snd($sock_b, $port_a, rtp(8, 2004, 4640, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 2004, 4640, $ssrc, "\x00" x 160));







new_call;

offer('add some other codec, accept second PT',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['G722'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 3002 RTP/AVP 8 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 9
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:9 G722/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('add some other codec, accept second PT',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 4002 RTP/AVP 0 9
c=IN IP4 198.51.101.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# ^- reordered!




($sock_a, $sock_b) = new_call([qw(198.51.101.1 3002)], [qw(198.51.101.3 4002)]);

($port_a) = offer('add CN, accept second PT',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['CN'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 3002 RTP/AVP 8 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 13
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:13 CN/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('add CN, accept second PT',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 4002 RTP/AVP 0 13
c=IN IP4 198.51.101.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(13, 2001, 4160, 0x3456, "\x12\x23\x23\x34\x56"));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, $ssrc, "\xce\x56\x69\xcc\x61\xca\x63\xd2\x66\x57\xe2\x47\x65\x59\x6a\x74\x5d\x4a\x68\xe9\x60\x4a\x63\x4b\xf4\x43\x4b\x48\x48\x52\x39\x57\x37\x4c\x39\x4c\x48\x3b\x43\x47\x44\x57\x48\xf5\x3e\x59\x3e\x52\x3b\x53\x3d\x53\x3b\x41\x5b\x38\x4a\x4b\x35\x48\x4a\x3e\x52\x50\x4b\x46\xfd\x3e\xf1\x3a\xd6\x35\x54\x5d\x3a\x58\x45\x42\x3d\x3e\x4c\x42\x3a\x58\x3c\x50\x3b\x6e\x36\x60\x3e\x3d\x3b\x41\x3a\x47\x35\x48\x35\x4b\x3e\x3d\x47\x3a\x3d\x39\x4f\x40\x42\x4a\x47\x3d\x6b\x42\x5a\x75\x53\x45\x5a\x4b\x4f\x48\x59\x48\x78\x43\x77\x4c\x42\x59\x47\x46\x3e\x67\x44\x3a\x67\x4b\x3f\x51\x48\x44\x3e\x54\x37\x6c\x45\x45\x3f\x6e\x3a\x68\x49\x4e\x3f\x47\x4b\x3e\xf3\x39"));
snd($sock_b, $port_a, rtp(0, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2002, 4320, $ssrc, "\x00" x 160));
snd($sock_b, $port_a, rtp(13, 2003, 4480, 0x3456, "\x12\x23\x23\x34\x56"));
rcv($sock_a, $port_b, rtpm(0, 2003, 4480, $ssrc, "\x7a\x4d\x44\x42\x42\x3a\x46\x3c\x4c\x3e\x4e\x3a\x44\x38\x53\x34\x3a\x3b\x3e\x41\x45\x4d\x3e\x47\x3b\x3d\x4d\x33\x62\x3f\x3e\x3a\x53\x2f\x40\x45\x3b\x37\x42\x38\x46\x47\x34\x3e\x49\x34\x3b\x36\x43\x31\x4e\x39\x36\x4e\x3d\x42\x3e\x3f\x3a\x52\x3f\x45\x54\x3a\x4b\x4e\x3d\x48\x55\x36\x53\x37\x77\x2f\xe3\x3b\x3c\x42\x39\x4d\x3b\x39\x42\x40\x3c\x38\x53\x3e\x3b\x67\x34\x3f\x60\x37\x60\x4e\x59\x3d\xcc\x3a\x6e\x4c\x42\x64\x69\x39\x4f\x76\x3a\xdb\x45\x45\xe9\x3b\x43\xde\x3d\x47\x41\x40\x4c\x44\x3f\x3c\x4e\x49\x3a\x5a\x4f\x4e\x51\x3e\x6e\x37\x52\x53\x4f\x48\x72\x48\x69\x3e\xd0\x47\x67\xe8\x50\xcc\x40\xc8\x41\xd6\x42\xcc\x6a\x5f\x50\x66\x41\xd9"));
snd($sock_b, $port_a, rtp(0, 2004, 4640, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2004, 4640, $ssrc, "\x00" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.101.1 3006)], [qw(198.51.101.3 4006)]);

($port_a) = offer('add CN, accept second PT, reject CN',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['CN'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 3006 RTP/AVP 8 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 13
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:13 CN/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('add CN, accept second PT, reject CN',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 4006 RTP/AVP 0
c=IN IP4 198.51.101.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));





($sock_a, $sock_b) = new_call([qw(198.51.101.1 3004)], [qw(198.51.101.3 4004)]);

($port_a) = offer('add CN and 2nd codec, accept second PT',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['PCMU', 'CN'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 3004 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 13
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:13 CN/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('add CN and 2nd codec, accept second PT',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.1
s=tester
t=0 0
m=audio 4004 RTP/AVP 0 13
c=IN IP4 198.51.101.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x2a" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(8, 2000, 4000, -1, "\x2a" x 160));
snd($sock_b, $port_a, rtp(13, 2001, 4160, 0x3456, "\x12\x23\x23\x34\x56"));
rcv($sock_a, $port_b, rtpm(8, 2001, 4160, $ssrc, "\xfb\x70\x58\xe4\x43\xe6\x41\xfc\x44\x71\xc0\x63\x44\x77\x58\x50\x49\x66\x5a\xd8\x42\x66\x41\x67\xd0\x6f\x67\x60\x60\x7c\x10\x71\x12\x64\x10\x65\x60\x16\x6c\x63\x6c\x76\x60\xd1\x15\x74\x15\x7c\x16\x7d\x14\x7d\x16\x69\x4a\x13\x66\x67\x1c\x60\x66\x15\x7c\x7e\x67\x62\xd5\x15\xd2\x11\xf0\x1c\x72\x49\x11\x76\x6d\x6e\x14\x15\x64\x6e\x11\x76\x17\x7e\x16\x5c\x1d\x42\x15\x14\x16\x69\x11\x63\x1c\x60\x1d\x67\x6a\x15\x63\x11\x14\x10\x79\x68\x6e\x66\x60\x14\x59\x6e\x74\x50\x7d\x6d\x74\x67\x79\x60\x77\x60\x56\x6f\x56\x64\x6e\x77\x63\x62\x15\x45\x6c\x11\x45\x67\x6a\x7c\x60\x6c\x6a\x72\x12\x5f\x6d\x6d\x6a\x5d\x11\x5b\x61\x7b\x6a\x63\x67\x15\xd0\x10"));
snd($sock_b, $port_a, rtp(0, 2002, 4320, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 2002, 4320, $ssrc, "\x2a" x 160));
snd($sock_b, $port_a, rtp(13, 2003, 4480, 0x3456, "\x12\x23\x23\x34\x56"));
rcv($sock_a, $port_b, rtpm(8, 2003, 4480, $ssrc, "\x57\x65\x6c\x6e\x6f\x11\x63\x17\x64\x15\x7b\x11\x6c\x13\x7d\x1f\x11\x16\x15\x69\x6d\x65\x15\x63\x16\x14\x65\x1e\x40\x6b\x6a\x11\x7d\x1a\x68\x6d\x16\x12\x6e\x13\x62\x63\x1f\x15\x61\x1f\x16\x1d\x6f\x18\x7b\x10\x1d\x7b\x14\x6e\x15\x6b\x11\x7c\x6b\x6d\x72\x11\x67\x7a\x14\x60\x73\x1d\x7d\x12\x51\x1a\xc6\x16\x17\x6e\x10\x65\x16\x10\x6e\x68\x17\x13\x7d\x15\x16\x45\x1f\x6b\x43\x12\x42\x7b\x77\x14\xe4\x11\x5d\x65\x6e\x46\x58\x10\x78\x51\x11\xf5\x6d\x6d\xd8\x16\x6f\xcf\x14\x63\x69\x68\x64\x6c\x6b\x17\x7a\x61\x11\x75\x79\x7a\x7f\x15\x5d\x12\x7c\x7d\x79\x60\x53\x60\x58\x15\xfe\x63\x45\xda\x7e\xe5\x68\xe0\x69\xf0\x6e\xe4\x58\x4d\x7e\x45\x69\xf7"));
snd($sock_b, $port_a, rtp(0, 2004, 4640, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 2004, 4640, $ssrc, "\x2a" x 160));





new_call;

offer('dup codec number', {
	codec => {
		mask => ['all'],
		transcode => ['G722', 'opus/48000/1//test=1', 'speex', 'PCMA', 'telephone-event'],
	}
}, <<SDP);
v=0
o=- 3816337545 3816337545 IN IP4 ims.example.com
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 44964 RTP/AVP 111 108 8 101 96
a=ptime:20
a=rtpmap:111 opus/48000
a=rtpmap:108 speex/16000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/48000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=fmtp:101 0-15
----------------------------------
v=0
o=- 3816337545 3816337545 IN IP4 ims.example.com
s=-
t=0 0
m=audio PORT RTP/AVP 9 97 108 8 96 98 101
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:97 opus/48000
a=fmtp:97 useinbandfec=1
a=rtpmap:108 speex/16000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=rtpmap:98 telephone-event/16000
a=fmtp:98 0-15
a=rtpmap:101 telephone-event/48000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP



if ($extended_tests) {

new_call;

offer('t/c and implicit number of channels',
	{ codec => { transcode => ['AMR','PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6000 RTP/AVP 0 102
c=IN IP4 198.51.100.20
a=rtpmap:102 AMR/8000/1
a=fmtp:102 mode-change-capability=2;max-red=0
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 102 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:102 AMR/8000
a=fmtp:102 mode-change-capability=2;max-red=0
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('t/c and implicit number of channels',
	{ }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6002 RTP/AVP 102
c=IN IP4 198.51.100.20
a=rtpmap:102 AMR/8000
a=fmtp:102 octet-align=0; mode-set=7; max-red=0; mode-change-capability=2
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 102
c=IN IP4 203.0.113.1
a=rtpmap:102 AMR/8000
a=fmtp:102 octet-align=0; mode-set=7; max-red=0; mode-change-capability=2
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP



# AMR-WB b2b transcoding

($sock_a, $sock_b) = new_call([qw(198.51.100.10 3062)], [qw(198.51.100.10 3064)]);

($port_a) = offer('AMR-WB b2b transcoding',
	{ ICE => 'remove', replace => ['origin'],
	codec => {
		mask => ['all'],
		transcode => [
			'PCMA',
			'AMR',
			'AMR-WB/16000/1///mode-set--0,1,2;mode-change-period--2;mode-change-capability--2/dtx--1',
			'telephone-event',
		],
	} }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3062 RTP/AVP 8 108 101 111 96
c=IN IP4 198.51.100.10
a=ptime:20
a=rtpmap:8 PCMA/8000
a=rtpmap:108 AMR/8000
a=fmtp:108 mode-set=7
a=rtpmap:101 telephone-event/8000
a=rtpmap:111 AMR-WB/16000
a=fmtp:111 mode-set=0,1,2; mode-change-period=2; mode-change-capability=2
a=rtpmap:96 telephone-event/16000
a=fmtp:101 0-15
a=fmtp:96 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 108 97 96 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:108 AMR/8000
a=fmtp:108 mode-set=7
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 mode-set=0,1,2;mode-change-period=2;mode-change-capability=2
a=rtpmap:96 telephone-event/16000
a=fmtp:96 0-15
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

($port_b) = answer('AMR-WB b2b transcoding',
	{ ICE => 'remove', replace => ['origin'], flags => [] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3064 RTP/AVP 97 96
c=IN IP4 198.51.100.10
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=0; mode-set=0,1,2; max-red=0; mode-change-capability=2
a=rtpmap:96 telephone-event/16000
a=fmtp:96 0-16
a=ptime:20
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 111 96
c=IN IP4 203.0.113.1
a=rtpmap:111 AMR-WB/16000
a=fmtp:111 mode-set=0,1,2; mode-change-period=2; mode-change-capability=2
a=rtpmap:96 telephone-event/16000
a=fmtp:96 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP



($sock_a, $sock_b) = new_call([qw(198.51.100.10 3066)], [qw(198.51.100.10 3068)]);

($port_a) = offer('AMR-WB b2b transcoding',
	{ ICE => 'remove', replace => ['origin'],
	codec => {
		mask => ['all'],
		transcode => [
			'PCMA',
			'AMR',
			'AMR-WB/16000/1///mode-set--0,1,2;mode-change-period--2;mode-change-capability--2/dtx--1',
			'telephone-event',
		],
	} }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3066 RTP/AVP 8 108 101 111 96
c=IN IP4 198.51.100.10
a=ptime:20
a=rtpmap:8 PCMA/8000
a=rtpmap:108 AMR/8000
a=fmtp:108 mode-set=7
a=rtpmap:101 telephone-event/8000
a=rtpmap:111 AMR-WB/16000
a=fmtp:111 mode-set=0,1,2; mode-change-period=2; mode-change-capability=2
a=rtpmap:96 telephone-event/16000
a=fmtp:101 0-15
a=fmtp:96 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 108 97 96 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:108 AMR/8000
a=fmtp:108 mode-set=7
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 mode-set=0,1,2;mode-change-period=2;mode-change-capability=2
a=rtpmap:96 telephone-event/16000
a=fmtp:96 0-15
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

($port_b) = answer('AMR-WB b2b transcoding',
	{ ICE => 'remove', replace => ['origin'], flags => ['reorder-codecs'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3068 RTP/AVP 97 96
c=IN IP4 198.51.100.10
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 octet-align=0; mode-set=0,1,2; max-red=0; mode-change-capability=2
a=rtpmap:96 telephone-event/16000
a=fmtp:96 0-16
a=ptime:20
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 111 96
c=IN IP4 203.0.113.1
a=rtpmap:111 AMR-WB/16000
a=fmtp:111 mode-set=0,1,2; mode-change-period=2; mode-change-capability=2
a=rtpmap:96 telephone-event/16000
a=fmtp:96 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP




# GH 1098

new_call;

offer('gh 1098', {
	codec => {
		mask => ['all'],
		transcode => ['G722', 'AMR-WB/16000/1///mode-set--0,1,2;mode-change-period--2;mode-change-capability--2/dtx--1', 'AMR', 'PCMA', 'telephone-event'],
	}
}, <<SDP);
v=0
o=- 3812713289 3812713289 IN IP4 foo.bar.com
s=-
c=IN IP4 1.1.1.1
t=0 0
m=audio 40732 RTP/AVP 111 108 8 101 96
a=ptime:20
a=rtpmap:111 AMR-WB/16000
a=fmtp:111 mode-set=0,1,2; mode-change-period=2; mode-change-capability=2
a=rtpmap:108 AMR/8000
a=fmtp:108 mode-set=7
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/16000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=fmtp:101 0-15
----------------------------------
v=0
o=- 3812713289 3812713289 IN IP4 foo.bar.com
s=-
t=0 0
m=audio PORT RTP/AVP 9 97 108 8 96 101
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 mode-set=0,1,2;mode-change-period=2;mode-change-capability=2
a=rtpmap:108 AMR/8000
a=fmtp:108 mode-set=7
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=rtpmap:101 telephone-event/16000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

answer('gh 1098', {
	flags => ['single-codec'],
}, <<SDP);
v=0
o=FreeSWITCH 1603706241 1603706242 IN IP4 3.3.3.3
s=FreeSWITCH
c=IN IP4 3.3.3.3
t=0 0
m=audio 18248 RTP/AVP 9 96
a=rtpmap:9 G722/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-16
a=silenceSupp:off - - - -
a=ptime:20
a=rtcp:18249 IN IP4 3.3.3.3
----------------------------------
v=0
o=FreeSWITCH 1603706241 1603706242 IN IP4 3.3.3.3
s=FreeSWITCH
t=0 0
m=audio PORT RTP/AVP 111 101
c=IN IP4 203.0.113.1
a=rtpmap:111 AMR-WB/16000
a=fmtp:111 mode-set=0,1,2; mode-change-period=2; mode-change-capability=2
a=rtpmap:101 telephone-event/16000
a=fmtp:101 0-15
a=silenceSupp:off - - - -
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP



new_call;

offer('gh 1098', {
	codec => {
		mask => ['all'],
		transcode => ['G722', 'AMR-WB/16000/1///mode-set--0,1,2;mode-change-period--2;mode-change-capability--2/dtx--1', 'AMR', 'PCMA', 'telephone-event'],
	}
}, <<SDP);
v=0
o=- 3812713289 3812713289 IN IP4 foo.bar.com
s=-
c=IN IP4 1.1.1.1
t=0 0
m=audio 40732 RTP/AVP 111 108 8 101 96
a=ptime:20
a=rtpmap:111 AMR-WB/16000
a=fmtp:111 mode-set=0,1,2; mode-change-period=2; mode-change-capability=2
a=rtpmap:108 AMR/8000
a=fmtp:108 mode-set=7
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/16000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=fmtp:101 0-15
----------------------------------
v=0
o=- 3812713289 3812713289 IN IP4 foo.bar.com
s=-
t=0 0
m=audio PORT RTP/AVP 9 97 108 8 96 101
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 mode-set=0,1,2;mode-change-period=2;mode-change-capability=2
a=rtpmap:108 AMR/8000
a=fmtp:108 mode-set=7
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=rtpmap:101 telephone-event/16000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

answer('gh 1098', {
	codec => {
		strip => ['all'],
		offer => ['PCMA'],
	}
}, <<SDP);
v=0
o=FreeSWITCH 1603707514 1603707515 IN IP4 3.3.3.3
s=FreeSWITCH
c=IN IP4 3.3.3.3
t=0 0
m=audio 17766 RTP/AVP 8 96
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-16
a=silenceSupp:off - - - -
a=ptime:20
a=rtcp:17767 IN IP4 3.3.3.3
----------------------------------
v=0
o=FreeSWITCH 1603707514 1603707515 IN IP4 3.3.3.3
s=FreeSWITCH
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=silenceSupp:off - - - -
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP



new_call;

offer('gh 1098', {
	codec => {
		mask => ['all'],
		transcode => ['G722', 'AMR-WB/16000/1///mode-set--0,1,2;mode-change-period--2;mode-change-capability--2/dtx--1', 'AMR', 'PCMA', 'telephone-event'],
	}
}, <<SDP);
v=0
o=- 3812713289 3812713289 IN IP4 foo.bar.com
s=-
c=IN IP4 1.1.1.1
t=0 0
m=audio 40732 RTP/AVP 111 108 8 101 96
a=ptime:20
a=rtpmap:111 AMR-WB/16000
a=fmtp:111 mode-set=0,1,2; mode-change-period=2; mode-change-capability=2
a=rtpmap:108 AMR/8000
a=fmtp:108 mode-set=7
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/16000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=fmtp:101 0-15
----------------------------------
v=0
o=- 3812713289 3812713289 IN IP4 foo.bar.com
s=-
t=0 0
m=audio PORT RTP/AVP 9 97 108 8 96 101
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 mode-set=0,1,2;mode-change-period=2;mode-change-capability=2
a=rtpmap:108 AMR/8000
a=fmtp:108 mode-set=7
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=rtpmap:101 telephone-event/16000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

answer('gh 1098', {
	codec => {
		strip => ['all'],
		offer => ['PCMA', 'telephone-event'],
	}
}, <<SDP);
v=0
o=FreeSWITCH 1603707514 1603707515 IN IP4 3.3.3.3
s=FreeSWITCH
c=IN IP4 3.3.3.3
t=0 0
m=audio 17766 RTP/AVP 8 96
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-16
a=silenceSupp:off - - - -
a=ptime:20
a=rtcp:17767 IN IP4 3.3.3.3
----------------------------------
v=0
o=FreeSWITCH 1603707514 1603707515 IN IP4 3.3.3.3
s=FreeSWITCH
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=silenceSupp:off - - - -
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

}




# inject DTMF with mismatched codecs

($sock_a, $sock_b) = new_call([qw(198.51.100.11 3000)], [qw(198.51.100.11 3002)]);

($port_a) = offer('inject, U/A offer',
	{ ICE => 'remove', replace => ['origin'], flags => [qw(inject-DTMF)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8 101
c=IN IP4 198.51.100.11
a=sendrecv
a=rtpmap:101 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('inject, A/U offer',
	{ ICE => 'remove', replace => ['origin'], flags => [qw(inject-DTMF)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.11
s=tester
t=0 0
m=audio 3002 RTP/AVP 8 0 101
c=IN IP4 198.51.100.11
a=sendrecv
a=rtpmap:101 telephone-event/8000
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(8, 2000, 4000, 0x3210, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 2000, 4000, -1, "\x00" x 160));

snd($sock_a, $port_b, rtp(0, 4000, 6000, 0x21d4, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 4000, 6000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 5000, 7000, 0x41b0, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 5000, 7000, -1, "\x00" x 160));





if ($extended_tests) {

# AMR-WB mode tests

($sock_a, $sock_b) = new_call([qw(198.51.100.10 3000)], [qw(198.51.100.10 3002)]);

($port_a) = offer('PCM -> AMR-WB default',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['AMR-WB'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3000 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1;mode-change-capability=2
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('PCM -> AMR-WB default',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3002 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1;mode-change-capability=2
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_a, $port_b, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 1000, 3000, -1, "\xf0\x1c\xd0\x46\x09\xa1\xf1\x73\x02\x71\x71\x00\x0a\x16\x87\x74\xea\x6a\x8c\x06\x67\x66\xec\xf5\x67\x6c\x54\x6d\x45\x4c\x7c\x59\x8d\x7c\x55\xc4\x6c\x50"));



($sock_a, $sock_b) = new_call([qw(198.51.100.10 3004)], [qw(198.51.100.10 3006)]);

($port_a) = offer('PCM -> AMR-WB force bitrate',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['AMR-WB/16000/1/23850'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3004 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1;mode-change-capability=2
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('PCM -> AMR-WB force bitrate',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3006 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1;mode-change-capability=2
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_a, $port_b, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 1000, 3000, -1, "\xf0\x44\xd0\x46\x0d\x8d\xd6\xf3\x02\x71\x71\xf0\x00\x00\x0a\x16\x87\x77\x22\x31\xc8\x21\x00\x8b\xe8\x45\xf2\x94\x41\xd6\xf7\xd1\x68\xb1\xed\x39\x5f\x37\xbe\xbc\xd6\x47\x89\xc4\x14\xad\xff\x1b\x69\xe7\x72\x80\x44\xc4\x97\x2f\x9f\xc7\xc4\xa8\x94\xc0"));

($sock_a, $sock_b) = new_call([qw(198.51.100.10 3008)], [qw(198.51.100.10 3010)]);

($port_a) = offer('PCM -> AMR-WB answer mode-set',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['AMR-WB/16000/1/23850'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3008 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1;mode-change-capability=2
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('PCM -> AMR-WB answer mode-set',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3010 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=0,1,2,3,4; mode-change-capability=2
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_a, $port_b, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 1000, 3000, -1, "\xf0\x24\xd0\x46\x01\xa9\x75\x53\x02\x71\x71\x42\x0a\x16\x87\x76\xa6\x22\x0c\x8c\x44\x40\xee\x68\x45\xfc\xce\xc5\xfc\x4d\xc8\x64\xd6\x4d\xec\xd9\xc5\x64\xc7\x44\x7c\x50"));



($sock_a, $sock_b) = new_call([qw(198.51.100.10 3012)], [qw(198.51.100.10 3014)]);

($port_a) = offer('PCM -> AMR-WB offer mode-set',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['AMR-WB/16000/1/23850//mode-set=0,1,2,3,4,5'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3012 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,1,2,3,4,5
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('PCM -> AMR-WB offer mode-set',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3014 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,1,2,3,4,5
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_a, $port_b, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 1000, 3000, -1, "\xf2\xf4\x11\x80\x26\x75\x75\xc0\x9c\x5c\x50\x02\x85\xa1\xdc\x22\x61\x38\x74\x8f\x26\xf7\x2a\xed\xef\x53\x87\xfc\x10\x4c\x0c\x06\x61\x1c\x62\xad\x85\x81\xb1\x6e\x8c\xd0\x4f\x63\x6b\xef\xa4"));



($sock_a, $sock_b) = new_call([qw(198.51.100.10 3016)], [qw(198.51.100.10 3018)]);

($port_a) = offer('PCM -> AMR-WB offer mode-set, restrict answer',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['AMR-WB/16000/1/23850//mode-set=0,1,2,3,4,5'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3016 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,1,2,3,4,5
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('PCM -> AMR-WB offer mode-set, restrict answer',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3018 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 mode-set=0,1,2,3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_a, $port_b, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(96, 1000, 3000, -1, "\xf1\xf4\x11\x82\x68\x7c\x5c\xc0\x9c\x5c\x40\x02\x85\xa1\xdd\x3a\x9a\xa3\x01\x99\xd9\xbb\x3d\x59\xdb\x15\x1b\x51\x53\x1f\x16\x63\x5f\x15\x71\x1b\x14"));



($sock_a, $sock_b) = new_call([qw(198.51.100.10 3020)], [qw(198.51.100.10 3022)]);

($port_a) = offer('AMR-WB -> PCM default',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3020 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('AMR-WB -> PCM default',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3022 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\xf0\x1c\xd0\x46\x09\xa1\xf1\x73\x02\x71\x71\x00\x0a\x16\x87\x74\xea\x6a\x8c\x06\x67\x66\xec\xf5\x67\x6c\x54\x6d\x45\x4c\x7c\x59\x8d\x7c\x55\xc4\x6c\x50"));



($sock_a, $sock_b) = new_call([qw(198.51.100.10 3024)], [qw(198.51.100.10 3026)]);

($port_a) = offer('AMR-WB -> PCM force bitrate',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['PCMA'],
	'set' => ['AMR-WB/16000/1/23850'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3024 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('AMR-WB -> PCM force bitrate',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3026 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\xf0\x44\xd0\x46\x0d\x8d\xd6\xf3\x02\x71\x71\xf0\x00\x00\x0a\x16\x87\x77\x22\x31\xc8\x21\x00\x8b\xe8\x45\xf2\x94\x41\xd6\xf7\xd1\x68\xb1\xed\x39\x5f\x37\xbe\xbc\xd6\x47\x89\xc4\x14\xad\xff\x1b\x69\xe7\x72\x80\x44\xc4\x97\x2f\x9f\xc7\xc4\xa8\x94\xc0"));
# control for CMR test below:
snd($sock_b, $port_a, rtp(8, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 1001, 3320, $ssrc, "\xf0\x44\xe0\x94\x24\x91\xd6\x45\x0d\x23\xdf\x00\x01\xad\xc9\x47\xc5\x2f\xf7\xfb\x62\x39\x06\xaf\x4d\x1c\x1e\x02\x6d\x94\xd1\x98\x28\x16\x25\x11\x1f\x56\xaa\x25\x40\x79\x19\x7e\x98\x8b\xbf\x78\x24\xe4\x37\x80\xad\x54\x59\x6d\xfd\x74\xcc\x40\x3f\x10"));



($sock_a, $sock_b) = new_call([qw(198.51.100.10 3028)], [qw(198.51.100.10 3030)]);

($port_a) = offer('AMR-WB -> PCM offer mode-set',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['PCMA'],
	'set' => ['AMR-WB/16000/1/23850'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3028 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=0
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=0
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('AMR-WB -> PCM offer mode-set',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3030 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-set=0
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\xf0\x04\x89\xf1\xd9\x1c\xd6\x0c\x80\x15\xe3\x0d\x5a\x18\xfa\xda\xfa\xfa\xc0"));



($sock_a, $sock_b) = new_call([qw(198.51.100.10 3024)], [qw(198.51.100.10 3026)]);

($port_a) = offer('AMR-WB -> PCM CMR',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['PCMA'],
	'set' => ['AMR-WB/16000/1/23850'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3024 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('AMR-WB -> PCM CMR',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3026 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\xf0\x44\xd0\x46\x0d\x8d\xd6\xf3\x02\x71\x71\xf0\x00\x00\x0a\x16\x87\x77\x22\x31\xc8\x21\x00\x8b\xe8\x45\xf2\x94\x41\xd6\xf7\xd1\x68\xb1\xed\x39\x5f\x37\xbe\xbc\xd6\x47\x89\xc4\x14\xad\xff\x1b\x69\xe7\x72\x80\x44\xc4\x97\x2f\x9f\xc7\xc4\xa8\x94\xc0"));
# send packet with CMR 1
snd($sock_a, $port_b, rtp(96, 2000, 4000, 0x5678, "\x10\x04\x89\xf1\xd9\x1c\xd6\x0c\x80\x15\xe3\x0d\x5a\x18\xfa\xda\xfa\xfa\xc0"));
Time::HiRes::usleep(20000); # 20 ms, wait to be processed
snd($sock_b, $port_a, rtp(8, 1002, 3320, 0x1234, "\x00" x 160));
# receive one more mode 8 frame, then CMR kicks in
rcv($sock_a, $port_b, rtpm(96, 1001, 3320, $ssrc, "\xf0\x44\xe0\x94\x24\x91\xd6\x45\x0d\x23\xdf\x00\x01\xad\xc9\x47\xc5\x2f\xf7\xfb\x62\x39\x06\xaf\x4d\x1c\x1e\x02\x6d\x94\xd1\x98\x28\x16\x25\x11\x1f\x56\xaa\x25\x40\x79\x19\x7e\x98\x8b\xbf\x78\x24\xe4\x37\x80\xad\x54\x59\x6d\xfd\x74\xcc\x40\x3f\x10"));
snd($sock_b, $port_a, rtp(8, 1003, 3480, 0x1234, "\x00" x 160));
# now mode 1
rcv($sock_a, $port_b, rtpm(96, 1002, 3640, $ssrc, "\xf0\x0c\x54\x01\x1e\x01\x14\x6c\xb0\x53\xa3\x87\x8d\x76\x75\xd0\x30\x76\x70\x10\x24\x6a\x10\x62\x00"));



($sock_a, $sock_b) = new_call([qw(198.51.100.10 3028)], [qw(198.51.100.10 3030)]);

($port_a) = offer('mode-change-neighbor',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['PCMA'],
	'set' => ['AMR-WB/16000/1/23850'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3028 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-change-neighbor=1; mode-set=0,2,4,6
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-change-neighbor=1; mode-set=0,2,4,6
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('mode-change-neighbor',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3030 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-change-neighbor=1; mode-set=0,2,4,6
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
# recv mode 6
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\xf0\x34\xd2\x46\x0c\x24\x74\xf3\x02\x71\x71\x40\x02\x16\x97\x74\x79\x65\xc5\x66\xc1\x27\x41\xbe\x1a\x48\x53\xf7\xb4\x27\x77\x04\xf4\x27\xcc\x63\xba\xd7\xf8\xd1\xff\x7a\xec\x52\x7f\x83\x24\xf2\xc1\x31\xce\xe8"));
# send packet with CMR 0
snd($sock_a, $port_b, rtp(96, 2000, 4000, 0x5678, "\x00\x04\x89\xf1\xd9\x1c\xd6\x0c\x80\x15\xe3\x0d\x5a\x18\xfa\xda\xfa\xfa\xc0"));
Time::HiRes::usleep(20000); # 20 ms, wait to be processed
snd($sock_b, $port_a, rtp(8, 1002, 3320, 0x1234, "\x00" x 160));
# recv one more frame with mode 6 before CMR kicks in
rcv($sock_a, $port_b, rtpm(96, 1001, 3320, $ssrc, "\xf0\x34\xe2\x98\x10\xea\xff\xc9\x7d\x23\xdf\x6d\xd9\x47\xd5\x41\xbe\x02\xa2\xd8\xb6\x5a\x18\xfa\x62\x01\xd6\x1c\x5f\x1a\xe6\xef\x1d\x23\xd0\xf5\x3c\x05\xd1\xbd\x4e\x9b\xd5\xc3\x9b\x49\x2b\x19\x41\x0c\x60\x80"));
snd($sock_b, $port_a, rtp(8, 1003, 3480, 0x1234, "\x00" x 160));
# recv mode 4
rcv($sock_a, $port_b, rtpm(96, 1002, 3640, $ssrc, "\xf0\x24\x41\x44\x30\x11\x12\x46\x3c\xb0\x53\x25\x8f\x8d\x46\x5c\x7d\xc7\xc2\x7b\x06\xb4\xd9\x48\x41\x74\xa1\x06\x04\x1c\xd2\x94\x09\x4e\x6c\x1c\x20\xbc\x98\x47\x47\x28"));
snd($sock_b, $port_a, rtp(8, 1004, 3640, 0x1234, "\x00" x 160));
# recv mode 2
rcv($sock_a, $port_b, rtpm(96, 1003, 3960, $ssrc, "\xf0\x14\x41\x46\x30\x77\x75\xde\x11\x15\x55\x79\x8a\x06\x44\xc0\x70\x7f\x07\x85\x81\x87\x86\xb7\xa5\xa5\x18\x33\x35\x39\x98\xa0\x4c\x20"));
snd($sock_b, $port_a, rtp(8, 1005, 3800, 0x1234, "\x00" x 160));
# recv mode 0
rcv($sock_a, $port_b, rtpm(96, 1004, 4280, $ssrc, "\xf0\x04\x30\x01\x00\x28\x1c\x10\x30\x0b\x02\x07\x8b\x00\x84\x00\xc4\x80\x00"));






($sock_a, $sock_b) = new_call([qw(198.51.100.10 3032)], [qw(198.51.100.10 3034)]);

($port_a) = offer('mode-change-period',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['PCMA'],
	'set' => ['AMR-WB/16000/1/6600'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3032 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-change-neighbor=1; mode-set=0,1,3,6,7; mode-change-period=2
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-change-neighbor=1; mode-set=0,1,3,6,7; mode-change-period=2
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('mode-change-period',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3034 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1; mode-change-neighbor=1; mode-set=0,1,3,6,7; mode-change-period=2
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
# recv mode 0
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\xf0\x04\x89\xf1\xd9\x1c\xd6\x0c\x80\x15\xe3\x0d\x5a\x18\xfa\xda\xfa\xfa\xc0"));
# send packet with CMR 7
snd($sock_a, $port_b, rtp(96, 2000, 4000, 0x5678, "\x70\x04\x89\xf1\xd9\x1c\xd6\x0c\x80\x15\xe3\x0d\x5a\x18\xfa\xda\xfa\xfa\xc0"));
Time::HiRes::usleep(20000); # 20 ms, wait to be processed
snd($sock_b, $port_a, rtp(8, 1002, 3320, 0x1234, "\x00" x 160));
# recv one more frame with mode 0 before CMR kicks in
rcv($sock_a, $port_b, rtpm(96, 1001, 3320, $ssrc, "\xf0\x04\xe0\x34\x00\x39\x83\x38\x90\x82\xd2\xc2\xca\x8c\x8c\x03\x18\x8b\x90"));
snd($sock_b, $port_a, rtp(8, 1003, 3480, 0x1234, "\x00" x 160));
# mode change suppressed due to period=2, so one more mode 0
rcv($sock_a, $port_b, rtpm(96, 1002, 3640, $ssrc, "\xf0\x04\x10\x31\x00\x38\x9c\x7c\xb6\x01\x72\x05\x1b\xd2\xd6\x84\x34\x76\x00"));
snd($sock_b, $port_a, rtp(8, 1004, 3640, 0x1234, "\x00" x 160));
# recv mode 1
rcv($sock_a, $port_b, rtpm(96, 1003, 3960, $ssrc, "\xf0\x0c\x54\x00\x0f\x00\x0e\x31\x15\x77\xf7\x8a\x96\x3a\x97\x07\x80\x42\x02\x72\x0a\x24\xa4\x4c\x00"));
snd($sock_b, $port_a, rtp(8, 1005, 3800, 0x1234, "\x00" x 160));
# recv mode 1
rcv($sock_a, $port_b, rtpm(96, 1004, 4280, $ssrc, "\xf0\x0c\x14\x00\x0f\x00\x0e\x08\x44\x91\x16\x79\xf6\xde\x12\xcd\x81\x28\x02\x64\x3b\x64\x29\x5e\x80"));
snd($sock_b, $port_a, rtp(8, 1006, 3960, 0x1234, "\x00" x 160));
# recv mode 3
rcv($sock_a, $port_b, rtpm(96, 1005, 4600, $ssrc, "\xf0\x1c\x01\x44\x00\x22\x2c\x88\xe8\x41\x94\xa0\x09\x82\xb2\xc5\x23\xfa\x5d\x5e\x33\xb1\x41\xfd\x04\x52\x55\x51\x4b\x15\x31\x38\x55\x00\x59\xd5\x98\x80"));
snd($sock_b, $port_a, rtp(8, 1007, 4120, 0x1234, "\x00" x 160));
# recv mode 3
rcv($sock_a, $port_b, rtpm(96, 1006, 4920, $ssrc, "\xf0\x1c\x41\x06\x00\xee\xe3\xb8\x4d\x80\x61\xa6\x48\xc2\x92\x80\x33\x37\xdf\x3e\x81\x76\xf2\x60\x4f\x4a\x24\x45\x01\x34\xc3\x32\x20\x67\x3b\x30\x67\x48"));
snd($sock_b, $port_a, rtp(8, 1008, 4280, 0x1234, "\x00" x 160));
# recv mode 6
rcv($sock_a, $port_b, rtpm(96, 1007, 5240, $ssrc, "\xf0\x34\x01\x46\x00\xee\xeb\xb8\x29\xc0\xd7\xe6\x69\xfa\xb2\xdf\xc3\x3a\xfa\xa1\xa3\x10\x81\xd9\x7b\xd5\x60\x11\x82\x03\x18\x87\x41\x49\xb6\x62\x3b\x79\x44\x50\x46\x3a\xfb\x1c\x00\x07\x16\x92\x8c\x95\x81\x00"));
snd($sock_b, $port_a, rtp(8, 1009, 4440, 0x1234, "\x00" x 160));
# recv mode 6
rcv($sock_a, $port_b, rtpm(96, 1008, 5560, $ssrc, "\xf0\x34\x41\x44\x10\xff\xff\xfc\x40\xc1\x24\xa2\x0c\xca\xb2\xbf\x43\x02\xbc\x90\x01\x2a\xe1\xcd\x71\x1d\x02\x41\xa6\x37\xbd\xc5\x95\xd7\x98\x44\x12\x61\xcc\x62\x41\xd6\x22\x36\x4c\x82\x14\x66\x08\x8d\x0b\x70"));
snd($sock_b, $port_a, rtp(8, 1010, 4600, 0x1234, "\x00" x 160));
# recv mode 7
rcv($sock_a, $port_b, rtpm(96, 1009, 5880, $ssrc, "\xf0\x3c\x01\x46\x30\xee\xeb\xb8\x19\xc0\xd5\xe6\xf9\xea\x92\xda\xd6\x5b\x4b\x2f\x83\x13\x60\x2e\x1a\xdc\xae\x8c\x44\x31\x81\x95\x6b\x19\x21\x54\xc6\x2c\x41\x9f\x90\xf1\x46\xc9\x8d\x10\xaa\xdf\x70\x0d\x71\x07\x09\x1b\x32\x0d\x3c\x2a\x01\x10"));
snd($sock_b, $port_a, rtp(8, 1011, 4760, 0x1234, "\x00" x 160));
# recv mode 7
rcv($sock_a, $port_b, rtpm(96, 1010, 6200, $ssrc, "\xf0\x3c\x41\x46\x00\xee\xef\xb8\x60\xc1\x22\xe5\x14\xc2\xa2\xe8\xb4\xc1\x42\x09\x12\x0a\x08\xb6\x86\xd4\x78\xaf\x57\xc1\xa0\x94\x6d\x5c\x29\xd8\xf6\x88\x90\xba\xaf\x7d\xd2\x60\x94\x0e\xd0\x20\x4e\x2f\xcf\x02\x0b\x9b\x10\xe8\x10\xec\x05\xd8"));





($sock_a, $sock_b) = new_call([qw(198.51.100.10 3036)], [qw(198.51.100.10 3038)]);

($port_a) = offer('CMR-interval',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['PCMA'],
	'set' => ['AMR-WB/16000/1////CMR-interval=200'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3036 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('CMR-interval',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3038 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
a=rtcp:PORT
SDP



# send some mode 3 AMR
snd($sock_a, $port_b, rtp(96, 2000, 4000, 0x5678, "\xf0\x1c\xd0\x46\x09\xa1\xf1\x73\x02\x71\x71\x00\x0a\x16\x87\x74\xea\x6a\x8c\x06\x67\x66\xec\xf5\x67\x6c\x54\x6d\x45\x4c\x7c\x59\x8d\x7c\x55\xc4\x6c\x50"));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_a, $port_b, rtp(96, 2001, 4240, 0x5678, "\xf0\x1c\xe0\x92\x30\xf3\xf4\xff\x3d\x23\xdb\x6b\x59\x4f\xd5\x12\xad\xff\x5b\xf8\x88\x53\x85\x74\x19\x6d\x65\x63\x6e\x94\xbb\x5b\x9f\x7d\x97\x3c\x28\xe8"));
snd($sock_a, $port_b, rtp(96, 2002, 4560, 0x5678, "\xf0\x1c\x41\x42\x00\xd9\xd7\x64\x3c\xb0\x51\xe7\x1f\x95\x56\x3b\x34\x76\x35\x73\x46\x32\x16\x72\x67\xc4\x54\x16\x02\x64\x30\x36\x34\x18\xba\x14\xce\xd8"));
snd($sock_a, $port_b, rtp(96, 2003, 4880, 0x5678, "\xf0\x1c\x41\x46\x30\xff\xf7\xfc\x31\x15\x57\x3b\x0a\x1e\x44\xcd\x5e\x0e\xa7\xe4\x3a\x1b\xb5\x7b\x38\x2a\x90\x13\x08\xf3\x5f\xaa\xba\x57\xb0\x30\xd3\xe8"));

# wait for CMR interval to pass
Time::HiRes::usleep(220000); # 220 ms

# send some PCM and receive CMR for mode 4
snd($sock_b, $port_a, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
# receive 3 packets with CMRs
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\x40\x1c\xd0\x46\x09\xa1\xf1\x73\x02\x71\x71\x00\x0a\x16\x87\x74\xea\x6a\x8c\x06\x67\x66\xec\xf5\x67\x6c\x54\x6d\x45\x4c\x7c\x59\x8d\x7c\x55\xc4\x6c\x50"));
snd($sock_b, $port_a, rtp(8, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 1001, 3320, $ssrc, "\x40\x1c\xe0\x92\x30\xf3\xf4\xff\x3d\x23\xdb\x6b\x59\x4f\xd5\x12\xad\xff\x5b\xf8\x88\x53\x85\x74\x19\x6d\x65\x63\x6e\x94\xbb\x5b\x9f\x7d\x97\x3c\x28\xe8"));
snd($sock_b, $port_a, rtp(8, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 1002, 3640, $ssrc, "\x40\x1c\x41\x42\x00\xd9\xd7\x64\x3c\xb0\x51\xe7\x1f\x95\x56\x3b\x34\x76\x35\x73\x46\x32\x16\x72\x67\xc4\x54\x16\x02\x64\x30\x36\x34\x18\xba\x14\xce\xd8"));
snd($sock_b, $port_a, rtp(8, 1004, 3640, 0x1234, "\x00" x 160));
# back to no CMR
rcv($sock_a, $port_b, rtpm(96, 1003, 3960, $ssrc, "\xf0\x1c\x41\x46\x30\xff\xf7\xfc\x31\x15\x57\x3b\x0a\x1e\x44\xcd\x5e\x0e\xa7\xe4\x3a\x1b\xb5\x7b\x38\x2a\x90\x13\x08\xf3\x5f\xaa\xba\x57\xb0\x30\xd3\xe8"));




($sock_a, $sock_b) = new_call([qw(198.51.100.10 3040)], [qw(198.51.100.10 3042)]);

($port_a) = offer('AMR-WB -> PCM CMR w/ mode-change-interval',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['PCMA'],
	'set' => ['AMR-WB/16000/1/23850///mode-change-interval=200'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3040 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('AMR-WB -> PCM CMR w/ mode-change-interval',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3042 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\xf0\x44\xd0\x46\x0d\x8d\xd6\xf3\x02\x71\x71\xf0\x00\x00\x0a\x16\x87\x77\x22\x31\xc8\x21\x00\x8b\xe8\x45\xf2\x94\x41\xd6\xf7\xd1\x68\xb1\xed\x39\x5f\x37\xbe\xbc\xd6\x47\x89\xc4\x14\xad\xff\x1b\x69\xe7\x72\x80\x44\xc4\x97\x2f\x9f\xc7\xc4\xa8\x94\xc0"));
# send packet with CMR 1
snd($sock_a, $port_b, rtp(96, 2000, 4000, 0x5678, "\x10\x1c\xd0\x46\x09\xa1\xf1\x73\x02\x71\x71\x00\x0a\x16\x87\x74\xea\x6a\x8c\x06\x67\x66\xec\xf5\x67\x6c\x54\x6d\x45\x4c\x7c\x59\x8d\x7c\x55\xc4\x6c\x50"));
Time::HiRes::usleep(20000); # 20 ms, wait to be processed
snd($sock_b, $port_a, rtp(8, 1002, 3320, 0x1234, "\x00" x 160));
# receive one more mode 8 frame, then CMR kicks in
rcv($sock_a, $port_b, rtpm(96, 1001, 3320, $ssrc, "\xf0\x44\xe0\x94\x24\x91\xd6\x45\x0d\x23\xdf\x00\x01\xad\xc9\x47\xc5\x2f\xf7\xfb\x62\x39\x06\xaf\x4d\x1c\x1e\x02\x6d\x94\xd1\x98\x28\x16\x25\x11\x1f\x56\xaa\x25\x40\x79\x19\x7e\x98\x8b\xbf\x78\x24\xe4\x37\x80\xad\x54\x59\x6d\xfd\x74\xcc\x40\x3f\x10"));
snd($sock_b, $port_a, rtp(8, 1003, 3480, 0x1234, "\x00" x 160));
# now mode 1
rcv($sock_a, $port_b, rtpm(96, 1002, 3640, $ssrc, "\xf0\x0c\x54\x01\x1e\x01\x14\x6c\xb0\x53\xa3\x87\x8d\x76\x75\xd0\x30\x76\x70\x10\x24\x6a\x10\x62\x00"));

# wait for mode-change-interval
Time::HiRes::usleep(220000); # 220 ms

# send a non-CMR AMR in to trigger check
snd($sock_a, $port_b, rtp(96, 2001, 4240, 0x5678, "\xf0\x1c\xe0\x92\x30\xf3\xf4\xff\x3d\x23\xdb\x6b\x59\x4f\xd5\x12\xad\xff\x5b\xf8\x88\x53\x85\x74\x19\x6d\x65\x63\x6e\x94\xbb\x5b\x9f\x7d\x97\x3c\x28\xe8"));
Time::HiRes::usleep(20000); # 20 ms, wait to be processed

snd($sock_b, $port_a, rtp(8, 1004, 3640, 0x1234, "\x00" x 160));
# one more mode 1
rcv($sock_a, $port_b, rtpm(96, 1003, 3960, $ssrc, "\xf0\x0c\x54\x10\x0f\x00\x0a\x21\x15\x55\x79\x82\x16\x54\xb8\x7c\x48\x00\xc8\x20\x40\x11\x88\x68\x00"));
snd($sock_b, $port_a, rtp(8, 1005, 3800, 0x1234, "\x00" x 160));
# now mode 2
rcv($sock_a, $port_b, rtpm(96, 1004, 4280, $ssrc, "\xf0\x14\x41\x00\x30\x44\x41\x10\x09\x50\x63\x20\x92\x8a\x82\xf5\x85\xf8\x20\x25\x84\x92\x02\x01\xa1\xb2\x24\x06\x0f\x60\x03\x0f\xd1\x10"));



($sock_a, $sock_b) = new_call([qw(198.51.100.10 3044)], [qw(198.51.100.10 3046)]);

($port_a) = offer('ditto w/ codec-mask',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['PCMA'],
	'set' => ['AMR-WB/16000/1/23850///mode-change-interval=200'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3044 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('ditto w/ codec-mask',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3046 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\xf0\x44\xd0\x46\x0d\x8d\xd6\xf3\x02\x71\x71\xf0\x00\x00\x0a\x16\x87\x77\x22\x31\xc8\x21\x00\x8b\xe8\x45\xf2\x94\x41\xd6\xf7\xd1\x68\xb1\xed\x39\x5f\x37\xbe\xbc\xd6\x47\x89\xc4\x14\xad\xff\x1b\x69\xe7\x72\x80\x44\xc4\x97\x2f\x9f\xc7\xc4\xa8\x94\xc0"));
# send packet with CMR 1
snd($sock_a, $port_b, rtp(96, 2000, 4000, 0x5678, "\x10\x1c\xd0\x46\x09\xa1\xf1\x73\x02\x71\x71\x00\x0a\x16\x87\x74\xea\x6a\x8c\x06\x67\x66\xec\xf5\x67\x6c\x54\x6d\x45\x4c\x7c\x59\x8d\x7c\x55\xc4\x6c\x50"));
Time::HiRes::usleep(20000); # 20 ms, wait to be processed
snd($sock_b, $port_a, rtp(8, 1002, 3320, 0x1234, "\x00" x 160));
# receive one more mode 8 frame, then CMR kicks in
rcv($sock_a, $port_b, rtpm(96, 1001, 3320, $ssrc, "\xf0\x44\xe0\x94\x24\x91\xd6\x45\x0d\x23\xdf\x00\x01\xad\xc9\x47\xc5\x2f\xf7\xfb\x62\x39\x06\xaf\x4d\x1c\x1e\x02\x6d\x94\xd1\x98\x28\x16\x25\x11\x1f\x56\xaa\x25\x40\x79\x19\x7e\x98\x8b\xbf\x78\x24\xe4\x37\x80\xad\x54\x59\x6d\xfd\x74\xcc\x40\x3f\x10"));
snd($sock_b, $port_a, rtp(8, 1003, 3480, 0x1234, "\x00" x 160));
# now mode 1
rcv($sock_a, $port_b, rtpm(96, 1002, 3640, $ssrc, "\xf0\x0c\x54\x01\x1e\x01\x14\x6c\xb0\x53\xa3\x87\x8d\x76\x75\xd0\x30\x76\x70\x10\x24\x6a\x10\x62\x00"));

# wait for mode-change-interval
Time::HiRes::usleep(220000); # 220 ms

# send a non-CMR AMR in to trigger check
snd($sock_a, $port_b, rtp(96, 2001, 4240, 0x5678, "\xf0\x1c\xe0\x92\x30\xf3\xf4\xff\x3d\x23\xdb\x6b\x59\x4f\xd5\x12\xad\xff\x5b\xf8\x88\x53\x85\x74\x19\x6d\x65\x63\x6e\x94\xbb\x5b\x9f\x7d\x97\x3c\x28\xe8"));
Time::HiRes::usleep(20000); # 20 ms, wait to be processed

snd($sock_b, $port_a, rtp(8, 1004, 3640, 0x1234, "\x00" x 160));
# one more mode 1
rcv($sock_a, $port_b, rtpm(96, 1003, 3960, $ssrc, "\xf0\x0c\x54\x10\x0f\x00\x0a\x21\x15\x55\x79\x82\x16\x54\xb8\x7c\x48\x00\xc8\x20\x40\x11\x88\x68\x00"));
snd($sock_b, $port_a, rtp(8, 1005, 3800, 0x1234, "\x00" x 160));
# now mode 2
rcv($sock_a, $port_b, rtpm(96, 1004, 4280, $ssrc, "\xf0\x14\x41\x00\x30\x44\x41\x10\x09\x50\x63\x20\x92\x8a\x82\xf5\x85\xf8\x20\x25\x84\x92\x02\x01\xa1\xb2\x24\x06\x0f\x60\x03\x0f\xd1\x10"));



($sock_b, $sock_a) = new_call([qw(198.51.100.10 3048)], [qw(198.51.100.10 3050)]);

($port_b) = offer('ditto in forward direction',
	{ ICE => 'remove', replace => ['origin'], codec => { 
	'transcode' => ['AMR-WB/16000/1/23850//octet-align=1/mode-change-interval=200'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3048 RTP/AVP 8
c=IN IP4 198.51.100.10
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
a=rtcp:PORT
SDP

($port_a) = answer('ditto in forward direction',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.10
s=tester
t=0 0
m=audio 3050 RTP/AVP 96
c=IN IP4 198.51.100.10
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_b, $port_a, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(8, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\xf0\x44\xd0\x46\x0d\x8d\xd6\xf3\x02\x71\x71\xf0\x00\x00\x0a\x16\x87\x77\x22\x31\xc8\x21\x00\x8b\xe8\x45\xf2\x94\x41\xd6\xf7\xd1\x68\xb1\xed\x39\x5f\x37\xbe\xbc\xd6\x47\x89\xc4\x14\xad\xff\x1b\x69\xe7\x72\x80\x44\xc4\x97\x2f\x9f\xc7\xc4\xa8\x94\xc0"));
# send packet with CMR 1
snd($sock_a, $port_b, rtp(96, 2000, 4000, 0x5678, "\x10\x1c\xd0\x46\x09\xa1\xf1\x73\x02\x71\x71\x00\x0a\x16\x87\x74\xea\x6a\x8c\x06\x67\x66\xec\xf5\x67\x6c\x54\x6d\x45\x4c\x7c\x59\x8d\x7c\x55\xc4\x6c\x50"));
Time::HiRes::usleep(20000); # 20 ms, wait to be processed
snd($sock_b, $port_a, rtp(8, 1002, 3320, 0x1234, "\x00" x 160));
# receive one more mode 8 frame, then CMR kicks in
rcv($sock_a, $port_b, rtpm(96, 1001, 3320, $ssrc, "\xf0\x44\xe0\x94\x24\x91\xd6\x45\x0d\x23\xdf\x00\x01\xad\xc9\x47\xc5\x2f\xf7\xfb\x62\x39\x06\xaf\x4d\x1c\x1e\x02\x6d\x94\xd1\x98\x28\x16\x25\x11\x1f\x56\xaa\x25\x40\x79\x19\x7e\x98\x8b\xbf\x78\x24\xe4\x37\x80\xad\x54\x59\x6d\xfd\x74\xcc\x40\x3f\x10"));
snd($sock_b, $port_a, rtp(8, 1003, 3480, 0x1234, "\x00" x 160));
# now mode 1
rcv($sock_a, $port_b, rtpm(96, 1002, 3640, $ssrc, "\xf0\x0c\x54\x01\x1e\x01\x14\x6c\xb0\x53\xa3\x87\x8d\x76\x75\xd0\x30\x76\x70\x10\x24\x6a\x10\x62\x00"));

# wait for mode-change-interval
Time::HiRes::usleep(220000); # 220 ms

# send a non-CMR AMR in to trigger check
snd($sock_a, $port_b, rtp(96, 2001, 4240, 0x5678, "\xf0\x1c\xe0\x92\x30\xf3\xf4\xff\x3d\x23\xdb\x6b\x59\x4f\xd5\x12\xad\xff\x5b\xf8\x88\x53\x85\x74\x19\x6d\x65\x63\x6e\x94\xbb\x5b\x9f\x7d\x97\x3c\x28\xe8"));
Time::HiRes::usleep(20000); # 20 ms, wait to be processed

snd($sock_b, $port_a, rtp(8, 1004, 3640, 0x1234, "\x00" x 160));
# one more mode 1
rcv($sock_a, $port_b, rtpm(96, 1003, 3960, $ssrc, "\xf0\x0c\x54\x10\x0f\x00\x0a\x21\x15\x55\x79\x82\x16\x54\xb8\x7c\x48\x00\xc8\x20\x40\x11\x88\x68\x00"));
snd($sock_b, $port_a, rtp(8, 1005, 3800, 0x1234, "\x00" x 160));
# now mode 2
rcv($sock_a, $port_b, rtpm(96, 1004, 4280, $ssrc, "\xf0\x14\x41\x00\x30\x44\x41\x10\x09\x50\x63\x20\x92\x8a\x82\xf5\x85\xf8\x20\x25\x84\x92\x02\x01\xa1\xb2\x24\x06\x0f\x60\x03\x0f\xd1\x10"));



}




new_call;

offer('DTMF-inject w tp-e', {
		ICE => 'remove',
		flags => ['inject-DTMF'],
		codec => {transcode => ['G722']},
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 8 9 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0 8 9 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

answer('DTMF-inject w tp-e', {
		ICE => 'remove',
		flags => ['inject-DTMF'],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 8 0 101
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 8 0 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP


new_call;

offer('symmetric codecs w missing answer codec, no flag', {
		ICE => 'remove',
		flags => [],
		codec => {transcode => ['G722']},
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 8
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0 8 9
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('symmetric codecs w missing answer codec, no flag', {
		ICE => 'remove',
		flags => [],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


new_call;

offer('some t/c options with answer only non-t/c codec', {
		codec => {
			mask => ['all'],
			transcode => ['G722', 'opus/48000/1', 'PCMA', 'telephone-event']
		},
	}, <<SDP);
v=0
o=- 3815883745 3815883745 IN IP4 ims.example.com
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 38722 RTP/AVP 111 8 101 96
a=ptime:20
a=rtpmap:111 opus/48000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/48000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=fmtp:101 0-15
--------------------------------------
v=0
o=- 3815883745 3815883745 IN IP4 ims.example.com
s=-
t=0 0
m=audio PORT RTP/AVP 9 111 8 96 101
c=IN IP4 203.0.113.1
a=rtpmap:9 G722/8000
a=rtpmap:111 opus/48000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=rtpmap:101 telephone-event/48000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

answer('some t/c options with answer only non-t/c codec', {}, <<SDP);
v=0
o=FreeSWITCH 1606876265 1606876266 IN IP4 192.168.1.1
s=FreeSWITCH
c=IN IP4 192.168.1.1
t=0 0
m=audio 18680 RTP/AVP 8 96
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-16
a=silenceSupp:off - - - -
a=ptime:20
a=rtcp:18681 IN IP4 192.168.1.1
--------------------------------------
v=0
o=FreeSWITCH 1606876265 1606876266 IN IP4 192.168.1.1
s=FreeSWITCH
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=silenceSupp:off - - - -
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

new_call;

offer('symmetric codecs w missing answer codec, no flag', {
		ICE => 'remove',
		flags => [],
		codec => {transcode => ['G722']},
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 8
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0 8 9
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('symmetric codecs w missing answer codec, no flag', {
		ICE => 'remove',
		flags => [],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 8
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('symmetric codecs w missing answer codec, no flag', {
		ICE => 'remove',
		flags => [],
		codec => {transcode => ['G722']},
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 8
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0 8 9
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('symmetric codecs w missing answer codec, no flag', {
		ICE => 'remove',
		flags => [],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 9
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


new_call;

offer('symmetric codecs w missing answer codec', {
		ICE => 'remove',
		flags => [],
		codec => {transcode => ['G722']},
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 8
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0 8 9
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('symmetric codecs w missing answer codec, no flag', {
		ICE => 'remove',
		flags => ['single codec'],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 9
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP





new_call;

offer('multi codec offer/answer', {
		ICE => 'remove',
		flags => [],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 8
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('multi codec offer/answer', {
		ICE => 'remove',
		flags => [],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 8
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('multi codec offer/answer w single-codec', {
		ICE => 'remove',
		flags => [],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 8
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('multi codec offer/answer', {
		ICE => 'remove',
		flags => ['single codec'],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 8
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('single-codec w telephone-event in wrong order', {
		ICE => 'remove',
		flags => [],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 101 8 0
a=sendrecv
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 101 8 0
c=IN IP4 203.0.113.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('single-codec w telephone-event in wrong order', {
		ICE => 'remove',
		flags => ['single codec'],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 101 8
a=sendrecv
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 101 8
c=IN IP4 203.0.113.1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('multi codec offer/answer w single-codec and tp-event', {
		ICE => 'remove',
		flags => [],
		codec => {transcode => ['opus']},
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 8 101
a=rtpmap:101 telephone-event/8000
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0 8 96 97 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=rtpmap:97 telephone-event/48000
a=fmtp:97 0-15
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('multi codec offer/answer', {
		ICE => 'remove',
		flags => ['single codec'],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 8 96 101 98
a=rtpmap:96 opus/48000/2
a=rtpmap:101 telephone-event/8000
a=rtpmap:98 telephone-event/48000
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP



new_call;

offer('multi codec offer/answer w single-codec and tp-event', {
		ICE => 'remove',
		flags => [],
		codec => {mask => ['all'], transcode => ['opus/48000/1', 'PCMA', 'telephone-event']},
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 96 8 102 101
a=rtpmap:96 opus/48000/2
a=rtpmap:102 telephone-event/48000
a=rtpmap:101 telephone-event/8000
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 97 8 101 102
c=IN IP4 203.0.113.1
a=rtpmap:97 opus/48000
a=fmtp:97 useinbandfec=1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=rtpmap:102 telephone-event/48000
a=sendrecv
a=rtcp:PORT
SDP

answer('multi codec offer/answer', {
		ICE => 'remove',
		flags => ['single codec'],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 97 102
a=rtpmap:97 opus/48000
a=rtpmap:102 telephone-event/48000
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 96 102
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; useinbandfec=1
a=rtpmap:102 telephone-event/48000
a=sendrecv
a=rtcp:PORT
SDP





new_call;

offer('add transcode w supp codec', {
		ICE => 'remove',
		flags => [],
		codec => {transcode => ['PCMA']},
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 101
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0 8 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=rtcp:PORT
SDP





new_call;

offer('fingerprint selection', {
		ICE => 'remove',
		flags => [],
		'transport-protocol' => 'RTP/SAVP',
		SDES => ['off'],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 101 8
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/SAVP 0 101 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

answer('fingerprint selection', {
		flags => [],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 9000 RTP/SAVP 0
a=setup:actpass
a=fingerprint:SHA-1 f1:d2:d2:f9:24:e9:86:ac:86:fd:f7:b3:6c:94:bc:df:32:be:ec:15
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('fingerprint selection', {
		flags => [],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 101 8
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/SAVP 0 101 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP


new_call;

offer('fingerprint selection', {
		ICE => 'remove',
		flags => [],
		'transport-protocol' => 'RTP/SAVP',
		SDES => ['off'],
		'DTLS-fingerprint' => 'SHA-1',
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 101 8
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/SAVP 0 101 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=setup:actpass
a=fingerprint:sha-1 FINGERPRINT
a=tls-id:TLS_ID
SDP

answer('fingerprint selection', {
		flags => [],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 9000 RTP/SAVP 0
a=setup:actpass
a=fingerprint:SHA-256 DA:89:F7:04:38:D9:04:E1:9E:25:1A:43:87:8D:F5:BD:6E:4C:BB:88:12:A6:D5:FA:B1:4A:34:BC:32:C0:05:FE
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('fingerprint selection', {
		flags => [],
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 101 8
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/SAVP 0 101 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=setup:actpass
a=fingerprint:sha-1 FINGERPRINT
a=tls-id:TLS_ID
SDP

new_call;

offer('fingerprint selection', {
		ICE => 'remove',
		flags => [],
		'transport-protocol' => 'RTP/SAVP',
		SDES => ['off'],
		'DTLS-fingerprint' => 'sha-256',
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 101 8
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/SAVP 0 101 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP






# GH 1086

new_call;

offer('GH 1086', {
		ICE => 'remove',
		flags => [],
		'transport-protocol' => 'RTP/SAVP',
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 101 8
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/SAVP 0 101 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP

rtpe_req('delete', 'GH 1086', { 'from-tag' => ft() });

offer('GH 1086', {
		ICE => 'remove',
		flags => [],
		'transport-protocol' => 'RTP/SAVP',
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 101 8
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/SAVP 0 101 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP




# stray answer protocol changes

new_call;

offer('stray answer protocol changes, default', {
		ICE => 'remove',
		flags => [],
		'transport-protocol' => 'RTP/SAVP',
		DTLS => 'off',
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 101 8
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/SAVP 0 101 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('stray answer protocol changes, default', {
		ICE => 'remove',
		flags => [],
		DTLS => 'off',
	}, <<SDP);
v=0
o=- 810178487 810178487 IN IP4 0.0.0.0
s=-
c=IN IP4 0.0.0.0
t=0 0
m=audio 40444 RTP/SAVPF 0 101 8
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=rtpmap:8 PCMA/8000
a=direction:both
a=sendonly
a=rtcp:40445
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:05sglrIFGQuJpqOblofVYYh+PF93dGyOjFW6Q934
--------------------------------------
v=0
o=- 810178487 810178487 IN IP4 0.0.0.0
s=-
t=0 0
m=audio PORT RTP/AVP 0 101 8
c=IN IP4 0.0.0.0
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=rtpmap:8 PCMA/8000
a=direction:both
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('stray answer protocol changes, proto accept', {
		ICE => 'remove',
		flags => [],
		'transport-protocol' => 'RTP/SAVP',
		DTLS => 'off',
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 101 8
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/SAVP 0 101 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('stray answer protocol changes, proto accept', {
		ICE => 'remove',
		flags => [],
		DTLS => 'off',
		'transport-protocol' => 'accept',
	}, <<SDP);
v=0
o=- 810178487 810178487 IN IP4 0.0.0.0
s=-
c=IN IP4 0.0.0.0
t=0 0
m=audio 40444 RTP/SAVPF 0 101 8
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=rtpmap:8 PCMA/8000
a=direction:both
a=sendonly
a=rtcp:40445
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:05sglrIFGQuJpqOblofVYYh+PF93dGyOjFW6Q934
--------------------------------------
v=0
o=- 810178487 810178487 IN IP4 0.0.0.0
s=-
t=0 0
m=audio PORT RTP/SAVPF 0 101 8
c=IN IP4 0.0.0.0
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=rtpmap:8 PCMA/8000
a=direction:both
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('stray answer protocol changes, proto override', {
		ICE => 'remove',
		flags => [],
		'transport-protocol' => 'RTP/SAVP',
		DTLS => 'off',
	}, <<SDP);
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
c=IN IP4 192.168.1.1
t=0 0
m=audio 8000 RTP/AVP 0 101 8
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
--------------------------------------
v=0
o=Z 58440449 0 IN IP4 192.168.1.1
s=Z
t=0 0
m=audio PORT RTP/SAVP 0 101 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('stray answer protocol changes, proto accept', {
		ICE => 'remove',
		flags => [],
		DTLS => 'off',
		'transport-protocol' => 'RTP/AVPF',
	}, <<SDP);
v=0
o=- 810178487 810178487 IN IP4 0.0.0.0
s=-
c=IN IP4 0.0.0.0
t=0 0
m=audio 40444 RTP/SAVPF 0 101 8
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=rtpmap:8 PCMA/8000
a=direction:both
a=sendonly
a=rtcp:40445
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:05sglrIFGQuJpqOblofVYYh+PF93dGyOjFW6Q934
--------------------------------------
v=0
o=- 810178487 810178487 IN IP4 0.0.0.0
s=-
t=0 0
m=audio PORT RTP/AVPF 0 101 8
c=IN IP4 0.0.0.0
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=rtpmap:8 PCMA/8000
a=direction:both
a=sendonly
a=rtcp:PORT
SDP




# GH 1058

new_call;

offer('missing codec in re-invite', {
		ICE => 'remove',
		flags => ["codec-mask-all", "codec-strip-telephone-event", "codec-transcode-PCMU", "codec-transcode-G722", "codec-transcode-t38", "codec-offer-telephone-event", "port-latching"],
		'to-tag' => tt(),
	}, <<SDP);
v=0
o=dev 623840 205550 IN IP4 8.8.8.61
s=SIP Media Capabilities
c=IN IP4 8.8.8.61
t=0 0
m=audio 6304 RTP/AVP 0 8 3 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=maxptime:20
--------------------------------------
v=0
o=dev 623840 205550 IN IP4 8.8.8.61
s=SIP Media Capabilities
t=0 0
m=audio PORT RTP/AVP 0 9 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:9 G722/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=maxptime:20
SDP

answer('missing codec in re-invite', {
		ICE => 'remove',
		flags => ["trust-address", "symmetric-codecs"],
	}, <<SDP);
v=0
o=dev 5418 9648 IN IP4 8.8.8.60
s=SIP Call
c=IN IP4 8.8.8.60
t=0 0
m=audio 6004 RTP/AVP 9 101
c=IN IP4 8.8.8.60
a=rtpmap:9 G722/8000
a=fmtp:9 bitrate=64
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
--------------------------------------
v=0
o=dev 5418 9648 IN IP4 8.8.8.60
s=SIP Call
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

offer('missing codec in re-invite', {
		ICE => 'remove',
		flags => ["codec-mask-all", "codec-strip-telephone-event", "codec-transcode-PCMU", "codec-transcode-G722", "codec-transcode-t38", "codec-offer-telephone-event", "port-latching"],
		'to-tag' => tt(),
	}, <<SDP);
v=0
o=dev 623840 205550 IN IP4 8.8.8.61
s=SIP Media Capabilities
c=IN IP4 8.8.8.61
t=0 0
m=audio 6304 RTP/AVP 0 8 3 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=maxptime:20
--------------------------------------
v=0
o=dev 623840 205550 IN IP4 8.8.8.61
s=SIP Media Capabilities
t=0 0
m=audio PORT RTP/AVP 0 9 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:9 G722/8000
a=fmtp:9 bitrate=64
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=maxptime:20
SDP




# DTLS-reverse flag

new_call;

offer('DTLS-reverse not set', {
		ICE => 'remove', 'transport-protocol' => 'RTP/AVP',
	}, <<SDP);
v=0
o=test 2350 1824 IN IP4 198.51.100.4
s=test
c=IN IP4 198.51.100.4
t=0 0
m=audio 2000 UDP/TLS/RTP/SAVPF 0
a=setup:actpass
a=fingerprint:SHA-256 DA:89:F7:04:38:D9:04:E1:9E:25:1A:43:87:8D:F5:BD:6E:4C:BB:88:12:A6:D5:FA:B1:4A:34:BC:32:C0:05:FE
--------------------------------------
v=0
o=test 2350 1824 IN IP4 198.51.100.4
s=test
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


answer('DTLS-reverse not set', {
		ICE => 'remove',
	}, <<SDP);
v=0
o=test 2350 1824 IN IP4 198.51.100.4
s=test
c=IN IP4 198.51.100.4
t=0 0
m=audio 2000 RTP/AVP 0
--------------------------------------
v=0
o=test 2350 1824 IN IP4 198.51.100.4
s=test
t=0 0
m=audio PORT UDP/TLS/RTP/SAVPF 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=setup:active
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP




new_call;

offer('DTLS-reverse set', {
		ICE => 'remove', 'transport-protocol' => 'RTP/AVP',
		'DTLS-reverse' => 'passive',
	}, <<SDP);
v=0
o=test 2350 1824 IN IP4 198.51.100.4
s=test
c=IN IP4 198.51.100.4
t=0 0
m=audio 2000 UDP/TLS/RTP/SAVPF 0
a=setup:actpass
a=fingerprint:SHA-256 DA:89:F7:04:38:D9:04:E1:9E:25:1A:43:87:8D:F5:BD:6E:4C:BB:88:12:A6:D5:FA:B1:4A:34:BC:32:C0:05:FE
--------------------------------------
v=0
o=test 2350 1824 IN IP4 198.51.100.4
s=test
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


answer('DTLS-reverse set', {
		ICE => 'remove',
	}, <<SDP);
v=0
o=test 2350 1824 IN IP4 198.51.100.4
s=test
c=IN IP4 198.51.100.4
t=0 0
m=audio 2000 RTP/AVP 0
--------------------------------------
v=0
o=test 2350 1824 IN IP4 198.51.100.4
s=test
t=0 0
m=audio PORT UDP/TLS/RTP/SAVPF 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=setup:passive
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
SDP



if ($extended_tests) {

# DTLS early start with ICE (GH 1035 TT 84804)

($sock_a, $sock_b, $sock_c, $sock_d) = new_call([qw(198.51.100.4 2000)], [qw(198.51.100.4 2001)], [qw(198.51.100.8 3000)], [qw(198.51.100.8 3001)]);

offer('ICE offer with DTLS', {
		ICE => 'remove', 'transport-protocol' => 'RTP/AVP', 'rtcp-mux' => ['demux'],
	}, <<SDP);
v=0
o=safarov 2350 1824 IN IP4 198.51.100.4
s=Talk
c=IN IP4 198.51.100.4
t=0 0
a=ice-pwd:bd5e845657ecb8d6dd8e1bc6
a=ice-ufrag:q2758e93
m=audio 2000 UDP/TLS/RTP/SAVPF 0 101
a=rtpmap:101 telephone-event/8000
a=setup:actpass
a=fingerprint:SHA-256 DA:89:F7:04:38:D9:04:E1:9E:25:1A:43:87:8D:F5:BD:6E:4C:BB:88:12:A6:D5:FA:B1:4A:34:BC:32:C0:05:FE
a=rtcp:2001
a=candidate:1 1 UDP 2130706303 198.51.100.4 2000 typ host
a=candidate:1 2 UDP 2130706302 198.51.100.4 2001 typ host
a=candidate:2 1 UDP 2130706301 198.51.100.8 3000 typ host
a=candidate:2 2 UDP 2130706300 198.51.100.8 3001 typ host
--------------------------------------
v=0
o=safarov 2350 1824 IN IP4 198.51.100.4
s=Talk
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

# first consume the reqs sent to us

#                              req     len   cookie            transx                   software                    ufrag1    ufrag2             ice controlled tie brk              prio                             msg integrity                      fprint
@ret1 = rcv($sock_a, -1, qr/^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine.*?\x00\x06\x00\x11q2758e93:(........)\x00\x00\x00\x80\x29\x00\x08........\x00\x24\x00\x04\x6e\xff\xff\xff\x00\x08\x00\x14....................\x80\x28\x00\x04....$/s);
@ret2 = rcv($sock_c, -1, qr/^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine.*?\x00\x06\x00\x11q2758e93:(........)\x00\x00\x00\x80\x29\x00\x08........\x00\x24\x00\x04\x6e\xff\xff\xff\x00\x08\x00\x14....................\x80\x28\x00\x04....$/s);
# RTCP reqs, prio one less
@ret3 = rcv($sock_b, -1, qr/^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine.*?\x00\x06\x00\x11q2758e93:(........)\x00\x00\x00\x80\x29\x00\x08........\x00\x24\x00\x04\x6e\xff\xff\xfe\x00\x08\x00\x14....................\x80\x28\x00\x04....$/s);
@ret4 = rcv($sock_d, -1, qr/^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine.*?\x00\x06\x00\x11q2758e93:(........)\x00\x00\x00\x80\x29\x00\x08........\x00\x24\x00\x04\x6e\xff\xff\xfe\x00\x08\x00\x14....................\x80\x28\x00\x04....$/s);

# send back RTP binding successes

snd($sock_a, $ret1[0], stun_succ($ret1[0], $ret1[1], 'bd5e845657ecb8d6dd8e1bc6'));
snd($sock_c, $ret2[0], stun_succ($ret2[0], $ret2[1], 'bd5e845657ecb8d6dd8e1bc6'));

# send secondary RTCP binding success

snd($sock_d, $ret4[0], stun_succ($ret4[0], $ret4[1], 'bd5e845657ecb8d6dd8e1bc6'));

# now we should be getting DTLS

rcv($sock_c, -1, qr/^\x16\xfe\xff\x00\x00\x00\x00\x00\x00\x00/);
rcv($sock_d, -1, qr/^\x16\xfe\xff\x00\x00\x00\x00\x00\x00\x00/);

}




# GH 1037

new_call;

offer('rtcp-mux branched w delete-delay', {
		ICE => 'remove',
		SDES => 'off',
		'via-branch' => 'foo.0',
		'transport-protocol' => 'RTP/SAVPF',
		'rtcp-mux' => ['offer'],
	}, <<SDP);
v=0
o=root 1965229132 1965229132 IN IP4 172.31.30.143
s=Wildix 5.02.20200622.2~8ea32507
c=IN IP4 172.31.30.143
t=0 0
m=audio 35972 RTP/AVPF 8 0
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=root 1965229132 1965229132 IN IP4 172.31.30.143
s=Wildix 5.02.20200622.2~8ea32507
t=0 0
m=audio PORT RTP/SAVPF 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
a=ptime:20
SDP

offer('rtcp-mux branched w delete-delay', {
		ICE => 'remove',
		SDES => 'off',
		'via-branch' => 'foo.1',
		'transport-protocol' => 'RTP/AVP',
		'rtcp-mux' => ['demux'],
	}, <<SDP);
v=0
o=root 1965229132 1965229132 IN IP4 172.31.30.143
s=Wildix 5.02.20200622.2~8ea32507
c=IN IP4 172.31.30.143
t=0 0
m=audio 35972 RTP/AVPF 8 0
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=root 1965229132 1965229132 IN IP4 172.31.30.143
s=Wildix 5.02.20200622.2~8ea32507
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

rtpe_req('delete', 'rtcp-mux branched w delete-delay', { 'from-tag' => ft(), 'via-branch' => 'foo.1' });

answer('rtcp-mux branched w delete-delay', {
		ICE => 'remove',
		SDES => 'off',
		'via-branch' => 'foo.0',
		'transport-protocol' => 'RTP/AVPF',
		'rtcp-mux' => ['demux'],
	}, <<SDP);
v=0
o=- 8520494338200249002 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE audio video
m=audio 63849 UDP/TLS/RTP/SAVPF 0
c=IN IP4 192.168.31.106
a=rtcp:9 IN IP4 0.0.0.0
a=fingerprint:sha-256 B5:CF:61:F3:C5:DF:F6:11:BF:B2:B5:1A:02:54:A1:2A:4A:B5:9E:1F:FF:C0:AA:96:16:9C:59:49:76:09:63:0B
a=setup:active
a=mid:audio
a=sendrecv
a=rtcp-mux
----------------------------------
v=0
o=- 8520494338200249002 2 IN IP4 127.0.0.1
s=-
t=0 0
m=audio PORT RTP/AVPF 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP





new_call;

offer('rtcp-mux branched delete-delay=0', {
		ICE => 'remove',
		SDES => 'off',
		'via-branch' => 'foo.0',
		'transport-protocol' => 'RTP/SAVPF',
		'rtcp-mux' => ['offer'],
	}, <<SDP);
v=0
o=root 1965229132 1965229132 IN IP4 172.31.30.143
s=Wildix 5.02.20200622.2~8ea32507
c=IN IP4 172.31.30.143
t=0 0
m=audio 35972 RTP/AVPF 8 0
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=root 1965229132 1965229132 IN IP4 172.31.30.143
s=Wildix 5.02.20200622.2~8ea32507
t=0 0
m=audio PORT RTP/SAVPF 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
a=ptime:20
SDP

offer('rtcp-mux branched delete-delay=0', {
		ICE => 'remove',
		SDES => 'off',
		'via-branch' => 'foo.1',
		'transport-protocol' => 'RTP/AVP',
		'rtcp-mux' => ['demux'],
	}, <<SDP);
v=0
o=root 1965229132 1965229132 IN IP4 172.31.30.143
s=Wildix 5.02.20200622.2~8ea32507
c=IN IP4 172.31.30.143
t=0 0
m=audio 35972 RTP/AVPF 8 0
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=root 1965229132 1965229132 IN IP4 172.31.30.143
s=Wildix 5.02.20200622.2~8ea32507
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

rtpe_req('delete', 'rtcp-mux branched delete-delay=0', {
		'from-tag' => ft(), 'via-branch' => 'foo.1',
		'delete-delay' => 0,
	});

answer('rtcp-mux branched delete-delay=0', {
		ICE => 'remove',
		SDES => 'off',
		'via-branch' => 'foo.0',
		'transport-protocol' => 'RTP/AVPF',
		'rtcp-mux' => ['demux'],
	}, <<SDP);
v=0
o=- 8520494338200249002 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE audio video
m=audio 63849 UDP/TLS/RTP/SAVPF 0
c=IN IP4 192.168.31.106
a=rtcp:9 IN IP4 0.0.0.0
a=fingerprint:sha-256 B5:CF:61:F3:C5:DF:F6:11:BF:B2:B5:1A:02:54:A1:2A:4A:B5:9E:1F:FF:C0:AA:96:16:9C:59:49:76:09:63:0B
a=setup:active
a=mid:audio
a=sendrecv
a=rtcp-mux
----------------------------------
v=0
o=- 8520494338200249002 2 IN IP4 127.0.0.1
s=-
t=0 0
m=audio PORT RTP/AVPF 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP






# RTP to SRTP switch (and SRTP re-invite) TT#81850

new_call;

(undef, undef, undef, undef, undef, undef, undef, undef, $srtp_key_a) = offer('RTP to SRTP switch (and SRTP re-invite)',
	{ "transport-protocol" => "RTP/SAVP", "ICE" => "remove", "rtcp-mux" => [ "demux" ],
	DTLS => 'off',
	"replace" => [ "origin" ],
	"via-branch" => "z9hG4bK0ae8.cc3c994fa8d0c0f1f2536bba541306fb.0",
	}, <<SDP);
v=0
o=- 3516723349074626749 3516723349074626751 IN IP4 198.51.100.1
s=
c=IN IP4 198.51.100.1
t=0 0
m=audio 31530 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=sendrecv
a=rtcp:31531
a=silenceSupp:off - - - -
a=mptime:20 -
a=oldmediaip:10.50.3.190
a=ptime:20
----------------------------------
v=0
o=- 3516723349074626749 3516723349074626751 IN IP4 203.0.113.1
s=
t=0 0
m=audio PORT RTP/SAVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=silenceSupp:off - - - -
a=mptime:20 -
a=oldmediaip:10.50.3.190
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=ptime:20
SDP

answer('RTP to SRTP switch (and SRTP re-invite)',
	{ "ICE" => "remove", "rtcp-mux" => [ "demux" ],
	DTLS => 'off',
	"replace" => [ "origin" ],
	"via-branch" => "z9hG4bK0ae8.cc3c994fa8d0c0f1f2536bba541306fb.0",
	}, <<SDP);
v=0
o=- 1889691184267178502 1889691184267178505 IN IP4 198.51.100.1
s=
c=IN IP4 198.51.100.1
t=0 0
m=audio 31498 RTP/SAVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=sendrecv
a=rtcp:31499
a=silenceSupp:off - - - -
a=mptime:20 -
a=oldmediaip:10.50.3.218
a=ptime:20
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:zC6Ea9EK/7YmDM79CK+TAnNXTI1pVmZuCMjUPMph
----------------------------------
v=0
o=- 1889691184267178502 1889691184267178505 IN IP4 203.0.113.1
s=
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=silenceSupp:off - - - -
a=mptime:20 -
a=oldmediaip:10.50.3.218
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

offer('RTP to SRTP switch (and SRTP re-invite)',
	{ "transport-protocol" => "RTP/SAVP", "ICE" => "remove", "rtcp-mux" => [ "demux" ],
	DTLS => 'off',
	"replace" => [ "origin" ],
	"via-branch" => "z9hG4bK0ae8.cc3c994fa8d0c0f1f2536bba541306fb.0",
	'to-tag' => tt(),
	}, <<SDP);
v=0
o=- 3516723349074626749 3516723349074626751 IN IP4 198.51.100.1
s=
c=IN IP4 198.51.100.1
t=0 0
m=audio 31530 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=sendrecv
a=rtcp:31531
a=silenceSupp:off - - - -
a=mptime:20 -
a=oldmediaip:10.50.3.190
a=ptime:20
----------------------------------
v=0
o=- 3516723349074626749 3516723349074626751 IN IP4 203.0.113.1
s=
t=0 0
m=audio PORT RTP/SAVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=silenceSupp:off - - - -
a=mptime:20 -
a=oldmediaip:10.50.3.190
a=sendrecv
a=rtcp:PORT
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:$srtp_key_a
a=crypto:8 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:9 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:10 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:11 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:12 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:13 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:14 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:15 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:16 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:17 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:18 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=ptime:20
SDP

answer('RTP to SRTP switch (and SRTP re-invite)',
	{ "ICE" => "remove", "rtcp-mux" => [ "demux" ],
	DTLS => 'off',
	"replace" => [ "origin" ],
	"via-branch" => "z9hG4bK0ae8.cc3c994fa8d0c0f1f2536bba541306fb.0",
	}, <<SDP);
v=0
o=- 1889691184267178502 1889691184267178505 IN IP4 198.51.100.1
s=
c=IN IP4 198.51.100.1
t=0 0
m=audio 31498 RTP/SAVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=sendrecv
a=rtcp:31499
a=silenceSupp:off - - - -
a=mptime:20 -
a=oldmediaip:10.50.3.218
a=ptime:20
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:zC6Ea9EK/7YmDM79CK+TAnNXTI1pVmZuCMjUPMph
----------------------------------
v=0
o=- 1889691184267178502 1889691184267178505 IN IP4 203.0.113.1
s=
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=silenceSupp:off - - - -
a=mptime:20 -
a=oldmediaip:10.50.3.218
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

# reverse re-invite from RTP to SRTP
reverse_tags();

offer('RTP to SRTP switch (and SRTP re-invite)',
	{ "transport-protocol" => "RTP/SAVP", "ICE" => "remove", "rtcp-mux" => [ "demux" ],
	DTLS => 'off',
	"replace" => [ "origin" ],
	"via-branch" => "z9hG4bK0ae8.cc3c994fa8d0c0f1f2536bba541306fb.0",
	'to-tag' => tt(),
	}, <<SDP);
v=0
o=- 1889691184267178502 1889691184267178505 IN IP4 198.51.100.1
s=
c=IN IP4 198.51.100.1
t=0 0
m=audio 31498 RTP/SAVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=sendrecv
a=rtcp:31499
a=silenceSupp:off - - - -
a=mptime:20 -
a=oldmediaip:10.50.3.218
a=ptime:20
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:zC6Ea9EK/7YmDM79CK+TAnNXTI1pVmZuCMjUPMph
----------------------------------
v=0
o=- 1889691184267178502 1889691184267178505 IN IP4 203.0.113.1
s=
t=0 0
m=audio PORT RTP/SAVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=silenceSupp:off - - - -
a=mptime:20 -
a=oldmediaip:10.50.3.218
a=sendrecv
a=rtcp:PORT
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:zC6Ea9EK/7YmDM79CK+TAnNXTI1pVmZuCMjUPMph
a=crypto:8 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:9 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:10 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:11 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:12 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:13 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:14 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:15 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:16 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:17 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:18 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=ptime:20
SDP





# SRTP w/ DTMF injection (TT#81600)

($sock_a, $sock_b) = new_call([qw(198.51.100.1 4328)], [qw(198.51.100.3 4330)]);

($port_a) = offer('SRTP w/ DTMF injection (TT#81600)',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off',
	'transport-protocol' => 'RTP/SAVP', flags => ['inject-DTMF'],
	'rtcp-mux' => ['demux'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
a=sendrecv
m=audio 4328 RTP/SAVP 0 8 9 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:101 telephone-event/8000
a=silenceSupp:off - - - -
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:1YiOLFFcF/OlCpW7u3fmSx1YllphIgh2cER3DWU3
a=fmtp:101 0-15
a=ptime:20
a=mptime:20 20 20 20 -
a=rtcp:4328 IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0 8 9 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:9 G722/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=silenceSupp:off - - - -
a=mptime:20 20 20 20 -
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:1YiOLFFcF/OlCpW7u3fmSx1YllphIgh2cER3DWU3
a=crypto:3 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:4 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:5 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:6 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:7 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:8 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
a=ptime:20
SDP

($port_b) = answer('SRTP w/ DTMF injection (TT#81600)',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off', ICE => 'remove', 
	flags => ['inject-DTMF'], 'rtcp-mux' => ['demux'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.3
t=0 0
a=sendrecv
m=audio 4330 RTP/SAVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=silenceSupp:off - - - -
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cdDuBSOp/rX/7ikmU1Tnuu337gXUUMFAhkARhB/j
a=fmtp:101 0-15
a=ptime:20
a=mptime:20 20 20 20 -
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=silenceSupp:off - - - -
a=mptime:20 20 20 20 -
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cdDuBSOp/rX/7ikmU1Tnuu337gXUUMFAhkARhB/j
a=ptime:20
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'QjnnaukLn7iwASAs0YLzPUplJkjOhTZK2dvOwo6c',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'cdDuBSOp/rX/7ikmU1Tnuu337gXUUMFAhkARhB/j',
};


srtp_snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x6543, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160), $srtp_ctx_b);




# RTCP

($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7400)],
	[qw(198.51.100.1 7401)],
	[qw(198.51.100.3 7402)],
	[qw(198.51.100.3 7403)],
);

($port_a, $port_ax) = offer('RTCP player', { ICE => 'remove', }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 198.51.100.1
t=0 0
m=audio 7400 RTP/AVP 8
a=rtpmap:8 PCMA/8000
a=sendrecv
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('RTCP player', { ICE => 'remove', }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 198.51.100.3
t=0 0
m=audio 7402 RTP/AVP 8
a=rtpmap:8 PCMA/8000
a=sendrecv
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(8, 2000, 4000, 0x3210, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 2000, 4000, 0x3210, "\x00" x 160));

$resp = rtpe_req('play media', 'media player', { 'from-tag' => ft(), blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

($seq, $ts, $ssrc) = rcv($sock_a, $port_b, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
#                                         SR  LEN    SSRC  NTP1  NTP2  RTP      PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR       DLSR           CNAME
@ret1 = rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c(.{4})(.{4})(.{4})(.{4})\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\xca\x00\x05(.{4})\x01\x0c([0-9a-f]{12})\x00\x00$/s);
is $ret1[0], $ssrc, 'SSRC matches';
is $ret1[3], $ts, 'TS matches';
is $ret1[4], $ssrc, 'SSRC matches';

rtpe_req('delete', "delete", { 'from-tag' => ft() });





($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7400)],
	[qw(198.51.100.1 7401)],
	[qw(198.51.100.3 7402)],
	[qw(198.51.100.3 7403)],
);

($port_a, $port_ax) = offer('RTCP player w/ previous SR', { ICE => 'remove', }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 198.51.100.1
t=0 0
m=audio 7400 RTP/AVP 8
a=rtpmap:8 PCMA/8000
a=sendrecv
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('RTCP player w/ previous SR', { ICE => 'remove', }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 198.51.100.3
t=0 0
m=audio 7402 RTP/AVP 8
a=rtpmap:8 PCMA/8000
a=sendrecv
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(8, 2000, 4000, 0x3210, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 2000, 4000, 0x3210, "\x00" x 160));

#                              SR  LEN          SSRC           NTP1          NTP2                 RTP          PACKETS         OCTETS
snd($sock_ax, $port_bx, "\x80\xc8\x00\x06\x00\x00\x12\x34\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x00\x0b\xb8\x00\x00\x00\x01\x00\x00\x00\xac");

Time::HiRes::usleep(50000); # 50 ms, wait for RTCP to be consumed

$resp = rtpe_req('play media', 'media player', { 'from-tag' => ft(), blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

($seq, $ts, $ssrc) = rcv($sock_a, $port_b, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
#                                         SR  LEN    SSRC  NTP1  NTP2  RTP      PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR     DLSR     CNAME
@ret1 = rcv($sock_ax, $port_bx, qr/^\x81\xc8\x00\x0c(.{4})(.{4})(.{4})(.{4})\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc(.{4})\x81\xca\x00\x05(.{4})\x01\x0c([0-9a-f]{12})\x00\x00$/s);
is $ret1[0], $ssrc, 'SSRC matches';
is $ret1[3], $ts, 'TS matches';
cmp_ok $ret1[4], '<', 6553, 'DSLR ok';
is $ret1[5], $ssrc, 'SSRC matches';

rtpe_req('delete', "delete", { 'from-tag' => ft() });




# SRTP control - accept diff suite from offer

($sock_a, $sock_b) = new_call([qw(198.51.100.1 3328)], [qw(198.51.100.3 3330)]);

($port_a, undef, undef, undef, undef, undef, undef, undef, $srtp_key_a) = offer('reg SRTP offer, accept, diff suite',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3328 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, undef, $srtp_key_b) = answer('reg SRTP offer, accept, diff suite',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3330 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_32},
	key => 'Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7',
};
$srtp_ctx_a_rev = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_32},
	key => $srtp_key_a,
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa',
};
$srtp_ctx_b_rev = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a_rev);
srtp_snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_b_rev);





# OSRTP

($sock_a, $sock_b) = new_call([qw(198.51.100.1 3380)], [qw(198.51.100.3 3382)]);

($port_a) = offer('OSRTP offer, reject, reinvite', { DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3380 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
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
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b) = answer('OSRTP offer, reject, reinvite', { DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3382 RTP/AVP 0
c=IN IP4 198.51.100.3
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

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));

reverse_tags();

offer('OSRTP offer, reject, reinvite', { DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3382 RTP/AVP 0
c=IN IP4 198.51.100.3
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

answer('OSRTP offer, reject, reinvite', { DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3380 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
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

snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160));



($sock_a, $sock_b) = new_call([qw(198.51.100.1 3316)], [qw(198.51.100.3 3318)]);

($port_a) = offer('OSRTP offer, accept, same suite',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3316 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b) = answer('OSRTP offer, accept, same suite',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3318 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa',
};

srtp_snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_b);



($sock_a, $sock_b) = new_call([qw(198.51.100.1 3320)], [qw(198.51.100.3 3322)]);

($port_a, undef, undef, undef, undef, undef, undef, undef, $srtp_key_a) = offer('OSRTP offer, accept, diff suite',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3320 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, undef, $srtp_key_b) = answer('OSRTP offer, accept, diff suite',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3322 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_32},
	key => 'Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7',
};
$srtp_ctx_a_rev = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_32},
	key => $srtp_key_a,
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa',
};
$srtp_ctx_b_rev = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_b,
};

srtp_snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a_rev);
srtp_snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_b_rev);




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3324)], [qw(198.51.100.3 3326)]);

($port_a) = offer('OSRTP offer, reject',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3324 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b) = answer('OSRTP offer, reject',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3326 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));



($sock_a, $sock_b) = new_call([qw(198.51.100.1 3324)], [qw(198.51.100.3 3326)]);

($port_a) = offer('OSRTP offer, reject w/ accept flag',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3324 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b, undef, $srtp_key_a) = answer('OSRTP offer, reject w/ accept flag',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off', OSRTP => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3326 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_a,
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa',
};

srtp_snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_b);
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
srtp_rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_a);

reverse_tags();

offer('OSRTP offer, reject w/ accept flag, reverse reinvite',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off', OSRTP => ['offer'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3326 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:$srtp_key_a
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('OSRTP offer, reject w/ accept flag, reverse reinvite',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off', OSRTP => ['accept'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3324 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

srtp_snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160), $srtp_ctx_b);
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2001, 4160, 0x3456, "\x00" x 160));
srtp_rcv($sock_a, $port_b, rtpm(0, 2001, 4160, 0x3456, "\x00" x 160), $srtp_ctx_a);


($sock_a, $sock_b) = new_call([qw(198.51.100.1 3336)], [qw(198.51.100.3 3338)]);

($port_a, undef, undef, undef, undef, undef, undef, undef, $srtp_key_a) = offer('non-OSRTP offer with offer flag, accept',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off', OSRTP => ['offer'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3336 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b) = answer('non-OSRTP offer with offer flag, accept',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off', }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3338 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_a,
};

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_a);
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3356)], [qw(198.51.100.3 3358)]);

($port_a, undef, undef, undef, undef, undef, undef, undef, $srtp_key_a) = offer('non-OSRTP offer with offer flag and protocol, accept',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off', OSRTP => ['offer'],
	'transport protocol' => 'RTP/AVP'}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3356 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b) = answer('non-OSRTP offer with offer flag and protocol, accept',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off', }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3358 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => $srtp_key_a,
};

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_b);
srtp_snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_a);
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));






($sock_a, $sock_b) = new_call([qw(198.51.100.1 3340)], [qw(198.51.100.3 3342)]);

($port_a, undef, $srtp_key_a) = offer('non-OSRTP offer with offer flag, reject',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off', OSRTP => ['offer'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3340 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b) = answer('non-OSRTP offer with offer flag, reject',
	{ ICE => 'remove', replace => ['origin'], DTLS => 'off', }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3342 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160));










# MSRP (GH 959)

new_call();

offer('gh 959 media c=', { ICE => 'remove', }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 1.2.3.4
t=0 0
m=audio 27998 RTP/AVP 96
a=rtpmap:96 opus/48000/2
m=message 28000 TCP/MSRP *
c=IN IP4 1.2.3.4
a=setup:active
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=sendrecv
a=rtcp:PORT
m=message 28000 TCP/MSRP *
c=IN IP4 1.2.3.4
a=setup:active
SDP

new_call();

offer('gh 959 media c= no session c=', { ICE => 'remove', }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio 27998 RTP/AVP 96
c=IN IP4 1.2.3.4
a=rtpmap:96 opus/48000/2
m=message 28000 TCP/MSRP *
c=IN IP4 1.2.3.4
a=setup:active
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=sendrecv
a=rtcp:PORT
m=message 28000 TCP/MSRP *
c=IN IP4 1.2.3.4
a=setup:active
SDP

new_call();

offer('gh 959 session c=', { ICE => 'remove', }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 1.2.3.4
t=0 0
m=audio 27998 RTP/AVP 96
a=rtpmap:96 opus/48000/2
m=message 28000 TCP/MSRP *
a=setup:active
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=sendrecv
a=rtcp:PORT
m=message 28000 TCP/MSRP *
c=IN IP4 1.2.3.4
a=setup:active
SDP

new_call();

offer('gh 959 session c= no attrs', { ICE => 'remove', }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 1.2.3.4
t=0 0
m=audio 27998 RTP/AVP 96
a=rtpmap:96 opus/48000/2
m=message 28000 TCP/MSRP *
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=sendrecv
a=rtcp:PORT
m=message 28000 TCP/MSRP *
c=IN IP4 1.2.3.4
SDP







# SDES key lifetime

new_call();

offer('gh 966', { ICE => 'remove', 'transport-protocol' => 'RTP/SAVP', SDES => ['lifetime'],
	DTLS => 'off' }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 1.2.3.4
t=0 0
m=audio 27998 RTP/AVP 96
a=rtpmap:96 opus/48000/2
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/SAVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S|2^31
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S|2^31
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256|2^31
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256|2^31
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192|2^31
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192|2^31
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128|2^31
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128|2^31
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128|2^31
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128|2^31
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128|2^31
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128|2^31
SDP





# PT collisions (GH 963)

new_call();

offer('gh 963', { ICE => 'remove', codec => { mask => ['full'], transcode => ['PCMA','telephone-event'] } }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 1.2.3.4
t=0 0
m=audio 27998 RTP/AVP 96 120
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1;maxplaybackrate=16000;sprop-maxcapturerate=16000;maxaveragebitrate=12000;cbr=1
a=rtpmap:120 telephone-event/48000
a=fmtp:120 0-16
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 8 97
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:97 telephone-event/8000
a=fmtp:97 0-15
a=sendrecv
a=rtcp:PORT
SDP

answer('gh 963', { ICE => 'remove', }, <<SDP);
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
t=0 0
m=audio 40935 RTP/AVP 8 97
c=IN IP4 172.17.0.2
a=rtpmap:8 PCMA/8000
a=rtpmap:97 telephone-event/8000
a=fmtp:97 0-15
----------------------------------
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
t=0 0
m=audio PORT RTP/AVP 96 120
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; useinbandfec=1
a=rtpmap:120 telephone-event/48000
a=fmtp:120 0-16
a=sendrecv
a=rtcp:PORT
SDP




new_call();

offer('gh 963 w mask all', { ICE => 'remove', codec => { mask => ['all'], transcode => ['PCMA','telephone-event'] } }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 1.2.3.4
t=0 0
m=audio 27998 RTP/AVP 96 120
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1;maxplaybackrate=16000;sprop-maxcapturerate=16000;maxaveragebitrate=12000;cbr=1
a=rtpmap:120 telephone-event/48000
a=fmtp:120 0-16
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 8 96
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
a=rtcp:PORT
SDP

answer('gh 963 w mask all', { ICE => 'remove', }, <<SDP);
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
t=0 0
m=audio 40935 RTP/AVP 8 96
c=IN IP4 172.17.0.2
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
----------------------------------
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
t=0 0
m=audio PORT RTP/AVP 96 120
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=0; useinbandfec=1
a=rtpmap:120 telephone-event/48000
a=fmtp:120 0-16
a=sendrecv
a=rtcp:PORT
SDP






# symmetric-codec flag (GH 953)

new_call();

offer('gh 953 w/o flag', { ICE => 'remove', codec => { transcode => ['G722'] } }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 1.2.3.4
t=0 0
m=audio 27998 RTP/AVP 8 107 101
a=rtpmap:8 PCMA/8000
a=rtpmap:107 opus/48000/2
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:20
a=sendrecv
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 8 107 9 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:107 opus/48000/2
a=rtpmap:9 G722/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:20
SDP

answer('gh 953 w/o flag', { ICE => 'remove', }, <<SDP);
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
b=AS:117
t=0 0
a=X-nat:0
m=audio 40935 RTP/AVP 107 101
c=IN IP4 172.17.0.2
b=TIAS:96000
a=rtcp:40936 IN IP4 172.17.0.2
a=sendrecv
a=ssrc:243811319 cname:04389d431bdd5c52
a=rtpmap:107 opus/48000/2
a=fmtp:107 useinbandfec=1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
----------------------------------
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
b=AS:117
t=0 0
a=X-nat:0
m=audio PORT RTP/AVP 107 101
c=IN IP4 203.0.113.1
b=TIAS:96000
a=rtpmap:107 opus/48000/2
a=fmtp:107 useinbandfec=1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ssrc:243811319 cname:04389d431bdd5c52
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP




new_call();

offer('gh 953 w/ flag', { ICE => 'remove', codec => { transcode => ['G722'] } }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 1.2.3.4
t=0 0
m=audio 27998 RTP/AVP 8 107 101
a=rtpmap:8 PCMA/8000
a=rtpmap:107 opus/48000/2
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:20
a=sendrecv
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 8 107 9 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:107 opus/48000/2
a=rtpmap:9 G722/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:20
SDP

answer('gh 953 w/ flag', { ICE => 'remove', flags => ['symmetric codecs'] }, <<SDP);
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
b=AS:117
t=0 0
a=X-nat:0
m=audio 40935 RTP/AVP 107 101
c=IN IP4 172.17.0.2
b=TIAS:96000
a=rtcp:40936 IN IP4 172.17.0.2
a=sendrecv
a=ssrc:243811319 cname:04389d431bdd5c52
a=rtpmap:107 opus/48000/2
a=fmtp:107 useinbandfec=1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
----------------------------------
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
b=AS:117
t=0 0
a=X-nat:0
m=audio PORT RTP/AVP 107 101
c=IN IP4 203.0.113.1
b=TIAS:96000
a=rtpmap:107 opus/48000/2
a=fmtp:107 useinbandfec=1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ssrc:243811319 cname:04389d431bdd5c52
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP




new_call;

offer('gh 953 722 accepted w/o flag', { ICE => 'remove', codec => { transcode => ['G722'] } }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 1.2.3.4
t=0 0
m=audio 27998 RTP/AVP 8 107 101
a=rtpmap:8 PCMA/8000
a=rtpmap:107 opus/48000/2
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:20
a=sendrecv
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 8 107 9 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:107 opus/48000/2
a=rtpmap:9 G722/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:20
SDP

answer('gh 953 722 accepted w/o flag', { ICE => 'remove', }, <<SDP);
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
b=AS:117
t=0 0
a=X-nat:0
m=audio 40935 RTP/AVP 107 101 9
c=IN IP4 172.17.0.2
b=TIAS:96000
a=rtcp:40936 IN IP4 172.17.0.2
a=sendrecv
a=ssrc:243811319 cname:04389d431bdd5c52
a=rtpmap:107 opus/48000/2
a=fmtp:107 useinbandfec=1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
----------------------------------
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
b=AS:117
t=0 0
a=X-nat:0
m=audio PORT RTP/AVP 107 8 101
c=IN IP4 203.0.113.1
b=TIAS:96000
a=rtpmap:107 opus/48000/2
a=fmtp:107 useinbandfec=1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ssrc:243811319 cname:04389d431bdd5c52
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP




new_call();

offer('gh 953 722 accepted w/ flag', { ICE => 'remove', codec => { transcode => ['G722'] } }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 1.2.3.4
t=0 0
m=audio 27998 RTP/AVP 8 107 101
a=rtpmap:8 PCMA/8000
a=rtpmap:107 opus/48000/2
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:20
a=sendrecv
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 8 107 9 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:107 opus/48000/2
a=rtpmap:9 G722/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:20
SDP

answer('gh 953 722 accepted w/ flag', { ICE => 'remove', flags => ['symmetric codecs'] }, <<SDP);
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
b=AS:117
t=0 0
a=X-nat:0
m=audio 40935 RTP/AVP 107 101 9
c=IN IP4 172.17.0.2
b=TIAS:96000
a=rtcp:40936 IN IP4 172.17.0.2
a=sendrecv
a=ssrc:243811319 cname:04389d431bdd5c52
a=rtpmap:107 opus/48000/2
a=fmtp:107 useinbandfec=1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
----------------------------------
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
b=AS:117
t=0 0
a=X-nat:0
m=audio PORT RTP/AVP 107 8 101
c=IN IP4 203.0.113.1
b=TIAS:96000
a=rtpmap:107 opus/48000/2
a=fmtp:107 useinbandfec=1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ssrc:243811319 cname:04389d431bdd5c52
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP





new_call();

offer('gh 953 only 722 accepted w/o flag', { ICE => 'remove', codec => { transcode => ['G722'] } }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 1.2.3.4
t=0 0
m=audio 27998 RTP/AVP 8 107 101
a=rtpmap:8 PCMA/8000
a=rtpmap:107 opus/48000/2
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:20
a=sendrecv
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 8 107 9 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:107 opus/48000/2
a=rtpmap:9 G722/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:20
SDP

answer('gh 953 only 722 accepted w/o flag', { ICE => 'remove', }, <<SDP);
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
b=AS:117
t=0 0
a=X-nat:0
m=audio 40935 RTP/AVP 9
c=IN IP4 172.17.0.2
b=TIAS:96000
a=rtcp:40936 IN IP4 172.17.0.2
a=sendrecv
a=ssrc:243811319 cname:04389d431bdd5c52
----------------------------------
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
b=AS:117
t=0 0
a=X-nat:0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
b=TIAS:96000
a=rtpmap:8 PCMA/8000
a=ssrc:243811319 cname:04389d431bdd5c52
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP




new_call();

offer('gh 953 only 722 accepted w/ flag', { ICE => 'remove', codec => { transcode => ['G722'] } }, <<SDP);
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
c=IN IP4 1.2.3.4
t=0 0
m=audio 27998 RTP/AVP 8 107 101
a=rtpmap:8 PCMA/8000
a=rtpmap:107 opus/48000/2
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:20
a=sendrecv
----------------------------------
v=0
o=- 1822058533 1822058533 IN IP4 1.2.3.4
s=Asterisk
t=0 0
m=audio PORT RTP/AVP 8 107 9 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:107 opus/48000/2
a=rtpmap:9 G722/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:20
SDP

answer('gh 953 only 722 accepted w/ flag', { ICE => 'remove', flags => ['symmetric codecs'] }, <<SDP);
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
b=AS:117
t=0 0
a=X-nat:0
m=audio 40935 RTP/AVP 9
c=IN IP4 172.17.0.2
b=TIAS:96000
a=rtcp:40936 IN IP4 172.17.0.2
a=sendrecv
a=ssrc:243811319 cname:04389d431bdd5c52
----------------------------------
v=0
o=- 3793596600 3793596601 IN IP4 172.17.0.2
s=pjmedia
b=AS:117
t=0 0
a=X-nat:0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
b=TIAS:96000
a=rtpmap:8 PCMA/8000
a=ssrc:243811319 cname:04389d431bdd5c52
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP




# T.38 signalling scenarios

new_call();

offer('forward T.38 invite without codecs given', { 'T.38' => [ 'decode' ], ICE => 'remove',
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=image 6000 udptl t38
c=IN IP4 198.51.100.1
a=sendrecv
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:262
a=T38FaxMaxDatagram:300
a=T38FaxUdpEC:t38UDPRedundancy
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

rtpe_req('delete', "delete", { 'from-tag' => ft() });





new_call();

offer('T.38 forward re-invite', { ICE => 'remove',
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6000 RTP/AVP 8 0
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('T.38 forward re-invite', { ICE => 'remove',
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6002 RTP/AVP 8 0
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('T.38 forward re-invite', { ICE => 'remove', 'T.38' => [ 'force' ],
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6000 RTP/AVP 8 0
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=image PORT udptl t38
c=IN IP4 203.0.113.1
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:1800
a=T38FaxMaxDatagram:512
a=T38FaxUdpEC:t38UDPRedundancy
a=sendrecv
SDP

answer('T.38 forward re-invite', { ICE => 'remove',
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=image 4018 udptl t38
c=IN IP4 198.51.100.1
a=sendrecv
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:262
a=T38FaxMaxDatagram:300
a=T38FaxUdpEC:t38UDPRedundancy
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

rtpe_req('delete', "delete", { 'from-tag' => ft() });




new_call();

offer('T.38 reverse re-invite', { ICE => 'remove',
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6000 RTP/AVP 8 0
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('T.38 reverse re-invite', { ICE => 'remove',
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6002 RTP/AVP 8 0
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('T.38 reverse re-invite', { ICE => 'remove', 'T.38' => [ 'decode' ],
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=image 6000 udptl t38
c=IN IP4 198.51.100.1
a=sendrecv
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:262
a=T38FaxMaxDatagram:300
a=T38FaxUdpEC:t38UDPRedundancy
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('T.38 reverse re-invite', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6002 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=image PORT udptl t38
c=IN IP4 203.0.113.1
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:1800
a=T38FaxMaxDatagram:512
a=T38FaxUdpEC:t38UDPRedundancy
a=sendrecv
SDP

rtpe_req('delete', "delete", { 'from-tag' => ft() });






new_call();

offer('T.38 forward re-invite w/ unsupported codec', { ICE => 'remove',
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6000 RTP/AVP 96 8 0
c=IN IP4 198.51.100.3
a=rtpmap:96 foobar/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8 0
c=IN IP4 203.0.113.1
a=rtpmap:96 foobar/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('T.38 forward re-invite w/ unsupported codec', { ICE => 'remove',
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6002 RTP/AVP 96
c=IN IP4 198.51.100.3
a=rtpmap:96 foobar/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 foobar/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('T.38 forward re-invite w/ unsupported codec', { ICE => 'remove', 'T.38' => [ 'force' ],
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6000 RTP/AVP 96 8 0
c=IN IP4 198.51.100.3
a=rtpmap:96 foobar/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=image PORT udptl t38
c=IN IP4 203.0.113.1
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:1800
a=T38FaxMaxDatagram:512
a=T38FaxUdpEC:t38UDPRedundancy
a=sendrecv
SDP

answer('T.38 forward re-invite w/ unsupported codec', { ICE => 'remove',
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=image 4018 udptl t38
c=IN IP4 198.51.100.1
a=sendrecv
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:262
a=T38FaxMaxDatagram:300
a=T38FaxUdpEC:t38UDPRedundancy
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

rtpe_req('delete', "delete", { 'from-tag' => ft() });




new_call();

offer('T.38 reverse re-invite w/ unsupported codec', { ICE => 'remove',
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6000 RTP/AVP 96 8 0
c=IN IP4 198.51.100.3
a=rtpmap:96 foobar/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8 0
c=IN IP4 203.0.113.1
a=rtpmap:96 foobar/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('T.38 reverse re-invite w/ unsupported codec', { ICE => 'remove',
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6002 RTP/AVP 96 8 0
c=IN IP4 198.51.100.3
a=rtpmap:96 foobar/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8 0
c=IN IP4 203.0.113.1
a=rtpmap:96 foobar/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

offer('T.38 reverse re-invite w/ unsupported codec', { ICE => 'remove', 'T.38' => [ 'decode' ],
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=image 6000 udptl t38
c=IN IP4 198.51.100.1
a=sendrecv
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:262
a=T38FaxMaxDatagram:300
a=T38FaxUdpEC:t38UDPRedundancy
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('T.38 reverse re-invite w/ unsupported codec', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6002 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=image PORT udptl t38
c=IN IP4 203.0.113.1
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:1800
a=T38FaxMaxDatagram:512
a=T38FaxUdpEC:t38UDPRedundancy
a=sendrecv
SDP

rtpe_req('delete', "delete", { 'from-tag' => ft() });



new_call;

offer('T.38 FEC invite', { ICE => 'remove', 'T.38' => [ 'force', 'FEC' ],
	 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6000 RTP/AVP 8 0
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=image PORT udptl t38
c=IN IP4 203.0.113.1
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:1800
a=T38FaxMaxDatagram:512
a=T38FaxUdpEC:t38UDPFEC
a=sendrecv
SDP

rtpe_req('delete', "delete", { 'from-tag' => ft() });





# github issue 850

new_call;

@ret1 = offer('gh 850',
	{
		ICE => 'force-relay', flags => [qw(SDES-off)], 'transport-protocol' => 'UDP/TLS/RTP/SAVPF',
		'rtcp-mux' => [qw(accept offer)], 'via-branch' => 'z9hG4bK9463.af303705.113',
	}, <<SDP);
v=0
o=- 9011363210357191088 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY
m=audio 14745 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126
c=IN IP4 192.168.1.1
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:661312077 1 udp 2122262783 2001:db8:2200:205:fd25:1ca1:96cd:8c2e 61773 typ host generation 0 network-id 2 network-cost 10
a=candidate:2313719679 1 udp 2122194687 192.168.1.54 55343 typ host generation 0 network-id 1 network-cost 10
a=candidate:521932948 1 udp 2122131711 2001:db8:5c0:3a15:b3ec:67e6:e268:b9e0 55344 typ host generation 0 network-id 3 network-cost 50
a=candidate:2982564287 1 udp 1686055167 2001:db8:0:8::f:111b 11344 typ srflx raddr 2001:db8:2200:205:fd25:1ca1:96cd:8c2e rport 61773 generation 0 network-id 2 network-cost 10
a=candidate:2147022507 1 udp 1685987071 192.168.1.1 14745 typ srflx raddr 192.168.1.54 rport 55343 generation 0 network-id 1 network-cost 10
a=candidate:1776889533 1 tcp 1518283007 2001:db8:2200:205:fd25:1ca1:96cd:8c2e 9 typ host tcptype active generation 0 network-id 2 network-cost 10
a=candidate:3345707919 1 tcp 1518214911 192.168.1.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:1369435236 1 tcp 1518151935 2001:db8:5c0:3a15:b3ec:67e6:e268:b9e0 9 typ host tcptype active generation 0 network-id 3 network-cost 50
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
a=fingerprint:sha-256 32:62:C7:5E:79:69:2A:15:DC:EA:1D:13:18:4C:C9:92:44:71:8A:B7:38:73:88:F9:99:A3:7A:05:D1:EE:98:B8
a=setup:actpass
a=rtcp-mux
a=mid:0
a=sendrecv
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10;useinbandfec=1
a=rtcp-fb:111 transport-cc
a=rtcp-fb:111 testing
a=rtcp-fb:111 foobar
a=rtpmap:103 ISAC/16000
a=rtpmap:104 ISAC/32000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:106 CN/32000
a=rtpmap:105 CN/16000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:112 telephone-event/32000
a=rtpmap:113 telephone-event/16000
a=rtpmap:126 telephone-event/8000
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=msid:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY 7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=ssrc:2628106563 cname:wMyHbPOf/cCq2tup
a=ssrc:2628106563 msid:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY 7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=ssrc:2628106563 mslabel:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY
a=ssrc:2628106563 label:7d669de6-65e9-4fbe-829e-e89dc4baf81c
--------------------------------------
v=0
o=- 9011363210357191088 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY
m=audio 14745 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126
c=IN IP4 192.168.1.1
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:661312077 1 udp 2122262783 2001:db8:2200:205:fd25:1ca1:96cd:8c2e 61773 typ host generation 0 network-id 2 network-cost 10
a=candidate:2313719679 1 udp 2122194687 192.168.1.54 55343 typ host generation 0 network-id 1 network-cost 10
a=candidate:521932948 1 udp 2122131711 2001:db8:5c0:3a15:b3ec:67e6:e268:b9e0 55344 typ host generation 0 network-id 3 network-cost 50
a=candidate:2982564287 1 udp 1686055167 2001:db8:0:8::f:111b 11344 typ srflx raddr 2001:db8:2200:205:fd25:1ca1:96cd:8c2e rport 61773 generation 0 network-id 2 network-cost 10
a=candidate:2147022507 1 udp 1685987071 192.168.1.1 14745 typ srflx raddr 192.168.1.54 rport 55343 generation 0 network-id 1 network-cost 10
a=candidate:1776889533 1 tcp 1518283007 2001:db8:2200:205:fd25:1ca1:96cd:8c2e 9 typ host tcptype active generation 0 network-id 2 network-cost 10
a=candidate:3345707919 1 tcp 1518214911 192.168.1.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:1369435236 1 tcp 1518151935 2001:db8:5c0:3a15:b3ec:67e6:e268:b9e0 9 typ host tcptype active generation 0 network-id 3 network-cost 50
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
a=fingerprint:sha-256 32:62:C7:5E:79:69:2A:15:DC:EA:1D:13:18:4C:C9:92:44:71:8A:B7:38:73:88:F9:99:A3:7A:05:D1:EE:98:B8
a=setup:actpass
a=rtcp-mux
a=mid:0
a=sendrecv
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10;useinbandfec=1
a=rtcp-fb:111 transport-cc
a=rtcp-fb:111 testing
a=rtcp-fb:111 foobar
a=rtpmap:103 ISAC/16000
a=rtpmap:104 ISAC/32000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:106 CN/32000
a=rtpmap:105 CN/16000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:112 telephone-event/32000
a=rtpmap:113 telephone-event/16000
a=rtpmap:126 telephone-event/8000
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=msid:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY 7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=ssrc:2628106563 cname:wMyHbPOf/cCq2tup
a=ssrc:2628106563 msid:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY 7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=ssrc:2628106563 mslabel:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY
a=ssrc:2628106563 label:7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=candidate:ICEBASE 1 UDP 16777215 203.0.113.1 PORT typ relay raddr 203.0.113.1 rport PORT
a=candidate:ICEBASE 1 UDP 16776959 2001:db8:4321::1 PORT typ relay raddr 2001:db8:4321::1 rport PORT
a=candidate:ICEBASE 2 UDP 16777214 203.0.113.1 PORT typ relay raddr 203.0.113.1 rport PORT
a=candidate:ICEBASE 2 UDP 16776958 2001:db8:4321::1 PORT typ relay raddr 2001:db8:4321::1 rport PORT
SDP

is $ret1[0], $ret1[6], 'ice base 1';
is $ret1[1], $ret1[2], 'rtp rport 1';
is $ret1[3], $ret1[9], 'ice base 2';
is $ret1[4], $ret1[5], 'rtp rport 2';
is $ret1[7], $ret1[8], 'rtcp rport 1';
is $ret1[10], $ret1[11], 'rtcp rport 2';

@ret1 = answer('gh 850',
	{
		ICE => 'force-relay', flags => [qw(SDES-off)], 'transport-protocol' => 'UDP/TLS/RTP/SAVPF', 
		'rtcp-mux' => [qw(accept offer)], 'via-branch' => 'z9hG4bK9463.af303705.113',
	}, <<SDP);
v=0
o=- 262597839645727503 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS 9z51ZTKhoszc7zqj5gxEX309ODe940YpMplv
m=audio 5308 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126
c=IN IP4 192.168.1.1
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:661312077 1 udp 2122262783 2001:db8:2200:205:fd25:1ca1:96cd:8c2e 55347 typ host generation 0 network-id 2 network-cost 10
a=candidate:2313719679 1 udp 2122194687 192.168.1.54 52949 typ host generation 0 network-id 1 network-cost 10
a=candidate:521932948 1 udp 2122131711 2001:db8:5c0:3a15:b3ec:67e6:e268:b9e0 52950 typ host generation 0 network-id 3 network-cost 50
a=candidate:2982564287 1 udp 1686055167 2001:db8:0:8::f:111b 27536 typ srflx raddr 2001:db8:2200:205:fd25:1ca1:96cd:8c2e rport 55347 generation 0 network-id 2 network-cost 10
a=candidate:2147022507 1 udp 1685987071 192.168.1.1 5308 typ srflx raddr 192.168.1.54 rport 52949 generation 0 network-id 1 network-cost 10
a=ice-ufrag:Opvv
a=ice-pwd:nxh4YdcCu2rHq1h1aBOYzlqD
a=ice-options:trickle
a=fingerprint:sha-256 43:92:E2:A9:BC:FD:53:00:32:4D:EC:97:55:B5:C9:52:95:40:BE:CB:1A:26:4B:34:7A:48:42:96:09:F7:50:97
a=setup:active
a=mid:0
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=sendrecv
a=msid:9z51ZTKhoszc7zqj5gxEX309ODe940YpMplv 8a622ecc-1fff-4675-8bf4-7b924845b3fd
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=rtcp-fb:111 transport-cc
a=fmtp:111 minptime=10;useinbandfec=1
a=rtpmap:103 ISAC/16000
a=rtpmap:104 ISAC/32000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:106 CN/32000
a=rtpmap:105 CN/16000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:112 telephone-event/32000
a=rtpmap:113 telephone-event/16000
a=rtpmap:126 telephone-event/8000
a=ssrc:97254339 cname:d7zRWvteaW9fc2Yu
--------------------------------------
v=0
o=- 262597839645727503 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS 9z51ZTKhoszc7zqj5gxEX309ODe940YpMplv
m=audio 5308 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126
c=IN IP4 192.168.1.1
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:661312077 1 udp 2122262783 2001:db8:2200:205:fd25:1ca1:96cd:8c2e 55347 typ host generation 0 network-id 2 network-cost 10
a=candidate:2313719679 1 udp 2122194687 192.168.1.54 52949 typ host generation 0 network-id 1 network-cost 10
a=candidate:521932948 1 udp 2122131711 2001:db8:5c0:3a15:b3ec:67e6:e268:b9e0 52950 typ host generation 0 network-id 3 network-cost 50
a=candidate:2982564287 1 udp 1686055167 2001:db8:0:8::f:111b 27536 typ srflx raddr 2001:db8:2200:205:fd25:1ca1:96cd:8c2e rport 55347 generation 0 network-id 2 network-cost 10
a=candidate:2147022507 1 udp 1685987071 192.168.1.1 5308 typ srflx raddr 192.168.1.54 rport 52949 generation 0 network-id 1 network-cost 10
a=ice-ufrag:Opvv
a=ice-pwd:nxh4YdcCu2rHq1h1aBOYzlqD
a=ice-options:trickle
a=fingerprint:sha-256 43:92:E2:A9:BC:FD:53:00:32:4D:EC:97:55:B5:C9:52:95:40:BE:CB:1A:26:4B:34:7A:48:42:96:09:F7:50:97
a=setup:active
a=mid:0
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=sendrecv
a=msid:9z51ZTKhoszc7zqj5gxEX309ODe940YpMplv 8a622ecc-1fff-4675-8bf4-7b924845b3fd
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=rtcp-fb:111 transport-cc
a=fmtp:111 minptime=10;useinbandfec=1
a=rtpmap:103 ISAC/16000
a=rtpmap:104 ISAC/32000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:106 CN/32000
a=rtpmap:105 CN/16000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:112 telephone-event/32000
a=rtpmap:113 telephone-event/16000
a=rtpmap:126 telephone-event/8000
a=ssrc:97254339 cname:d7zRWvteaW9fc2Yu
a=candidate:ICEBASE 1 UDP 16777215 203.0.113.1 PORT typ relay raddr 203.0.113.1 rport PORT
a=candidate:ICEBASE 1 UDP 16776959 2001:db8:4321::1 PORT typ relay raddr 2001:db8:4321::1 rport PORT
SDP

is $ret1[1], $ret1[2], 'rtp rport 1';
is $ret1[4], $ret1[5], 'rtp rport 2';



new_call;

@ret1 = offer('gh 850 EOC',
	{
		ICE => 'force-relay', flags => [qw(SDES-off)], 'transport-protocol' => 'UDP/TLS/RTP/SAVPF',
		'rtcp-mux' => [qw(accept offer)], 'via-branch' => 'z9hG4bK9463.af303705.113',
	}, <<SDP);
v=0
o=- 9011363210357191088 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY
m=audio 14745 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126
c=IN IP4 192.168.1.1
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:661312077 1 udp 2122262783 2001:db8:2200:205:fd25:1ca1:96cd:8c2e 61773 typ host generation 0 network-id 2 network-cost 10
a=candidate:2313719679 1 udp 2122194687 192.168.1.54 55343 typ host generation 0 network-id 1 network-cost 10
a=candidate:521932948 1 udp 2122131711 2001:db8:5c0:3a15:b3ec:67e6:e268:b9e0 55344 typ host generation 0 network-id 3 network-cost 50
a=candidate:2982564287 1 udp 1686055167 2001:db8:0:8::f:111b 11344 typ srflx raddr 2001:db8:2200:205:fd25:1ca1:96cd:8c2e rport 61773 generation 0 network-id 2 network-cost 10
a=candidate:2147022507 1 udp 1685987071 192.168.1.1 14745 typ srflx raddr 192.168.1.54 rport 55343 generation 0 network-id 1 network-cost 10
a=candidate:1776889533 1 tcp 1518283007 2001:db8:2200:205:fd25:1ca1:96cd:8c2e 9 typ host tcptype active generation 0 network-id 2 network-cost 10
a=candidate:3345707919 1 tcp 1518214911 192.168.1.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:1369435236 1 tcp 1518151935 2001:db8:5c0:3a15:b3ec:67e6:e268:b9e0 9 typ host tcptype active generation 0 network-id 3 network-cost 50
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
a=fingerprint:sha-256 32:62:C7:5E:79:69:2A:15:DC:EA:1D:13:18:4C:C9:92:44:71:8A:B7:38:73:88:F9:99:A3:7A:05:D1:EE:98:B8
a=setup:actpass
a=rtcp-mux
a=mid:0
a=sendrecv
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10;useinbandfec=1
a=rtcp-fb:111 transport-cc
a=rtcp-fb:111 testing
a=rtcp-fb:111 foobar
a=rtpmap:103 ISAC/16000
a=rtpmap:104 ISAC/32000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:106 CN/32000
a=rtpmap:105 CN/16000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:112 telephone-event/32000
a=rtpmap:113 telephone-event/16000
a=rtpmap:126 telephone-event/8000
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=msid:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY 7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=ssrc:2628106563 cname:wMyHbPOf/cCq2tup
a=ssrc:2628106563 msid:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY 7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=ssrc:2628106563 mslabel:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY
a=ssrc:2628106563 label:7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=end-of-candidates
--------------------------------------
v=0
o=- 9011363210357191088 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY
m=audio 14745 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126
c=IN IP4 192.168.1.1
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:661312077 1 udp 2122262783 2001:db8:2200:205:fd25:1ca1:96cd:8c2e 61773 typ host generation 0 network-id 2 network-cost 10
a=candidate:2313719679 1 udp 2122194687 192.168.1.54 55343 typ host generation 0 network-id 1 network-cost 10
a=candidate:521932948 1 udp 2122131711 2001:db8:5c0:3a15:b3ec:67e6:e268:b9e0 55344 typ host generation 0 network-id 3 network-cost 50
a=candidate:2982564287 1 udp 1686055167 2001:db8:0:8::f:111b 11344 typ srflx raddr 2001:db8:2200:205:fd25:1ca1:96cd:8c2e rport 61773 generation 0 network-id 2 network-cost 10
a=candidate:2147022507 1 udp 1685987071 192.168.1.1 14745 typ srflx raddr 192.168.1.54 rport 55343 generation 0 network-id 1 network-cost 10
a=candidate:1776889533 1 tcp 1518283007 2001:db8:2200:205:fd25:1ca1:96cd:8c2e 9 typ host tcptype active generation 0 network-id 2 network-cost 10
a=candidate:3345707919 1 tcp 1518214911 192.168.1.54 9 typ host tcptype active generation 0 network-id 1 network-cost 10
a=candidate:1369435236 1 tcp 1518151935 2001:db8:5c0:3a15:b3ec:67e6:e268:b9e0 9 typ host tcptype active generation 0 network-id 3 network-cost 50
a=ice-ufrag:Ci7n
a=ice-pwd:l9QndxLG6OycZRcQe9zcT95c
a=ice-options:trickle
a=fingerprint:sha-256 32:62:C7:5E:79:69:2A:15:DC:EA:1D:13:18:4C:C9:92:44:71:8A:B7:38:73:88:F9:99:A3:7A:05:D1:EE:98:B8
a=setup:actpass
a=rtcp-mux
a=mid:0
a=sendrecv
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10;useinbandfec=1
a=rtcp-fb:111 transport-cc
a=rtcp-fb:111 testing
a=rtcp-fb:111 foobar
a=rtpmap:103 ISAC/16000
a=rtpmap:104 ISAC/32000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:106 CN/32000
a=rtpmap:105 CN/16000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:112 telephone-event/32000
a=rtpmap:113 telephone-event/16000
a=rtpmap:126 telephone-event/8000
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=msid:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY 7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=ssrc:2628106563 cname:wMyHbPOf/cCq2tup
a=ssrc:2628106563 msid:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY 7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=ssrc:2628106563 mslabel:qDSKVQw0XQOFzGhek25Kn3RLxyHTM2ooxMUY
a=ssrc:2628106563 label:7d669de6-65e9-4fbe-829e-e89dc4baf81c
a=candidate:ICEBASE 1 UDP 16777215 203.0.113.1 PORT typ relay raddr 203.0.113.1 rport PORT
a=candidate:ICEBASE 1 UDP 16776959 2001:db8:4321::1 PORT typ relay raddr 2001:db8:4321::1 rport PORT
a=candidate:ICEBASE 2 UDP 16777214 203.0.113.1 PORT typ relay raddr 203.0.113.1 rport PORT
a=candidate:ICEBASE 2 UDP 16776958 2001:db8:4321::1 PORT typ relay raddr 2001:db8:4321::1 rport PORT
a=end-of-candidates
SDP

if (0) {

# github issue 854

($sock_a, $sock_b) = new_call([qw(198.51.100.1 7326)], [qw(198.51.100.3 7328)]);

($port_a) = offer('gh854 inbound 30 ms',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7326 RTP/AVP 96
c=IN IP4 198.51.100.1
a=rtpmap:96 iLBC/8000
a=fmtp:96 mode=30
a=ptime:30
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 iLBC/8000
a=fmtp:96 mode=30
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('gh854 inbound 30 ms',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7328 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 iLBC/8000
a=fmtp:96 mode=30
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

snd($sock_a, $port_b, rtp(96, 1000, 3000, 0x6543, "\xa2\xff\x30\x0e\x5b\x3e\xa0\xac\x40\x40\x00\x57\xff\xff\xfd\xa4\x58\x8b\x62\x10\xcf\xff\xb9\xaa\xbb\xff\xcc\xc0\x00\x00\x00\x00\x00\x0c\x31\x1c\xc1\x74\xaf\x85\x85\x9a\x32\x33\x63\x60\x21\x61\x58\x76"));
($ssrc) = rcv($sock_b, $port_a, rtpm(8, 1000, 3000, -1, "\xd5\x55\x57\x5e\x65\x03\x2a\x2a\x2a\xaa\xaa\xaa\xaa\x2a\xaa\x2a\xaa\x2a\x2a\xaa\xaa\xaa\xaa\xaa\xaa\x2a\xaa\xaa\xaa\xaa\xab\x2a\xaa\xa8\x2a\xaa\x2a\xaa\x2a\x2a\x2a\x2a\x2a\x2b\x2a\x2e\x2e\x2a\x2a\x2e\x26\xaa\xaa\xaa\x3c\x2a\x2a\xad\xad\xa3\xa7\xa7\xa3\xa2\xa1\xa3\xa4\xba\xbe\xb2\xb6\x8a\x86\x9f\x96\xee\x9b\x81\x84\x9d\x99\x9a\x85\x87\x84\x8f\x8d\x82\x83\xed\x97\x95\x87\x8b\xb1\x81\x81\x9b\x9c\xea\xcc\x79\x6c\x11\x13\x1b\x18\x19\x19\x1f\x12\x10\x12\x1d\x10\x16\x14\x6b\x68\x66\x64\x7a\x7e\x7d\x72\x72\x7c\x7f\x79\x65\x65\x60\x61\x61\x61\x7f\x7c\x72\x78\x67\x62\x78\x7a\x78\x7f\x71\x48\x44\x5c\x55\xd3\xd9\xc4\xc6\xc1\xc1\xc6\xc4\xda\xd8\xd8\xd9\xdc\xda\xdd\xdf\xd3\xd2\xd6\xda\xdd\xdf\xde\xd8\xdb\xda\xdb\xda\xdb\xda\xd8\xd9\xde\xdf\xdc\xdd\xdd\xd2\xd3\xd3\xd3\xd0\xd0\xd1\xd1\xd0\xd1\xd1\xd1\xd1\xd1\xd1\xd1\xd6\xd6\xd6\xd7\xd7\xd7\xd4\xd4\xd4\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\x55\xd5\x55\x55\x55\x55\x55\x55\x55\x55\x54\x54\x54\x54\x54\x54\x54\x54"));

# mode switch
snd($sock_a, $port_b, rtp(96, 1001, 3240, 0x6543, "\xa2\xff\x37\xd3\xe2\xb8\x50\x40\x00\x5f\xff\xff\xff\x89\xcc\xff\x76\x6a\xae\xff\xcc\x00\x00\x00\x00\x00\x00\x00\x36\x52\x9d\x93\xf8\x45\x45\x45\x12\x16"));
($ssrc) = rcv($sock_b, $port_a, rtpm(8, 1001, 3240, -1, "\xd5\xd5\x55\xaa\x2a\xaa\xaa\x2a\xaa\xaa\xaa\x2a\x2a\xaa\x2a\x2a\x2a\x2a\xaa\xaa\x2a\xaa\x2a\xaa\x2a\xaa\x2a\x2a\xa7\x2a\x2a\x2a\xaa\xaa\x2a\xaa\xaa\x2a\x2a\x2a\x2a\xaa\xaa\xaa\xaa\x2a\x2a\xaa\xaa\xaa\x2a\x2a\x2a\x2a\xaa\x2a\xaa\x2a\xaa\xaa\x2a\x2a\x2a\x2a\x2a\x2a\xaa\x2a\x2a\x2a\x2a\x28\xaa\x2a\x28\xaa\x3e\xaa\xaa\x2a\x2a\xaa\x2a\x2a\xaa\x2a\xaa\xaa\xaa\x81\x36\x2a\x2a\x2a\x2a\xaa\xaa\x2a\xaa\xaa\x2a\xaa\x2a\x2a\x2a\xa5\xaa\xaa\xaa\xaa\xaa\x2a\x2a\xaa\x2a\x2a\xaa\x2a\xaa\xaa\xaa\xaa\xa2\xa4\xaf\x7e\xec\x37\x26\x21\x2f\x28\x29\x2a\x28\x2e\x2f\x22\x20\x27\x25\x39\x32\x31\x34\x0b\x0e\x0c\x0d\x02\x03\x01\x01\x06\x06\x06\x07\x04\x05\x1e"));

snd($sock_b, $port_a, rtp(8, 1000, 3000, 0x1234, "\x00" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\xa2\xff\x30\x0e\x5b\x3e\xa0\xac\x40\x40\x00\x57\xff\xff\xfd\xa4\x58\x8b\x62\x10\xcf\xff\xb9\xaa\xbb\xff\xcc\xc0\x00\x00\x00\x00\x00\x0c\x31\x1c\xc1\x74\xaf\x85\x85\x9a\x32\x33\x63\x60\x21\x61\x58\x76"));



($sock_a, $sock_b) = new_call([qw(198.51.100.1 7322)], [qw(198.51.100.3 7324)]);

($port_a) = offer('gh854 inbound 20 ms',
	{ ICE => 'remove', replace => ['origin'], codec => { transcode => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7322 RTP/AVP 96
c=IN IP4 198.51.100.1
a=rtpmap:96 iLBC/8000
a=fmtp:96 mode=20
a=ptime:20
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 8
c=IN IP4 203.0.113.1
a=rtpmap:96 iLBC/8000
a=fmtp:96 mode=20
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

($port_b) = answer('gh854 inbound 20 ms',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7324 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96
c=IN IP4 203.0.113.1
a=rtpmap:96 iLBC/8000
a=fmtp:96 mode=20
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

snd($sock_a, $port_b, rtp(96, 1000, 3000, 0x6543, "\xa2\xff\x37\xd3\xe2\xb8\x50\x40\x00\x5f\xff\xff\xff\x89\xcc\xff\x76\x6a\xae\xff\xcc\x00\x00\x00\x00\x00\x00\x00\x36\x52\x9d\x93\xf8\x45\x45\x45\x12\x16"));
($ssrc) = rcv($sock_b, $port_a, rtpm(8, 1000, 3000, -1, "\xd5\xd5\x55\xaa\x2a\xaa\xaa\x2a\xaa\xaa\xaa\x2a\x2a\xaa\x2a\x2a\x2a\x2a\xaa\xaa\x2a\xaa\x2a\xaa\x2a\xaa\x2a\x2a\xa7\x2a\x2a\x2a\xaa\xaa\x2a\xaa\xaa\x2a\x2a\x2a\x2a\xaa\xaa\xaa\xaa\x2a\x2a\xaa\xaa\xaa\x2a\x2a\x2a\x2a\xaa\x2a\xaa\x2a\xaa\xaa\x2a\x2a\x2a\x2a\x2a\x2a\xaa\x2a\x2a\x2a\x2a\x28\xaa\x2a\x28\xaa\x3e\xaa\xaa\x2a\x2a\xaa\x2a\x2a\xaa\x2a\xaa\xaa\xaa\x81\x36\x2a\x2a\x2a\x2a\xaa\xaa\x2a\xaa\xaa\x2a\xaa\x2a\x2a\x2a\xa5\xaa\xaa\xaa\xaa\xaa\x2a\x2a\xaa\x2a\x2a\xaa\x2a\xaa\xaa\xaa\xaa\xa2\xa4\xaf\x7e\xec\x37\x26\x21\x2f\x28\x29\x2a\x28\x2e\x2f\x22\x20\x27\x25\x39\x32\x31\x34\x0b\x0e\x0c\x0d\x02\x03\x01\x01\x06\x06\x06\x07\x04\x05\x1e"));

# mode switch
snd($sock_a, $port_b, rtp(96, 1001, 3160, 0x6543, "\xa2\xff\x30\x0e\x5b\x3e\xa0\xac\x40\x40\x00\x57\xff\xff\xfd\xa4\x58\x8b\x62\x10\xcf\xff\xb9\xaa\xbb\xff\xcc\xc0\x00\x00\x00\x00\x00\x0c\x31\x1c\xc1\x74\xaf\x85\x85\x9a\x32\x33\x63\x60\x21\x61\x58\x76"));
($ssrc) = rcv($sock_b, $port_a, rtpm(8, 1001, 3160, -1, "\xd5\x55\x57\x5e\x65\x03\x2a\x2a\x2a\xaa\xaa\xaa\xaa\x2a\xaa\x2a\xaa\x2a\x2a\xaa\xaa\xaa\xaa\xaa\xaa\x2a\xaa\xaa\xaa\xaa\xab\x2a\xaa\xa8\x2a\xaa\x2a\xaa\x2a\x2a\x2a\x2a\x2a\x2b\x2a\x2e\x2e\x2a\x2a\x2e\x26\xaa\xaa\xaa\x3c\x2a\x2a\xad\xad\xa3\xa7\xa7\xa3\xa2\xa1\xa3\xa4\xba\xbe\xb2\xb6\x8a\x86\x9f\x96\xee\x9b\x81\x84\x9d\x99\x9a\x85\x87\x84\x8f\x8d\x82\x83\xed\x97\x95\x87\x8b\xb1\x81\x81\x9b\x9c\xea\xcc\x79\x6c\x11\x13\x1b\x18\x19\x19\x1f\x12\x10\x12\x1d\x10\x16\x14\x6b\x68\x66\x64\x7a\x7e\x7d\x72\x72\x7c\x7f\x79\x65\x65\x60\x61\x61\x61\x7f\x7c\x72\x78\x67\x62\x78\x7a\x78\x7f\x71\x48\x44\x5c\x55\xd3\xd9\xc4\xc6\xc1\xc1\xc6\xc4\xda\xd8\xd8\xd9\xdc\xda\xdd\xdf\xd3\xd2\xd6\xda\xdd\xdf\xde\xd8\xdb\xda\xdb\xda\xdb\xda\xd8\xd9\xde\xdf\xdc\xdd\xdd\xd2\xd3\xd3\xd3\xd0\xd0\xd1\xd1\xd0\xd1\xd1\xd1\xd1\xd1\xd1\xd1\xd6\xd6\xd6\xd7\xd7\xd7\xd4\xd4\xd4\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\x55\xd5\x55\x55\x55\x55\x55\x55\x55\x55\x54\x54\x54\x54\x54\x54\x54\x54"));

snd($sock_b, $port_a, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(96, 1000, 3000, -1, "\xa2\xff\x37\xd3\xe2\xb8\x50\x40\x00\x5f\xff\xff\xff\x89\xcc\xff\x76\x6a\xae\xff\xcc\x00\x00\x00\x00\x00\x00\x00\x36\x52\x9d\x93\xf8\x45\x45\x45\x12\x16"));


}




# github issue 829

($sock_a, $sock_b) = new_call([qw(198.51.100.1 7316)], [qw(198.51.100.3 7318)]);

($port_a) = offer('gh829 control',
	{ ICE => 'remove', replace => ['origin'], flags => ['pad crypto'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7316 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
a=crypto:4 AES_CM_128_HMAC_SHA1_32 inline:Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhH?
a=crypto:4 AES_CM_128_HMAC_SHA1_32 inline:Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q?
a=crypto:5 AEAD_AES_256_GCM inline:CRYPTO256S=
a=crypto:6 AEAD_AES_128_GCM inline:CRYPTO128S==
a=crypto:7 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256==
a=crypto:8 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256==
a=crypto:9 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192=
a=crypto:10 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192=
a=crypto:11 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:13 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:14 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b) = answer('gh829 control',
	{ ICE => 'remove', replace => ['origin'], flags => ['pad crypto'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7318 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:IDdiM2QzOWYzMjA2YzkwZWIxY2NmOWVhOTc4MjE1
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:IDdiM2QzOWYzMjA2YzkwZWIxY2NmOWVhOTc4MjE?
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'IDdiM2QzOWYzMjA2YzkwZWIxY2NmOWVhOTc4MjE1',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa',
};

srtp_snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_b);


($sock_a, $sock_b) = new_call([qw(198.51.100.1 7310)], [qw(198.51.100.3 7312)]);

($port_a) = offer('gh829',
	{ ICE => 'remove', replace => ['origin'], flags => ['pad crypto'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7310 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:EPm8bCW0w2BvozGK++QzjF4m6ARVCpXrn8GAMAoIiDW8BQRDZ+fFRwDjLFALJQ==
a=crypto:2 AES_256_CM_HMAC_SHA1_32 inline:7Io806fF2XLWT782TTPsrSQTptu9HPGRnJ3Y5QDwk9HbhRi+nNwJ/nqNQP+tDg==
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa
a=crypto:4 AES_CM_128_HMAC_SHA1_32 inline:Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q7
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:EPm8bCW0w2BvozGK++QzjF4m6ARVCpXrn8GAMAoIiDW8BQRDZ+fFRwDjLFALJ?==
a=crypto:2 AES_256_CM_HMAC_SHA1_32 inline:7Io806fF2XLWT782TTPsrSQTptu9HPGRnJ3Y5QDwk9HbhRi+nNwJ/nqNQP+tD?==
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhH?
a=crypto:4 AES_CM_128_HMAC_SHA1_32 inline:Kl3GFJ5Gqz5x07xYkoyHODkVkSpiplZnXsQIw+Q?
a=crypto:5 AEAD_AES_256_GCM inline:CRYPTO256S=
a=crypto:6 AEAD_AES_128_GCM inline:CRYPTO128S==
a=crypto:7 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192=
a=crypto:8 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192=
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

($port_b) = answer('gh829',
	{ ICE => 'remove', replace => ['origin'], flags => ['pad crypto'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7312 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:IDdiM2QzOWYzMjA2YzkwZWIxY2NmOWVhOTc4MjE1
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:IDdiM2QzOWYzMjA2YzkwZWIxY2NmOWVhOTc4MjE?
SDP

$srtp_ctx_a = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'IDdiM2QzOWYzMjA2YzkwZWIxY2NmOWVhOTc4MjE1',
};
$srtp_ctx_b = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'Qk0TvVeyfqfjFd/YebnyyklqSEhJntpVKV1KAhHa',
};

srtp_snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160), $srtp_ctx_a);
srtp_snd($sock_b, $port_a, rtp(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_b);
srtp_rcv($sock_a, $port_b, rtpm(0, 2000, 4000, 0x3456, "\x00" x 160), $srtp_ctx_b);


# DTMF injection
#
# no transcoding, RFC payload type present

($sock_a, $sock_b) = new_call([qw(198.51.100.1 6010)], [qw(198.51.100.3 6012)]);

($port_a) = offer('no transcoding, RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6010 RTP/AVP 0 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('no transcoding, RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6012 RTP/AVP 0 8 96
c=IN IP4 198.51.100.3
a=rtpmap:96 telephone-event/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => '0', volume => 10, duration => 100 });

snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96 | 0x80, 1002, 3320, $ssrc, "\x00\x0a\x00\xa0"));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1003, 3320, $ssrc, "\x00\x0a\x01\x40"));
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1004, 3320, $ssrc, "\x00\x0a\x01\xe0"));
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1005, 3320, $ssrc, "\x00\x0a\x02\x80"));
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1006, 3320, $ssrc, "\x00\x8a\x03\x20"));
rcv($sock_b, $port_a, rtpm(96, 1007, 3320, $ssrc, "\x00\x8a\x03\x20"));
rcv($sock_b, $port_a, rtpm(96, 1008, 3320, $ssrc, "\x00\x8a\x03\x20"));
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1009, 4120, $ssrc, "\x00" x 160));



snd($sock_b, $port_a, rtp(0, 4000, 8000, 0x6543, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 8000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 8160, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 8160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards A',
	{ 'from-tag' => tt(), code => '*', volume => 10, duration => 100 });

snd($sock_b, $port_a, rtp(0, 4002, 8320, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96 | 0x80, 4002, 8320, $ssrc, "\x0a\x0a\x00\xa0"));
snd($sock_b, $port_a, rtp(0, 4003, 8480, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 4003, 8320, $ssrc, "\x0a\x0a\x01\x40"));
snd($sock_b, $port_a, rtp(0, 4004, 8640, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 4004, 8320, $ssrc, "\x0a\x0a\x01\xe0"));
snd($sock_b, $port_a, rtp(0, 4005, 8800, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 4005, 8320, $ssrc, "\x0a\x0a\x02\x80"));
snd($sock_b, $port_a, rtp(0, 4006, 8960, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(96, 4006, 8320, $ssrc, "\x0a\x8a\x03\x20"));
rcv($sock_a, $port_b, rtpm(96, 4007, 8320, $ssrc, "\x0a\x8a\x03\x20"));
rcv($sock_a, $port_b, rtpm(96, 4008, 8320, $ssrc, "\x0a\x8a\x03\x20"));
snd($sock_b, $port_a, rtp(0, 4007, 9120, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4009, 9120, $ssrc, "\x00" x 160));




# transcoding, RFC payload type present on both sides

($sock_a, $sock_b) = new_call([qw(198.51.100.1 6110)], [qw(198.51.100.3 6112)]);

($port_a) = offer('transcoding, RFC payload type present on both sides',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'],
	codec => { transcode => ['PCMA'] }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6110 RTP/AVP 0 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('transcoding, RFC payload type present on both sides',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6112 RTP/AVP 8 96
c=IN IP4 198.51.100.3
a=rtpmap:96 telephone-event/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(8, 1000, 3000, -1, "\x2a" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1001, 3160, $ssrc, "\x2a" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => '0', volume => 10, duration => 100 });

snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96 | 0x80, 1002, 3320, $ssrc, "\x00\x0a\x00\xa0"));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1003, 3320, $ssrc, "\x00\x0a\x01\x40"));
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1004, 3320, $ssrc, "\x00\x0a\x01\xe0"));
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1005, 3320, $ssrc, "\x00\x0a\x02\x80"));
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1006, 3320, $ssrc, "\x00\x8a\x03\x20"));
rcv($sock_b, $port_a, rtpm(96, 1007, 3320, $ssrc, "\x00\x8a\x03\x20"));
rcv($sock_b, $port_a, rtpm(96, 1008, 3320, $ssrc, "\x00\x8a\x03\x20"));
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1009, 4120, $ssrc, "\x2a" x 160));



snd($sock_b, $port_a, rtp(8, 4000, 8000, 0x6543, "\x2a" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 8000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(8, 4001, 8160, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 8160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards A',
	{ 'from-tag' => tt(), code => '#', volume => -10, duration => 100 });

snd($sock_b, $port_a, rtp(8, 4002, 8320, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(96 | 0x80, 4002, 8320, $ssrc, "\x0b\x0a\x00\xa0"));
snd($sock_b, $port_a, rtp(8, 4003, 8480, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(96, 4003, 8320, $ssrc, "\x0b\x0a\x01\x40"));
snd($sock_b, $port_a, rtp(8, 4004, 8640, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(96, 4004, 8320, $ssrc, "\x0b\x0a\x01\xe0"));
snd($sock_b, $port_a, rtp(8, 4005, 8800, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(96, 4005, 8320, $ssrc, "\x0b\x0a\x02\x80"));
snd($sock_b, $port_a, rtp(8, 4006, 8960, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(96, 4006, 8320, $ssrc, "\x0b\x8a\x03\x20"));
rcv($sock_a, $port_b, rtpm(96, 4007, 8320, $ssrc, "\x0b\x8a\x03\x20"));
rcv($sock_a, $port_b, rtpm(96, 4008, 8320, $ssrc, "\x0b\x8a\x03\x20"));
snd($sock_b, $port_a, rtp(8, 4007, 9120, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4009, 9120, $ssrc, "\x00" x 160));



# no transcoding, no RFC payload type present

($sock_a, $sock_b) = new_call([qw(198.51.100.1 6014)], [qw(198.51.100.3 6016)]);

($port_a) = offer('no transcoding, no RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6014 RTP/AVP 0 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('no transcoding, no RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6016 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => 'C', volume => 5, duration => 120, pause => 110 });

snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, $ssrc, "\xff\x93\x94\xbc\x2e\x56\xbf\x2b\x13\x1b\xa7\x8e\x98\x47\x25\x41\xe2\x24\x16\x2b\x99\x8e\x9f\x28\x1e\x3d\x5b\x23\x1c\xdf\x92\x8f\xb6\x1c\x1c\x40\x5d\x26\x25\xaa\x8f\x95\x3b\x15\x1d\x5e\xde\x2c\x38\x9d\x8f\x9e\x1f\x11\x20\xc0\xc1\x37\xdd\x99\x92\xb7\x15\x10\x2c\xac\xb5\x49\xb8\x97\x99\x37\x0f\x13\x58\xa0\xae\x67\xae\x99\xa4\x1f\x0d\x1a\xae\x9b\xad\x7b\xad\x9d\xbf\x16\x0e\x27\x9d\x98\xb0\x55\xb1\xa6\x3a\x11\x11\x63\x95\x98\xbf\x3e\xbb\xb4\x26\x10\x1a\xa9\x90\x9a\x4e\x30\xce\xd4\x1e\x12\x29\x99\x8e\xa1\x2d\x29\x6d\x4b\x1c\x18\xef\x91\x8f\xb6\x1f\x24\x57\x3e\x1d\x20\xa9\x8e\x95\x3e\x19\x23\x67\x3e\x21\x31\x9c\x8e\x9e\x22\x14\x26\xcd\x4a"));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3480, $ssrc, "\x2a\xdf\x96\x90\xb5\x17\x13\x2f\xb6\xf5\x36\xb1\x93\x96\x39\x10\x15\x55\xaa\xc8\x4c\xa7\x95\xa0\x1f\x0e\x1b\xb4\xa1\xbd\xed\xa4\x99\xbb\x15\x0e\x27\xa0\x9d\xbd\xda\xa4\x9f\x39\x10\x11\x58\x98\x9c\xc8\xf9\xa9\xac\x23\x0e\x19\xab\x92\x9e\x59\x4c\xb0\xca\x1b\x10\x27\x9a\x90\xa5\x35\x3a\xbe\x43\x18\x15\x6c\x92\x91\xb7\x26\x30\xd6\x32\x18\x1d\xa9\x8e\x96\x44\x1d\x2d\xfc\x2e\x1b\x2d\x9a\x8d\x9e\x25\x19\x2d\xe7\x2f\x20\xea\x94\x8f\xb3\x19\x17\x36\xc8\x36\x2c\xae\x90\x95\x3b\x12\x18\x55\xb7\x43\x3e\xa1\x91\x9e\x1f\x0f\x1d\xba\xac\x64\xe8\x9d\x95\xb7\x15\x0e\x29\xa6\xa6\xda\xc3\x9d\x9b\x39\x0f\x11\x51\x9c\xa2\xd8\xbe\x9f\xa7\x21\x0e\x18\xad"));
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1004, 3640, $ssrc, "\x96\xa3\x68\xc4\xa5\xc2\x19\x0e\x26\x9c\x93\xa9\x3f\xdb\xae\x3e\x14\x12\x5b\x93\x93\xb9\x2e\x51\xbe\x2c\x14\x1b\xa9\x8f\x97\x4c\x25\x3f\xde\x25\x16\x2a\x9a\x8e\x9e\x29\x1e\x3b\x5e\x24\x1b\x7b\x92\x8f\xb2\x1c\x1c\x3e\x61\x27\x25\xac\x8f\x94\x3e\x15\x1c\x59\xdb\x2d\x37\x9e\x8f\x9d\x20\x11\x1f\xc2\xbf\x38\xea\x99\x92\xb4\x16\x10\x2b\xad\xb4\x49\xba\x98\x98\x3a\x0f\x12\x4e\xa1\xad\x68\xaf\x99\xa3\x20\x0d\x19\xb0\x9b\xac\x7b\xae\x9d\xbc\x17\x0e\x25\x9e\x98\xaf\x55\xb2\xa6\x3d\x12\x11\x52\x96\x97\xbd\x3e\xbc\xb3\x28\x10\x19\xab\x90\x9a\x54\x2f\xd0\xcf\x1f\x12\x27\x9a\x8e\xa0\x2e\x28\x66\x4e\x1d\x18\x62\x92\x8f\xb2\x20\x23\x53\x3f\x1d\x1f"));
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1005, 3800, $ssrc, "\xab\x8e\x94\x44\x19\x22\x61\x40\x21\x2f\x9c\x8e\x9d\x23\x14\x25\xce\x4d\x2a\xf7\x96\x8f\xb1\x18\x13\x2e\xb7\xe8\x36\xb3\x94\x96\x3c\x10\x15\x4d\xaa\xc5\x4b\xa8\x95\x9f\x20\x0e\x1a\xb6\xa0\xbc\xf5\xa4\x99\xb8\x16\x0e\x26\xa1\x9d\xbb\xdd\xa5\x9f\x3c\x10\x10\x4c\x99\x9b\xc5\x78\xaa\xac\x24\x0f\x18\xac\x93\x9d\x5f\x4a\xb1\xc7\x1c\x0f\x25\x9b\x90\xa3\x36\x39\xbf\x47\x18\x14\x56\x92\x90\xb4\x27\x2f\xd7\x34\x18\x1c\xab\x8e\x95\x4b\x1d\x2c\xfe\x2f\x1b\x2c\x9b\x8d\x9d\x27\x19\x2c\xe7\x30\x20\x6d\x94\x8f\xaf\x1a\x17\x34\xc8\x37\x2b\xaf\x91\x94\x3f\x12\x18\x4e\xb6\x45\x3d\xa3\x91\x9e\x20\x0f\x1c\xbc\xab\x6c\xf5\x9e\x95\xb3\x16\x0e\x27\xa7\xa5"));
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3960, $ssrc, "\xd6\xc6\x9d\x9b\x3d\x0f\x11\x49\x9c\xa1\xd4\xbf\x9f\xa6\x22\x0e\x18\xaf\x96\xa2\x6e\xc6\xa5\xbe\x19\x0e\x24\x9d\x93\xa8\x40\xe1\xae\x42\x15\x12\x4e\x94\x93\xb7\x2e\x4e\xbe\x2d\x14\x1a\xab\x8f\x97\x52\x25\x3e\xdc\x26\x16\x28\x9b\x8e\x9e\x2b\x1e\x3a\x61\x25\x1b\x5d\x93\x8f\xaf\x1d\x1c\x3d\x67\x27\x24\xad\x8f\x93\x45\x15\x1c\x53\xd7\x2d\x35\x9f\x8f\x9c\x22\x11\x1f\xc5\xbe\x38\x7a\x9a\x91\xb0\x17\x10\x29\xad\xb3\x4a\xbc\x98\x98\x3e\x10\x12\x48\xa1\xad\x6a\xb1\x9a\xa1\x21\x0e\x18\xb3\x9b\xab\x7d\xaf\x9d\xb9\x18\x0e\x23\x9f\x97\xae\x55\xb4\xa5\x40\x12\x10\x49\x96\x97\xbb\x3d\xbd\xb2\x29\x10\x18\xac\x90\x99\x5d\x2f\xd4\xcd\x1f\x12\x25\x9b"));
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1007, 4120, $ssrc, "\x8e\x9f\x2f\x28\x5f\x51\x1d\x17\x52\x92\x8f\xaf\x20\x22\x50\x42\x1e\x1f\xad\x8e\x93\x4b\x19\x21\x5d\x42\x22\x2e\x9d\x8e\x9c\x25\x14\x24\xd0\x4f\x2a\x68\x97\x8f\xae\x18\x12\x2c\xb7\xdf\x36\xb6\x94\x95\x41\x11\x14\x48\xaa\xc3\x4a\xaa\x95\x9e\x21\x0e\x19\xb8\xa0\xba\xfe\xa5\x99\xb4\x17\x0e\x24\xa2\x9c\xba\xe0\xa6\x9e\x40\x10\x10\x45\x99\x9b\xc2\x6d\xaa\xab\x26\x0f\x17\xae\x93\x9c\x6a\x48\xb2\xc3\x1c\x0f\x23\x9c\x90\xa2\x37\x38\xbf\x4b\x19\x14\x4b\x93\x90\xb1\x27\x2e\xd8\x36\x19\x1c\xad\x8e\x94\x52\x1d\x2b\x7d\x30\x1b\x2a\x9c\x8d\x9c\x28\x19\x2b\xe7\x31\x20\x5a\x95\x8f\xad\x1a\x16\x32\xc8\x39\x2b\xb2\x91\x94\x46\x13\x17\x4a\xb6\x48\x3c"));
# pause
snd($sock_a, $port_b, rtp(0, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1008, 4280, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1009, 4440, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1009, 4440, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1011, 4760, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1012, 4920, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1013, 5080, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1013, 5080, $ssrc, "\xff" x 80 . "\x00" x 80));



snd($sock_b, $port_a, rtp(0, 4000, 8000, 0x6543, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 8000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 8160, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 8160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards A',
	{ 'from-tag' => tt(), code => '4', volume => 3, duration => 150, pause => 100 });

snd($sock_b, $port_a, rtp(0, 4002, 8320, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 8320, $ssrc, "\xff\x90\x8a\x93\xd9\x1b\x18\x27\x65\xe5\x33\x29\x4c\x9e\x8f\x91\xb8\x15\x09\x0d\x32\x98\x8e\x96\xbb\x2c\x2b\x4c\xd8\x34\x1c\x18\x2e\x9d\x8c\x8c\xa5\x1a\x0b\x0d\x27\xa3\x97\x9e\xbd\x4f\xc4\xaa\xb2\x2c\x12\x0e\x1e\xa1\x8b\x8a\x9c\x25\x0e\x10\x25\xb7\xa7\xb7\x5e\xcb\xa2\x98\x9f\x30\x0f\x0a\x16\xae\x8d\x8a\x98\x3a\x18\x19\x2c\xdd\xfd\x30\x2b\xce\x99\x8e\x95\x4c\x0f\x09\x10\xdf\x93\x8e\x9a\xec\x28\x2c\x56\xee\x2d\x1a\x1a\x48\x97\x8b\x8e\xba\x14\x0a\x0f\x39\x9d\x96\xa1\xcd\x4e\xbe\xab\xbe\x23\x10\x10\x2b\x99\x8a\x8c\xa7\x1b\x0d\x12\x2f\xad\xa7\xbc\x5e\xbd\x9f\x99\xa8\x23\x0d\x0b\x1d\x9f\x8b\x8c\x9f\x29\x16\x1b\x34\xcd\x60\x2f\x2f\xb6\x96"));
snd($sock_b, $port_a, rtp(0, 4003, 8480, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4003, 8480, $ssrc, "\x8e\x9b\x2b\x0c\x09\x17\xae\x8f\x8e\x9e\x3f\x25\x2e\x65\x5c\x28\x1a\x1e\xc2\x92\x8a\x92\x44\x0f\x0a\x14\xd6\x99\x97\xa6\x7c\x4e\xba\xad\xe5\x1d\x0f\x13\x49\x92\x89\x8e\xbe\x15\x0d\x16\x43\xa8\xa7\xc1\x66\xb5\x9d\x9a\xb6\x1b\x0c\x0d\x2b\x98\x8a\x8d\xab\x1f\x15\x1d\x3f\xc7\x52\x2e\x39\xaa\x93\x8f\xa3\x1e\x0b\x0b\x1e\x9f\x8d\x8f\xa7\x30\x23\x31\x7c\x4a\x24\x1a\x24\xac\x8e\x8b\x99\x28\x0c\x0a\x1a\xb0\x96\x98\xac\x4f\x53\xb7\xaf\x44\x19\x0f\x18\xba\x8e\x89\x93\x3f\x10\x0d\x1a\xd5\xa3\xa8\xca\xf9\xae\x9c\x9d\xec\x16\x0b\x10\x4e\x91\x89\x90\xc6\x1a\x14\x20\x55\xc3\x4a\x2f\x49\xa2\x91\x92\xb2\x17\x09\x0c\x2d\x99\x8d\x92\xb3\x29\x23\x36\xf2"));
snd($sock_b, $port_a, rtp(0, 4004, 8640, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4004, 8640, $ssrc, "\x3e\x20\x1b\x2d\xa0\x8d\x8c\xa1\x1c\x0a\x0c\x22\xa3\x94\x9a\xb5\x44\x5c\xb5\xb6\x32\x16\x0f\x1e\xa6\x8c\x8a\x99\x28\x0e\x0e\x20\xb7\xa1\xab\xd4\xdb\xaa\x9c\xa1\x38\x11\x0b\x15\xb5\x8d\x8a\x96\x3f\x16\x15\x26\xdd\xc2\x43\x31\xdf\x9d\x90\x96\x6d\x11\x09\x0f\x5a\x93\x8c\x97\xd2\x23\x23\x3b\xf6\x37\x1f\x1d\x40\x9a\x8c\x8e\xb2\x15\x09\x0e\x31\x9c\x93\x9c\xc2\x3e\x74\xb4\xbf\x29\x14\x11\x29\x9b\x8a\x8b\xa3\x1c\x0d\x0f\x2a\xab\x9f\xad\xe0\xcc\xa6\x9c\xa9\x28\x0e\x0c\x1c\xa2\x8b\x8b\x9c\x2a\x14\x17\x2c\xc6\xc4\x3e\x36\xbd\x99\x90\x9b\x30\x0d\x09\x15\xb3\x8f\x8d\x9b\x42\x1f\x25\x42\x70\x30\x1e\x1f\xcf\x95\x8b\x92\x58\x0f\x09\x12\x6f\x98\x93"));
snd($sock_b, $port_a, rtp(0, 4005, 8800, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 8800, $ssrc, "\x9f\xe5\x3b\xe2\xb5\xd9\x21\x12\x14\x3e\x95\x89\x8d\xb6\x16\x0c\x13\x3a\xa4\x9f\xb1\xf1\xc0\xa3\x9d\xb4\x1e\x0d\x0d\x27\x99\x8a\x8c\xa7\x1f\x12\x19\x37\xbc\xc8\x3c\x3c\xaf\x97\x91\xa2\x21\x0b\x0a\x1c\xa2\x8d\x8e\xa2\x2f\x1e\x28\x4c\x5d\x2c\x1e\x25\xb0\x90\x8c\x98\x2c\x0c\x0a\x18\xb4\x94\x94\xa6\x4d\x3a\xd4\xb8\x4f\x1d\x11\x18\xc5\x8f\x89\x91\x4d\x10\x0c\x17\xec\x9f\xa0\xb8\xff\xba\xa1\x9f\xd3\x19\x0c\x0f\x3f\x92\x89\x8f\xbb\x19\x11\x1c\x48\xb8\xce\x3b\x4a\xa8\x95\x93\xaf\x19\x0a\x0c\x29\x99\x8c\x8f\xad\x27\x1d\x2b\x59\x4f\x29\x1e\x2d\xa5\x8e\x8d\x9f\x1e\x0b\x0b\x1e\xa4\x91\x96\xad\x3e\x3b\xcc\xbc\x3a\x1a\x12\x1e\xaa\x8d\x8a\x98\x2b"));
snd($sock_b, $port_a, rtp(0, 4006, 8960, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4006, 8960, $ssrc, "\x0e\x0c\x1d\xb8\x9d\xa2\xbe\xf9\xb4\xa0\xa3\x3f\x14\x0c\x14\xbd\x8e\x89\x93\x49\x15\x12\x1f\xe7\xb5\xd9\x3c\x7c\xa1\x93\x97\xd5\x13\x09\x0e\x45\x93\x8b\x93\xc4\x20\x1d\x2e\x6b\x46\x26\x1f\x3d\x9d\x8d\x8e\xae\x17\x09\x0d\x2c\x9c\x90\x98\xba\x36\x3d\xc7\xc4\x2e\x17\x13\x27\x9e\x8b\x8b\x9f\x1e\x0c\x0e\x25\xaa\x9c\xa5\xc8\xe8\xae\xa0\xaa\x2d\x10\x0c\x1b\xa6\x8c\x8a\x9a\x2c\x12\x13\x27\xc3\xb3\xed\x3e\xc8\x9d\x93\x9b\x38\x0f\x09\x13\xba\x8f\x8b\x98\x4a\x1d\x1e\x34\xf9\x3e\x24\x23\xea\x98\x8c\x92\xdf\x10\x09\x0f\x4d\x97\x90\x9c\xd2\x31\x3f\xc5\xd6\x28\x16\x16\x39\x97\x8a\x8d\xaf\x17\x0b\x10\x32\xa2\x9b\xa8\xd6\xd9\xac\xa1\xb3\x22\x0e\x0e"));
snd($sock_b, $port_a, rtp(0, 4007, 9120, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4007, 9120, $ssrc, "\x24\x9b\x8a\x8b\xa2\x1f\x10\x15\x2f\xb8\xb4\x68\x43\xb8\x9a\x94\xa1\x25\x0c\x0a\x1a\xa5\x8d\x8c\x9e\x30\x1b\x1f\x3c\xee\x38\x23\x28\xb8\x93\x8d\x97\x31\x0d\x09\x15\xb9\x93\x90\xa0\x4f\x2f\x46\xc4\x5e\x21\x15\x19\xd7\x91\x89\x90\x7b\x10\x0b\x14\x5b\x9d\x9c\xad\xed\xcd\xa9\xa3\xca\x1c\x0d\x10\x38\x94\x89\x8e\xb3\x19\x0f\x18\x3e\xb0\xb5\x59\x4d\xae\x98\x95\xad\x1c\x0b\x0c\x25\x9b\x8b\x8e\xa9\x26\x1a\x22\x46\xf5\x33\x23\x2e\xaa\x90\x8d\x9e\x21\x0b\x0a\x1c\xa6\x90\x92\xa8\x3b\x2e\x4d\xc7\x43\x1e\x15\x1e\xaf\x8e\x8a\x96\x2e\x0e\x0b\x1a\xbb\x9b\x9d\xb2\x68\xc5\xa8\xa7\x4c\x17\x0d\x14\xcb\x8f\x89\x91\x5e\x14\x0f\x1c\x6e\xad\xb8\x52\x68\xa8"));
snd($sock_b, $port_a, rtp(0, 4008, 9280, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4008, 9280, $ssrc, "\x97\x98\xc7\x16\x0a\x0e\x3a\x94\x8a\x90\xbb\x1e\x1a\x27\x56\x6f\x2f\x25\x3b\xa0\x8e\x8f\xaa\x19\x09\x0c\x28\x9c\x8f\x95\xb2\x31\x2e\x59\xcc\x37\x1b\x16\x26\xa1\x8c\x8b\x9d\x1f\x0c\x0c\x20\xab\x99\x9e\xbb\x5d\xbe\xa7\xac\x32\x13\x0d\x1a\xab\x8c\x89\x97\x2e\x10\x10\x21\xc3\xab\xbc\x4f\xd4\xa2\x96\x9c\x3f\x10\x0a\x12\xc4\x8f\x8a\x95\x57\x1b\x1a\x2b\xfd\x5d\x2d\x27\x62\x9b\x8e\x92\xc9\x12\x09\x0e\x3f\x97\x8e\x98\xc6\x2c\x2f\x6b\xd9\x2e\x1a\x18\x34\x9a\x8b\x8d\xab\x18\x0a\x0e\x2d\xa1\x98\xa1\xc7\x5b\xb9\xa7\xb4\x27\x10\x0e\x22\x9d\x8a\x8b\x9f\x20\x0e\x12\x2a\xb4\xaa\xc0\x50\xc0\x9e\x97\xa1\x2a\x0e\x0a\x19\xa8\x8c\x8b\x9b\x31\x18\x1b\x31"));
snd($sock_b, $port_a, rtp(0, 4009, 9440, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4009, 9440, $ssrc, "\xda\x50\x2c\x2b\xc0\x97\x8e\x97\x39\x0e\x09\x13\xbf\x92\x8e\x9c\x57\x29\x31\xef\x72\x28\x19\x1b\x6d\x94\x8a\x8f\xce\x11\x0a\x11\x48\x9c\x98\xa5\xdc\x5e\xb5\xa9\xc6\x1f\x0f\x10\x31\x96\x89\x8d\xad\x19\x0e\x15\x37\xac\xaa\xc8\x57\xb7\x9c\x98\xac\x1e\x0c\x0c\x21\x9c\x8b\x8d\xa4\x25\x17\x1d\x3b\xcf\x48\x2b\x30\xae\x93\x8e" . "\xff" x 80));
# pause
snd($sock_b, $port_a, rtp(0, 4010, 9600, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4010, 9600, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(0, 4011, 9760, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4011, 9760, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(0, 4012, 9920, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4012, 9920, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(0, 4013, 10080, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4013, 10080, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(0, 4014, 10240, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4014, 10240, $ssrc, "\xff" x 80 . "\x00" x 80));




# transcoding, no RFC payload type present

($sock_a, $sock_b) = new_call([qw(198.51.100.1 6018)], [qw(198.51.100.3 6020)]);

($port_a) = offer('transcoding, no RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'],
	codec => { transcode => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6018 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('transcoding, no RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6020 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(8, 1000, 3000, -1, "\x2a" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1001, 3160, $ssrc, "\x2a" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => 'C', volume => 5, duration => 120 });

snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1002, 3320, $ssrc, "\xd5\xb9\xbe\x97\x05\x70\xea\x01\x3e\x31\x82\xa5\xb2\x63\x0f\x69\xc1\x0f\x3d\x06\xb3\xa4\x8a\x03\x35\x14\x75\x0e\x36\xcc\xb8\xa5\x9d\x36\x36\x68\x49\x0d\x0c\x81\xa5\xbf\x16\x3f\x37\x4f\xcf\x07\x13\xb4\xa5\xb4\x0a\x3b\x0b\xeb\xe9\x12\xc9\xb3\xb8\x92\x3c\x3a\x07\x87\x9c\x61\x93\xb2\xb3\x12\x25\x39\x76\x8b\x85\x5a\x85\xb3\x8e\x35\x24\x30\x85\xb1\x87\x57\x84\xb7\xeb\x3c\x24\x0d\xb4\xb2\x9b\x70\x98\x8c\x11\x3b\x38\x41\xbf\xb2\xeb\x15\x96\x9f\x0d\x3a\x30\x83\xba\xb1\x7b\x1b\xfa\xf2\x34\x39\x03\xb0\xa5\x88\x04\x03\x5f\x67\x37\x32\xdd\xb8\xba\x9d\x35\x0e\x71\x15\x37\x0a\x80\xa4\xbf\x15\x33\x09\x45\x15\x0b\x18\xb6\xa4\xb4\x08\x3f\x0d\xe5\x66"));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1003, 3480, $ssrc, "\x00\xcd\xbc\xba\x9c\x3d\x39\x1a\x9d\xd1\x1d\x98\xbe\xbd\x10\x3a\x3f\x73\x80\xe0\x64\x82\xbf\x8b\x35\x24\x31\x9f\x8b\x94\xdf\x8e\xb3\x96\x3c\x24\x02\x8b\xb7\x94\xf4\x8f\xb5\x10\x3a\x3b\x76\xb2\xb6\xe0\xd6\x80\x87\x09\x25\x33\x81\xb9\xb4\x74\x64\x9b\xe6\x31\x3a\x0d\xb1\xba\x8f\x1c\x11\x95\x6f\x32\x3f\x5e\xb8\xbb\x92\x0d\x1a\xf0\x19\x32\x37\x83\xa4\xbc\x6d\x37\x07\xd4\x04\x31\x07\xb1\xa4\xb4\x0c\x33\x04\xc5\x05\x0b\xd8\xbe\xa5\x9e\x30\x3d\x1d\xe0\x1d\x06\x84\xbb\xbf\x16\x38\x33\x73\x92\x6f\x15\x88\xbb\xb5\x35\x25\x37\x91\x86\x46\xda\xb7\xbf\x92\x3c\x25\x03\x8d\x8c\xf4\xef\xb7\xb6\x10\x25\x3b\x7f\xb6\x89\xf6\x95\xb5\x82\x0b\x24\x33\x84"));
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1004, 3640, $ssrc, "\xbd\x8e\x5a\xec\x8c\xee\x33\x24\x0c\xb6\xbe\x80\x6b\xf5\x85\x6a\x3f\x39\x4a\xbe\xbe\x90\x05\x7f\x95\x06\x3e\x31\x80\xa5\xbd\x64\x0f\x6b\xcc\x0c\x3d\x00\xb0\xa4\xb5\x00\x34\x16\x4e\x0e\x36\x57\xb9\xa5\x99\x36\x36\x6a\x43\x0d\x0f\x86\xa5\xbe\x15\x3f\x36\x77\xf5\x07\x12\xb4\xa5\xb4\x0b\x3b\x0a\xee\xeb\x13\xd8\xb0\xb8\x9f\x3c\x3a\x01\x87\x9f\x66\x91\xb2\xb3\x11\x25\x39\x7a\x8b\x84\x5b\x9a\xb0\x89\x0a\x24\x33\x9b\xb1\x87\x54\x85\xb7\x97\x3d\x24\x0c\xb4\xb2\x9a\x73\x99\x8c\x14\x38\x3b\x7c\xbc\xbd\x94\x15\x97\x9e\x02\x3a\x33\x81\xba\xb0\x73\x1a\xfe\xf9\x35\x39\x02\xb1\xa4\x8a\x05\x03\x44\x7a\x37\x32\x40\xb8\xa5\x99\x0a\x0e\x72\x6b\x34\x35"));
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1005, 3800, $ssrc, "\x81\xa4\xbe\x6c\x33\x08\x43\x68\x08\x1a\xb7\xa4\xb7\x0e\x3f\x0c\xfb\x65\x00\xd1\xbd\xba\x98\x32\x39\x04\x92\xdb\x1d\x9e\xbe\xbc\x17\x3a\x3f\x65\x80\xed\x67\x83\xbf\xb5\x0a\x24\x30\x9d\x8b\x97\xd0\x8f\xb3\x93\x3c\x24\x0c\x88\xb7\x96\xc9\x8c\xb5\x17\x3a\x3a\x64\xb3\xb6\xed\x56\x80\x86\x0f\x25\x32\x87\xb9\xb7\x4d\x66\x98\xe3\x36\x3a\x0c\xb1\xba\x8e\x1d\x10\xea\x63\x33\x3f\x70\xb9\xbb\x9f\x0d\x05\xf1\x1f\x33\x36\x81\xa4\xbf\x67\x34\x06\xd5\x05\x31\x06\xb6\xa4\xb7\x0d\x33\x07\xc5\x1a\x0a\x5f\xbe\xa5\x9a\x30\x3d\x1f\xe0\x12\x06\x9a\xbb\xbf\x6b\x39\x32\x7b\x9d\x62\x14\x89\xbb\xb4\x0b\x25\x36\x97\x86\x5e\xd1\xb4\xbf\x9e\x3c\x24\x0d\x82\x8c"));
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1006, 3960, $ssrc, "\xf0\xe2\xb7\xb1\x14\x3a\x3b\x61\xb6\x88\xf3\xeb\xb5\x8d\x09\x24\x32\x85\xbd\x89\x5c\xe2\x8c\x95\x30\x24\x0e\xb7\xb9\x83\x68\xc3\x85\x6e\x3f\x38\x7a\xbe\xb9\x92\x05\x7a\x95\x07\x3e\x30\x86\xa5\xbd\x7c\x0f\x15\xcb\x0d\x3d\x03\xb1\xa4\xb4\x01\x34\x11\x40\x0f\x36\x48\xb9\xa5\x85\x37\x36\x14\x45\x02\x0f\x84\xa5\xbe\x6d\x3c\x36\x7d\xf1\x04\x1c\xb5\xa5\xb7\x09\x3b\x35\xed\xea\x13\x57\xb0\xb8\x9b\x3d\x3a\x00\x84\x9e\x66\x97\xb2\xb2\x15\x3a\x38\x60\x8b\x87\x58\x98\xb0\x88\x08\x24\x32\x9e\xb1\x86\x54\x9a\xb7\x90\x32\x24\x0e\xb5\xb2\x84\x73\x9f\x8c\x68\x38\x3b\x61\xbc\xbd\x96\x14\x94\x99\x03\x3b\x32\x87\xba\xb3\x48\x1a\xf2\xe5\x0a\x39\x0c\xb1"));
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1007, 4120, $ssrc, "\xa4\xb5\x1a\x02\x4c\x7f\x37\x32\x7c\xb9\xa5\x9a\x0a\x09\x7e\x6e\x34\x35\x87\xa5\xbe\x67\x33\x0b\x48\x6e\x08\x05\xb7\xa4\xb6\x0f\x3f\x0e\xfe\x79\x00\x5a\xbd\xa5\x85\x32\x39\x07\x92\xcd\x1d\x9d\xbe\xbc\x69\x3b\x3e\x60\x80\xef\x66\x80\xbf\xb5\x08\x24\x30\x90\x8b\x91\xd5\x8c\xb3\x9f\x3d\x24\x0e\x89\xb7\x91\xc2\x8c\xb5\x68\x3b\x3a\x6d\xb3\xb1\xee\x5c\x81\x81\x0c\x25\x3d\x85\xb9\xb7\x58\x60\x99\xef\x37\x3a\x0e\xb6\xba\x89\x12\x13\xeb\x67\x33\x3e\x67\xb9\xba\x98\x02\x05\xf7\x1d\x33\x36\x87\xa4\xbe\x7c\x34\x01\x54\x1a\x31\x01\xb6\xa4\xb6\x03\x33\x06\xda\x18\x0a\x75\xbf\xa5\x84\x31\x3d\x19\xe0\x10\x01\x99\xbb\xbe\x62\x39\x3d\x66\x9d\x60\x17"));
# pause
snd($sock_a, $port_b, rtp(0, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1008, 4280, $ssrc, "\xd5" x 160));
snd($sock_a, $port_b, rtp(0, 1009, 4440, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1009, 4440, $ssrc, "\xd5" x 160));
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1010, 4600, $ssrc, "\xd5" x 160));
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1011, 4760, $ssrc, "\xd5" x 160));
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1012, 4920, $ssrc, "\xd5" x 160));
snd($sock_a, $port_b, rtp(0, 1013, 5080, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1013, 5080, $ssrc, "\x2a" x 160));




snd($sock_b, $port_a, rtp(8, 4000, 8000, 0x6543, "\x2a" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 8000, -1, "\x00" x 160));
snd($sock_b, $port_a, rtp(8, 4001, 8160, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 8160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards A',
	{ 'from-tag' => tt(), code => '4', volume => 3, duration => 150 });

snd($sock_b, $port_a, rtp(8, 4002, 8320, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 8320, $ssrc, "\xff\x90\x8a\x93\xd9\x1b\x18\x27\x65\xe5\x33\x29\x4c\x9e\x8f\x91\xb8\x15\x09\x0d\x32\x98\x8e\x96\xbb\x2c\x2b\x4c\xd8\x34\x1c\x18\x2e\x9d\x8c\x8c\xa5\x1a\x0b\x0d\x27\xa3\x97\x9e\xbd\x4f\xc4\xaa\xb2\x2c\x12\x0e\x1e\xa1\x8b\x8a\x9c\x25\x0e\x10\x25\xb7\xa7\xb7\x5e\xcb\xa2\x98\x9f\x30\x0f\x0a\x16\xae\x8d\x8a\x98\x3a\x18\x19\x2c\xdd\xfd\x30\x2b\xce\x99\x8e\x95\x4c\x0f\x09\x10\xdf\x93\x8e\x9a\xec\x28\x2c\x56\xee\x2d\x1a\x1a\x48\x97\x8b\x8e\xba\x14\x0a\x0f\x39\x9d\x96\xa1\xcd\x4e\xbe\xab\xbe\x23\x10\x10\x2b\x99\x8a\x8c\xa7\x1b\x0d\x12\x2f\xad\xa7\xbc\x5e\xbd\x9f\x99\xa8\x23\x0d\x0b\x1d\x9f\x8b\x8c\x9f\x29\x16\x1b\x34\xcd\x60\x2f\x2f\xb6\x96"));
snd($sock_b, $port_a, rtp(8, 4003, 8480, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4003, 8480, $ssrc, "\x8e\x9b\x2b\x0c\x09\x17\xae\x8f\x8e\x9e\x3f\x25\x2e\x65\x5c\x28\x1a\x1e\xc2\x92\x8a\x92\x44\x0f\x0a\x14\xd6\x99\x97\xa6\x7c\x4e\xba\xad\xe5\x1d\x0f\x13\x49\x92\x89\x8e\xbe\x15\x0d\x16\x43\xa8\xa7\xc1\x66\xb5\x9d\x9a\xb6\x1b\x0c\x0d\x2b\x98\x8a\x8d\xab\x1f\x15\x1d\x3f\xc7\x52\x2e\x39\xaa\x93\x8f\xa3\x1e\x0b\x0b\x1e\x9f\x8d\x8f\xa7\x30\x23\x31\x7c\x4a\x24\x1a\x24\xac\x8e\x8b\x99\x28\x0c\x0a\x1a\xb0\x96\x98\xac\x4f\x53\xb7\xaf\x44\x19\x0f\x18\xba\x8e\x89\x93\x3f\x10\x0d\x1a\xd5\xa3\xa8\xca\xf9\xae\x9c\x9d\xec\x16\x0b\x10\x4e\x91\x89\x90\xc6\x1a\x14\x20\x55\xc3\x4a\x2f\x49\xa2\x91\x92\xb2\x17\x09\x0c\x2d\x99\x8d\x92\xb3\x29\x23\x36\xf2"));
snd($sock_b, $port_a, rtp(8, 4004, 8640, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4004, 8640, $ssrc, "\x3e\x20\x1b\x2d\xa0\x8d\x8c\xa1\x1c\x0a\x0c\x22\xa3\x94\x9a\xb5\x44\x5c\xb5\xb6\x32\x16\x0f\x1e\xa6\x8c\x8a\x99\x28\x0e\x0e\x20\xb7\xa1\xab\xd4\xdb\xaa\x9c\xa1\x38\x11\x0b\x15\xb5\x8d\x8a\x96\x3f\x16\x15\x26\xdd\xc2\x43\x31\xdf\x9d\x90\x96\x6d\x11\x09\x0f\x5a\x93\x8c\x97\xd2\x23\x23\x3b\xf6\x37\x1f\x1d\x40\x9a\x8c\x8e\xb2\x15\x09\x0e\x31\x9c\x93\x9c\xc2\x3e\x74\xb4\xbf\x29\x14\x11\x29\x9b\x8a\x8b\xa3\x1c\x0d\x0f\x2a\xab\x9f\xad\xe0\xcc\xa6\x9c\xa9\x28\x0e\x0c\x1c\xa2\x8b\x8b\x9c\x2a\x14\x17\x2c\xc6\xc4\x3e\x36\xbd\x99\x90\x9b\x30\x0d\x09\x15\xb3\x8f\x8d\x9b\x42\x1f\x25\x42\x70\x30\x1e\x1f\xcf\x95\x8b\x92\x58\x0f\x09\x12\x6f\x98\x93"));
snd($sock_b, $port_a, rtp(8, 4005, 8800, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 8800, $ssrc, "\x9f\xe5\x3b\xe2\xb5\xd9\x21\x12\x14\x3e\x95\x89\x8d\xb6\x16\x0c\x13\x3a\xa4\x9f\xb1\xf1\xc0\xa3\x9d\xb4\x1e\x0d\x0d\x27\x99\x8a\x8c\xa7\x1f\x12\x19\x37\xbc\xc8\x3c\x3c\xaf\x97\x91\xa2\x21\x0b\x0a\x1c\xa2\x8d\x8e\xa2\x2f\x1e\x28\x4c\x5d\x2c\x1e\x25\xb0\x90\x8c\x98\x2c\x0c\x0a\x18\xb4\x94\x94\xa6\x4d\x3a\xd4\xb8\x4f\x1d\x11\x18\xc5\x8f\x89\x91\x4d\x10\x0c\x17\xec\x9f\xa0\xb8\xff\xba\xa1\x9f\xd3\x19\x0c\x0f\x3f\x92\x89\x8f\xbb\x19\x11\x1c\x48\xb8\xce\x3b\x4a\xa8\x95\x93\xaf\x19\x0a\x0c\x29\x99\x8c\x8f\xad\x27\x1d\x2b\x59\x4f\x29\x1e\x2d\xa5\x8e\x8d\x9f\x1e\x0b\x0b\x1e\xa4\x91\x96\xad\x3e\x3b\xcc\xbc\x3a\x1a\x12\x1e\xaa\x8d\x8a\x98\x2b"));
snd($sock_b, $port_a, rtp(8, 4006, 8960, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4006, 8960, $ssrc, "\x0e\x0c\x1d\xb8\x9d\xa2\xbe\xf9\xb4\xa0\xa3\x3f\x14\x0c\x14\xbd\x8e\x89\x93\x49\x15\x12\x1f\xe7\xb5\xd9\x3c\x7c\xa1\x93\x97\xd5\x13\x09\x0e\x45\x93\x8b\x93\xc4\x20\x1d\x2e\x6b\x46\x26\x1f\x3d\x9d\x8d\x8e\xae\x17\x09\x0d\x2c\x9c\x90\x98\xba\x36\x3d\xc7\xc4\x2e\x17\x13\x27\x9e\x8b\x8b\x9f\x1e\x0c\x0e\x25\xaa\x9c\xa5\xc8\xe8\xae\xa0\xaa\x2d\x10\x0c\x1b\xa6\x8c\x8a\x9a\x2c\x12\x13\x27\xc3\xb3\xed\x3e\xc8\x9d\x93\x9b\x38\x0f\x09\x13\xba\x8f\x8b\x98\x4a\x1d\x1e\x34\xf9\x3e\x24\x23\xea\x98\x8c\x92\xdf\x10\x09\x0f\x4d\x97\x90\x9c\xd2\x31\x3f\xc5\xd6\x28\x16\x16\x39\x97\x8a\x8d\xaf\x17\x0b\x10\x32\xa2\x9b\xa8\xd6\xd9\xac\xa1\xb3\x22\x0e\x0e"));
snd($sock_b, $port_a, rtp(8, 4007, 9120, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4007, 9120, $ssrc, "\x24\x9b\x8a\x8b\xa2\x1f\x10\x15\x2f\xb8\xb4\x68\x43\xb8\x9a\x94\xa1\x25\x0c\x0a\x1a\xa5\x8d\x8c\x9e\x30\x1b\x1f\x3c\xee\x38\x23\x28\xb8\x93\x8d\x97\x31\x0d\x09\x15\xb9\x93\x90\xa0\x4f\x2f\x46\xc4\x5e\x21\x15\x19\xd7\x91\x89\x90\x7b\x10\x0b\x14\x5b\x9d\x9c\xad\xed\xcd\xa9\xa3\xca\x1c\x0d\x10\x38\x94\x89\x8e\xb3\x19\x0f\x18\x3e\xb0\xb5\x59\x4d\xae\x98\x95\xad\x1c\x0b\x0c\x25\x9b\x8b\x8e\xa9\x26\x1a\x22\x46\xf5\x33\x23\x2e\xaa\x90\x8d\x9e\x21\x0b\x0a\x1c\xa6\x90\x92\xa8\x3b\x2e\x4d\xc7\x43\x1e\x15\x1e\xaf\x8e\x8a\x96\x2e\x0e\x0b\x1a\xbb\x9b\x9d\xb2\x68\xc5\xa8\xa7\x4c\x17\x0d\x14\xcb\x8f\x89\x91\x5e\x14\x0f\x1c\x6e\xad\xb8\x52\x68\xa8"));
snd($sock_b, $port_a, rtp(8, 4008, 9280, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4008, 9280, $ssrc, "\x97\x98\xc7\x16\x0a\x0e\x3a\x94\x8a\x90\xbb\x1e\x1a\x27\x56\x6f\x2f\x25\x3b\xa0\x8e\x8f\xaa\x19\x09\x0c\x28\x9c\x8f\x95\xb2\x31\x2e\x59\xcc\x37\x1b\x16\x26\xa1\x8c\x8b\x9d\x1f\x0c\x0c\x20\xab\x99\x9e\xbb\x5d\xbe\xa7\xac\x32\x13\x0d\x1a\xab\x8c\x89\x97\x2e\x10\x10\x21\xc3\xab\xbc\x4f\xd4\xa2\x96\x9c\x3f\x10\x0a\x12\xc4\x8f\x8a\x95\x57\x1b\x1a\x2b\xfd\x5d\x2d\x27\x62\x9b\x8e\x92\xc9\x12\x09\x0e\x3f\x97\x8e\x98\xc6\x2c\x2f\x6b\xd9\x2e\x1a\x18\x34\x9a\x8b\x8d\xab\x18\x0a\x0e\x2d\xa1\x98\xa1\xc7\x5b\xb9\xa7\xb4\x27\x10\x0e\x22\x9d\x8a\x8b\x9f\x20\x0e\x12\x2a\xb4\xaa\xc0\x50\xc0\x9e\x97\xa1\x2a\x0e\x0a\x19\xa8\x8c\x8b\x9b\x31\x18\x1b\x31"));
snd($sock_b, $port_a, rtp(8, 4009, 9440, 0x6543, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, 4009, 9440, $ssrc, "\xda\x50\x2c\x2b\xc0\x97\x8e\x97\x39\x0e\x09\x13\xbf\x92\x8e\x9c\x57\x29\x31\xef\x72\x28\x19\x1b\x6d\x94\x8a\x8f\xce\x11\x0a\x11\x48\x9c\x98\xa5\xdc\x5e\xb5\xa9\xc6\x1f\x0f\x10\x31\x96\x89\x8d\xad\x19\x0e\x15\x37\xac\xaa\xc8\x57\xb7\x9c\x98\xac\x1e\x0c\x0c\x21\x9c\x8b\x8d\xa4\x25\x17\x1d\x3b\xcf\x48\x2b\x30\xae\x93\x8e" . "\xff" x 80));
# pause
snd($sock_b, $port_a, rtp(8, 4010, 9600, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4010, 9600, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(8, 4011, 9760, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4011, 9760, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(8, 4012, 9920, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4012, 9920, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(8, 4013, 10080, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4013, 10080, $ssrc, "\xff" x 160));
snd($sock_b, $port_a, rtp(8, 4014, 10240, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 4014, 10240, $ssrc, "\xff" x 80 . "\x29" x 80));




# multiple consecutive DTMF events

($sock_a, $sock_b) = new_call([qw(198.51.100.1 6024)], [qw(198.51.100.3 6026)]);

($port_a) = offer('multiple consecutive DTMF events',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6024 RTP/AVP 0 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('multiple consecutive DTMF events',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6026 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => 'C', volume => 5, duration => 100 });
$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => '4', volume => 5, duration => 100 });

snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3320, $ssrc, "\xff\x93\x94\xbc\x2e\x56\xbf\x2b\x13\x1b\xa7\x8e\x98\x47\x25\x41\xe2\x24\x16\x2b\x99\x8e\x9f\x28\x1e\x3d\x5b\x23\x1c\xdf\x92\x8f\xb6\x1c\x1c\x40\x5d\x26\x25\xaa\x8f\x95\x3b\x15\x1d\x5e\xde\x2c\x38\x9d\x8f\x9e\x1f\x11\x20\xc0\xc1\x37\xdd\x99\x92\xb7\x15\x10\x2c\xac\xb5\x49\xb8\x97\x99\x37\x0f\x13\x58\xa0\xae\x67\xae\x99\xa4\x1f\x0d\x1a\xae\x9b\xad\x7b\xad\x9d\xbf\x16\x0e\x27\x9d\x98\xb0\x55\xb1\xa6\x3a\x11\x11\x63\x95\x98\xbf\x3e\xbb\xb4\x26\x10\x1a\xa9\x90\x9a\x4e\x30\xce\xd4\x1e\x12\x29\x99\x8e\xa1\x2d\x29\x6d\x4b\x1c\x18\xef\x91\x8f\xb6\x1f\x24\x57\x3e\x1d\x20\xa9\x8e\x95\x3e\x19\x23\x67\x3e\x21\x31\x9c\x8e\x9e\x22\x14\x26\xcd\x4a"));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3480, $ssrc, "\x2a\xdf\x96\x90\xb5\x17\x13\x2f\xb6\xf5\x36\xb1\x93\x96\x39\x10\x15\x55\xaa\xc8\x4c\xa7\x95\xa0\x1f\x0e\x1b\xb4\xa1\xbd\xed\xa4\x99\xbb\x15\x0e\x27\xa0\x9d\xbd\xda\xa4\x9f\x39\x10\x11\x58\x98\x9c\xc8\xf9\xa9\xac\x23\x0e\x19\xab\x92\x9e\x59\x4c\xb0\xca\x1b\x10\x27\x9a\x90\xa5\x35\x3a\xbe\x43\x18\x15\x6c\x92\x91\xb7\x26\x30\xd6\x32\x18\x1d\xa9\x8e\x96\x44\x1d\x2d\xfc\x2e\x1b\x2d\x9a\x8d\x9e\x25\x19\x2d\xe7\x2f\x20\xea\x94\x8f\xb3\x19\x17\x36\xc8\x36\x2c\xae\x90\x95\x3b\x12\x18\x55\xb7\x43\x3e\xa1\x91\x9e\x1f\x0f\x1d\xba\xac\x64\xe8\x9d\x95\xb7\x15\x0e\x29\xa6\xa6\xda\xc3\x9d\x9b\x39\x0f\x11\x51\x9c\xa2\xd8\xbe\x9f\xa7\x21\x0e\x18\xad"));
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1004, 3640, $ssrc, "\x96\xa3\x68\xc4\xa5\xc2\x19\x0e\x26\x9c\x93\xa9\x3f\xdb\xae\x3e\x14\x12\x5b\x93\x93\xb9\x2e\x51\xbe\x2c\x14\x1b\xa9\x8f\x97\x4c\x25\x3f\xde\x25\x16\x2a\x9a\x8e\x9e\x29\x1e\x3b\x5e\x24\x1b\x7b\x92\x8f\xb2\x1c\x1c\x3e\x61\x27\x25\xac\x8f\x94\x3e\x15\x1c\x59\xdb\x2d\x37\x9e\x8f\x9d\x20\x11\x1f\xc2\xbf\x38\xea\x99\x92\xb4\x16\x10\x2b\xad\xb4\x49\xba\x98\x98\x3a\x0f\x12\x4e\xa1\xad\x68\xaf\x99\xa3\x20\x0d\x19\xb0\x9b\xac\x7b\xae\x9d\xbc\x17\x0e\x25\x9e\x98\xaf\x55\xb2\xa6\x3d\x12\x11\x52\x96\x97\xbd\x3e\xbc\xb3\x28\x10\x19\xab\x90\x9a\x54\x2f\xd0\xcf\x1f\x12\x27\x9a\x8e\xa0\x2e\x28\x66\x4e\x1d\x18\x62\x92\x8f\xb2\x20\x23\x53\x3f\x1d\x1f"));
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1005, 3800, $ssrc, "\xab\x8e\x94\x44\x19\x22\x61\x40\x21\x2f\x9c\x8e\x9d\x23\x14\x25\xce\x4d\x2a\xf7\x96\x8f\xb1\x18\x13\x2e\xb7\xe8\x36\xb3\x94\x96\x3c\x10\x15\x4d\xaa\xc5\x4b\xa8\x95\x9f\x20\x0e\x1a\xb6\xa0\xbc\xf5\xa4\x99\xb8\x16\x0e\x26\xa1\x9d\xbb\xdd\xa5\x9f\x3c\x10\x10\x4c\x99\x9b\xc5\x78\xaa\xac\x24\x0f\x18\xac\x93\x9d\x5f\x4a\xb1\xc7\x1c\x0f\x25\x9b\x90\xa3\x36\x39\xbf\x47\x18\x14\x56\x92\x90\xb4\x27\x2f\xd7\x34\x18\x1c\xab\x8e\x95\x4b\x1d\x2c\xfe\x2f\x1b\x2c\x9b\x8d\x9d\x27\x19\x2c\xe7\x30\x20\x6d\x94\x8f\xaf\x1a\x17\x34\xc8\x37\x2b\xaf\x91\x94\x3f\x12\x18\x4e\xb6\x45\x3d\xa3\x91\x9e\x20\x0f\x1c\xbc\xab\x6c\xf5\x9e\x95\xb3\x16\x0e\x27\xa7\xa5"));
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3960, $ssrc, "\xd6\xc6\x9d\x9b\x3d\x0f\x11\x49\x9c\xa1\xd4\xbf\x9f\xa6\x22\x0e\x18\xaf\x96\xa2\x6e\xc6\xa5\xbe\x19\x0e\x24\x9d\x93\xa8\x40\xe1\xae\x42\x15\x12\x4e\x94\x93\xb7\x2e\x4e\xbe\x2d\x14\x1a\xab\x8f\x97\x52\x25\x3e\xdc\x26\x16\x28\x9b\x8e\x9e\x2b\x1e\x3a\x61\x25\x1b\x5d\x93\x8f\xaf\x1d\x1c\x3d\x67\x27\x24\xad\x8f\x93\x45\x15\x1c\x53\xd7\x2d\x35\x9f\x8f\x9c\x22\x11\x1f\xc5\xbe\x38\x7a\x9a\x91\xb0\x17\x10\x29\xad\xb3\x4a\xbc\x98\x98\x3e\x10\x12\x48\xa1\xad\x6a\xb1\x9a\xa1\x21\x0e\x18\xb3\x9b\xab\x7d\xaf\x9d\xb9\x18\x0e\x23\x9f\x97\xae\x55\xb4\xa5\x40\x12\x10\x49\x96\x97\xbb\x3d\xbd\xb2\x29\x10\x18\xac\x90\x99\x5d\x2f\xd4\xcd\x1f\x12\x25\x9b"));
# pause
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1007, 4120, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1008, 4280, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1009, 4440, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1009, 4440, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1011, 4760, $ssrc, "\xff" x 160));
# next event
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1012, 4920, $ssrc, "\xff\x96\x8e\x99\xdd\x1f\x1d\x2c\x69\xe9\x39\x2d\x50\xa3\x95\x97\xbd\x1a\x0e\x12\x38\x9d\x93\x9b\xbf\x30\x2f\x4f\xdc\x39\x20\x1d\x33\xa2\x90\x91\xaa\x1f\x0f\x12\x2c\xa9\x9c\xa3\xc2\x55\xc9\xaf\xb8\x30\x18\x14\x24\xa7\x8f\x8e\xa0\x2a\x14\x16\x2a\xbc\xac\xbc\x61\xcf\xa8\x9d\xa6\x36\x15\x0f\x1b\xb4\x92\x8f\x9d\x3e\x1d\x1e\x31\xe0\xfe\x36\x30\xd3\x9e\x94\x9b\x50\x15\x0d\x17\xe3\x99\x93\x9e\xee\x2c\x30\x5b\xf0\x32\x1f\x1f\x4c\x9c\x8f\x94\xbe\x19\x0e\x15\x3d\xa2\x9b\xa7\xd2\x52\xc3\xaf\xc4\x29\x16\x16\x2f\x9e\x8e\x90\xac\x20\x13\x18\x34\xb2\xac\xc0\x61\xc2\xa5\x9d\xad\x29\x12\x10\x23\xa5\x8f\x90\xa5\x2d\x1b\x1f\x39\xd1\x65\x34\x36\xbb\x9b"));
snd($sock_a, $port_b, rtp(0, 1013, 5080, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1013, 5080, $ssrc, "\x94\x9f\x2f\x11\x0e\x1c\xb3\x95\x94\xa4\x45\x2a\x33\x69\x60\x2d\x1e\x23\xc7\x98\x8f\x98\x49\x15\x0e\x1a\xda\x9d\x9c\xab\x7d\x53\xbe\xb1\xe8\x22\x15\x19\x4d\x98\x8d\x94\xc3\x1b\x12\x1b\x48\xac\xac\xc7\x69\xba\xa2\x9f\xbb\x1f\x10\x12\x2f\x9c\x8e\x93\xb0\x25\x1a\x22\x44\xcb\x57\x34\x3d\xae\x99\x96\xa9\x23\x0f\x0f\x24\xa6\x93\x96\xac\x36\x29\x37\x7c\x4e\x29\x1e\x29\xb0\x94\x8f\x9e\x2d\x11\x0f\x1f\xb6\x9b\x9d\xb0\x55\x58\xbc\xb5\x49\x1e\x15\x1d\xbe\x94\x8e\x99\x45\x17\x12\x1f\xd9\xa9\xad\xce\xfa\xb3\xa0\xa2\xef\x1b\x0f\x16\x52\x97\x8e\x96\xcb\x1e\x1a\x26\x59\xc8\x4e\x35\x4d\xa8\x97\x98\xb8\x1c\x0e\x11\x31\x9d\x91\x98\xb9\x2d\x29\x3b\xf5"));
snd($sock_a, $port_b, rtp(0, 1014, 5240, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1014, 5240, $ssrc, "\x43\x27\x1f\x32\xa6\x92\x91\xa7\x21\x0f\x10\x28\xa9\x99\x9e\xba\x49\x60\xba\xbb\x38\x1b\x16\x23\xab\x90\x8e\x9e\x2d\x14\x13\x26\xbc\xa7\xaf\xd8\xde\xae\xa0\xa7\x3d\x17\x0f\x1a\xba\x93\x8e\x9b\x44\x1b\x1b\x2b\xe0\xc8\x48\x37\xe4\xa2\x96\x9b\x6f\x17\x0e\x15\x5d\x99\x91\x9c\xd7\x29\x29\x3f\xf8\x3c\x24\x21\x46\x9e\x90\x94\xb8\x1a\x0e\x14\x37\xa1\x99\xa1\xc8\x43\x76\xba\xc5\x2d\x19\x17\x2d\xa0\x8f\x8f\xa8\x21\x11\x16\x2e\xaf\xa6\xb2\xe5\xcf\xab\xa0\xad\x2d\x14\x10\x20\xa8\x90\x8f\xa1\x2e\x19\x1c\x31\xcb\xc9\x44\x3b\xc2\x9e\x96\x9f\x36\x13\x0e\x1a\xb8\x95\x92\xa0\x48\x26\x2a\x48\x73\x36\x23\x25\xd4\x9a\x90\x98\x5c\x15\x0e\x18\x72\x9c\x99"));
snd($sock_a, $port_b, rtp(0, 1015, 5400, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1015, 5400, $ssrc, "\xa6\xe8\x3f\xe7\xba\xdd\x27\x18\x1a\x43\x9a\x8e\x93\xbb\x1b\x10\x19\x3e\xaa\xa5\xb7\xf4\xc6\xa9\xa2\xba\x23\x12\x12\x2c\x9e\x8e\x91\xac\x25\x18\x1e\x3c\xc1\xcd\x41\x40\xb5\x9c\x97\xa8\x27\x10\x0f\x21\xa8\x92\x93\xa8\x35\x24\x2c\x50\x61\x30\x23\x2b\xb7\x97\x90\x9d\x31\x11\x0e\x1c\xb9\x9a\x9a\xab\x52\x3f\xd9\xbc\x54\x22\x18\x1d\xca\x96\x8e\x97\x52\x17\x10\x1c\xef\xa5\xa6\xbc\xff\xbe\xa7\xa5\xd8\x1d\x10\x16\x45\x98\x8e\x95\xbf\x1e\x17\x20\x4d\xbc\xd2\x3f\x4e\xad\x9a\x99\xb4\x1e\x0e\x10\x2d\x9e\x90\x96\xb2\x2c\x22\x2f\x5c\x54\x2d\x24\x32\xaa\x94\x91\xa5\x24\x0f\x0f\x24\xaa\x98\x9b\xb2\x43\x3f\xcf\xc0\x3e\x1e\x18\x23\xaf\x92\x8e\x9c\x2f"));
snd($sock_a, $port_b, rtp(0, 1016, 5560, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1016, 5560, $ssrc, "\x13\x11\x21\xbd\xa2\xa8\xc3\xfa\xb9\xa6\xa9\x45\x19\x10\x1a\xc2\x94\x8e\x99\x4e\x1a\x18\x26\xeb\xba\xdd\x40\x7d\xa7\x99\x9c\xda\x19\x0e\x14\x4a\x99\x90\x99\xc9\x26\x23\x34\x6d\x4b\x2b\x25\x41\xa1\x92\x94\xb3\x1c\x0e\x12\x30\xa0\x96\x9d\xbe\x3b\x41\xcc\xc9\x34\x1c\x19\x2c\xa3\x8f\x8f\xa5\x23\x10\x13\x2a\xaf\xa0\xaa\xcd\xeb\xb4\xa6\xae\x31\x16\x11\x1f\xab\x90\x8e\x9e\x30\x18\x19\x2c\xc8\xb9\xf0\x43\xcc\xa2\x99\x9f\x3c\x14\x0e\x19\xbe\x95\x90\x9d\x4e\x22\x24\x3a\xfa\x43\x2a\x28\xec\x9d\x91\x98\xe4\x16\x0d\x16\x51\x9c\x96\xa0\xd7\x37\x45\xca\xda\x2c\x1b\x1b\x3d\x9c\x8e\x92\xb4\x1c\x0f\x16\x38\xa8\xa0\xad\xda\xdd\xb0\xa7\xb9\x28\x14\x13"));
# pause
snd($sock_a, $port_b, rtp(0, 1017, 5720, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1017, 5720, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1018, 5880, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1018, 5880, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1019, 6040, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1019, 6040, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1020, 6200, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1020, 6200, $ssrc, "\xff" x 160));
snd($sock_a, $port_b, rtp(0, 1021, 6360, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1021, 6360, $ssrc, "\xff" x 160));
# resume
snd($sock_a, $port_b, rtp(0, 1022, 6520, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1022, 6520, $ssrc, "\x00" x 160));




# RFC payload type present

($sock_a, $sock_b) = new_call([qw(198.51.100.1 6210)], [qw(198.51.100.3 6212)]);

($port_a) = offer('multi- no transcoding, RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 6210 RTP/AVP 0 8 96
c=IN IP4 198.51.100.1
a=rtpmap:96 telephone-event/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('multi- no transcoding, RFC payload type present',
	{ ICE => 'remove', replace => ['origin'], flags => ['inject DTMF'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 6212 RTP/AVP 0 8 96
c=IN IP4 198.51.100.3
a=rtpmap:96 telephone-event/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, $ssrc, "\x00" x 160));

$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => '0', volume => 10, duration => 100 });
$resp = rtpe_req('play DTMF', 'inject DTMF towards B',
	{ 'from-tag' => ft(), code => '1', volume => 6, duration => 100 });

snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96 | 0x80, 1002, 3320, $ssrc, "\x00\x0a\x00\xa0"));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1003, 3320, $ssrc, "\x00\x0a\x01\x40"));
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1004, 3320, $ssrc, "\x00\x0a\x01\xe0"));
snd($sock_a, $port_b, rtp(0, 1005, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1005, 3320, $ssrc, "\x00\x0a\x02\x80"));
snd($sock_a, $port_b, rtp(0, 1006, 3960, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1006, 3320, $ssrc, "\x00\x8a\x03\x20"));
rcv($sock_b, $port_a, rtpm(96, 1007, 3320, $ssrc, "\x00\x8a\x03\x20"));
rcv($sock_b, $port_a, rtpm(96, 1008, 3320, $ssrc, "\x00\x8a\x03\x20"));
snd($sock_a, $port_b, rtp(0, 1007, 4120, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1009, 4120, $ssrc, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1008, 4280, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4280, $ssrc, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1009, 4440, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1011, 4440, $ssrc, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1012, 4600, $ssrc, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1011, 4760, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1013, 4760, $ssrc, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1012, 4920, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96 | 0x80, 1014, 4920, $ssrc, "\x01\x06\x00\xa0"));
snd($sock_a, $port_b, rtp(0, 1013, 5080, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1015, 4920, $ssrc, "\x01\x06\x01\x40"));
snd($sock_a, $port_b, rtp(0, 1014, 5240, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1016, 4920, $ssrc, "\x01\x06\x01\xe0"));
snd($sock_a, $port_b, rtp(0, 1015, 5400, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1017, 4920, $ssrc, "\x01\x06\x02\x80"));
snd($sock_a, $port_b, rtp(0, 1016, 5560, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(96, 1018, 4920, $ssrc, "\x01\x86\x03\x20"));
rcv($sock_b, $port_a, rtpm(96, 1019, 4920, $ssrc, "\x01\x86\x03\x20"));
rcv($sock_b, $port_a, rtpm(96, 1020, 4920, $ssrc, "\x01\x86\x03\x20"));
snd($sock_a, $port_b, rtp(0, 1017, 5720, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1021, 5720, $ssrc, "\x00" x 160));





# extmap stripping

new_call;

offer('strip extmap control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=extmap:0 foobar
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=extmap:0 foobar
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('strip extmap', { flags => ['strip extmap'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=extmap:0 foobar
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



# SDP in/out tests, various ICE options

new_call;

offer('plain SDP, no ICE', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
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

answer('plain SDP, no ICE', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
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

new_call;

offer('plain SDP, ICE default', { ICE => 'default' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
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

answer('plain SDP, ICE default', { ICE => 'default' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
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

new_call;

offer('plain SDP, add default ICE', { ICE => 'optional' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('plain SDP, ICE removed', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
-------------------------------
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

new_call;

offer('plain SDP, ICE removed', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------
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

answer('plain SDP, no ICE option given', { ICE => 'optional' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------
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

new_call;

offer('ICE SDP, default ICE option w media-address', { 'media-address' => '3.4.5.6',
	flags => ['full-rtcp-attribute'], ICE => 'optional', }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 3.4.5.6
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
a=candidate:ICEBASE 1 UDP 2097152255 3.4.5.6 PORT typ host
a=candidate:ICEBASE 1 UDP 4294967295 3.4.5.6 PORT typ host
a=candidate:ICEBASE 2 UDP 2097152254 3.4.5.6 PORT typ host
a=candidate:ICEBASE 2 UDP 4294967294 3.4.5.6 PORT typ host
SDP

new_call;

offer('ICE SDP, default ICE option', { ICE => 'optional' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
a=candidate:ICEBASE 1 UDP 2097152255 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 4294967295 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2097152254 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 4294967294 2001:db8:4321::1 PORT typ host
SDP

answer('plain SDP, ICE rejected, no ICE option given', { ICE => 'optional' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
SDP

new_call;

offer('trickle ICE offer', { ICE => 'force', flags => ['trickle ICE'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=ice-options:trickle
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
a=end-of-candidates
SDP

new_call;

offer('ICE SDP with ICE force', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('plain SDP, ICE rejected, no ICE option given', { ICE => 'optional' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('ICE SDP with ICE force', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('ICE SDP, no ICE option given', { ICE => 'optional' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ice-ufrag:bmnhkfdf
a=ice-pwd:jetyhsdfgsdtjhtyjktrthsrhH
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfbhdcfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfbhdcfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ice-ufrag:bmnhkfdf
a=ice-pwd:jetyhsdfgsdtjhtyjktrthsrhH
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfbhdcfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfbhdcfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
a=candidate:ICEBASE 1 UDP 2097152255 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 4294967295 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2097152254 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 4294967294 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('ICE SDP with ICE force', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('ICE SDP with ICE force', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ice-ufrag:bmnhkfdf
a=ice-pwd:jetyhsdfgsdtjhtyjktrthsrhH
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfbhdcfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfbhdcfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('ICE SDP with ICE default', { ICE => 'default' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-ufrag:asbsdfds
a=ice-pwd:sfhwsrgyergws45ujhsrthsrhH
a=candidate:sfthqw45hdfgdfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfdfgdfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:sfthqw45hdfgdfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfdfgdfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('ICE SDP with ICE default', { ICE => 'default' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ice-ufrag:bmnhkfdf
a=ice-pwd:jetyhsdfgsdtjhtyjktrthsrhH
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfbhdcfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfbhdcfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
--------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

# ICE re-invite tests (GH #1147)

new_call;

offer('plain SDP, ICE default', { ICE => 'default' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
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

answer('plain SDP, ICE default', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
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

offer('plain SDP, ICE default', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
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

new_call;

offer('plain SDP, ICE force', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
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
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('plain SDP, ICE force', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ice-ufrag:bmnhkfdf
a=ice-pwd:jetyhsdfgsdtjhtyjktrthsrhH
a=candidate:keutydghfbhdcfsb 1 UDP 2130706431 198.51.100.3 2002 typ host
a=candidate:ujksdfghfbhdcfsb 1 UDP 2130706175 2001:db8:abcd::3 2002 typ host
a=candidate:keutydghfbhdcfsb 2 UDP 2130706430 198.51.100.3 2003 typ host
a=candidate:ujksdfghfbhdcfsb 2 UDP 2130706174 2001:db8:abcd::3 2003 typ host
--------------------------------------
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

offer('plain SDP, ICE force', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
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
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('plain SDP, ICE force + reject', { ICE => 'force' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
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
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

answer('plain SDP, ICE force + reject', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
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

offer('plain SDP, ICE force + reject', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
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


# github issue #686

new_call;

offer('gh 686', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
c=IN IP4 198.51.100.1
m=audio 0 RTP/AVP 8 101
m=image 2000 udptl t38
c=IN IP4 198.51.100.1
a=T38FaxVersion:0
a=T38FaxRateManagement:transferredTCF
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 0 RTP/AVP 8 101
c=IN IP4 0.0.0.0
m=image PORT udptl t38
c=IN IP4 203.0.113.1
a=T38FaxVersion:0
a=T38FaxRateManagement:transferredTCF
SDP

# github issue #661

new_call;

offer('gh 661 plain', { ICE => 'remove', DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyH?
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8?
a=crypto:5 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:6 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:7 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:8 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 plain', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
SDP

# #661 for transcoding to RTP

offer('gh 661 plain to RTP', { ICE => 'remove', DTLS => 'off', 'transport protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==
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

answer('gh 661 plain to RTP', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
SDP

# #661 for transcoding from RTP

new_call;

offer('gh 661 plain from RTP', { ICE => 'remove', DTLS => 'off', 'transport protocol' => 'RTP/SAVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:2 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:5 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:6 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('gh 661 plain from RTP', { ICE => 'remove' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/SAVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:dfgadgdfgdfgdfgd6AYjs3vKw7CeBdWZCj0isbJv
--------------------------------------
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

# codec masking gh#664

new_call;

offer('gh 664 codec masking plain', { ICE => 'remove', replace => [qw(origin)],
	flags => [qw(codec-mask-opus codec-mask-G722 codec-strip-G7221)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 120 8 0 101
c=IN IP4 198.51.100.1
a=rtpmap:120 opus/48000/2
a=fmtp:120 useinbandfec=1; usedtx=1; maxaveragebitrate=64000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

answer('gh 664 codec masking plain', { ICE => 'remove', replace => [qw(origin)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
c=IN IP4 198.51.100.3
t=0 0
m=audio 2002 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP


new_call;

offer('gh 664 codec masking a/t', { ICE => 'remove', replace => [qw(origin)],
	flags => [qw(codec-mask-opus codec-mask-G722 codec-strip-G7221 always-transcode)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 120 8 0 101
c=IN IP4 198.51.100.1
a=rtpmap:120 opus/48000/2
a=fmtp:120 useinbandfec=1; usedtx=1; maxaveragebitrate=64000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

answer('gh 664 codec masking a/t', { ICE => 'remove', replace => [qw(origin)] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
c=IN IP4 198.51.100.3
t=0 0
m=audio 2002 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 120
c=IN IP4 203.0.113.1
a=rtpmap:120 opus/48000/2
a=fmtp:120 stereo=0; useinbandfec=1
a=sendrecv
a=rtcp:PORT
SDP





# RTP sequencing tests

($sock_a, $sock_b) = new_call([qw(198.51.100.1 2010)], [qw(198.51.100.3 2012)]);

($port_a) = offer('two codecs, no transcoding', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2010 RTP/AVP 0 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('two codecs, no transcoding', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2012 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1010, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1001, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1001, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(8, 1010, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1010, 3000, 0x1234, "\x00" x 160));


($sock_a, $sock_b) = new_call([qw(198.51.100.1 2010)], [qw(198.51.100.3 2012)]);

($port_a) = offer('one codec with one for transcoding', { ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['PCMA'] }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2010 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('one codec with one for transcoding', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2012 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));

snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2001, 4000+160, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4000+160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2010, 4000+1600, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2010, 4000+1600, $ssrc, "\x00" x 160));

snd($sock_b, $port_a,  rtp(8, 2011, 4000+160*11, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2011, 4000+160*11, $ssrc, ")" x 160));
# #664 seq reset
snd($sock_b, $port_a,  rtp(8, 62011, 4000+160*12, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2012, 4000+160*12, $ssrc, ")" x 160));
snd($sock_b, $port_a,  rtp(8, 62012, 4000+160*13, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2013, 4000+160*13, $ssrc, ")" x 160));
snd($sock_b, $port_a,  rtp(0, 62013, 4000+160*14, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2014, 4000+160*14, $ssrc, "\x00" x 160));



($sock_a, $sock_b) = new_call([qw(198.51.100.1 2210)], [qw(198.51.100.3 2212)]);

($port_a) = offer('one codec with one for transcoding, lower case', { ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['PCMA'] }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2210 RTP/AVP 0
c=IN IP4 198.51.100.1
a=rtpmap:0 pcmu/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 pcmu/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('one codec with one for transcoding, lower case', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2212 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=rtpmap:0 pcmu/8000
a=rtpmap:8 pcma/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 pcmu/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));

snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2001, 4000+160, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4000+160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2010, 4000+1600, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2010, 4000+1600, $ssrc, "\x00" x 160));

snd($sock_b, $port_a,  rtp(8, 2011, 4000+160*11, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2011, 4000+160*11, $ssrc, ")" x 160));
# #664 seq reset
snd($sock_b, $port_a,  rtp(8, 62011, 4000+160*12, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2012, 4000+160*12, $ssrc, ")" x 160));
snd($sock_b, $port_a,  rtp(8, 62012, 4000+160*13, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2013, 4000+160*13, $ssrc, ")" x 160));
snd($sock_b, $port_a,  rtp(0, 62013, 4000+160*14, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2014, 4000+160*14, $ssrc, "\x00" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 2216)], [qw(198.51.100.3 2218)]);

($port_a) = offer('one codec with one for transcoding, lower case 2', { ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['pcma'] }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2216 RTP/AVP 0
c=IN IP4 198.51.100.1
a=rtpmap:0 pcmu/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 pcmu/8000
a=rtpmap:8 pcma/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('one codec with one for transcoding, lower case 2', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2218 RTP/AVP 0 8
c=IN IP4 198.51.100.3
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1010, 4600, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1010, 4600, 0x1234, "\x00" x 160));

snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 2000, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2000, 4000, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2001, 4000+160, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2001, 4000+160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2010, 4000+1600, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2010, 4000+1600, $ssrc, "\x00" x 160));

snd($sock_b, $port_a,  rtp(8, 2011, 4000+160*11, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2011, 4000+160*11, $ssrc, ")" x 160));
# #664 seq reset
snd($sock_b, $port_a,  rtp(8, 62011, 4000+160*12, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2012, 4000+160*12, $ssrc, ")" x 160));
snd($sock_b, $port_a,  rtp(8, 62012, 4000+160*13, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2013, 4000+160*13, $ssrc, ")" x 160));
snd($sock_b, $port_a,  rtp(0, 62013, 4000+160*14, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 2014, 4000+160*14, $ssrc, "\x00" x 160));





# media playback

($sock_a) = new_call([qw(198.51.100.1 2020)]);

offer('media playback, offer only', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2020 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

$resp = rtpe_req('play media', 'media playback, offer only', { 'from-tag' => ft(), blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

(undef, $seq, $ts, $ssrc) = rcv($sock_a, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_a, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_a, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_a, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_a, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 2020)], [qw(198.51.100.3 2022)]);

offer('media playback, side A', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2020 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('media playback, side A', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2022 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


$resp = rtpe_req('play media', 'media playback, side A', { 'from-tag' => ft(), blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

(undef, $seq, $ts, $ssrc) = rcv($sock_a, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_a, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_a, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_a, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_a, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 2100)], [qw(198.51.100.3 2102)]);

offer('media playback, side A, repeat', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2100 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('media playback, side A, repeat', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2102 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


$resp = rtpe_req('play media', 'media playback, side A, repeat', { 'from-tag' => ft(), blob => $wav_file, 'repeat-times' => 2 });
is $resp->{duration}, 100, 'media duration';

(undef, $seq, $ts, $ssrc) = rcv($sock_a, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_a, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_a, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_a, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_a, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));
rcv($sock_a, -1, rtpm(8, $seq + 5, $ts + 160 * 5, $ssrc, $pcma_1));
rcv($sock_a, -1, rtpm(8, $seq + 6, $ts + 160 * 6, $ssrc, $pcma_2));
rcv($sock_a, -1, rtpm(8, $seq + 7, $ts + 160 * 7, $ssrc, $pcma_3));
rcv($sock_a, -1, rtpm(8, $seq + 8, $ts + 160 * 8, $ssrc, $pcma_4));
rcv($sock_a, -1, rtpm(8, $seq + 9, $ts + 160 * 9, $ssrc, $pcma_5));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 2030)], [qw(198.51.100.3 2032)]);

offer('media playback, side B', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2030 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('media playback, side B', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2032 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


$resp = rtpe_req('play media', 'media playback, side B', { 'from-tag' => tt(), blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

(undef, $seq, $ts, $ssrc) = rcv($sock_b, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_b, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_b, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_b, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_b, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));

$resp = rtpe_req('play media', 'restart media playback', { 'from-tag' => tt(), blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

$ts += 160 * 5;
my $old_ts = $ts;
(undef, $ts) = rcv($sock_b, -1, rtpm(8 | 0x80, $seq + 5, -1, $ssrc, $pcma_1));
print("ts $ts old $old_ts\n");
SKIP: {
	skip 'random timestamp too close to margin', 2 if $old_ts < 500 or $old_ts > 4294966795;
	cmp_ok($ts, '<', $old_ts + 500, 'ts within < range');
	cmp_ok($ts, '>', $old_ts - 500, 'ts within > range');
}
rcv($sock_b, -1, rtpm(8, $seq + 6, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_b, -1, rtpm(8, $seq + 7, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_b, -1, rtpm(8, $seq + 8, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_b, -1, rtpm(8, $seq + 9, $ts + 160 * 4, $ssrc, $pcma_5));




($sock_a, $sock_b) = new_call([qw(198.51.100.9 2020)], [qw(198.51.100.9 2022)]);

offer('media playback, side A, select by label', { ICE => 'remove', replace => ['origin'],
	label => 'foobar' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.9
s=tester
t=0 0
m=audio 2020 RTP/AVP 8
c=IN IP4 198.51.100.9
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('media playback, side A, select by label', { replace => ['origin'], label => 'blah' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.9
s=tester
t=0 0
m=audio 2022 RTP/AVP 8
c=IN IP4 198.51.100.9
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


$resp = rtpe_req('play media', 'media playback, side A, select by label', { label => 'foobar',
		blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

(undef, $seq, $ts, $ssrc) = rcv($sock_a, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_a, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_a, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_a, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_a, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));




($sock_a, $sock_b) = new_call([qw(198.51.100.9 2030)], [qw(198.51.100.9 2032)]);

offer('media playback, side B, select by label', { ICE => 'remove', replace => ['origin'],
	label => 'quux' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.9
s=tester
t=0 0
m=audio 2030 RTP/AVP 8
c=IN IP4 198.51.100.9
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('media playback, side B, select by label', { replace => ['origin'], label => 'meh' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.9
s=tester
t=0 0
m=audio 2032 RTP/AVP 8
c=IN IP4 198.51.100.9
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP


$resp = rtpe_req('play media', 'media playback, side B, select by label', { label => 'meh', blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

(undef, $seq, $ts, $ssrc) = rcv($sock_b, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_b, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_b, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_b, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_b, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));





($sock_a, $sock_b) = new_call([qw(198.51.100.1 2050)], [qw(198.51.100.3 2052)]);

offer('media playback, SRTP', { ICE => 'remove', replace => ['origin'], DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2050 RTP/SAVP 8
c=IN IP4 198.51.100.1
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:eMlRvW8mWU4WodT9JOvAM+pn6I0/EXOhT9n0KeKk
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:eMlRvW8mWU4WodT9JOvAM+pn6I0/EXOhT9n0KeKk
a=crypto:2 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:3 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:4 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:5 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:6 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:7 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:8 AES_CM_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

answer('media playback, SRTP', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2052 RTP/SAVP 8
c=IN IP4 198.51.100.3
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF
SDP


$resp = rtpe_req('play media', 'media playback, SRTP', { 'from-tag' => ft(), blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

my $srtp_ctx = {
	cs => $NGCP::Rtpclient::SRTP::crypto_suites{AES_CM_128_HMAC_SHA1_80},
	key => 'DVM+BTeYX2UI1LaA9bgXrcBEDBxoItA9/39fSoRF',
};
(undef, $seq, $ts, $ssrc) = srtp_rcv($sock_a, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1), $srtp_ctx);
srtp_rcv($sock_a, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2), $srtp_ctx);
srtp_rcv($sock_a, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3), $srtp_ctx);
srtp_rcv($sock_a, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4), $srtp_ctx);
srtp_rcv($sock_a, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5), $srtp_ctx);






# ptime tests

($sock_a, $sock_b) = new_call([qw(198.51.100.1 3000)], [qw(198.51.100.3 3002)]);

($port_a) = offer('default ptime in/out', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('default ptime in/out', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4000, 5000, 0x4567, "\x88" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3000)], [qw(198.51.100.3 3002)]);

($port_a) = offer('mismatched ptime but no change requested', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:20
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

($port_b) = answer('mismatched ptime but no change requested', { ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:30
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x1234, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, 0x1234, "\x00" x 240));
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4000, 5000, 0x4567, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5160, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, 0x4567, "\x88" x 240));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3004)], [qw(198.51.100.3 3006)]);

($port_a) = offer('default ptime in, ptime=30 out, default response', {
	ICE => 'remove', replace => ['origin'], ptime => 30 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3004 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('default ptime in, ptime=30 out, default response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3006 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# A->B: 5x 20 ms packets -> 3x 30 ms
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1002, 3320, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1003, 3480, 0x1234, "\x00" x 160));
Time::HiRes::usleep(1000);
snd($sock_a, $port_b, rtp(0, 1004, 3640, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));

# A->B: 60 ms packet -> 2x 30 ms
# also perform TS and seq reset
snd($sock_a, $port_b, rtp(0, 8000, 500000, 0x1234, "\x00" x 480));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1004, 3960, $ssrc, "\x00" x 240));

# B->A: 2x 60 ms packet -> 6x 20 ms
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 480));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 5320, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5480, 0x4567, "\x88" x 480));
rcv($sock_a, $port_b, rtpm(0, 4003, 5480, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4004, 5640, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 5800, $ssrc, "\x88" x 160));

# B->A: 4x 10 ms packet -> 2x 20 ms
snd($sock_b, $port_a, rtp(0, 4002, 5960, 0x4567, "\x88" x 80));
Time::HiRes::usleep(1000);
snd($sock_b, $port_a, rtp(0, 4003, 6040, 0x4567, "\x88" x 80));
rcv($sock_a, $port_b, rtpm(0, 4006, 5960, $ssrc, "\x88" x 160));
# out of order packet input
snd($sock_b, $port_a, rtp(0, 4005, 6200, 0x4567, "\x88" x 80));
Time::HiRes::usleep(10000);
snd($sock_b, $port_a, rtp(0, 4004, 6120, 0x4567, "\x88" x 80));
rcv($sock_a, $port_b, rtpm(0, 4007, 6120, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4006, 6280, 0x4567, "\x88" x 80));
Time::HiRes::usleep(1000);
snd($sock_b, $port_a, rtp(0, 4007, 6360, 0x4567, "\x88" x 80));
rcv($sock_a, $port_b, rtpm(0, 4008, 6280, $ssrc, "\x88" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3008)], [qw(198.51.100.3 3010)]);

($port_a) = offer('default ptime in, no change, ptime=30 response', {
	ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3008 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('default ptime in, no change, ptime=30 response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3010 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:30
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

# A->B: 20 ms unchanged
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
# A->B: 30 ms unchanged
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, $ssrc, "\x00" x 240));

# B->A: 20 ms unchanged
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
# B->A: 30 ms unchanged
snd($sock_b, $port_a, rtp(0, 4001, 5160, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 240));



($sock_a, $sock_b) = new_call([qw(198.51.100.1 3012)], [qw(198.51.100.3 3014)]);

($port_a) = offer('ptime=50 in, change to 30, default response', {
	ICE => 'remove', replace => ['origin'], ptime => 30 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3012 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:50
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=50 in, change to 30, default response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3014 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:50
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\x00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));

# B->A: 4x 30 ms -> 2x 50 ms (plus 20 ms left)
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 400));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
Time::HiRes::usleep(1000);
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5400, $ssrc, "\x88" x 400));
# B->A: add another 30 ms for another full 50 ms
snd($sock_b, $port_a, rtp(0, 4004, 5960, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4002, 5800, $ssrc, "\x88" x 400));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3016)], [qw(198.51.100.3 3018)]);

($port_a) = offer('ptime=50 in, change to 30, reverse to 50, response 30', {
	ICE => 'remove', replace => ['origin'], ptime => 30, 'ptime-reverse' => 50 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3016 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:50
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=50 in, change to 30, reverse to 50, response 30',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:30
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:50
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\x00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));

# B->A: 4x 30 ms -> 2x 50 ms (plus 20 ms left)
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 400));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
Time::HiRes::usleep(1000);
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5400, $ssrc, "\x88" x 400));
# B->A: add another 30 ms for another full 50 ms
snd($sock_b, $port_a, rtp(0, 4004, 5960, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4002, 5800, $ssrc, "\x88" x 400));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3012)], [qw(198.51.100.3 3014)]);

($port_a) = offer('ptime=50 in, change to 30, response 30', {
	ICE => 'remove', replace => ['origin'], ptime => 30 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3012 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:50
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=50 in, change to 30, response 30',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3014 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:30
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:50
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\x00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));

# B->A: 4x 30 ms -> 2x 50 ms (plus 20 ms left)
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 400));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
Time::HiRes::usleep(1000);
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5400, $ssrc, "\x88" x 400));
# B->A: add another 30 ms for another full 50 ms
snd($sock_b, $port_a, rtp(0, 4004, 5960, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4002, 5800, $ssrc, "\x88" x 400));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3016)], [qw(198.51.100.3 3018)]);

($port_a) = offer('ptime=50 in, change to 30, reverse to 50, default response', {
	ICE => 'remove', replace => ['origin'], ptime => 30, 'ptime-reverse' => 50 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3016 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:50
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=50 in, change to 30, reverse to 50, default response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:50
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\x00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));

# B->A: 4x 30 ms -> 2x 50 ms (plus 20 ms left)
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 400));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
Time::HiRes::usleep(1000);
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5400, $ssrc, "\x88" x 400));
# B->A: add another 30 ms for another full 50 ms
snd($sock_b, $port_a, rtp(0, 4004, 5960, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4002, 5800, $ssrc, "\x88" x 400));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3016)], [qw(198.51.100.3 3018)]);

($port_a) = offer('ptime=50 in, change to 30, reverse to 20, default response', {
	ICE => 'remove', replace => ['origin'], ptime => 30, 'ptime-reverse' => 20 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3016 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:50
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=50 in, change to 30, reverse to 20, default response',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\x00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));

# B->A: 4x 30 ms -> 6x 20 ms
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 5320, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4003, 5480, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4004, 5640, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 5800, $ssrc, "\x88" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3016)], [qw(198.51.100.3 3018)]);

($port_a) = offer('ptime=50 in, change to 30, reverse to 20, response 40', {
	ICE => 'remove', replace => ['origin'], ptime => 30, 'ptime-reverse' => 20 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3016 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:50
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=50 in, change to 30, reverse to 20, response 40',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:40
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\x00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));

# B->A: 4x 30 ms -> 6x 20 ms
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 5320, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4003, 5480, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4004, 5640, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 5800, $ssrc, "\x88" x 160));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 3016)], [qw(198.51.100.3 3018)]);

($port_a) = offer('ptime=30 in, no change, reverse to 20, response 40', {
	ICE => 'remove', replace => ['origin'], 'ptime-reverse' => 20 }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3016 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ptime:30
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:30
SDP

($port_b) = answer('ptime=30 in, no change, reverse to 20, response 40',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3018 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
a=ptime:40
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

# A->B: 2x 50 ms -> 3x 30 ms (plus 10 ms left)
snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 400));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 240));
snd($sock_a, $port_b, rtp(0, 1001, 3400, 0x1234, "\x00" x 400));
rcv($sock_b, $port_a, rtpm(0, 1001, 3240, $ssrc, "\x00" x 240));
rcv($sock_b, $port_a, rtpm(0, 1002, 3480, $ssrc, "\x00" x 240));
# A->B: add another 20 ms for another full 30 ms
snd($sock_a, $port_b, rtp(0, 1002, 3800, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1003, 3720, $ssrc, "\x00" x 240));

# B->A: 4x 30 ms -> 6x 20 ms
snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 240));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5240, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4002, 5320, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4002, 5480, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4003, 5480, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4003, 5720, 0x4567, "\x88" x 240));
rcv($sock_a, $port_b, rtpm(0, 4004, 5640, $ssrc, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4005, 5800, $ssrc, "\x88" x 160));




# gh #730

($sock_a, $sock_b) = new_call([qw(198.51.100.1 7300)], [qw(198.51.100.3 7302)]);

($port_a) = offer('gh 730', {
	ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7300 RTP/AVP 0 106 101 98
c=IN IP4 198.51.100.1
a=sendrecv
a=rtpmap:0 PCMU/8000
a=rtpmap:106 opus/48000/2
a=fmtp:106 maxplaybackrate=16000; sprop-maxcapturerate=16000; minptime=20; cbr=1; maxaveragebitrate=20000; useinbandfec=1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:98 telephone-event/48000
a=fmtp:98 0-16
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 106 101 98
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:106 opus/48000/2
a=fmtp:106 useinbandfec=1; cbr=1; maxplaybackrate=16000; maxaveragebitrate=20000; sprop-maxcapturerate=16000; minptime=20
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:98 telephone-event/48000
a=fmtp:98 0-16
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('gh 730',
	{ ICE => 'remove', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7302 RTP/AVP 0 101
c=IN IP4 198.51.100.3
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b, rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, $ssrc, "\x00" x 160));
snd($sock_a, $port_b, rtp(101 | 0x80, 1002, 3320, 0x1234, "\x05\x0a\x00\xa0"));
rcv($sock_b, $port_a, rtpm(101 | 0x80, 1002, 3320, $ssrc, "\x05\x0a\x00\xa0"));
snd($sock_a, $port_b, rtp(101, 1003, 3320, 0x1234, "\x05\x0a\x01\x40"));
rcv($sock_b, $port_a, rtpm(101, 1003, 3320, $ssrc, "\x05\x0a\x01\x40"));

snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));
snd($sock_b, $port_a, rtp(0, 4001, 5160, 0x4567, "\x88" x 160));
rcv($sock_a, $port_b, rtpm(0, 4001, 5160, $ssrc, "\x88" x 160));
snd($sock_b, $port_a, rtp(101 | 0x80, 4002, 5320, 0x4567, "\x05\x0a\x00\xa0"));
rcv($sock_a, $port_b, rtpm(101 | 0x80, 4002, 5320, $ssrc, "\x05\x0a\x00\xa0"));
snd($sock_b, $port_a, rtp(101, 4003, 5320, 0x4567, "\x05\x0a\x01\x40"));
rcv($sock_a, $port_b, rtpm(101, 4003, 5320, $ssrc, "\x05\x0a\x01\x40"));




# gh #766

($sock_a, $sock_b, $sock_c) = new_call([qw(198.51.100.5 7300)], [qw(198.51.100.6 7302)], [qw(198.51.100.7 7304)]);

(undef, $port_a) = offer('gh 766 orig', {
	ICE => 'remove', replace => ['origin'],
	flags => [ "loop-protect", "asymmetric" ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.5
s=tester
c=IN IP4 198.51.100.5
t=0 0
m=audio 7300 RTP/AVP 0 8 18 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=maxptime:20
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
a=rtpengine:LOOPER
m=audio PORT RTP/AVP 0 8 18 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
a=maxptime:20
SDP

(undef, $port_b) = answer('gh 766 orig',
	{ ICE => 'remove', replace => ['origin'],
	flags => [ "loop-protect", "asymmetric" ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.6
s=tester
c=IN IP4 198.51.100.6
t=0 0
m=audio 7302 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=ptime:20
a=xg726bitorder:big-endian
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
a=rtpengine:LOOPER
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=xg726bitorder:big-endian
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));

snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));

# reverse re-invite
reverse_tags();

(undef, $port_b) = offer('gh 766 reinvite',
	{ 'to-tag' => tt(),
	ICE => 'remove', replace => ['origin'],
	flags => [ "loop-protect", "asymmetric" ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.7
s=tester
c=IN IP4 198.51.100.7
t=0 0
m=image 7304 udptl t38
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:200
a=T38FaxMaxDatagram:180
a=T38FaxUdpEC:t38UDPRedundancy
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
a=rtpengine:LOOPER
m=image PORT udptl t38
c=IN IP4 203.0.113.1
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:200
a=T38FaxMaxDatagram:180
a=T38FaxUdpEC:t38UDPRedundancy
SDP

(undef, $port_a) = answer('gh 766 reinvite', {
	ICE => 'remove', replace => ['origin'],
	flags => [ "loop-protect", "asymmetric" ] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.5
s=tester
c=IN IP4 198.51.100.5
t=0 0
m=image 7300 udptl t38
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:262
a=T38FaxMaxDatagram:176
a=T38FaxUdpEC:t38UDPRedundancy
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
a=rtpengine:LOOPER
m=image PORT udptl t38
c=IN IP4 203.0.113.1
a=T38FaxVersion:0
a=T38MaxBitRate:14400
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:262
a=T38FaxMaxDatagram:176
a=T38FaxUdpEC:t38UDPRedundancy
a=sendrecv
SDP

snd($sock_b, $port_a, rtp(0, 4000, 5000, 0x4567, "\x88" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 4000, 5000, -1, "\x88" x 160));

snd($sock_a, $port_b, "\x00\x00\x01\x00\x00\x01\x01\x00");
rcv($sock_c, $port_a, qr/^\x00\x00\x01\x00\x00\x01\x01\x00$/s);




($sock_a, $sock_b) = new_call([qw(198.51.100.1 7010)], [qw(198.51.100.3 7012)]);

($port_a) = offer('PCM to RFC DTMF transcoding', { ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['telephone-event'] }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7010 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('PCM to RFC DTMF transcoding', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7012 RTP/AVP 0 96
c=IN IP4 198.51.100.3
a=rtpmap:0 PCMU/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($seq, $ssrc) = rcv($sock_b, $port_a, rtpm(0, -1, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq+1, 3160, $ssrc, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1002, 3000+160*2, 0x1234, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
# DTMF not detected yet
rcv($sock_b, $port_a, rtpm(0, $seq+2, 3000+160*2, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_a, $port_b,  rtp(0, 1003, 3000+160*3, 0x1234, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
# DTMF detection kicking in mid-frame
rcv($sock_b, $port_a, rtpm(0, $seq+3, 3000+160*3, $ssrc, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_a, $port_b,  rtp(0, 1004, 3000+160*4, 0x1234, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
# DTMF detected now
rcv($sock_b, $port_a, rtpm(96 | 0x80, $seq+4, 3000+160*4, $ssrc, "\x08\x0f\x00\xa0", "\x08\x10\x00\xa0")); # start event 8, vol -15, duration 160
snd($sock_a, $port_b,  rtp(0, 1005, 3000+160*5, 0x1234, "\x00" x 160));
# reverting to audio, but DTMF event still progressing
rcv($sock_b, $port_a, rtpm(96, $seq+5, 3000+160*4, $ssrc, "\x08\x0f\x01\x40", "\x08\x10\x01\x40")); # event 8, vol -15, duration 320
snd($sock_a, $port_b,  rtp(0, 1006, 3000+160*6, 0x1234, "\x00" x 160));
# end event, 3 times
rcv($sock_b, $port_a, rtpm(96, $seq+6, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0", "\x08\x90\x01\xe0")); # end event 8, vol -15, duration 480
rcv($sock_b, $port_a, rtpm(96, $seq+7, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0", "\x08\x90\x01\xe0")); # end event 8, vol -15, duration 480
rcv($sock_b, $port_a, rtpm(96, $seq+8, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0", "\x08\x90\x01\xe0")); # end event 8, vol -15, duration 480
# audio passing through again
snd($sock_a, $port_b,  rtp(0, 1007, 3000+160*7, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq+9, 3000+160*7, $ssrc, "\x00" x 160));

snd($sock_b, $port_a,  rtp(0, 2000, 4000, 0x5678, "\x00" x 160));
($seq, $ssrc) = rcv($sock_a, $port_b, rtpm(0, -1, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 2001, 4000+160, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+1, 4000+160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(96, 2002, 4000+320, 0x5678, "\x08\x10\x00\xa0"));
rcv($sock_a, $port_b, rtpm(0, $seq+2, 4000+320, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_b, $port_a,  rtp(96, 2003, 4000+320, 0x5678, "\x08\x10\x01\x40"));
rcv($sock_a, $port_b, rtpm(0, $seq+3, 4000+480, $ssrc, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_b, $port_a,  rtp(96, 2004, 4000+320, 0x5678, "\x08\x90\x01\xe0")); # end event to get out of DTMF state
rcv($sock_a, $port_b, rtpm(0, $seq+4, 4000+640, $ssrc, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
# test out of seq
snd($sock_b, $port_a,  rtp(0, 2006, 4000+160*25, 0x5678, "\x00" x 160)); # processed because TS difference too large
rcv($sock_a, $port_b, rtpm(0, $seq+6, 4000+160*5, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(96, 2005, 4000+320, 0x5678, "\x08\x10\x01\xe0")); # repeat, no-op, dup, consumed
# resume normal
snd($sock_b, $port_a,  rtp(0, 2007, 4000+160*26, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+7, 4000+160*6, $ssrc, "\x00" x 160));
# test TS reset
snd($sock_b, $port_a,  rtp(0, 2008, 2000, 0x5678, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+8, 4000+160*7, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(96, 2009, 2160, 0x5678, "\x08\x10\x00\xa0"));
rcv($sock_a, $port_b, rtpm(0, $seq+9, 4000+160*8, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 7020)], [qw(198.51.100.3 7022)]);

($port_a) = offer('PCM to RFC DTMF transcoding w/ PCM transcoding', { ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['PCMA', 'telephone-event'] }}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7020 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8 96
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('PCM to RFC DTMF transcoding w/ PCM transcoding', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7022 RTP/AVP 8 96
c=IN IP4 198.51.100.3
a=rtpmap:0 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000+160*0, 0x1234, "\x00" x 160));
($seq, $ssrc) = rcv($sock_b, $port_a, rtpm(8, -1, 3000+160*0, -1, "\x2a" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3000+160*1, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, $seq+1, 3000+160*1, $ssrc, "\x2a" x 160));
snd($sock_a, $port_b,  rtp(0, 1002, 3000+160*2, 0x1234, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
# DTMF not detected yet
rcv($sock_b, $port_a, rtpm(8, $seq+2, 3000+160*2, $ssrc, "\xd5\x9b\x87\x97\x64\x10\x6b\x41\xdc\x73\x66\xd1\x91\x9a\x97\x6d\x07\x04\x67\x91\x9a\x96\x5c\x60\x7d\xd3\x4d\x6b\x11\x7c\x91\x87\x9e\x4f\x1a\x04\x15\xe0\x93\xe8\xda\x59\xf1\xe4\x44\x10\x1b\x6b\xeb\x87\x85\xfc\x12\x1a\x17\xc3\xe2\xfc\x51\xc9\xeb\x96\xcb\x13\x07\x1c\xff\x85\x84\xee\x6f\x12\x68\x5c\xc5\x76\x7b\xc9\x93\x98\xef\x14\x06\x1a\x4f\x9c\x9a\x95\x77\x6c\x7f\xd7\x75\x6b\x14\x59\x9d\x87\x93\x66\x04\x04\x63\xeb\x9d\xe9\xd7\x41\xf4\xff\x71\x12\x19\x61\x91\x86\x9b\xd5\x1e\x1a\x68\xfc\xee\xff\x55\xf4\xeb\x95\x53\x1c\x04\x11\xec\x87\x85\xe5\x14\x1d\x6f\xd1\xcd\x4b\x73\xfc\x92\x9f\xfb\x12\x06\x19\xcd\x98\x9a\xef\x65\x69\x7e\x55\x77\x68"));
snd($sock_a, $port_b,  rtp(0, 1003, 3000+160*3, 0x1234, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
# DTMF detection kicking in mid-frame
rcv($sock_b, $port_a, rtpm(8, $seq+3, 3000+160*3, $ssrc, "\x68\xc2\x9e\x84\x94\x6b\x07\x1a\x72\x96\x9c\xec\x59\x49\xcf\xf7\x7b\x12\x1c\x76\x9c\x86\x9f\x7c\x1a\x1a\x63\xe6\xeb\xfe\xd5\xf6\xe9\xef\x71\x19\x05\x68\x97\x86\x9b\xc2\x10\x1c\x62\xc1\xf5\x43\x49\xe4\x92\x92\xda\x1e\x06\x12\xe7\x85\x9b\xe7\x62\x6b\x7e\x55\x76\x69\x62\xf9\x98\x85\xe2\x10\x06\x18\x54\x92\x9c\xe0\x49\x76\xc7\xc3\x66\x12\x13\xd3\x98\x86\x91\x6c\x05\x1b\x79\xef\x95\xff\x54\xf6\xef\xe1\x67\x1b\x1a\x64\x9d\x86\x9e\x43\x1c\x1c\x67\xf6\xf0\x5a\x5a\xe0\x92\x91\x49\x1b\x07\x17\xeb\x84\x98\xf6\x68\x15\x7c\xd7\x76\x6c\x64\xe0\x9b\x9b\xf0\x1f\x06\x1c\xf3\x9e\x9c\xe5\x72\x72\xde\xdd\x63\x12\x17\xfd\x9a\x87\xe8\x17\x04\x1e\x41\x95"));
snd($sock_a, $port_b,  rtp(0, 1004, 3000+160*4, 0x1234, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
# DTMF detected now
rcv($sock_b, $port_a, rtpm(96 | 0x80, $seq+4, 3000+160*4, $ssrc, "\x08\x0f\x00\xa0", "\x08\x10\x00\xa0")); # start event 8, vol -15, duration 160
snd($sock_a, $port_b,  rtp(0, 1005, 3000+160*5, 0x1234, "\x00" x 160));
# reverting to audio, but DTMF event still progressing
rcv($sock_b, $port_a, rtpm(96, $seq+5, 3000+160*4, $ssrc, "\x08\x0f\x01\x40", "\x08\x10\x01\x40")); # event 8, vol -15, duration 320
snd($sock_a, $port_b,  rtp(0, 1006, 3000+160*6, 0x1234, "\x00" x 160));
# end event, 3 times
rcv($sock_b, $port_a, rtpm(96, $seq+6, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0", "\x08\x90\x01\xe0")); # end event 8, vol -15, duration 480
rcv($sock_b, $port_a, rtpm(96, $seq+7, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0", "\x08\x90\x01\xe0")); # end event 8, vol -15, duration 480
rcv($sock_b, $port_a, rtpm(96, $seq+8, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0", "\x08\x90\x01\xe0")); # end event 8, vol -15, duration 480
# audio passing through again
snd($sock_a, $port_b,  rtp(0, 1007, 3000+160*7, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, $seq+9, 3000+160*7, $ssrc, "\x2a" x 160));

snd($sock_b, $port_a,  rtp(8, 2000, 4000, 0x5678, "\x2a" x 160));
($seq, $ssrc) = rcv($sock_a, $port_b, rtpm(0, -1, 4000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(8, 2001, 4000+160, 0x5678, "\x2a" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+1, 4000+160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(96, 2002, 4000+320, 0x5678, "\x08\x10\x00\xa0"));
rcv($sock_a, $port_b, rtpm(0, $seq+2, 4000+320, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_b, $port_a,  rtp(96, 2003, 4000+320, 0x5678, "\x08\x10\x01\x40"));
rcv($sock_a, $port_b, rtpm(0, $seq+3, 4000+480, $ssrc, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_b, $port_a,  rtp(96, 2004, 4000+320, 0x5678, "\x08\x10\x01\xe0"));
rcv($sock_a, $port_b, rtpm(0, $seq+4, 4000+640, $ssrc, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));





# test telephone-event synth options

new_call;

offer('several clock rates input w/ transcode DTMF',
	{ ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['telephone-event'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0 96 8 97 9
c=IN IP4 198.51.100.1
a=rtpmap:96 opus/48000
a=rtpmap:8 PCMA/8000
a=rtpmap:97 speex/16000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 96 8 97 9 99 100 98
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:96 opus/48000
a=rtpmap:8 PCMA/8000
a=rtpmap:97 speex/16000
a=rtpmap:9 G722/8000
a=rtpmap:99 telephone-event/16000
a=fmtp:99 0-15
a=rtpmap:100 telephone-event/48000
a=fmtp:100 0-15
a=rtpmap:98 telephone-event/8000
a=fmtp:98 0-15
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('DTMF PT already present, add one codec',
	{ ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['opus'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 8 97
c=IN IP4 198.51.100.1
a=rtpmap:8 PCMA/8000
a=rtpmap:97 telephone-event/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 96 98 97
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=rtpmap:98 telephone-event/48000
a=fmtp:98 0-15
a=rtpmap:97 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('DTMF PT already present, strip one codec',
	{ ICE => 'remove', replace => ['origin'],
	codec => { strip => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 8 96 97 98
c=IN IP4 198.51.100.1
a=rtpmap:8 PCMA/8000
a=rtpmap:96 opus/48000/2
a=rtpmap:97 telephone-event/8000
a=rtpmap:98 telephone-event/48000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 98
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=rtpmap:98 telephone-event/48000
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('DTMF PT already present, add one codec, mask another',
	{ ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['opus'], mask => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 8 97
c=IN IP4 198.51.100.1
a=rtpmap:8 PCMA/8000
a=rtpmap:97 telephone-event/8000
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 96 98
c=IN IP4 203.0.113.1
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=rtpmap:98 telephone-event/48000
a=fmtp:98 0-15
a=sendrecv
a=rtcp:PORT
SDP




new_call;

offer('strip CN',
	{ ICE => 'remove', replace => ['origin'],
	codec => { strip => [qw/PCMU RED CN G729/]} }, <<SDP);
v=0
o=- 100263 0 IN IP4 127.0.0.1
s=session
c=IN IP4 52.113.56.34
b=CT:10000000
t=0 0
m=audio 49954 RTP/AVP 104 9 103 111 18 0 8 97 101 13 118
c=IN IP4 52.113.56.34
a=rtcp:49955
a=label:main-audio
a=mid:1
a=sendrecv
a=rtpmap:104 SILK/16000
a=rtpmap:9 G722/8000
a=rtpmap:103 SILK/8000
a=rtpmap:111 SIREN/16000
a=fmtp:111 bitrate=16000
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:97 RED/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=rtpmap:13 CN/8000
a=rtpmap:118 CN/16000
a=ptime:20
----------------------------------
v=0
o=- 100263 0 IN IP4 203.0.113.1
s=session
b=CT:10000000
t=0 0
m=audio PORT RTP/AVP 104 9 103 111 8 101
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:104 SILK/16000
a=rtpmap:9 G722/8000
a=rtpmap:103 SILK/8000
a=rtpmap:111 SIREN/16000
a=fmtp:111 bitrate=16000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=label:main-audio
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP




($sock_a, $sock_b) = new_call([qw(198.51.100.1 8050)], [qw(198.51.100.3 8052)]);

($port_a) = offer('reverse DTMF transcoding - no-op', { ICE => 'remove', replace => ['origin'],
	flags => ['always transcode'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 8050 RTP/AVP 0 101
c=IN IP4 198.51.100.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('reverse DTMF transcoding - no-op', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 8052 RTP/AVP 0 101
c=IN IP4 198.51.100.3
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($ssrc) = rcv($sock_b, $port_a, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1001, 3160, $ssrc, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1002, 3000+160*2, 0x1234, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
rcv($sock_b, $port_a, rtpm(0, 1002, 3000+160*2, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_a, $port_b,  rtp(0, 1003, 3000+160*3, 0x1234, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
rcv($sock_b, $port_a, rtpm(0, 1003, 3000+160*3, $ssrc, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_a, $port_b,  rtp(0, 1004, 3000+160*4, 0x1234, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
rcv($sock_b, $port_a, rtpm(0, 1004, 3000+160*4, $ssrc, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
snd($sock_a, $port_b,  rtp(0, 1005, 3000+160*5, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1005, 3000+160*5, $ssrc, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1006, 3000+160*6, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, 1006, 3000+160*6, $ssrc, "\x00" x 160));
snd($sock_a, $port_b,  rtp(101 | 0x80, 1007, 3000+160*7, 0x1234, "\x08\x10\x00\xa0"));
rcv($sock_b, $port_a, rtpm(101 | 0x80, 1007, 3000+160*7, $ssrc, "\x08\x10\x00\xa0"));

snd($sock_b, $port_a,  rtp(0, 1000, 3000, 0x3456, "\x00" x 160));
($ssrc) = rcv($sock_a, $port_b, rtpm(0, 1000, 3000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 1001, 3160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 1001, 3160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 1002, 3000+160*2, 0x3456, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
rcv($sock_a, $port_b, rtpm(0, 1002, 3000+160*2, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_b, $port_a,  rtp(0, 1003, 3000+160*3, 0x3456, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
rcv($sock_a, $port_b, rtpm(0, 1003, 3000+160*3, $ssrc, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_b, $port_a,  rtp(0, 1004, 3000+160*4, 0x3456, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
rcv($sock_a, $port_b, rtpm(0, 1004, 3000+160*4, $ssrc, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
snd($sock_b, $port_a,  rtp(0, 1005, 3000+160*5, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 1005, 3000+160*5, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 1006, 3000+160*6, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, 1006, 3000+160*6, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(101 | 0x80, 1007, 3000+160*7, 0x3456, "\x08\x10\x00\xa0"));
rcv($sock_a, $port_b, rtpm(101 | 0x80, 1007, 3000+160*7, $ssrc, "\x08\x10\x00\xa0"));




($sock_a, $sock_b) = new_call([qw(198.51.100.1 7050)], [qw(198.51.100.3 7052)]);

($port_a) = offer('reverse DTMF transcoding - active', { ICE => 'remove', replace => ['origin'],
	flags => ['always transcode'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7050 RTP/AVP 0 101
c=IN IP4 198.51.100.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('reverse DTMF transcoding - active', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7052 RTP/AVP 0
c=IN IP4 198.51.100.3
a=rtpmap:0 PCMU/8000
a=fmtp:101 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(0, 1000, 3000, 0x1234, "\x00" x 160));
($seq, $ssrc) = rcv($sock_b, $port_a, rtpm(0, -1, 3000, -1, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1001, 3160, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq+1, 3160, $ssrc, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1002, 3000+160*2, 0x1234, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
rcv($sock_b, $port_a, rtpm(0, $seq+2, 3000+160*2, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_a, $port_b,  rtp(0, 1003, 3000+160*3, 0x1234, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
rcv($sock_b, $port_a, rtpm(0, $seq+3, 3000+160*3, $ssrc, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_a, $port_b,  rtp(0, 1004, 3000+160*4, 0x1234, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
rcv($sock_b, $port_a, rtpm(0, $seq+4, 3000+160*4, $ssrc, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
snd($sock_a, $port_b,  rtp(0, 1005, 3000+160*5, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq+5, 3000+160*5, $ssrc, "\x00" x 160));
snd($sock_a, $port_b,  rtp(0, 1006, 3000+160*6, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(0, $seq+6, 3000+160*6, $ssrc, "\x00" x 160));
snd($sock_a, $port_b,  rtp(101 | 0x80, 1007, 3000+160*7, 0x1234, "\x08\x10\x00\xa0"));
rcv($sock_b, $port_a, rtpm(0, $seq+7, 3000+160*7, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));

snd($sock_b, $port_a,  rtp(0, 1000, 3000, 0x3456, "\x00" x 160));
($seq, $ssrc) = rcv($sock_a, $port_b, rtpm(0, -1, 3000, -1, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 1001, 3160, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+1, 3160, $ssrc, "\x00" x 160));
snd($sock_b, $port_a,  rtp(0, 1002, 3000+160*2, 0x3456, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
# DTMF not detected yet
rcv($sock_a, $port_b, rtpm(0, $seq+2, 3000+160*2, $ssrc, "\xff\xb0\xac\xbc\x4c\x39\x3f\x63\xee\x55\x4a\xf6\xba\xaf\xbc\x45\x2c\x2d\x4b\xba\xaf\xbb\x6e\x48\x53\xf3\x5f\x3f\x3a\x52\xba\xac\xb3\x5e\x2f\x2d\x3e\xc8\xb8\xc0\xe8\x6b\xd7\xcc\x66\x39\x30\x3f\xbf\xac\xae\xd2\x37\x2f\x3c\xe1\xc6\xd2\x77\xdd\xbf\xbb\xdc\x38\x2c\x35\xd1\xae\xad\xc2\x43\x37\x40\x6e\xe7\x58\x4e\xdd\xb8\xb1\xc3\x3d\x2b\x2f\x5e\xb5\xaf\xbe\x59\x44\x51\xfb\x5b\x3f\x3d\x6b\xb6\xac\xb8\x4a\x2d\x2d\x47\xbf\xb6\xc1\xfa\x63\xda\xd1\x57\x37\x32\x49\xba\xab\xb0\xfe\x33\x2f\x40\xd2\xc2\xd1\x7e\xda\xbf\xbe\x73\x35\x2d\x3a\xc4\xac\xae\xcd\x3d\x36\x43\xf6\xdf\x5c\x55\xd2\xb7\xb4\xce\x37\x2b\x32\xdf\xb1\xaf\xc3\x4d\x41\x50\x7e\x59\x40"));
snd($sock_b, $port_a,  rtp(0, 1003, 3000+160*3, 0x3456, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
# DTMF detection kicking in mid-frame
rcv($sock_a, $port_b, rtpm(0, $seq+3, 3000+160*3, $ssrc, "\x40\xe0\xb3\xad\xbd\x3f\x2c\x2f\x54\xbb\xb5\xc4\x6b\x5d\xde\xd9\x4e\x37\x35\x58\xb5\xab\xb4\x52\x2f\x2f\x47\xca\xbf\xd0\xfe\xd8\xc1\xc3\x57\x32\x2e\x40\xbc\xab\xb0\xe0\x39\x35\x46\xe3\xdb\x61\x5d\xcc\xb7\xb7\xe8\x33\x2b\x37\xcb\xae\xb0\xcb\x46\x3f\x50\x7e\x58\x41\x46\xcf\xb1\xae\xc6\x39\x2b\x31\x7d\xb7\xb5\xc8\x5d\x58\xe5\xe1\x4a\x37\x38\xf2\xb1\xab\xba\x44\x2e\x30\x4f\xc3\xbe\xd1\x7d\xd8\xc3\xc9\x4b\x30\x2f\x4c\xb6\xab\xb3\x61\x35\x35\x4b\xd8\xd6\x68\x68\xc8\xb7\xba\x5d\x30\x2c\x3c\xbf\xad\xb1\xd8\x40\x3e\x52\xfb\x58\x44\x4c\xc8\xb0\xb0\xd6\x34\x2b\x35\xd5\xb3\xb5\xcd\x54\x54\xec\xef\x47\x37\x3c\xd3\xaf\xac\xc0\x3c\x2d\x33\x63\xbe"));
snd($sock_b, $port_a,  rtp(0, 1004, 3000+160*4, 0x3456, "\xbd\xd3\x77\xd9\xc5\xd0\x44\x30\x32\x65\xb2\xab\xb8\x4c\x32\x35\x50\xcf\xd2\x70\x7a\xc6\xb8\xbe\x4c\x2e\x2d\x45\xb9\xac\xb4\xfd\x3c\x3d\x55\xf2\x5a\x47\x56\xc1\xb0\xb4\x71\x30\x2b\x3a\xc7\xb0\xb6\xd7\x4d\x50\xf6\x78\x45\x38\x41\xc7\xae\xae\xcc\x37\x2c\x36\xe5\xbb\xbd\xd7\x6d\xdb\xc9\xdd\x3f\x30\x36\xdc\xae\xab\xbd\x41\x2f\x37\x5d\xcb\xcf\x7b\xef\xc4\xb9\xc6\x42\x2d\x2e\x55\xb4\xac\xb8\x58\x39\x3d\x59\xea\x5c\x4a\x66\xbd\xb0\xb8\x50\x2e\x2c\x40\xbd\xaf\xb8\xe8\x48\x4e\x7d\x6b\x43\x3a\x4a\xbf\xad\xaf\xe4\x32\x2c\x3a\xcf\xb8\xbd\xdc\x66\xde\xcc\xf5\x3c\x30\x3b\xca\xad\xac\xc6\x3b\x2e\x39\x7c\xc6\xcd\xfa\xe7\xc3\xbb\xce\x3c\x2d\x31\xf2"));
# DTMF detected now
rcv($sock_a, $port_b, rtpm(101 | 0x80, $seq+4, 3000+160*4, $ssrc, "\x08\x0f\x00\xa0", "\x08\x10\x00\xa0"));
snd($sock_b, $port_a,  rtp(0, 1005, 3000+160*5, 0x3456, "\x00" x 160));
# reverting to audio, but DTMF event still progressing
rcv($sock_a, $port_b, rtpm(101, $seq+5, 3000+160*4, $ssrc, "\x08\x0f\x01\x40", "\x08\x10\x01\x40"));
snd($sock_b, $port_a,  rtp(0, 1006, 3000+160*6, 0x3456, "\x00" x 160));
# end event, 3 times
rcv($sock_a, $port_b, rtpm(101, $seq+6, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0", "\x08\x90\x01\xe0"));
rcv($sock_a, $port_b, rtpm(101, $seq+7, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0", "\x08\x90\x01\xe0"));
rcv($sock_a, $port_b, rtpm(101, $seq+8, 3000+160*4, $ssrc, "\x08\x8f\x01\xe0", "\x08\x90\x01\xe0")); 
# audio passing through again
snd($sock_b, $port_a,  rtp(0, 1007, 3000+160*7, 0x3456, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(0, $seq+9, 3000+160*7, $ssrc, "\x00" x 160));





($sock_a, $sock_b) = new_call([qw(198.51.100.1 7060)], [qw(198.51.100.3 7062)]);

($port_a) = offer('DTMF scaling', { ICE => 'remove', replace => ['origin'],
	codec => { transcode => ['PCMA', 'telephone-event/8000'] },
	flags => ['always transcode'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7060 RTP/AVP 100 101
c=IN IP4 198.51.100.1
a=rtpmap:100 PCMU/16000
a=rtpmap:101 telephone-event/16000
a=fmtp:101 0-15
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 100 8 96 101
c=IN IP4 203.0.113.1
a=rtpmap:100 PCMU/16000
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=rtpmap:101 telephone-event/16000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('DTMF scaling', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7062 RTP/AVP 8 96
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=rtpmap:96 telephone-event/8000
a=fmtp:96 0-15
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 100 101
c=IN IP4 203.0.113.1
a=rtpmap:100 PCMU/16000
a=rtpmap:101 telephone-event/16000
a=fmtp:101 0-15
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b,  rtp(100, 1000, 3000+320*0, 0x1234, "\x00" x 320));
# resample buffer is stalling
Time::HiRes::usleep(20000); # 20 ms, needed to ensure that packet 1000 is received first
snd($sock_a, $port_b,  rtp(100, 1001, 3000+320*1, 0x1234, "\x00" x 320));
($ssrc) = rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, -1, "\x2a" x 160));
snd($sock_a, $port_b,  rtp(100, 1002, 3000+320*2, 0x1234, "\x00" x 320));
rcv($sock_b, $port_a, rtpm(8, 1001, 3000+160*1, $ssrc, "\x2a" x 160));
# start dtmf
snd($sock_a, $port_b,  rtp(101 | 0x80, 1003, 3000+320*3, 0x1234, "\x08\x0f\x01\x40"));
rcv($sock_b, $port_a, rtpm(96 | 0x80, 1002, 3000+160*2, $ssrc, "\x08\x0f\x00\xa0"));
snd($sock_a, $port_b,  rtp(101, 1004, 3000+320*3, 0x1234, "\x08\x0f\x02\x80"));
rcv($sock_b, $port_a, rtpm(96, 1003, 3000+160*2, $ssrc, "\x08\x0f\x01\x40"));
# end event
snd($sock_a, $port_b,  rtp(101, 1005, 3000+320*3, 0x1234, "\x08\x8f\x03\xc0"));
rcv($sock_b, $port_a, rtpm(96, 1004, 3000+160*2, $ssrc, "\x08\x8f\x01\xe0"));
snd($sock_a, $port_b,  rtp(101, 1006, 3000+320*3, 0x1234, "\x08\x8f\x03\xc0"));
rcv($sock_b, $port_a, rtpm(96, 1005, 3000+160*2, $ssrc, "\x08\x8f\x01\xe0"));
snd($sock_a, $port_b,  rtp(101, 1007, 3000+320*3, 0x1234, "\x08\x8f\x03\xc0"));
rcv($sock_b, $port_a, rtpm(96, 1006, 3000+160*2, $ssrc, "\x08\x8f\x01\xe0"));
# back to audio
snd($sock_a, $port_b,  rtp(100, 1008, 3000+320*6, 0x1234, "\x00" x 320));
rcv($sock_b, $port_a, rtpm(8, 1007, 3000+160*5, $ssrc, "\x2a" x 160));






new_call;

offer('DTMF repacketising',
	{ ICE => 'remove', replace => ['origin'],
	flags => ['strict-source'],
	ptime => 20, 'ptime-reverse' => 60, 'rtcp-mux' => ['demux'],
	}, <<SDP);
v=0
o=- 3768297181 3768297181 IN IP4 10.10.12.22
s=Blink Lite 4.6.0 (MacOSX)
t=0 0
m=audio 50036 RTP/AVP 0 8 101
c=IN IP4 10.10.12.22
a=rtcp:50037
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
----------------------------------
v=0
o=- 3768297181 3768297181 IN IP4 203.0.113.1
s=Blink Lite 4.6.0 (MacOSX)
t=0 0
m=audio PORT RTP/AVP 0 8 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP




# gh #793

new_call;

offer('gh #793 b1', { ICE => 'remove', 'via-branch' => 'x123', 'rtcp-mux' => ['demux'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=rtcp-mux
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

offer('gh #793 b1', { ICE => 'remove', 'via-branch' => 'x456', 'rtcp-mux' => ['offer'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=rtcp-mux
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
a=rtcp-mux
SDP

answer('gh #793 b1', { ICE => 'remove', 'via-branch' => 'x123' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=rtcp-mux
SDP

new_call;

offer('gh #793 b2', { ICE => 'remove', 'via-branch' => 'x123', 'rtcp-mux' => ['demux'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=rtcp-mux
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

offer('gh #793 b2', { ICE => 'remove', 'via-branch' => 'x456', 'rtcp-mux' => ['offer'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=rtcp-mux
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
a=rtcp-mux
SDP

answer('gh #793 b2', { ICE => 'remove', 'via-branch' => 'x456' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
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




# media playback after a delete

($sock_a, $sock_b) = new_call([qw(198.51.100.1 3020)], [qw(198.51.100.3 3022)]);

offer('media playback after delete', { ICE => 'remove', replace => ['origin'],
	'rtcp-mux' => ['demux'], 'via-branch' => 'xxxx', flags => ['strict-source', 'record-call'],
	'transport-protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3020 RTP/AVP 98 97 8 0 3 101
c=IN IP4 198.51.100.1
a=rtpmap:98 speex/16000
a=rtpmap:97 speex/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=sendrecv
a=ptime:20
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 98 97 8 0 3 101
c=IN IP4 203.0.113.1
a=rtpmap:98 speex/16000
a=rtpmap:97 speex/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

answer('media playback after delete', { replace => ['origin'], 'transport-protocol' => 'RTP/AVP',
	'rtcp-mux' => ['demux'], 'via-branch' => 'xxxx' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3022 RTP/AVP 8 0 3 101
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 3 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

rtpe_req('delete', 'media playback after delete', { 'from-tag' => ft() });

# new to-tag
new_tt();

offer('media playback after delete', { ICE => 'remove', replace => ['origin'],
	'transport-protocol' => 'transparent', flags => ['strict-source', 'record-call'],
	'rtcp-mux' => ['demux'], 'via-branch' => 'xxxx' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3020 RTP/AVP 98 97 8 0 3 101
c=IN IP4 198.51.100.1
a=rtpmap:98 speex/16000
a=rtpmap:97 speex/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=sendrecv
a=ptime:20
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 98 97 8 0 3 101
c=IN IP4 203.0.113.1
a=rtpmap:98 speex/16000
a=rtpmap:97 speex/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=direction:both
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

answer('media playback after delete', { replace => ['origin'], 'transport-protocol' => 'RTP/AVP',
	'rtcp-mux' => ['demux'], 'via-branch' => 'xxxx' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3022 RTP/AVP 8 0 101
c=IN IP4 198.51.100.3
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=direction:both
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8 0 101
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=direction:both
a=sendrecv
a=rtcp:PORT
a=ptime:20
SDP

#rtpe_req('block media', 'media playback after delete', { });

$resp = rtpe_req('play media', 'media playback after delete', { 'from-tag' => tt(), 'to-tag' => tt(),
		blob => $wav_file });
is $resp->{duration}, 100, 'media duration';

(undef, $seq, $ts, $ssrc) = rcv($sock_b, -1, rtpm(8 | 0x80, -1, -1, -1, $pcma_1));
rcv($sock_b, -1, rtpm(8, $seq + 1, $ts + 160 * 1, $ssrc, $pcma_2));
rcv($sock_b, -1, rtpm(8, $seq + 2, $ts + 160 * 2, $ssrc, $pcma_3));
rcv($sock_b, -1, rtpm(8, $seq + 3, $ts + 160 * 3, $ssrc, $pcma_4));
rcv($sock_b, -1, rtpm(8, $seq + 4, $ts + 160 * 4, $ssrc, $pcma_5));



# GH 1042

$resp = rtpe_req('statistics', 'statistics');


new_call;

offer('GH #1461', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
m=application 0 RTP/AVP 124
m=application 0 * 
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=application 0 RTP/AVP 124
c=IN IP4 0.0.0.0
m=application 0 * 
c=IN IP4 0.0.0.0
SDP

new_call;

offer('GH #1461', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
m=application 0 RTP/AVP 124
m=application 0 *
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
m=application 0 RTP/AVP 124
c=IN IP4 0.0.0.0
m=application 0 * 
c=IN IP4 0.0.0.0
SDP



new_call;

offer('MKI re-invite (GH #1474)', { DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AIdPArobTMNWc5AHzFZhl31S/mYjUdLFjBHiHD2r|1:32
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:l+ZCWtSLM0RvUvGhovOXXNxnJve4FOfL9ervJeYb|2:32
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AIdPArobTMNWc5AHzFZhl31S/mYjUdLFjBHiHD2r|1:32
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:l+ZCWtSLM0RvUvGhovOXXNxnJve4FOfL9ervJeYb|2:32
a=crypto:3 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:4 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:5 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:6 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:7 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:8 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP

offer('MKI re-invite (GH #1474)', { DTLS => 'off' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/SAVP 0
c=IN IP4 198.51.100.1
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AIdPArobTMNWc5AHzFZhl31S/mYjUdLFjBHiHD2r|1:32
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:l+ZCWtSLM0RvUvGhovOXXNxnJve4FOfL9ervJeYb|2:32
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/SAVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AIdPArobTMNWc5AHzFZhl31S/mYjUdLFjBHiHD2r|1:32
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:l+ZCWtSLM0RvUvGhovOXXNxnJve4FOfL9ervJeYb|2:32
a=crypto:3 AEAD_AES_256_GCM inline:CRYPTO256S
a=crypto:4 AEAD_AES_128_GCM inline:CRYPTO128S
a=crypto:5 AES_256_CM_HMAC_SHA1_80 inline:CRYPTO256
a=crypto:6 AES_256_CM_HMAC_SHA1_32 inline:CRYPTO256
a=crypto:7 AES_192_CM_HMAC_SHA1_80 inline:CRYPTO192
a=crypto:8 AES_192_CM_HMAC_SHA1_32 inline:CRYPTO192
a=crypto:9 F8_128_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:10 F8_128_HMAC_SHA1_32 inline:CRYPTO128
a=crypto:11 NULL_HMAC_SHA1_80 inline:CRYPTO128
a=crypto:12 NULL_HMAC_SHA1_32 inline:CRYPTO128
SDP



new_call;

($port_a) = offer('re-invite sendonly port change (control)', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0
----------------------------
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

($port_b) = offer('re-invite sendonly port change (control)', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2002 RTP/AVP 0
----------------------------
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

isnt($port_a, $port_b, 'port changed');



new_call;

($port_a) = offer('re-invite sendonly port change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0
----------------------------
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

($port_ax) = answer('re-invite sendonly port change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2010 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
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

($port_b) = offer('re-invite sendonly port change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2002 RTP/AVP 0
a=sendonly
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is($port_a, $port_b, 'port not changed');

($port_bx) = answer('re-invite sendonly port change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2012 RTP/AVP 0
c=IN IP4 198.51.100.3
a=recvonly
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=recvonly
a=rtcp:PORT
SDP

isnt($port_ax, $port_bx, 'port changed');

($port_b) = offer('re-invite sendonly port change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0
----------------------------
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

is($port_a, $port_b, 'original port');

($port_bx) = answer('re-invite sendonly port change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2010 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
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

is($port_ax, $port_bx, 'original port');

reverse_tags();

($port_bx) = offer('re-invite sendonly port change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2012 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendonly
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendonly
a=rtcp:PORT
SDP

is($port_ax, $port_bx, 'port unchanged');

($port_b) = answer('re-invite sendonly port change', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0
a=recvonly
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=recvonly
a=rtcp:PORT
SDP

is($port_a, $port_b, 'port unchanged');


# GH #1715
# for the `m=application` we just copy-paste original attributes
new_call;
offer('GH #1715', {ICE => 'remove', "transport-protocol" => "RTP/AVP"}, <<SDP);
v=0
o=sip:001011000000001\@ims.mnc001.mcc001.3gppnetwork.org 1611848049 1611848049 IN IP4 10.42.44.243
s=-
c=IN IP4 10.42.44.243
b=AS:41
b=RS:512
b=RR:1537
t=0 0
m=audio 30322 RTP/AVP 99 97 9 8 0 105 100
b=AS:41
b=RS:512
b=RR:1537
a=maxptime:240
a=des:qos mandatory local sendrecv
a=curr:qos local none
a=des:qos optional remote sendrecv
a=curr:qos remote none
a=rtpmap:99 AMR-WB/16000
a=fmtp:99 mode-set=0,1,2,5,7,8; max-red=0; mode-change-capability=2
a=rtpmap:97 AMR/8000
a=fmtp:97 mode-set=0,2,5,7; max-red=0; mode-change-capability=2
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:105 telephone-event/16000
a=fmtp:105 0-15
a=rtpmap:100 telephone-event/8000
a=fmtp:100 0-15
a=sendrecv
a=rtcp:30323
a=ptime:20
m=application 52718 UDP/DTLS/SCTP webrtc-datachannel
b=AS:500
a=max-message-size:1024
a=sctp-port:5000
a=setup:passive
a=fingerprint:SHA-1 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB
a=tls-id: abc3de65cddef001be82
a=dcmap:10 subprotocol="http"
a=dcmap:38754 max-time=150;label="low latency"
a=dcmap:7216 max-retr=5;label="low loss"
a=3gpp-qos-hint:loss=0.01;latency=100
-------------------------------
v=0
o=sip:001011000000001\@ims.mnc001.mcc001.3gppnetwork.org 1611848049 1611848049 IN IP4 10.42.44.243
s=-
b=AS:41
b=RR:1537
b=RS:512
t=0 0
m=audio PORT RTP/AVP 99 97 9 8 0 105 100
c=IN IP4 203.0.113.1
b=AS:41
b=RR:1537
b=RS:512
a=rtpmap:99 AMR-WB/16000
a=fmtp:99 mode-set=0,1,2,5,7,8; max-red=0; mode-change-capability=2
a=rtpmap:97 AMR/8000
a=fmtp:97 mode-set=0,2,5,7; max-red=0; mode-change-capability=2
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:105 telephone-event/16000
a=fmtp:105 0-15
a=rtpmap:100 telephone-event/8000
a=fmtp:100 0-15
a=des:qos mandatory local sendrecv
a=curr:qos local none
a=des:qos optional remote sendrecv
a=curr:qos remote none
a=sendrecv
a=rtcp:PORT
a=ptime:20
a=maxptime:240
m=application PORT UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 203.0.113.1
b=AS:500
a=max-message-size:1024
a=sctp-port:5000
a=setup:passive
a=fingerprint:SHA-1 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB
a=tls-id: abc3de65cddef001be82
a=dcmap:10 subprotocol="http"
a=dcmap:38754 max-time=150;label="low latency"
a=dcmap:7216 max-retr=5;label="low loss"
a=3gpp-qos-hint:loss=0.01;latency=100
SDP


# a=rtcp-fb:*

new_call;

offer('rtcp-fb', { codec => { strip => ['PCMA'] } }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0 8
c=IN IP4 198.51.100.1
a=rtcp-fb:* foobar
a=rtcp-fb:0 blah
a=rtcp-fb:8 quux
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtcp-fb:0 blah
a=rtcp-fb:* foobar
a=sendrecv
a=rtcp:PORT
SDP




# a=rtcp-fb with RTP/AVP

($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.55 2412)], [qw(198.51.100.55 2413)], [qw(198.51.100.55 3412)], [qw(198.51.100.55 3413)]);

($port_a, $port_ax) = offer('rtcp-fb with RTP/AVP - control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.55
t=0 0
m=audio 2412 RTP/AVPF 0
a=rtcp-fb:0 foobar
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVPF 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtcp-fb:0 foobar
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('rtcp-fb with RTP/AVP - control', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.55
t=0 0
m=audio 3412 RTP/AVPF 0
a=rtcp-fb:* foobar
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVPF 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtcp-fb:* foobar
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_ax, $port_bx, "\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01");
rcv($sock_bx, $port_ax, qr/^\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01$/s);

snd($sock_bx, $port_ax, "\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01");
rcv($sock_ax, $port_bx, qr/^\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01$/s);




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.55 2420)], [qw(198.51.100.55 2421)], [qw(198.51.100.55 3420)], [qw(198.51.100.55 3421)]);

($port_a, $port_ax) = offer('rtcp-fb with RTP/AVP - control 2', { 'transport protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.55
t=0 0
m=audio 2420 RTP/AVPF 0
a=rtcp-fb:0 foobar
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtcp-fb:0 foobar
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('rtcp-fb with RTP/AVP - control 2', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.55
t=0 0
m=audio 3420 RTP/AVP 0
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVPF 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_ax, $port_bx, "\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01");
rcv($sock_bx, $port_ax, qr/^\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00$/s);

snd($sock_bx, $port_ax, "\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01");
rcv($sock_ax, $port_bx, qr/^\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01$/s);



($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.55 2436)], [qw(198.51.100.55 2437)], [qw(198.51.100.55 3436)], [qw(198.51.100.55 3437)]);

($port_a, $port_ax) = offer('rtcp-fb with RTP/AVP', { 'transport protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.55
t=0 0
m=audio 2436 RTP/AVPF 0
a=rtcp-fb:0 foobar
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtcp-fb:0 foobar
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('rtcp-fb with RTP/AVP', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.55
t=0 0
m=audio 3436 RTP/AVP 0
a=rtcp-fb:* foobar
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVPF 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtcp-fb:* foobar
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_ax, $port_bx, "\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01");
rcv($sock_bx, $port_ax, qr/^\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01$/s);

snd($sock_bx, $port_ax, "\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01");
rcv($sock_ax, $port_bx, qr/^\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01$/s);




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.55 2444)], [qw(198.51.100.55 2445)], [qw(198.51.100.55 3444)], [qw(198.51.100.55 3445)]);

($port_a, $port_ax) = offer('rtcp-fb with RTP/AVP t2', { 'transport protocol' => 'RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.55
t=0 0
m=audio 2444 RTP/AVPF 0
a=rtcp-fb:* foobar
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtcp-fb:* foobar
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('rtcp-fb with RTP/AVP t2', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.55
t=0 0
m=audio 3444 RTP/AVP 0
a=rtcp-fb:* foobar
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVPF 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtcp-fb:* foobar
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_ax, $port_bx, "\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01");
rcv($sock_bx, $port_ax, qr/^\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01$/s);

snd($sock_bx, $port_ax, "\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01");
rcv($sock_ax, $port_bx, qr/^\x80\xc8\x00\x06\x69\x28\x80\x8c\xe9\x71\x56\xff\xcc\x1e\x68\xa0\x8a\xe2\x10\xa2\x00\x00\x01\x40\x00\x03\x9d\x3a\x81\xca\x00\x06\x69\x28\x80\x8c\x01\x10\x4f\x56\x67\x71\x68\x49\x64\x72\x79\x6f\x41\x32\x47\x74\x77\x6a\x00\x00\x8f\xce\x00\x05\x69\x28\x80\x8c\x00\x00\x00\x00\x52\x45\x4d\x42\x01\x13\x5d\x5a\x6b\x30\x8f\x01$/s);






offer('webrtc', { flags => ['WebRTC'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
c=IN IP4 198.51.100.1
t=0 0
m=audio 2000 RTP/AVP 0 8
----------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT UDP/TLS/RTP/SAVPF 0 8
c=IN IP4 203.0.113.1
a=mid:1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp-mux
a=setup:actpass
a=fingerprint:sha-256 FINGERPRINT256
a=tls-id:TLS_ID
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=ice-options:trickle
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=end-of-candidates
SDP

new_call;

$resp = rtpe_req('offer', 'SDP with just \n', { 'from-tag' => ft(), SDP => "v=0\no=- 1545997027 1 IN IP4 198.51.101.40\ns=tester\nt=0 0\nm=audio 3000 RTP/AVP 0 8\nc=IN IP4 198.51.100.1\na=foobar\n" } );
like($resp->{sdp}, qr/\r\na=foobar\r\na=sendrecv\r\na=rtcp:\d+\r\n$/s, 'SDP matches');

new_call;

$resp = rtpe_req('offer', 'non-terminated SDP', { 'from-tag' => ft(), SDP => "v=0\r\no=- 1545997027 1 IN IP4 198.51.101.40\r\ns=tester\r\nt=0 0\r\nm=audio 3000 RTP/AVP 0 8\r\nc=IN IP4 198.51.100.1\r\na=foobar" } );
like($resp->{sdp}, qr/\r\na=foobar\r\na=sendrecv\r\na=rtcp:\d+\r\n$/s, 'SDP matches');

new_call;

$resp = rtpe_req('offer', 'blank line in SDP', { 'from-tag' => ft(), SDP => "v=0\r\no=- 1545997027 1 IN IP4 198.51.101.40\r\ns=tester\r\nt=0 0\r\nm=audio 3000 RTP/AVP 0 8\r\nc=IN IP4 198.51.100.1\r\na=foobar\r\n\r\na=quux\r\n" } );
like($resp->{sdp}, qr/\r\na=foobar\r\na=sendrecv\r\na=rtcp:\d+\r\n$/s, 'SDP matches');


new_call;

offer('allow-no-codec-media control', {
		codec => { strip => ['all'], except => ['PCMA'] },
	}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 8
c=IN IP4 198.51.100.1
a=rtpmap:8 PCMA/8000
a=sendrecv
m=video 3000 RTP/AVP 97
c=IN IP4 198.51.100.1
a=rtpmap:97 H264/90000
a=fmtp:97 profile-level-id=428016;packetization-mode=0;max-mbps=490000;max-fs=8160;max-cpb=200;max-dpb=16320;max-br=5000;max-smbps=490000;max-fps=6000
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
m=video PORT RTP/AVP 97
c=IN IP4 203.0.113.1
a=rtpmap:97 H264/90000
a=fmtp:97 profile-level-id=428016;packetization-mode=0;max-mbps=490000;max-fs=8160;max-cpb=200;max-dpb=16320;max-br=5000;max-smbps=490000;max-fps=6000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('allow-no-codec-media control', {
		codec => { strip => ['all'], except => ['PCMA'] },
		flags => ['allow no codec media'],
	}, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 8
c=IN IP4 198.51.100.1
a=rtpmap:8 PCMA/8000
a=sendrecv
m=video 3000 RTP/AVP 97
c=IN IP4 198.51.100.1
a=rtpmap:97 H264/90000
a=fmtp:97 profile-level-id=428016;packetization-mode=0;max-mbps=490000;max-fs=8160;max-cpb=200;max-dpb=16320;max-br=5000;max-smbps=490000;max-fps=6000
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
m=video 0 RTP/AVP 0
c=IN IP4 0.0.0.0
SDP



#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
