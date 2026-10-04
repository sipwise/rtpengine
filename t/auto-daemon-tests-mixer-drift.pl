#!/usr/bin/perl

# Detect growing content age through permanent mixers, allowing their fixed input DTX delay.
# Two AMR-WB sources send uniquely identifiable speech bursts, SID frames and no-data gaps.
# Decode the actual AMR-WB phone outputs as well as per-source L16 reference taps.

use strict;
use warnings;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);
use IO::Select;
use FindBin;
use File::Temp qw(tempdir);
use File::Path qw(make_path);

plan skip_all => 'enable RTPENGINE_EXTENDED_TESTS for the 84-second AMR-WB content-age test'
	unless $ENV{RTPENGINE_EXTENDED_TESTS};

my $ffmpeg = $ENV{RTPENGINE_TEST_FFMPEG} // 'ffmpeg';
my $fixture_dir = "$FindBin::Bin/../fixtures/mixer-drift";
my $directory = $ENV{RTPENGINE_MIXER_DRIFT_ARTIFACTS} // tempdir(CLEANUP => 1);
make_path($directory);
my @amr_bytes = (17,23,32,36,40,46,50,58,60,5,0,0,0,0,0,0);
my $profiles = decode_json(read_file("$fixture_dir/profiles.json"));

# Query capabilities before producing TAP assertions, so missing optional codecs are explicit skips.
sub command_output {
	my (@command) = @_;
	open(my $pipe, '-|', @command) or return undef;
	local $/;
	my $text = <$pipe>;
	return close($pipe) ? $text : undef;
}

my $capabilities = command_output($ENV{RTPE_BIN}, '--config-file=none', '--codecs');
BAIL_OUT('cannot query test daemon codec capabilities') unless defined $capabilities;
plan skip_all => 'requires full AMR-WB encoding and decoding support'
	unless $capabilities =~ /^\s*AMR-WB:\s+fully supported/m;
my $decoders = command_output($ffmpeg, '-hide_banner', '-decoders');
plan skip_all => 'requires ffmpeg with an AMR-WB reference decoder'
	unless defined $decoders && $decoders =~ /^\s*A\S*\s+(?:amrwb|libopencore_amrwb)\s/m;

# Read a complete binary fixture or captured PCM file.
sub read_file {
	my ($path) = @_;
	open(my $file, '<:raw', $path) or die "cannot read $path: $!";
	local $/;
	return <$file>;
}

# Recover transmitted frames and their media positions; FT=15 advances time without an RTP packet.
sub amr_packets {
	my ($data) = @_;
	die 'invalid AMR-WB storage header' unless substr($data,0,9) eq "#!AMR-WB\n";
	my ($offset,$frame,$silence) = (9,0,1);
	my @packets;
	while ($offset < length($data)) {
		my $ft = (ord(substr($data,$offset,1)) >> 3) & 15;
		die "unexpected AMR-WB frame type $ft" unless $ft <= 9 || $ft == 15;
		my $length = 1 + $amr_bytes[$ft];
		die 'truncated AMR-WB fixture' if $offset+$length > length($data);
		# RFC 4867 section 4.1: only the first speech frame after silence has M=1.
		my $marker = $ft <= 8 && $silence;
		$silence = $ft >= 9 ? 1 : 0;
		push @packets, {frame=>$frame,body=>substr($data,$offset,$length),marker=>$marker}
			unless $ft == 15;
		$offset += $length;
		$frame++;
	}
	return \@packets;
}

# An ordered sample's median keeps the calibration insensitive to one timing outlier.
sub median {
	my @values = sort {$a <=> $b} @_;
	die 'empty median' unless @values;
	return $values[int(@values/2)] if @values % 2;
	return ($values[@values/2-1]+$values[@values/2])/2;
}

# Find the first four consecutive frames carrying each known, unique speech frequency.
# Analysis runs after collection and call deletion so it cannot hold up media reception.
sub marker_times {
	my ($packets,$pcm,$profile) = @_;
	my @coefficients = map {2*cos(2*3.141592653589793*$_->{frequency}/16000)} @{$profile->{bursts}};
	my (%first,$last,$run,$start);
	for my $n (0..$#$packets) {
		my @samples = unpack('s<320', substr($pcm,640*$n,640));
		my $energy = 0;
		$energy += $_*$_ for @samples;
		my ($best,$power) = (undef,0);
		if ($energy/320 > 200*200) {
			for my $i (0..$#coefficients) {
				my $age = $packets->[$n]{time}-$profile->{bursts}[$i]{start};
				next if $age < -0.05 || $age > 6;
				my ($a,$b) = (0,0);
				my $c = $coefficients[$i];
				for my $sample (@samples) {($a,$b) = ($sample+$c*$a-$b,$a);}
				my $value = $a*$a+$b*$b-$c*$a*$b;
				($best,$power) = ($i,$value) if $value > $power;
			}
			undef $best if $power/(320*$energy) < 0.15;
		}
		if (defined $best && defined $last && $best == $last) {$run++;}
		else {($last,$run,$start) = ($best,1,$packets->[$n]{time});}
		$first{$best} //= $start if defined $best && $run >= 4;
	}
	return \%first;
}

# Decode complete octet-aligned AMR-WB RTP payloads using the external reference decoder.
sub decode_phone {
	my ($packets,$name) = @_;
	open(my $awb, '>:raw', "$directory/$name.awb") or die $!;
	print {$awb} "#!AMR-WB\n";
	for my $packet (@$packets) {
		my $body = $packet->{body};
		die 'short AMR-WB output' if length($body) < 2;
		my $toc = ord(substr($body,1,1));
		my $ft = ($toc >> 3) & 15;
		die 'unexpected multi-frame AMR-WB output' if $toc & 0x80;
		die 'invalid AMR-WB payload length' unless length($body) == 2+$amr_bytes[$ft];
		print {$awb} chr($toc & 0x7c),substr($body,2);
	}
	close($awb);
	my $status = system($ffmpeg,'-v','error','-y','-f','amr','-i',"$directory/$name.awb",
		'-f','s16le','-ar','16000','-ac','1',"$directory/$name.s16");
	die 'reference AMR-WB decoder failed; no content-age conclusion' if $status;
	return read_file("$directory/$name.s16");
}

my @input;
for my $profile (@$profiles) {
	my $data = read_file("$fixture_dir/$profile->{file}");
	is(sha256_hex($data),$profile->{sha256},'synthetic AMR-WB fixture checksum');
	push @input, amr_packets($data);
}

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -n 2223 -f -L 7 -E
	--audio-player=always --dtx-delay=50 --max-dtx=10), @ARGV) or die;
my @tags = qw(phone-a phone-b capture-a capture-b);
my @sockets = new_call(map {['198.51.100.10',5000+2*$_]} 0..3);
my (@ports,@captures,@raw);
for my $i (0..3) {
	my ($codec,$pt) = $i < 2 ? ('AMR-WB/16000',96) : ('L16/16000/1',97);
	my $sdp = "v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=mixer content age\r\nt=0 0\r\n"
		. "c=IN IP4 198.51.100.10\r\nm=audio " . (5000+2*$i) . " RTP/AVP $pt\r\n"
		. "a=rtpmap:$pt $codec\r\n" . ($i < 2 ? "a=fmtp:96 octet-align=1\r\n" : '')
		. "a=sendrecv\r\n";
	my $response = rtpe_req('publish',"publish $tags[$i]",{
		'from-tag'=>$tags[$i],sdp=>$sdp,flags=>['bidirectional'],'audio-player'=>'always',
	});
	($ports[$i]) = $response->{sdp} =~ /m=audio (\d+)/;
	ok($ports[$i],"$tags[$i] media port negotiated");
	my $mapping = $i < 2 ? 'AMR-WB/16000' : 'L16/16000';
	like($response->{sdp},qr{a=rtpmap:$pt \Q$mapping\E(?:/1)?\r?\n},"$tags[$i] codec negotiated");
	open(my $raw,'>:raw',"$directory/$tags[$i].rtp") or die $!;
	push @raw,$raw;
	push @captures,[];
}
rtpe_req('mesh','two AMR-WB phones with per-source L16 taps',{
	calls=>[cid()],flags=>['unsubscribe'],
	tags=>[{from=>'phone-a',to=>['phone-b','capture-a']},
		   {from=>'phone-b',to=>['phone-a','capture-b']}],
});
my $selector = IO::Select->new(@sockets);
my %endpoint = map {fileno($sockets[$_])=>$_} 0..3;
my @next = (0,0);
my @sequence = (100,200);
my @sent = ({},{});
my @max_lateness = (0,0);
my $started = clock_gettime(CLOCK_MONOTONIC);
open(my $sent_log,'>',"$directory/sent.csv") or die $!;
print {$sent_log} "source,frame,scheduled,actual\n";
while (clock_gettime(CLOCK_MONOTONIC)-$started < $profiles->[0]{duration}+4) {
	for my $i (0..1) {
		while ($next[$i] < @{$input[$i]}) {
			my $frame = $input[$i][$next[$i]];
			my $planned = $frame->{frame}*0.02
				+ $profiles->[$i]{jitter_amplitude}*sin($frame->{frame}*$profiles->[$i]{jitter_step});
			last if $planned > clock_gettime(CLOCK_MONOTONIC)-$started;
			snd($sockets[$i],$ports[$i],rtp(96 | ($frame->{marker} ? 0x80 : 0),
				$sequence[$i]++,100000+$frame->{frame}*320,
				0x11110000+$i,"\xf0".$frame->{body}));
			my $actual = clock_gettime(CLOCK_MONOTONIC)-$started;
			$sent[$i]{$frame->{frame}} = $actual;
			my $late = $actual-$planned;
			$max_lateness[$i] = $late if $late > $max_lateness[$i];
			print {$sent_log} join(',',$i,$frame->{frame},$planned,$actual),"\n";
			$next[$i]++;
		}
	}
	for my $socket ($selector->can_read(0.001)) {
		my $packet;
		$socket->recv($packet,65535);
		my $time = clock_gettime(CLOCK_MONOTONIC)-$started;
		my $i = $endpoint{fileno($socket)};
		print {$raw[$i]} pack('d>N',$time,length($packet)),$packet;
		next if length($packet) < 12;
		my ($header,$pt,$seq,$ts,$ssrc) = unpack('CCnNN',$packet);
		next unless ($pt & 127) == ($i < 2 ? 96 : 97);
		die 'unexpected RTP header in marker capture' unless $header == 0x80;
		push @{$captures[$i]}, {time=>$time,seq=>$seq,ts=>$ts,ssrc=>$ssrc,body=>substr($packet,12)};
	}
}
close($sent_log);
close($_) for @raw;
rtpe_req('delete','mixer drift cleanup',{});
open(my $log,'>',"$directory/daemon.log") or die $!;
print {$log} rtpe_log(); close($log);

# The latency oracle is valid only if the test delivered its bounded-jitter inputs on time.
for my $i (0..1) {
	diag(sprintf('source %d: %d packets; maximum sender lateness %.3f ms',
		$i,$next[$i],$max_lateness[$i]*1000));
	is($next[$i],scalar(@{$input[$i]}),"source $i complete speech/SID trace sent");
	cmp_ok($max_lateness[$i],'<',0.02,"source $i pacing stayed within 20-ms validity bound");
}
my @results;
for my $i (0..3) {
	my $source = ($i == 0 || $i == 3) ? 1 : 0;
	my $packets = $captures[$i];
	cmp_ok(scalar(@$packets),'>',100,"$tags[$i] receives RTP");
	next unless @$packets;
	my ($seq_errors,$ts_errors) = (0,0);
	my %ssrcs;
	for my $n (0..$#$packets) {
		$ssrcs{$packets->[$n]{ssrc}}++;
		next unless $n && $packets->[$n]{ssrc} == $packets->[$n-1]{ssrc};
		$seq_errors++ if (($packets->[$n]{seq}-$packets->[$n-1]{seq}) & 0xffff) != 1;
		$ts_errors++ if (($packets->[$n]{ts}-$packets->[$n-1]{ts}) & 0xffffffff) != 320;
	}
	is(scalar(keys %ssrcs),1,"$tags[$i] uses one output SSRC");
	is($seq_errors,0,"$tags[$i] output sequence stays continuous");
	is($ts_errors,0,"$tags[$i] output RTP clock stays continuous");
	my $pcm = $i < 2 ? decode_phone($packets,$tags[$i])
		: join('',map {pack('s<*',unpack('s>*',$_->{body}))} @$packets);
	is(length($pcm),640*@$packets,"$tags[$i] decoded PCM matches captured packet count");
	next unless length($pcm) == 640*@$packets;
	my $detected = marker_times($packets,$pcm,$profiles->[$source]);
	my @lags;
	my @markers;
	for my $n (0..$#{$profiles->[$source]{bursts}}) {
		my $burst = $profiles->[$source]{bursts}[$n];
		my $input_time = $sent[$source]{int($burst->{start}*50+0.5)};
		my $lag = defined $detected->{$n} && defined $input_time ? $detected->{$n}-$input_time : undef;
		push @markers,{marker=>$n,input=>$input_time,output=>$detected->{$n},lag=>$lag};
		push @lags,$lag if defined $lag;
	}
	is(scalar(@lags),scalar(@{$profiles->[$source]{bursts}}),"$tags[$i] receives every distinct speech marker");
	next unless @lags == @{$profiles->[$source]{bursts}};
	my $baseline = median(@lags[0..2]);
	my $worst = $baseline;
	for my $n (2..$#lags) {
		my $m = median(@lags[$n-2..$n]);
		$worst = $m if $m > $worst;
	}
	my $late = median(@lags[$#lags-2..$#lags]);
	my $growth = $worst-$baseline;
	diag(sprintf('%s: initial median %.1f ms, final median %.1f ms, worst sustained median %.1f ms, growth %.1f ms',
		$tags[$i],1000*$baseline,1000*$late,1000*$worst,1000*$growth));
	SKIP: {
		skip 'invalid sender pacing: content-age growth cannot be attributed to the daemon',1
			if grep {$_ >= 0.02} @max_lateness;
		# Allow 250 ms above measured initial latency: fixed DTX and codec delays cancel.
		cmp_ok($growth,'<',0.25,"$tags[$i] content age does not grow by 250 ms");
	}
	push @results,{endpoint=>$tags[$i],source=>$source,initial=>$baseline,final=>$late,
		worst=>$worst,growth=>$growth,markers=>\@markers,sequence_errors=>$seq_errors,timestamp_errors=>$ts_errors};
}
open(my $results,'>',"$directory/results.json") or die $!;
print {$results} JSON::PP->new->canonical->pretty->encode(\@results);
close($results);
diag("synthetic packet, marker and decoder evidence: $directory") if $ENV{RTPENGINE_MIXER_DRIFT_ARTIFACTS};
done_testing();
