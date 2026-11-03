#!/usr/bin/perl

# Reconstruct conference admission and private playback before measuring live audio age.
# Two AMR-WB phones feed an Opus browser and a shared L16 recording endpoint.

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

plan skip_all => 'enable RTPENGINE_EXTENDED_TESTS for the conference admission test'
	unless $ENV{RTPENGINE_EXTENDED_TESTS};

my $ffmpeg = $ENV{RTPENGINE_TEST_FFMPEG} // 'ffmpeg';
my $fixture_dir = "$FindBin::Bin/../fixtures/mixer-drift";
my $directory = $ENV{RTPENGINE_MIXER_DRIFT_ARTIFACTS}
	// $ENV{RTPENGINE_CONFERENCE_LATENCY_ARTIFACTS} // tempdir(CLEANUP => 1);
make_path($directory);
my @amr_bytes = (17,23,32,36,40,46,50,58,60,5,0,0,0,0,0,0);
my $profiles = decode_json(read_file("$fixture_dir/profiles.json"));

# Query capabilities before producing TAP assertions, so missing optional codecs are explicit skips.
sub command_output {
	my (@command) = @_;
	open(my $pipe, '-|', @command) or return;
	local $/ = undef;
	my $text = <$pipe>;
	return close($pipe) ? $text : undef;
}

my $capabilities = command_output($ENV{RTPE_BIN}, '--config-file=none', '--codecs');
BAIL_OUT('cannot query test daemon codec capabilities') unless defined $capabilities;
plan skip_all => 'requires full AMR-WB encoding and decoding support'
	unless $capabilities =~ /^\s*AMR-WB:\s+fully supported/m;
plan skip_all => 'requires full Opus encoding and decoding support'
	unless $capabilities =~ /^\s*opus:\s+fully supported/m;
my $decoders = command_output($ffmpeg, '-hide_banner', '-decoders');
plan skip_all => 'requires ffmpeg with an AMR-WB reference decoder'
	unless defined $decoders && $decoders =~ /^\s*A\S*\s+(?:amrwb|libopencore_amrwb)\s/m;
plan skip_all => 'requires ffmpeg with an Opus reference decoder'
	unless $decoders =~ /^\s*A\S*\s+(?:opus|libopus)\s/m;

# Read a complete binary fixture or captured PCM file.
sub read_file {
	my ($path) = @_;
	open(my $file, '<:raw', $path) or die "cannot read $path: $!";
	local $/ = undef;
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
				my ($A,$B) = (0,0);
				my $C = $coefficients[$i];
				for my $sample (@samples) {($A,$B) = ($sample+$C*$A-$B,$A);}
				my $value = $A*$A+$B*$B-$C*$A*$B;
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


# Make synthetic private prompt media without adding a recorded-voice fixture.
sub prompt_wav {
	my ($seconds, $frequency) = @_;
	my $pcm = join('',map {pack('s<',10000*sin(2*3.141592653589793*$frequency*$_/16000))}
		0..int(16000*$seconds)-1);
	return 'RIFF'.pack('V',36+length($pcm)).'WAVEfmt '.pack('VvvVVvv',16,1,1,16000,32000,2,16)
		.'data'.pack('V',length($pcm)).$pcm;
}

# Write one Ogg page per packet so FFmpeg can independently decode captured Opus RTP.
sub ogg_page {
	my ($packet,$sequence,$granule,$flags) = @_;
	my @lacing = ((255) x int(length($packet)/255),length($packet)%255);
	my $page = 'OggS'.pack('CCQ<VVV C',0,$flags,$granule,1,$sequence,0,scalar(@lacing))
		.pack('C*',@lacing).$packet;
	my $crc = 0;
	for my $byte (unpack('C*',$page)) {
		$crc ^= $byte << 24;
		for (1..8) {$crc = (($crc << 1) ^ (($crc & 0x80000000) ? 0x04c11db7 : 0)) & 0xffffffff;}
	}
	substr($page,22,4,pack('V',$crc));
	return $page;
}

# Count decoded frames containing the private prompt's known frequency.
sub prompt_frames {
	my ($packets,$pcm) = @_;
	my $coefficient=2*cos(2*3.141592653589793*3000/16000);
	my $frames=0;
	for my $n (0..$#$packets) {
		next unless $packets->[$n]{time}>2 && $packets->[$n]{time}<8;
		my @samples=unpack('s<320',substr($pcm,640*$n,640));
		my ($A,$B,$energy)=(0,0,0);
		for my $sample (@samples) {($A,$B)=($sample+$coefficient*$A-$B,$A);$energy+=$sample*$sample;}
		$frames++ if $energy>320*200*200
			&& ($A*$A+$B*$B-$coefficient*$A*$B)/(320*$energy)>.2;
	}
	return $frames;
}

# Decode the browser's real Opus output, including its algorithmic delay in observed age.
sub decode_browser {
	my ($packets) = @_;
	open(my $ogg,'>:raw',"$directory/browser.ogg") or die $!;
	print {$ogg} ogg_page('OpusHead'.pack('CCvVvC',1,2,0,48000,0,0),0,0,2);
	print {$ogg} ogg_page('OpusTags'.pack('VV',0,0),1,0,0);
	for my $n (0..$#$packets) {
		print {$ogg} ogg_page($packets->[$n]{body},$n+2,960*($n+1),$n==$#$packets ? 4 : 0);
	}
	close($ogg);
	my $status = system($ffmpeg,'-v','error','-y','-i',"$directory/browser.ogg",
		'-f','s16le','-ar','16000','-ac','1',"$directory/browser.s16");
	die 'reference Opus decode failed' if $status;
	return read_file("$directory/browser.s16");
}

# Build an answer for a created endpoint, keeping the engine-selected payload identifier.
sub endpoint_sdp {
	my ($i,$destination) = @_;
	my $codec = $i<2 ? 'AMR-WB/16000' : 'L16/16000/1';
	return "v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=conference admission\r\nt=0 0\r\n"
		."c=IN IP4 198.51.100.10\r\nm=audio $destination RTP/AVP 96\r\na=rtpmap:96 $codec\r\n"
		.($i<2 ? "a=fmtp:96 octet-align=1; mode-set=0,1,2\r\n" : '')."a=sendrecv\r\n";
}

my $duration = $ENV{RTPENGINE_MIXER_DRIFT_DURATION} // 180;
die 'RTPENGINE_MIXER_DRIFT_DURATION must be an integer of at least 180 seconds'
	unless $duration =~ /^\d+$/ && $duration >= 180;
my (@cycle_starts, @silence_intervals);
for (my $start = 0; $start < $duration; $start += 80) {
	push @cycle_starts, $start;
	# Exercise speech resumption after both an early and a later SID-only interval.
	if (@cycle_starts == 1 || @cycle_starts == 5) {
		push @silence_intervals, [$start + 80, $start + 100];
		$start += 20;
	}
}
my @input;
my @offset = (0.33,0.63);
for my $source (0..1) {
	my $profile = $profiles->[$source];
	my $data = read_file("$fixture_dir/$profile->{file}");
	is(sha256_hex($data),$profile->{sha256},'synthetic AMR-WB fixture checksum');
	my $original = amr_packets($data);
	my @packets;
	my @bursts = @{$profile->{bursts}};
	# Repeat the speech/SID trace while keeping RTP clocks continuous through long silences.
	for my $shift (@cycle_starts) {
		push @packets,map {({%$_,frame=>$_->{frame}+50*$shift})} @$original;
	}
	my ($sid) = reverse grep {((ord(substr($_->{body},0,1)) >> 3) & 15)==9} @$original;
	die 'fixture has no SID' unless $sid;
	for my $interval (@silence_intervals) {
		push @packets,map {{frame=>50*$interval->[0]+8*$_,body=>$sid->{body},marker=>0}} 0..124;
	}
	@packets = sort {$a->{frame}<=>$b->{frame}} grep {
		$_->{frame}*.02+$offset[$source]+$profile->{jitter_amplitude}<$duration
	} @packets;
	$profile->{bursts} = [grep {$_->{end}<$duration} map {my $shift=$_;map {({%$_,start=>$_->{start}+$shift+$offset[$source],
		end=>$_->{end}+$shift+$offset[$source]})} @bursts} @cycle_starts];
	push @input,\@packets;
}
my $chirp = prompt_wav(0.7,3100);
my $welcome = prompt_wav(7.5,3000);
for my $entry (['chirp',$chirp],['welcome',$welcome]) {
	open(my $wav,'>:raw',"$directory/$entry->[0].wav") or die $!;
	print {$wav} $entry->[1];close($wav);
}
autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -n 2223 -f -L 7 -E
	--dtx-delay=50 --max-dtx=30 --audio-buffer-length=500 --audio-buffer-delay=5),@ARGV) or die;
my @tags = qw(phone-a phone-b browser room-capture);
my @sockets = new_call(map {['198.51.100.10',5000+2*$_]} 0..4);
my (@ports,@captures,@raw);
for my $i (0,1,3) {
	my $codec = $i<2 ? 'AMR-WB/16000' : 'L16/16000/1';
	my $response = rtpe_req('create',"create $tags[$i] before admission",{
		'from-tag'=>$tags[$i],'audio-player'=>'always',flags=>["codec-offer-$codec"],
	});
	($ports[$i]) = $response->{sdp}=~/m=audio (\d+)/;
	my $mapping=$i<2?'AMR-WB/16000':'L16/16000';
	like($response->{sdp},qr/a=rtpmap:96 \Q$mapping\E(?:\/1)?\r?\n/,"$tags[$i] codec negotiated");
}
rtpe_req('publish','existing Opus browser',{'from-tag'=>'browser','audio-player'=>'always',
	flags=>['bidirectional'],sdp=>"v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=browser\r\nt=0 0\r\n"
	."c=IN IP4 198.51.100.10\r\nm=audio 5004 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\na=sendrecv\r\n"});
rtpe_req('create answer','initial discard capture',{'from-tag'=>'room-capture',
	'audio-player'=>'always',sdp=>endpoint_sdp(3,5008)});
# Start from the established capture, avoiding unsubscribe of a fresh phone publication.
sub join_mesh {
	my ($joining) = @_;
	my @edges = ({from=>'browser',to=>[$joining,'room-capture']},
		{from=>'room-capture',to=>[$joining]});
	if ($joining eq 'phone-b') {
		$edges[0]{to} = ['phone-a','phone-b','room-capture'];
		push @edges,{from=>'phone-a',to=>['phone-b','room-capture']};
	}
	rtpe_req('mesh',"admit $joining with fresh-tag-safe topology",{
		calls=>[cid()],flags=>['unsubscribe','bidirectional'],tags=>\@edges});
}
my @events;
# Times mirror the recovered move/control log relative to the two phone creates.
for my $i (0..1) {
	my $source=$i;
	push @events,[$offset[$i],sub {
		rtpe_req('create answer',"answer $tags[$source]",{'from-tag'=>$tags[$source],
			'audio-player'=>'always',sdp=>endpoint_sdp($source,5000+2*$source)});
		join_mesh($tags[$source]);
	}];
}
push @events,[0.335,sub {rtpe_req('create answer','attach room recorder during admission',{
	'from-tag'=>'room-capture','audio-player'=>'always',sdp=>endpoint_sdp(3,5006)});}];
push @events,[0.635,sub {rtpe_req('create answer','refresh recorder after second answer',{
	'from-tag'=>'room-capture','audio-player'=>'always',sdp=>endpoint_sdp(3,5006)});}];
for my $spec ([0.64,0,'chirp',700],[1.34,0,'welcome',7500],[1.64,1,'welcome',7500],[9.14,1,'chirp',700]) {
	my ($at,$i,$blob,$duration)=@$spec;
	push @events,[$at,sub {
		my $response=rtpe_req('play media',"private prompt to $tags[$i] while RTP continues",{
			'from-tag'=>$tags[$i],file=>"$directory/$blob.wav",flags=>['block egress'],'repeat-times'=>1});
		is($response->{duration},$duration,'private prompt duration');
	}];
}
@events=sort {$a->[0]<=>$b->[0]} @events;
for my $i (0..3) {
	open(my $file,'>:raw',"$directory/$tags[$i].rtp") or die $!;
	push @raw,$file;push @captures,[];
}
open(my $sent_log,'>',"$directory/sent.csv") or die $!;
print {$sent_log} "source,frame,scheduled,actual\n";
my $selector=IO::Select->new(@sockets);
my %endpoint=map {fileno($sockets[$_])=>$_} 0..4;
my @next=(0,0);my @sequence=(100,200);my @sent=({},{});my @max_lateness=(0,0);
my @event_log;
my $started=clock_gettime(CLOCK_MONOTONIC);
while (clock_gettime(CLOCK_MONOTONIC)-$started<$duration+4) {
	for my $i (0..1) {
		while ($next[$i]<@{$input[$i]} && defined $ports[$i]) {
			my $frame=$input[$i][$next[$i]];
			my $planned=$offset[$i]+$frame->{frame}*0.02
				+$profiles->[$i]{jitter_amplitude}*sin($frame->{frame}*$profiles->[$i]{jitter_step});
			last if $planned>clock_gettime(CLOCK_MONOTONIC)-$started;
			snd($sockets[$i],$ports[$i],rtp(96|($frame->{marker}?128:0),$sequence[$i]++,
				100000+320*$frame->{frame},0x11110000+$i,"\xf0".$frame->{body}));
			my $actual=clock_gettime(CLOCK_MONOTONIC)-$started;
			$sent[$i]{$frame->{frame}}=$actual;
			$max_lateness[$i]=$actual-$planned if $actual-$planned>$max_lateness[$i];
			print {$sent_log} join(',',$i,$frame->{frame},$planned,$actual),"\n";
			$next[$i]++;
		}
	}
	if (@events && $events[0][0]<=clock_gettime(CLOCK_MONOTONIC)-$started) {
		my $event=shift @events;my $at=clock_gettime(CLOCK_MONOTONIC)-$started;
		$event->[1]->();push @event_log,{scheduled=>$event->[0],actual=>$at};
	}
	for my $socket ($selector->can_read(.001)) {
		my $packet;$socket->recv($packet,65535);my $i=$endpoint{fileno($socket)};
		next if $i==4;
		my $at=clock_gettime(CLOCK_MONOTONIC)-$started;
		print {$raw[$i]} pack('d>N',$at,length($packet)),$packet;
		next if length($packet)<12;
		my ($header,$pt,$seq,$ts,$ssrc)=unpack('CCnNN',$packet);
		next unless ($pt&127)==($i==2?111:96);
		die 'unexpected RTP header' unless $header==0x80;
		push @{$captures[$i]},{time=>$at,seq=>$seq,ts=>$ts,ssrc=>$ssrc,body=>substr($packet,12)};
	}
}
close($sent_log);close($_) for @raw;
rtpe_req('delete','conference admission cleanup',{});
open(my $log,'>',"$directory/daemon.log") or die $!;print {$log} rtpe_log();close($log);
is(scalar(@events),0,'all admission and prompt events completed');
for my $i (0..1) {
	is($next[$i],scalar(@{$input[$i]}),"source $i speech and SID trace complete");
	cmp_ok($max_lateness[$i],'<',.02,"source $i pacing remains valid");
}
my @results;
for my $i (0..3) {
	my $packets=$captures[$i];cmp_ok(scalar(@$packets),'>',100,"$tags[$i] receives media");
	my $pcm=$i<2 ? decode_phone($packets,$tags[$i]) : $i==2 ? decode_browser($packets)
		: join('',map {pack('s<*',unpack('s>*',$_->{body}))} @$packets);
	is(length($pcm),640*@$packets,"$tags[$i] reference PCM covers every output packet");
	if ($i<2) {
		cmp_ok(prompt_frames($packets,$pcm),'>=',200,"$tags[$i] receives its private welcome");
	} else {
		cmp_ok(prompt_frames($packets,$pcm),'<=',2,"$tags[$i] does not receive private welcomes");
	}
	my @steady=grep {$_->{time}>=12} @$packets;
	my ($seq_errors,$ts_errors)=(0,0);my %ssrcs;
	for my $n (0..$#steady) {
		$ssrcs{$steady[$n]{ssrc}}++;
		next unless $n && $steady[$n]{ssrc}==$steady[$n-1]{ssrc};
		$seq_errors++ if (($steady[$n]{seq}-$steady[$n-1]{seq})&0xffff)!=1;
		$ts_errors++ if (($steady[$n]{ts}-$steady[$n-1]{ts})&0xffffffff)!=($i==2?960:320);
	}
	is(scalar(keys %ssrcs),1,"$tags[$i] has one post-prompt output SSRC");
	is($seq_errors,0,"$tags[$i] post-prompt sequence stays continuous");
	is($ts_errors,0,"$tags[$i] post-prompt RTP clock stays continuous");
	my @sources=$i<2 ? (1-$i) : (0,1);
	for my $source (@sources) {
		my $detected=marker_times($packets,$pcm,$profiles->[$source]);my @markers;
		for my $n (0..$#{$profiles->[$source]{bursts}}) {
			my $burst=$profiles->[$source]{bursts}[$n];next if $burst->{start}<12;
			my $frame=int(($burst->{start}-$offset[$source])*50+.5);
			my $in=$sent[$source]{$frame};my $at=$detected->{$n};
			push @markers,{marker=>$n,input=>$in,output=>$at,lag=>defined($in)&&defined($at)?$at-$in:undef};
		}
		my @lags=map {$_->{lag}} grep {defined $_->{lag}} @markers;
		is(scalar(@lags),scalar(@markers),"$tags[$i] source $source every post-prompt marker arrives");
		my @windows;
		for (my $start=20;$start<$duration;$start+=20) {
			my @lag=map {$_->{lag}} grep {defined $_->{lag} && $_->{input}>=$start && $_->{input}<$start+20} @markers;
			push @windows,{start=>$start,median=>median(@lag)} if @lag;
		}
		if (@lags && @windows) {
			my $peak=0;for my $lag (@lags) {$peak=$lag if $lag>$peak;}
			my ($settled)=grep {$_->{start}>=40} @windows;
			my $growth=0;for my $w (grep {$_->{start}>=40} @windows) {
				$growth=$w->{median}-$settled->{median} if $w->{median}-$settled->{median}>$growth;
			}
			SKIP: {
				skip 'invalid sender pacing',2 if grep {$_>=.02} @max_lateness;
				cmp_ok($peak,'<',.25,"$tags[$i] source $source content age stays below 250 ms after prompts");
				cmp_ok($growth,'<',.04,"$tags[$i] source $source adds less than 40 ms settled delay");
			}
			push @results,{endpoint=>$tags[$i],source=>$source,markers=>\@markers,windows=>\@windows,peak=>$peak,growth=>$growth};
			diag(sprintf('%s source %d peak %.1f ms, sustained growth %.1f ms',$tags[$i],$source,$peak*1000,$growth*1000));
		}
	}
}
open(my $result,'>',"$directory/results.json") or die $!;
print {$result} JSON::PP->new->canonical->pretty->encode({streams=>\@results,events=>\@event_log,max_lateness=>\@max_lateness,
	duration=>$duration,cycle_starts=>\@cycle_starts,silence_intervals=>\@silence_intervals});close($result);
done_testing();
