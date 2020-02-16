package NGCP::Rtpclient::ICE;

use strict;
use warnings;
use Socket;
use Socket6;
use IO::Socket;
use IO::Multiplex;
use Math::BigInt;
use Digest::HMAC_SHA1 qw(hmac_sha1);
use Digest::CRC qw(crc32);
use Time::HiRes qw(time);

my @ice_chars = ('A' .. 'Z', 'a' .. 'z', '0' .. '9');
my %type_preferences = (
	host => 126,
	srflx => 100,
	prflx => 110,
	relay => 0,
);
my %protocols = ( 17 => 'UDP' );

sub random_string {
	my ($len) = @_;
	return join('', (map {$ice_chars[rand(@ice_chars)]} (1 .. $len)));
}

sub new {
	my ($class, $components, $controlling) = @_;

	my $self = {};
	bless $self, $class;

	$self->{my_ufrag} = random_string(8);
	$self->{my_pwd} = random_string(26);
	$self->{controlling} = $controlling;
	$self->{components} = $components;
	$self->{tie_breaker} = i64from32(rand(2**32), rand(2**32));

	$self->{candidates} = {}; # foundation -> candidate
	$self->{remote_candidates} = {}; # foundation -> candidate
	$self->{candidate_pairs} = {}; # foundation pairs -> pair
	$self->{remote_peers} = {}; # peer_hash_key -> component
	$self->{changed_foundations} = {}; # old -> new

	$self->{triggered_checks} = [];
	$self->{last_timer} = 0;
	$self->{start_nominating} = 0;
	$self->{completed} = 0;
	$self->{keepalives} = 0;

	$self->debug("created, control" . ($controlling ? "ing" : "ed")
		. ", tie breaker " . $self->{tie_breaker}->bstr() . "\n");

	return $self;
}

sub i64from32 {
	my ($hi, $lo) = @_;
	my $i = Math::BigInt->new(int($hi));
	$i->blsft(32);
	$i->badd(int($lo));
	return $i;
}

sub calc_priority {
	my ($type, $local_pref, $component) = @_;
	defined($type_preferences{$type}) or die;
	return (2 ** 24) * $type_preferences{$type} + (2 ** 8) * $local_pref + (256 - $component);
}

sub add_candidate {
	my ($self, $local_pref, $type, @components) = @_;
	# highest local pref = 65535, lowest = 0

	@components == $self->{components} or die;
	defined($type_preferences{$type}) or die;

	my $foundation = random_string(16);
	my $cands = $self->{candidates};
	$cands->{$foundation} and die;

	my $comps = [];
	my $comp_id = 1;
	for my $c (@components) {
		my $comp = bless { socket => $c, component => $comp_id,
				priority => calc_priority($type, $local_pref, $comp_id),
				foundation => $foundation,
				protocol => 'UDP', af => $c->sockdomain(),
				address => $c->sockhost(), port => $c->sockport(),
				agent => $self }, 'NGCP::Rtpclient::ICE::Component';
		push(@$comps, $comp);
		$comp->debug("is $comp->{address}/$comp->{port}\n");

		$comp_id++;
	}

	$cands->{$foundation} = bless { foundation => $foundation, preference => $local_pref,
		base_priority => calc_priority($type, $local_pref, 0),
		type => $type, components => $comps, protocol => 'UDP',
		af => $comps->[0]->{af}, address => $comps->[0]->{address},
		agent => $self }, 'NGCP::Rtpclient::ICE::Candidate';

	$self->pair_candidates();
}

sub encode {
	my ($self) = @_;

	my @ret;

	push(@ret, "a=ice-ufrag:$self->{my_ufrag}");
	push(@ret, "a=ice-pwd:$self->{my_pwd}");

	for my $cand (values(%{$self->{candidates}})) {
		for my $comp (@{$cand->{components}}) {
			my $prot = $comp->{socket}->protocol();
			my $sa = $comp->{socket}->sockhost();
			my $sp = $comp->{socket}->sockport();
			push(@ret, "a=candidate:$cand->{foundation} $comp->{component} $protocols{$prot} $comp->{priority} $sa $sp typ $cand->{type}");
		}
	}

	return @ret;
}

sub remote_foundation_change {
	my ($self, $old, $new, $type) = @_;

	if ($self->{changed_foundations}->{$old}) {
		$self->{changed_foundations}->{$old} eq $new or die;
		return;
	}
	$self->debug("changing remote candidate foundation from $old to $new\n");
	my $old_cand = $self->{remote_candidates}->{$old} or die;
	$old_cand->{type} = $type;
	$old_cand->{foundation} = $new;

	for my $comp (@{$old_cand->{components}}) {
		$comp->{foundation} = $new;
	}

	for my $foundation_pair (keys(%{$self->{candidate_pairs}})) {
		my $pair = $self->{candidate_pairs}->{$foundation_pair};
		$pair->{remote} == $old_cand or next;

		my $new_foundation = $pair->{local}->{foundation} . $new;
		delete($self->{candidate_pairs}->{$foundation_pair});
		$self->{candidate_pairs}->{$new_foundation} = $pair;
		$pair->{foundation} = $new_foundation;

		for my $comp (@{$pair->{components}}) {
			$comp->{foundation} = $new_foundation;
		}
	}

	$self->{remote_candidates}->{$new} = $old_cand;
	delete($self->{remote_candidates}->{$old});
	$self->{changed_foundations}->{$old} = $new;
}

sub new_remote_candidate {
	my ($self, $cand_str) = @_;
	$self->_new_remote_candidates_start();
	my $ret = $self->_new_remote_candidate($cand_str);
	$self->_got_new_candidates();
	return $ret;
}

sub _new_remote_candidates_start {
	my ($self) = @_;
	$self->{new_candidates} = {};
}

sub _new_remote_candidate {
	my ($self, $c) = @_;

	$self->debug("adding remote candidate $c\n");
	my ($foundation, $component, $protocol, $priority, $address, $port, $type)
		= $c =~ /^(\w+) (\d) (\w+) (\d+) ([0-9a-fA-F:.]+) (\d+) typ (\w+)/ or die $c;

	$protocol = uc($protocol);
	my $phk = "$protocol/$address/$port";

	if (my $old = $self->{remote_peers}->{$phk}) {
		# must be a previously learned prflx candidate
		$old = $old->{candidate};
		$old->{type} eq 'prflx' or die;
		# replace the learned prflx candidate with the new one
		$self->remote_foundation_change($old->{foundation}, $foundation, $type);
		return;
	}

	my $f = ($self->{new_candidates}->{$foundation} // (
		$self->{new_candidates}->{$foundation} = {
			foundation => $foundation,
			type => $type,
			protocol => $protocol,
			components => [],
		}));

	$f->{type} eq $type or die;
	$f->{protocol} eq $protocol or die;

	$f->{components}->[$component - 1] and die;
	my $comp = $f->{components}->[$component - 1] = {
		candidate => $f,
		foundation => $foundation,
		component => $component,
		priority => $priority,
		address => $address,
		port => $port,
		peer_hash_key => $phk,
	};

	if ($address =~ /^\d+\.\d+\.\d+\.\d+$/) {
		$f->{af} = $comp->{af} = &AF_INET;
		$comp->{packed_peer} = pack_sockaddr_in($port, inet_pton(&AF_INET, $address));
	}
	elsif ($address =~ /^[0-9a-fA-F:]+$/) {
		$f->{af} = $comp->{af} = &AF_INET6;
		$comp->{packed_peer} = pack_sockaddr_in6($port, inet_pton(&AF_INET6, $address));
	}
	else {
		die;
	}

	$self->{remote_peers}->{$phk} = $comp;

	return $comp;
}

sub _got_new_candidates {
	my ($self) = @_;

	# validate received info and eliminate duplicates
	my $r_cand = $self->{remote_candidates};
	my $r_peers = $self->{remote_peers};
	for my $c (values(%{$self->{new_candidates}})) {
		# @{$c->{components}} == $self->{components} or die;

		if (my $exist = $r_cand->{$c->{foundation}}) {
			# duplicate. OK if this is a learned prflx
			if ($exist->{type} eq 'prflx' && $c->{type} eq 'prflx') {
				# merge components
				for my $idx (0 .. $#{$c->{components}}) {
					defined($c->{components}->[$idx]) or next;
					defined($exist->{components}->[$idx]) and die;
					$exist->{components}->[$idx] = $c->{components}->[$idx];
				}
				next;
			}
			warn;
			next;
		}
		$r_cand->{$c->{foundation}} = $c;
	}

	delete($self->{new_candidates});
	$self->pair_candidates();
};

sub decode {
	my ($self, $h) = @_;
	# $h is output of SDP::Media->decode_ice()

	$self->{other_ufrag} = $h->{ufrag} or die;
	$self->{other_pwd} = $h->{pwd} or die;

	my $cands = $h->{candidates} or die;
	$self->_new_remote_candidates_start();
	for my $c (@$cands) {
		$self->_new_remote_candidate($c);
	}
	$self->_got_new_candidates();
}

sub pair_candidates {
	my ($self) = @_;

	my $pairs = $self->{candidate_pairs};

	for my $rem (values(%{$self->{remote_candidates}})) {
		for my $loc (values(%{$self->{candidates}})) {
			$loc->{protocol} eq $rem->{protocol} or next;
			$loc->{af} == $rem->{af} or next;

			@{$loc->{components}} == $self->{components} or die;

			my $foundation = $loc->{foundation} . $rem->{foundation};
			my $pair = $pairs->{$foundation} || ($pairs->{$foundation} =
					bless { foundation => $foundation, local => $loc, remote => $rem,
					components => [], agent => $self}, 'NGCP::Rtpclient::ICE::Candidate::Pair'
				);
			my $comps = $pair->{components};

			for my $idx (0 .. ($self->{components} - 1)) {
				defined($loc->{components}->[$idx]) or next;
				defined($rem->{components}->[$idx]) or next;

				my $c = $comps->[$idx] || ($comps->[$idx] =
					bless { foundation => $foundation,
					local => $loc->{components}->[$idx],
					remote => $rem->{components}->[$idx],
					agent => $self},
					'NGCP::Rtpclient::ICE::Component::Pair');
				$c->{state} = $c->{state} || ($idx == 0 ? 'waiting' : 'frozen');
			}
		}
	}
}

sub get_pair {
	my ($self, $local, $remote, $component) = @_;
	my $found = "$local$remote";
	my $pair = $self->{candidate_pairs}->{$found} or return;
	$component or return $pair;
	return $pair->{components}->[$component - 1];
}

sub is_ice {
	my ($s) = @_;

	length($s) < 20 and return 0;
	my $c = ord(substr($s, 0, 1));
	($c & 0xb0) != 0 and return 0;
	$c = ord(substr($s, 3, 1));
	($c & 0x03) != 0 and return 0;
	$c = substr($s, 4, 4);
	$c ne "\x21\x12\xA4\x42" and return 0;
	return 1;
}

sub input {
	my ($self, $fh, $s_r, $peer) = @_;

	$$s_r eq '' and return;
	is_ice($$s_r) or return;

	for my $cands (values(%{$self->{candidates}})) {
		for my $comp (@{$cands->{components}}) {
			$fh == $comp->{socket} or next;
			$self->do_input($comp, $$s_r, $peer);
			$$s_r = '';
			return;
		}
	}
}

my %attr_handlers = (
	0x0006 => \&stun_handler_USERNAME,
	0x0008 => \&stun_handler_MESSAGE_INTEGRITY,
	0x0009 => \&stun_handler_ERROR_CODE,
	0x000a => \&stun_handler_UNKNOWN_ATTRIBUTES,
	0x0020 => \&stun_handler_XOR_MAPPED_ADDRESS,
	0x0024 => \&stun_handler_PRIORITY,
	0x0025 => \&stun_handler_USE_CANDIDATE,
	0x8022 => \&stun_handler_SOFTWARE,
	0x8028 => \&stun_handler_FINGERPRINT,
	0x8029 => \&stun_handler_ICE_CONTROLLED,
	0x802a => \&stun_handler_ICE_CONTROLLING,
);

my %type_handlers = (
	1   => \&stun_handler_binding_request,
	17  => \&stun_handler_binding_indication,
	257 => \&stun_handler_binding_success,
	273 => \&stun_handler_binding_error,
);

sub do_input {
	my ($self, $comp, $s, $peer) = @_;

	my $hdr = substr($s, 0, 20, '');
	my ($mtype, $mlen, $cookie, $tid) = unpack('nnNa12', $hdr);
	$cookie == 0x2112A442 or return;

	my (@stack, %hash);

	while (my ($type, $len) = unpack('nn', $s)) {
		my $padding = 4 - ($len % 4);
		$padding == 4 and $padding = 0;

		my $raw = substr($s, 0, 4 + $len + $padding);

		substr($s, 0, 4) = '';
		my $data = substr($s, 0, $len, '');
		substr($s, 0, $padding) = '';

		my $handler = $attr_handlers{$type};
		if (!$handler) {
			warn("unknown STUN attribute $type data $data");
			next;
		}

		my $parsed = $handler->($data, $tid) or die;
		$parsed->{raw} = $raw;

		push(@stack, $parsed);
		$hash{$parsed->{name}} = $parsed;
	}

	$stack[$#stack]->{name} eq 'fingerprint' or die;
	$stack[$#stack - 1]->{name} eq 'integrity' or die;

	my $pwd_check = $mtype == 1 ? $self->{my_pwd} : $self->{other_pwd};
	# XXX unify these with sub integrity/fingerprint ?
	my $int_check = join('', (map {$_->{raw}} @stack[0 .. ($#stack - 2)]));
	$int_check = pack('nnNa12', $mtype, length($int_check) + 24, $cookie, $tid) . $int_check;
	my $digest = hmac_sha1($int_check, $pwd_check);
	$digest eq $hash{integrity}->{digest} or die;

	my $fp_check = join('', (map {$_->{raw}} @stack[0 .. ($#stack - 1)]));
	$fp_check = pack('nnNa12', $mtype, length($fp_check) + 8, $cookie, $tid) . $fp_check;
	my $crc = crc32($fp_check);
	($crc ^ 0x5354554e) == $hash{fingerprint}->{crc} or die;

	# decode peer address
	my $domain = $comp->{af};
	my (@peer, $address);
	if ($domain == &AF_INET) {
		@peer = unpack_sockaddr_in($peer);
	}
	elsif ($domain == &AF_INET6) {
		@peer = unpack_sockaddr_in6($peer);
	}
	else {
		die;
	}
	$address = inet_ntop($domain, $peer[1]);

	# process it
	my $handler = $type_handlers{$mtype} or die;
	my $response = $handler->($self, $comp, \@stack, \%hash, $tid, $peer, $peer[1], $address, $peer[0]);

	if ($response) {
		# construct and send response packet
		$self->integrity($response->{attrs}, $response->{mtype}, $tid, $self->{my_pwd});
		$self->fingerprint($response->{attrs}, $response->{mtype}, $tid);

		# XXX unify
		my $packet = join('', @{$response->{attrs}});
		$packet = pack('nnNa12', $response->{mtype}, length($packet), 0x2112A442, $tid) . $packet;
		$comp->{socket}->send($packet, 0, $peer);
	}
}

sub stun_reply {
	my ($self, $attrs, $mtype) = @_;

	unshift(@$attrs, attr(0x8022, 'perl:ICE.pm'));

	my $response = { mtype => $mtype, attrs => $attrs };
}

sub stun_success {
	my ($self, $attrs) = @_;
	return $self->stun_reply($attrs, 257);
}

sub stun_error {
	my ($self, $code, $msg) = @_;
	return $self->stun_reply([ attr(0x0009, pack('Na*', ((($code / 100) << 8) | ($code % 100)), $msg)) ], 273);
}

sub debug {
	my ($self, @rest) = @_;
	print("ICE agent", ' ', $self->{my_ufrag}, ' - ', @rest);
}

sub dummy_foundation {
	my ($protocol, $address) = @_;
	return $protocol . unpack('H*', $address);
}

sub stun_handler_binding_request {
	my ($self, $comp, $stack, $hash, $tid, $packed_peer, $packed_host, $address, $port) = @_;

	$hash->{username}->{my_ufrag} eq $self->{my_ufrag} or die;

	# check role
	if ($self->{controlling} && $hash->{controlling}) {
		if ($self->{tie_breaker}->bcmp($hash->{controlling}->{tie_breaker}) >= 0) {
			$self->debug("returning 487 role conflict\n");
			return $self->stun_error(487, "Role conflict");
		}
		$self->debug("role conflict, switching to controlled\n");
		$self->{controlling} = 0;
	}
	elsif (!$self->{controlling} && $hash->{controlled}) {
		if ($self->{tie_breaker}->bcmp($hash->{controlled}->{tie_breaker}) < 0) {
			$self->debug("returning 487 role conflict\n");
			return $self->stun_error(487, "Role conflict");
		}
		$self->debug("role conflict, switching to controlling\n");
		$self->{controlling} = 1;
	}

	$self->debug("binding request from $address/$port\n");

	# check if peer is known - learn prflx candidates
	my $cand = $self->{remote_peers}->{"UDP/$address/$port"};
	if (!$cand) {
		$cand = $self->new_remote_candidate(dummy_foundation('UDP', $packed_host)
			. " $comp->{component} UDP "
			. "$hash->{priority}->{priority} $address $port typ prflx");
		# this also pairs up the new candidate, which goes against 7.2.1.3
	}

	# get candidate pair and trigger check
	my $pair = $self->get_pair($comp->{foundation}, $cand->{foundation}, $comp->{component});
	$pair or die;
	$pair->trigger_check();

	# set and check nominations
	if ($hash->{use}) {
		$pair->{nominated} = 1;
		$self->debug("$pair->{foundation} - got nominated\n");
		$self->check_nominations();
	}

	# construct response
	my $attrs = [];

	if ($comp->{af} == &AF_INET) {
		push(@$attrs, attr(0x0020, pack('nna4', 1, $port ^ 0x2112, $packed_host ^ "\x21\x12\xa4\x42")));
	}
	elsif ($comp->{af} == &AF_INET6) {
		push(@$attrs, attr(0x0020, pack('nna16', 2, $port ^ 0x2112,
			$packed_host ^ ("\x21\x12\xa4\x42" . $tid))));
	}

	return $self->stun_success($attrs);
}

sub check_nominations {
	my ($self) = @_;

	$self->{controlling} and return;

	my @nominated;

	for my $pair (values(%{$self->{candidate_pairs}})) {
		my @comps = @{$pair->{components}};
		my @nominated_comps = grep {$_->{nominated}} @comps;
		@nominated_comps < $self->{components} and next;
		$self->debug("got fully nominated pair $pair->{foundation}\n");
		push(@nominated, $pair);
	}

	if (!@nominated) {
		$self->debug("no fully nominated pairs yet\n");
		return;
	}

	@nominated = sort_pairs(\@nominated);
	my $pair = $nominated[0];
	$self->debug("highest priority nominated pair is $pair->{foundation}\n");
	$self->{nominated_pair} = $pair;
	$self->{completed} ||= time();
}

sub stun_handler_binding_success {
	my ($self, $comp, $stack, $hash, $tid, $packed_peer, $packed_host, $address, $port) = @_;

	$self->debug("binding success from $address/$port\n");

	# check xor address
	$comp->{address} eq $hash->{address}->{address} or die("$comp->{address} $hash->{address}->{address}");
	$comp->{port} == $hash->{address}->{port} or die;

	# we must have remote candidate and a pair
	my $cand = $self->{remote_peers}->{"UDP/$address/$port"};
	$cand or die;
	my $pair = $self->get_pair($comp->{foundation}, $cand->{foundation}, $comp->{component});
	$pair or die;
	$tid eq $pair->{transaction} or die;

	$self->debug("$pair->{foundation} succeeded\n");
	$pair->{state} = 'succeeded';

	# unfreeze other components
	my $parent_pair = $self->{candidate_pairs}->{$pair->{foundation}};
	my $components = $parent_pair->{components};
	my @frozen_pairs = grep {$_->{state} eq 'frozen'} @$components;
	for my $p (@frozen_pairs) {
		$self->debug("unfreezing $p->{local}->{port}\n");
		$p->{state} = 'waiting';
	}

	$self->check_to_nominate();

	return;
}

sub check_to_nominate {
	my ($self) = @_;

	return unless $self->{controlling};
	return if $self->{start_nominating} && time() < $self->{start_nominating};
	return if $self->{nominate};
	return if @{$self->{triggered_checks}};

	my @succeeded;

	for my $pair (values(%{$self->{candidate_pairs}})) {
		my @comps = @{$pair->{components}};
		my @succeeded_comps = grep {$_->{state} eq 'succeeded'} @comps;
		next if @succeeded_comps < $self->{components};
		$self->debug("got fully succeeded pair $pair->{foundation}\n");
		push(@succeeded, $pair);
	}

	if (!@succeeded) {
		$self->debug("no fully succeeded pairs yet\n");
		return;
	}

	@succeeded = sort_pairs(\@succeeded);
	my $pair = $succeeded[0];
	$self->debug("highest priority succeeded pair is $pair->{foundation}\n");

	if (!$self->{start_nominating}) {
		$self->{start_nominating} = time() + 0.1;
		return;
	}

	$pair->{nominate} and return;

	$self->{nominate} = 1;
	$pair->{nominate} = 1;
	$self->{start_nominating} = 0;
	$self->{nominated_pair} = $pair;
	$self->{completed} ||= time();

	$pair->debug("nominating\n");
	$pair->nominate();
}

sub integrity {
	my ($self, $attrs, $mtype, $tid, $pwd) = @_;

	my $int_check = join('', @$attrs);
	$int_check = pack('nnNa12', $mtype, length($int_check) + 24, 0x2112A442, $tid) . $int_check;
	my $digest = hmac_sha1($int_check, $pwd);
	push(@$attrs, attr(0x0008, $digest));
}

sub fingerprint {
	my ($self, $attrs, $mtype, $tid) = @_;

	my $fp_check = join('', @$attrs);
	$fp_check = pack('nnNa12', $mtype, length($fp_check) + 8, 0x2112A442, $tid) . $fp_check;
	my $crc = crc32($fp_check);
	push(@$attrs, attr(0x8028, pack('N', ($crc ^ 0x5354554e))));
}

sub attr {
	my ($id, $data) = @_;
	my $len = length($data);
	my $padding = 4 - ($len % 4);
	$padding == 4 and $padding = 0;
	return pack('nn a*a*', $id, $len, $data, "\0" x $padding);
}

sub stun_handler_SOFTWARE {
	my ($data, $out) = @_;
	return { name => 'software', data => $data };
}
sub stun_handler_USE_CANDIDATE {
	my ($data, $out) = @_;
	return { name => 'use' };
}
sub stun_handler_ICE_CONTROLLED {
	my ($data) = @_;
	my $out = { name => 'controlled' };
	$out->{controlled} = 1;
	($out->{tie_breaker_hi}, $out->{tie_breaker_lo}) = unpack('NN', $data);
	$out->{tie_breaker} = i64from32($out->{tie_breaker_hi}, $out->{tie_breaker_lo});
	return $out;
}
sub stun_handler_ICE_CONTROLLING {
	my ($data) = @_;
	my $out = { name => 'controlling' };
	$out->{controlling} = 1;
	($out->{tie_breaker_hi}, $out->{tie_breaker_lo}) = unpack('NN', $data);
	$out->{tie_breaker} = i64from32($out->{tie_breaker_hi}, $out->{tie_breaker_lo});
	return $out;
}
sub stun_handler_USERNAME {
	my ($data) = @_;
	my $out = { name => 'username' };
	$data =~ /^(.*):(.*)$/ or die;
	$out->{my_ufrag} = $1;
	$out->{other_ufrag} = $2;
	return $out;
}
sub stun_handler_PRIORITY {
	my ($data) = @_;
	my $out = { name => 'priority' };
	($out->{priority}) = unpack('N', $data);
	return $out;
}
sub stun_handler_MESSAGE_INTEGRITY {
	my ($data) = @_;
	my $out = { name => 'integrity' };
	$out->{digest} = $data;
	return $out;
}
sub stun_handler_FINGERPRINT {
	my ($data) = @_;
	my $out = { name => 'fingerprint' };
	($out->{crc}) = unpack('N', $data);
	return $out;
}
sub stun_handler_ERROR_CODE {
	my ($data) = @_;
	my $out = { name => 'error' };
	my ($code, $msg) = unpack('Na*', $data);
	$out->{msg} = $msg;
	$out->{code} = (($code & 0x700) >> 8) * 100 + ($code & 0x0ff);
	return $out;
}
sub stun_handler_XOR_MAPPED_ADDRESS {
	my ($data, $tid) = @_;
	my $out = { name => 'address' };
	if (length($data) == 8) {
		my ($fam, $port, $addr) = unpack('nna4', $data);
		$fam == 1 or die;
		$out->{af} = &AF_INET;
		$out->{port} = $port ^ 0x2112;
		$out->{address} = $addr ^ "\x21\x12\xa4\x42";
	}
	elsif (length($data) == 20) {
		my ($fam, $port, $addr) = unpack('nna16', $data);
		$fam == 2 or die;
		$out->{af} = &AF_INET6;
		$out->{port} = $port ^ 0x2112;
		$out->{address} = $addr ^ ("\x21\x12\xa4\x42" . $tid);
	}
	else {
		die;
	}
	$out->{address} = inet_ntop($out->{af}, $out->{address});
	return $out;
}

sub timer {
	my ($self) = @_;
	my $now = time();
	$now - $self->{last_timer} < 0.02 and return;
	$self->{last_timer} = $now;

	# run checks

	# not enough info
	return if !defined($self->{other_ufrag}) || !defined($self->{other_pwd});

	if (my $pair = shift(@{$self->{triggered_checks}})) {
		$pair->debug("running triggered check\n");
		$pair->run_check();
		return;
	}

	# get all component pairs, sort by their priority and run check for the highest waiting one

	my @candidate_pairs = values(%{$self->{candidate_pairs}});
	my @component_pairs = map {@{$_->{components}}} @candidate_pairs;
	my @sorted_pairs = sort_pairs(\@component_pairs);
	my @waiting_pairs = grep {$_->{state} eq 'waiting'} @sorted_pairs;

	if (my $pair = shift(@waiting_pairs)) {
		$pair->debug("running scheduled check (waiting state)\n");
		$pair->run_check();
		return;
	}

	$self->check_to_nominate();

	if ($self->{completed}) {
		$self->{keepalives} ||= time() + 2;
		if (time() >= $self->{keepalives}) {
			$self->keepalives();
			$self->{keepalives} += 2;
		}
	}
}

sub keepalives {
	my ($self) = @_;

	$self->debug("sending keepalives");
	my $pair = $self->{nominated_pair} or return;
	$pair->nominate();
}

sub sort_pairs {
	my ($pair_list) = @_;
	my @sorted_list = sort {
		$a->priority() <=> $b->priority()
	} @{$pair_list};
	return @sorted_list;
}

sub get_send_component {
	my ($self, $component) = @_;

	my $pair = $self->{nominated_pair};

	if (!$pair) {
		my @pairs = values(%{$self->{candidate_pairs}});
		@pairs = sort_pairs(\@pairs);
		$pair = $pairs[0];
	}

	return ($pair->{components}->[$component]->{local}->{socket},
				$pair->{components}->[$component]->{remote}->{packed_peer});
}

package NGCP::Rtpclient::ICE::Candidate;

sub debug {
	my ($self, @rest) = @_;
	$self->{agent}->debug("candidate", $self->{foundation}, ' - ', @rest);
}

package NGCP::Rtpclient::ICE::Component;

sub debug {
	my ($self, @rest) = @_;
	$self->{agent}->debug("component $self->{foundation}/$self->{component}", ' - ', @rest);
}

package NGCP::Rtpclient::ICE::Candidate::Pair;

sub priority {
	my ($self) = @_;
	my $firstcomp = $self->{components}->[0];
	return $firstcomp->priority();
}

sub debug {
	my ($self, @rest) = @_;
	$self->{agent}->debug("candidate pair $self->{foundation}", ' - ', @rest);
}

sub nominate {
	my ($self) = @_;
	for my $comp (@{$self->{components}}) {
		$comp->cancel_check();
		$comp->{nominate} = 1;
		$comp->trigger_check();
	}
}

package NGCP::Rtpclient::ICE::Component::Pair;

sub debug {
	my ($self, @rest) = @_;
	$self->{agent}->debug("component pair $self->{foundation}", ' - ', @rest);
}

sub priority {
	my ($self) = @_;
	my $agent = $self->{agent};
	my $gk = $agent->{controlling} ? 'local' : 'remote';
	my $dk = $agent->{controlling} ? 'remote' : 'local';
	my $gc = $self->{$gk};
	my $dc = $self->{$dk};
	my $g = $gc->{priority};
	my $d = $dc->{priority};
	return (($g < $d ? $g : $d) << 32) + (($g > $d ? $g : $d) * 2) + ($g > $d ? 1 : 0);
}

sub trigger_check {
	my ($self) = @_;
	$self->debug("trigger check\n");
	if ($self->{state} eq 'succeeded') {
		$self->debug("already succeeded\n");
		return;
	}
	if ($self->{state} eq 'in progress') {
		$self->cancel_check();
	}
	push(@{$self->{agent}->{triggered_checks}}, $self);
}

sub run_check {
	my ($self) = @_;

	$self->{state} eq 'in progress' and return;

	$self->debug("running check\n");
	$self->{state} = 'in progress';
	$self->{transaction} = NGCP::Rtpclient::ICE::random_string(12);
	$self->send_check();
	# XXX handle retransmits
}

sub cancel_check {
	my ($self) = @_;
	$self->{transaction} or return;
	$self->debug("canceling existing check $self->{transaction}\n");
	$self->{previous_transactions}->{$self->{transaction}} = 1;
	delete $self->{transaction};
	$self->{state} = 'waiting';
}

sub send_check {
	my ($self) = @_;

	$self->debug("sending check $self->{transaction}\n");

	$self->{last_transmit} = time();
	my $local_comp = $self->{local};
	my $remote_comp = $self->{remote};
	my $local_cand = $self->{agent}->{candidates}->{$local_comp->{foundation}};

	my $attrs = [];
	unshift(@$attrs, NGCP::Rtpclient::ICE::attr(0x8022, 'perl:ICE.pm'));
	my $hexbrk = $self->{agent}->{tie_breaker}->as_hex();
	$hexbrk =~ s/^0x// or die;
	$hexbrk = ('0' x (16 - length($hexbrk))) . $hexbrk;
	unshift(@$attrs, NGCP::Rtpclient::ICE::attr($self->{agent}->{controlling} ? 0x802a : 0x8029, pack('H*', $hexbrk)));
	unshift(@$attrs, NGCP::Rtpclient::ICE::attr(0x0024, pack('N', NGCP::Rtpclient::ICE::calc_priority('prflx',
				$local_cand->{preference}, $local_comp->{component}))));
	unshift(@$attrs, NGCP::Rtpclient::ICE::attr(0x0006, "$self->{agent}->{other_ufrag}:$self->{agent}->{my_ufrag}"));
	$self->{nominate} and
		unshift(@$attrs, NGCP::Rtpclient::ICE::attr(0x0025, ''));

	$self->{agent}->integrity($attrs, 1, $self->{transaction}, $self->{agent}->{other_pwd});
	$self->{agent}->fingerprint($attrs, 1, $self->{transaction});

	my $packet = join('', @$attrs);
	$packet = pack('nnNa12', 1, length($packet), 0x2112A442, $self->{transaction}) . $packet;
	$local_comp->{socket}->send($packet, 0, $remote_comp->{packed_peer});
}

1;
