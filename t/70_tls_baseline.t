#!/usr/bin/env perl

# Acceptance test for the TLS baseline tooling:
#   1. structured JSON is produced and parseable for three target classes
#      (modern ciphers, legacy ciphers, handshake failure);
#   2. the baseline diff locates changes down to the individual cipher item;
#   3. handshake failures carry a stable classification category.
#
# The test spins up local "openssl s_server" instances so it does not
# depend on external network reachability.  It is skipped when openssl or
# python3 are unavailable.

use strict;
use warnings;
use Test::More;
use JSON::PP qw(decode_json);
use File::Temp qw(tempdir);
use FindBin;
use Socket;

my $openssl = `which openssl`;
chomp $openssl;
my $python  = `which python3`;
chomp $python;

if (!$openssl || !$python) {
     plan skip_all => "openssl and python3 are required for this test";
}

my $repo_root = "$FindBin::Bin/..";
my $tool      = "$repo_root/utils/tls_baseline.py";
my $work      = tempdir(CLEANUP => 1);
my $pki       = "$work/pki";
mkdir $pki;

# --- test PKI -------------------------------------------------------------
system("$openssl req -x509 -newkey rsa:2048 -keyout $pki/key.pem " .
       "-out $pki/cert.pem -days 1 -nodes -subj /CN=tls-baseline.test " .
       ">/dev/null 2>&1");
system("cat $pki/key.pem $pki/cert.pem > $pki/all.pem");
die "failed to create test PKI" unless -s "$pki/all.pem";

# Pick free ports.
sub free_port {
     my $sock;
     socket($sock, Socket::PF_INET(), Socket::SOCK_STREAM(), 0) or die $!;
     bind($sock, Socket::pack_sockaddr_in(0, Socket::inet_aton("127.0.0.1")))
          or die $!;
     my ($port, $addr) = sockaddr_in(getsockname($sock));
     close($sock);
     return $port;
}

my $modern_port  = free_port();
my $legacy_port  = free_port();
my $closed_port  = free_port();

# --- local TLS servers ----------------------------------------------------
my $modern_pid = fork();
if ($modern_pid == 0) {
     exec("$openssl s_server -accept $modern_port -cert $pki/all.pem " .
          "-tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384 " .
          "-www >/dev/null 2>&1");
     exit 1;
}
my $legacy_pid = fork();
if ($legacy_pid == 0) {
     exec("$openssl s_server -accept $legacy_port -cert $pki/all.pem " .
          "-tls1 -cipher 'ALL:\@SECLEVEL=0' -www >/dev/null 2>&1");
     exit 1;
}

END {
     # Make sure no local test server survives a failed run.
     kill 'TERM', $modern_pid, $legacy_pid if $modern_pid && $legacy_pid;
}

# Wait for the listeners.
my $ready = 0;
for my $try (1 .. 30) {
     my $listening = `ss -ltn 2>/dev/null`;
     if ($listening =~ /:$modern_port\s/ && $listening =~ /:$legacy_port\s/) {
          $ready = 1;
          last;
     }
     select(undef, undef, undef, 0.3);
}

if (!$ready) {
     kill 'TERM', $modern_pid, $legacy_pid;
     plan skip_all => "could not start local openssl s_server instances";
}

# Fixed assertions (21 lines outside the per-cipher loop) plus two per
# modern cipher. The modern test server offers exactly the two configured
# GCM suites, so the total is 21 + 2 * 2 = 25.
plan tests => 25;

my @common_scan = (
     "--ssl-native", "--openssl-timeout", "3",
     "--socket-timeout", "3", "--timeout", "300",
     "--probe-timeout", "2",
);

sub run_scan {
     my ($port, $out, $checks) = @_;
     my $cmd = join(" ",
          "$python $tool scan 127.0.0.1:$port",
          "-o $out", @common_scan, "'--checks=$checks'");
     return system($cmd);
}

sub slurp_json {
     my ($path) = @_;
     local $/;
     open(my $fh, "<", $path) or die "cannot open $path: $!";
     my $data = <$fh>;
     close($fh);
     return decode_json($data);
}

# --- 1. modern target -----------------------------------------------------
my $modern_json = "$work/modern.json";
is(run_scan($modern_port, $modern_json, "-p -E -P"), 0,
   "modern target scan exits cleanly");
my $modern = slurp_json($modern_json);
ok($modern->{schemaVersion}, "modern JSON has schema version");
my %proto = map { $_->{protocol} => $_ } @{ $modern->{protocols} };
ok($proto{TLS1_2}{offered}, "modern target offers TLS 1.2");
ok(!$proto{TLS1}{offered}, "modern target does not offer TLS 1.0");
my @modern_ciphers = @{ $modern->{ciphers} };
ok(@modern_ciphers >= 2, "modern target reports ciphers");
for my $cipher (@modern_ciphers) {
     like($cipher->{key}, qr/^cipher-tls1_2_x[0-9a-f]{2,4}$/,
          "modern cipher key is stable: $cipher->{key}");
     ok($cipher->{iana_name}, "modern cipher has IANA name");
}
my ($tls1_failure) = grep { $_->{protocol} eq "TLS1" } @{ $modern->{failures} };
is($tls1_failure->{category}, "tls_alert",
   "modern target classifies TLS 1.0 rejection as tls_alert");
is($tls1_failure->{alert_name}, "protocol_version",
   "modern target failure reason is protocol_version");

# --- 2. legacy target -----------------------------------------------------
my $legacy_json = "$work/legacy.json";
is(run_scan($legacy_port, $legacy_json, "-p -E -P"), 0,
   "legacy target scan exits cleanly");
my $legacy = slurp_json($legacy_json);
%proto = map { $_->{protocol} => $_ } @{ $legacy->{protocols} };
ok($proto{TLS1}{offered}, "legacy target offers TLS 1.0");
ok(!$proto{TLS1_2}{offered}, "legacy target does not offer TLS 1.2");
my @legacy_ciphers = @{ $legacy->{ciphers} };
ok(@legacy_ciphers >= 5, "legacy target reports multiple ciphers");
my $all_parsed = 1;
for my $cipher (@legacy_ciphers) {
     $all_parsed = 0 unless $cipher->{iana_name} && $cipher->{hex_code};
}
ok($all_parsed, "every legacy cipher is fully parsed (hex + IANA name)");
my ($legacy_tls12) = grep { $_->{protocol} eq "TLS1_2" }
                          @{ $legacy->{failures} };
ok($legacy_tls12, "legacy target records a TLS 1.2 failure");
# A TLS 1.0-only server may answer a TLS 1.2 hello with a downgraded
# ServerHello; both that and an alert are acceptable, the category must
# simply come from the stable enumeration.
ok($legacy_tls12->{category} =~ /^(tls_alert|tls_connection_closed|success)$/,
   "legacy TLS 1.2 failure has a stable category: "
   . ($legacy_tls12->{category} // "<undef>"));

# --- 3. handshake failure / unreachable target ----------------------------
my $fail_json = "$work/fail.json";
run_scan($closed_port, $fail_json, "-p");
my $fail = slurp_json($fail_json);
ok(!$fail->{scan}{connectivity}{reachable},
   "closed port target is marked unreachable");
my $category = $fail->{scan}{connectivity}{tcpCategory};
ok($category =~ /^tcp_timeout|tcp_refused|tcp_unreachable$/,
   "closed port target has TCP failure category: $category");
my ($scan_level) = grep { $_->{protocol} eq "ALL" } @{ $fail->{failures} };
ok($scan_level, "unreachable target gets a scan level failure record");

# --- 4. diff pinpoints cipher items --------------------------------------
my $diff_json = "$work/diff.json";
# Build a "current" document where one cipher is removed and one added.
my $current = decode_json(JSON::PP->new->encode($modern));
my $removed_key = $modern->{ciphers}[0]{key};
$current->{ciphers} = [
     grep { $_->{key} ne $removed_key } @{ $current->{ciphers} }
];
push @{ $current->{ciphers} }, {
     key          => "cipher-tls1_2_x009c",
     id           => "cipher-tls1_2_x009c",
     offered      => JSON::PP::true,
     severity     => "MEDIUM",
     protocol     => "TLSv1.2",
     hex_code     => "0x009c",
     iana_name    => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
     openssl_name => "DES-CBC3-SHA",
     key_exchange => "RSA",
     encryption   => "3DES",
     bits         => 168,
};
open(my $fh, ">", "$work/current.json") or die $!;
print $fh JSON::PP->new->pretty->encode($current);
close($fh);

is(system("$python $tool diff $modern_json $work/current.json -o $diff_json"),
   0, "diff command exits cleanly");
my $diff = slurp_json($diff_json);
my @removed = map { $_->{key} } @{ $diff->{ciphers}{removed} };
my @added   = map { $_->{key} } @{ $diff->{ciphers}{added} };
is("@removed", $removed_key, "diff pinpoints the removed cipher item");
is("@added", "cipher-tls1_2_x009c", "diff pinpoints the added cipher item");
ok($diff->{summary}{hasChanges}, "diff summary reports changes");

# --- cleanup --------------------------------------------------------------
kill 'TERM', $modern_pid, $legacy_pid;
waitpid($modern_pid, 0);
waitpid($legacy_pid, 0);

done_testing();

# vim:ts=5:sw=5:expandtab
