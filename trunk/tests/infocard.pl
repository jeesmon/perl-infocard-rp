#!/usr/bin/perl -I/var/www/perl-infocard-rp/InfoCard/lib

use strict;

use InfoCard;

my $PRIV_KEY_PATH = "/etc/ssl-keys/server.key";
my $PUB_KEY_PATH = "/etc/ssl-keys/server.crt";

if(@ARGV < 1) {
  print "Usage: $0 enc_token_file\n";
  exit(0);
}

undef $/;
open(IN, $ARGV[0]) or die $!;
my $encToken = <IN>;
close(IN);
$/ = "\n";

print "Encrypted Token\n";
print $encToken;
print "\n\n";

my $infoCard = new InfoCard({PRIV_KEY_PATH => $PRIV_KEY_PATH, PUB_KEY_PATH => $PUB_KEY_PATH});
$infoCard->process($encToken);

if($infoCard->error()) {
  print "Error processing encrypted token: " . $infoCard->error() . "\n";
}

my $decToken = $infoCard->decryptedToken();
print "Decrypted token\n";
print $decToken;
print "\n\n";

if($infoCard->signatureVerified()) {
  print "Signature verified\n";
}
else {
  print "Couldn't verify signature\n";
}

if($infoCard->tokenVerified()) {
  print "Token verified\n";
}
else {
  print "Couldn't verify token\n";
}

if($infoCard->valid) {
  print "Token is valid\n";
}
else {
  print "Invalid token\n";
}

print "Claims\n";
my %claims = %{$infoCard->claims};
foreach my $c(keys %claims) {
  print "$claims{$c}->[1] ($c) : $claims{$c}->[2]\n";
}

#print "Dump\n";
#my $dump = $infoCard->dump;
#$dump =~ s/</\&lt\;/g;
#print $dump . "\n\n";
