#!/usr/bin/perl -I/var/www/perl-infocard-rp/InfoCard/lib

use strict;

use CGI;
use InfoCard;

my $PRIV_KEY_PATH = "/etc/ssl-keys/server.key";
my $PUB_KEY_PATH = "/etc/ssl-keys/server.crt";

my $cgi = new CGI();

print $cgi->header;
print $cgi->start_html('infocard');

if($cgi->param('xmlToken')) {
  my $infoCard = new InfoCard({PRIV_KEY_PATH => $PRIV_KEY_PATH, PUB_KEY_PATH => $PUB_KEY_PATH});

  my $encToken = $cgi->param('xmlToken');

  print $cgi->h3('Encrypted token:');
  print $cgi->textarea('encryptedToken', $encToken, 20, 100);

  $infoCard->process($encToken);
  print $cgi->p($infoCard->error());

  my $decToken = $infoCard->decryptedToken();

  print $cgi->h3('Decrypted token:');
  print $cgi->textarea('decryptedToken', $decToken, 20, 100);  

  if($infoCard->signatureVerified()) {
    print $cgi->p("Signature verified");
  }
  else {
    print $cgi->p("Couldn't verify signature");
  }

  if($infoCard->tokenVerified()) {
    print $cgi->p("Token verified");
  }
  else {
    print $cgi->p("Couldn't verify token");
  }

  if($infoCard->valid) {
    print $cgi->p("Token is valid");
  }
  else {
    print $cgi->p("Invalid token");
  }

  my %claims = %{$infoCard->claims};
  print "<table border='1'>\n";
  print "<tr><th>Claim name</th><th>URI</th><th>Value(s)</th></tr>\n";
  foreach my $c(keys %claims) {
    print "<tr><td>$claims{$c}->[1]</td><td>$c</td><td>$claims{$c}->[2]</td></tr>\n";
  }
  print "</table>\n";

  print $cgi->h2("Dump");
  my $dump = $infoCard->dump;
  $dump =~ s/</\&lt\;/g;
  print $cgi->pre($dump);
}
else {
  print $cgi->p("No token");
}

END_HTML:
print $cgi->end_html;

exit (0);
