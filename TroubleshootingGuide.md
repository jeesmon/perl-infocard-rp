  * Make sure openssl library (http://www.openssl.org) is installed and openssl is in PATH. Optionally you can pass openssl path to InfoCard constructor with OPENSSL\_PATH key or set it using openSSLPath() method.
  * Make sure xmlsec library (http://www.aleksey.com/xmlsec) is installed and xmlsec1 is in PATH. Optionally you can pass xmlsec path to InfoCard constructor with XMLSEC\_PATH key or set it using xmlsecPath() method.
  * Make sure cgi script has read access to both private and public ssl key files.
  * Run stand-alone infocard.pl script in tests folder to debug failures. Running it with "perl -d" option will allow stepping through each line to find failing line #. infocard.pl takes file name of the encrypted token as the argument. Use control command "s" to step into InfoCard.pm
```
$ perl -d ./infocard.pl enctoken.xml 

Loading DB routines from perl5db.pl version 1.28
Editor support available.

Enter h or `h h' for help, or `man perldebug' for more help.

main::(./infocard.pl:7):	my $PRIV_KEY_PATH = "/etc/ssl-keys/server.key";
  DB<1> n
main::(./infocard.pl:8):	my $PUB_KEY_PATH = "/etc/ssl-keys/server.crt";
  DB<1> 
main::(./infocard.pl:10):	if(@ARGV < 1) {
  DB<1> 
main::(./infocard.pl:15):	undef $/;
  DB<1> 
main::(./infocard.pl:16):	open(IN, $ARGV[0]) or die $!;
  DB<1> 
main::(./infocard.pl:17):	my $encToken = <IN>;
  DB<1> 
main::(./infocard.pl:18):	close(IN);
  DB<1> 
main::(./infocard.pl:19):	$/ = "\n";
  DB<1> 
main::(./infocard.pl:21):	print "Encrypted Token\n";
  DB<1> 
Encrypted Token
main::(./infocard.pl:22):	print $encToken;
```

  * Command to decrypt token using xmlsec
```
xmlsec1 --decrypt --privkey-pem /etc/ssl-keys/server.key enctoken.xml > dectoken.xml
```

  * Command to verify token signature using xmlsec
```
xmlsec1 --verify --id-attr:AssertionID urn:oasis:names:tc:SAML:1.0:assertion:Assertion --node-xpath / --enabled-reference-uris same-doc dectoken.xml
OK
SignedInfo References (ok/all): 1/1
Manifests References (ok/all): 0/0
```