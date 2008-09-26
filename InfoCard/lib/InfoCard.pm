package InfoCard;

use strict;
use warnings;

use File::Temp qw(tempfile);
use XML::XPath;
use XML::XPath::NodeSet;
use XML::XPath::XMLParser;
use DateTime::Format::Strptime;
use URI::Split;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use InfoCard ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.01';

my $XENC_NS = "http://www.w3.org/2001/04/xmlenc#";
my $XENC_ELEMENT_TYPE = "http://www.w3.org/2001/04/xmlenc#Element";
my $XENC_ENC_ALGO = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
my $XENC_KEYINFO_ENC_ALGO = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

my $DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
my $DSIG_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
my $DSIG_ENVELOPED_SIG = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
my $DSIG_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";

my $CANON_EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#";

my $WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
my $WSSE_KEYID_VALUE_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1";

my $XMLSOAP_SELF_ISSUED = "http://schemas.xmlsoap.org/ws/2005/05/identity/issuer/self";

my $XMLSOAP_CLAIMS_NS = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims';

my $SAML_ASSERTION_1_0_NS = "urn:oasis:names:tc:SAML:1.0:assertion";
my $SAML_ASSERTION_1_1_NS = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";

my ($LD_LIB_PATH, $XMLSEC_PATH, $OPENSSL_PATH, $PUB_KEY_PATH, $PRIV_KEY_PATH);

sub new {
  my $self = shift;
  my $arg = shift;
  my $class = ref($self) || $self;

  if(ref $arg eq 'HASH') {
    $LD_LIB_PATH = $arg->{LIB_PATH} if defined $arg->{LIB_PATH};
    $XMLSEC_PATH = $arg->{XMLSEC_PATH} if defined $arg->{XMLSEC_PATH};
    $OPENSSL_PATH = $arg->{OPENSSL_PATH} if defined $arg->{OPENSSL_PATH};
    $PUB_KEY_PATH = $arg->{PUB_KEY_PATH} if defined $arg->{PUB_KEY_PATH};
    $PRIV_KEY_PATH = $arg->{PRIV_KEY_PATH} if defined $arg->{PRIV_KEY_PATH};
  } 

  return bless {}, $class;
}

sub libPath {
  my $self = shift;
  if(@_) {
    $LD_LIB_PATH = shift;
  }
}

sub xmlsecPath {
  my $self = shift;
  if(@_) {
    $XMLSEC_PATH = shift;
  }
}

sub openSSLPath {
  my $self = shift;
  if(@_) {
    $OPENSSL_PATH = shift;
  }
}

sub pubKeyPath {
  my $self = shift;
  if(@_) {
    $PUB_KEY_PATH = shift;
  }
}

sub privKeyPath {
  my $self = shift;
  if(@_) {
    $PRIV_KEY_PATH = shift;
  }
}

sub process {
  my ($self, $encToken) = @_;

  verifyArguments();

  $self->{ENC_TOKEN} = $encToken;
 
  my $err = checkEncryptedToken($encToken);
  if($err) {
    $self->{VALID_ENC_TOKEN} = 0;
    $self->{ERROR} = $err;

    return;
  }
  else {
    $self->{VALID_ENC_TOKEN} = 1;
  }

  $self->{DEC_TOKEN} = decrypt($encToken);  

  $self->{SIGNATURE_VERIFIED} = verifySignature(writeToTempFile($self->{DEC_TOKEN}));

  my $tokenInfo = getSignedTokenInfo($self->{DEC_TOKEN});

  foreach my $k(keys %$tokenInfo) {
    $self->{$k} = $tokenInfo->{$k};
  }
}

sub valid {
  my $self = shift;

  return $self->{VALID_ENC_TOKEN} && $self->{SIGNATURE_VERIFIED} && $self->{TOKEN_VERIFIED}
}

sub error {
  my $self = shift;

  return $self->{ERROR};
}

sub decryptedToken {
  my $self = shift;

  return $self->{DEC_TOKEN};
}

sub signatureVerified {
  my $self = shift;

  return $self->{SIGNATURE_VERIFIED};
}

sub tokenVerified {
  my $self = shift;

  return $self->{TOKEN_VERIFIED};
}

sub dump {
  my $self = shift;

  no warnings;
  my $s = "";
  foreach my $k(sort keys %$self) {
    if(ref $self->{$k} eq 'ARRAY') {
      $s .= "$k -> @{$self->{$k}}\n";
    }
    elsif(ref $self->{$k} eq 'HASH') {
      $s .= "$k -> [";
      foreach my $hk(keys %{$self->{$k}}) {
        $s .= "$hk => ";
        if(ref ${$self->{$k}}{$hk} eq 'ARRAY') {
          $s .= "[@{${$self->{$k}}{$hk}}] ";
        }
        else {
          $s .= "${$self->{$k}}{$hk} ";
        }
      }
      $s .= "]\n";
    }
    else {
      $s .= "$k -> $self->{$k}\n";
    }
  }

  return $s;
}

sub availableKeys {
  my $self = shift;

  return keys(%$self);
}

sub keyValue {
  my $self = shift;
  my $key = shift;

  no warnings;
  return $self->{$key};
}

sub claims {
  my $self = shift;

  return $self->{ATTRIBUTES}; 
}

sub getClaimByUri {
  my $self = shift;
  my $uri = shift;

  if($self->{ATTRIBUTES} && $self->{ATTRIBUTES}{$uri}) {
    return $self->{ATTRIBUTES}{$uri}->[2];
  }
  else {
    return undef;
  }
}

sub getClaimByName {
  my $self = shift;
  my $name = shift;

  my %claims = %{$self->{ATTRIBUTES}};
  foreach my $c(keys %claims) {
    if($claims{$c}->[1] eq $name) {
      return $claims{$c}->[2];
    }
  }

  return undef;
}

######### private methods ##########
sub writeToTempFile {
  my $content = shift;

  my ($fh, $fn) = tempfile(UNLINK => 1);
  print $fh $content;
  close($fh);

  return $fn;
}

sub xmlsecCmdPrefix {
  my $cmd = "";

  if($LD_LIB_PATH) {
    $cmd .= "LD_LIBRARY_PATH=$LD_LIB_PATH ";
  }

  if($XMLSEC_PATH) {
    $cmd .= "$XMLSEC_PATH ";
  }
  else {
    $cmd .= "xmlsec1 ";
  }
}

sub opensslCmdPrefix {
  my $cmd = "";
 
  if($LD_LIB_PATH) {
    $cmd .= "LD_LIBRARY_PATH=$LD_LIB_PATH ";
  }
  
  if($OPENSSL_PATH) {
    $cmd .= "$OPENSSL_PATH ";
  }
  else {
    $cmd .= "openssl ";
  }
}

sub decrypt {
  my $encToken = shift;

  my $fn = writeToTempFile($encToken);

  my $cmd = xmlsecCmdPrefix() .
            "--decrypt " .
            "--privkey-pem $PRIV_KEY_PATH " .
            $fn;

  return `$cmd`;
}

sub verify {
  my ($fn, $saml_ns) = @_;

  my $cmd = xmlsecCmdPrefix() .
            "--verify " .
            "--id-attr:AssertionID ${saml_ns}:Assertion " .
            "--node-xpath / " .
            "--enabled-reference-uris same-doc " .
            "$fn 2>&1";

  my $rslt = `$cmd`;

  my $valid = 0;
  if($rslt =~ /^OK/) {
    $valid = 1;
  }

  return $valid;
}

sub checkEncryptedToken {
  my $xml = shift;

  my $xp = XML::XPath->new(xml => $xml);
  $xp->set_namespace('xenc', $XENC_NS);
  $xp->set_namespace('ds', $DSIG_NS);
  $xp->set_namespace('wsse', $WSSE_NS);

  my $root_path = "/xenc:EncryptedData";
  $xp->find($root_path) or return "EncryptedData node not found \@ $root_path";

  my $type_attr_path = "${root_path}[\@Type='$XENC_ELEMENT_TYPE']";
  $xp->find($type_attr_path) or return "EncryptedData Type attribute not found \@ $type_attr_path";

  my $method_path = "$root_path/xenc:EncryptionMethod";
  $xp->find($method_path) or return "EncryptionMethod node not found \@ $method_path";

  my $method_algo_path = "${method_path}[\@Algorithm='$XENC_ENC_ALGO']";
  $xp->find($method_algo_path) or return "EncryptionMethod Algorithm attribute not found \@ $method_algo_path";

  my $keyinfo_path = "$root_path/ds:KeyInfo";
  $xp->find($keyinfo_path) or return "KeyInfo node not found \@ $keyinfo_path";

  my $enckey_path = "$keyinfo_path/xenc:EncryptedKey";
  $xp->find($enckey_path) or return "EncryptedKey node not found \@ $enckey_path";

  my $enckey_method_path = "$enckey_path/xenc:EncryptionMethod";
  $xp->find($enckey_method_path) or return "EncryptionMethod node not found \@ $enckey_method_path";

  my $enckey_method_algo_path = "${enckey_method_path}[\@Algorithm='$XENC_KEYINFO_ENC_ALGO']";
  $xp->find($enckey_method_algo_path) or return "EncryptionMethod Algorihm attribute not found \@ $enckey_method_algo_path";

  my $enckey_keyinfo_path = "$enckey_path/ds:KeyInfo";
  $xp->find($enckey_keyinfo_path) or return "KeyInfo node not found \@ $enckey_keyinfo_path";

  my $tokref_path = "$enckey_keyinfo_path/wsse:SecurityTokenReference";
  $xp->find($tokref_path) or return "SecurityTokenReference node not found \@ $tokref_path";

  my $keyid_path = "$tokref_path/wsse:KeyIdentifier";
  $xp->find($keyid_path) or return "KeyIdentifier node not found \@ $keyid_path";

  my $keyid_valuetype_path = "${keyid_path}[\@ValueType='$WSSE_KEYID_VALUE_TYPE']";
  $xp->find($keyid_valuetype_path) or return "KeyIdentifier ValueType not found \@ $keyid_valuetype_path";

  return;
}

sub verifySignature {
  my $fn = shift;

  foreach my $saml_ns(($SAML_ASSERTION_1_0_NS, $SAML_ASSERTION_1_1_NS)) {
    return 1 if verify($fn, $saml_ns);
  }

  return 0;
}

sub getSignedTokenInfo {
  my $xml = shift;

  my $parser = XML::XPath::XMLParser->new(xml => $xml);
  
  my %tokenInfo = ();

  my $root_node = ${$parser->parse}->getFirstChild;

  $tokenInfo{ROOT_NODE_NAME} = ${$root_node}->getLocalName;

  if(${$root_node}->getLocalName eq "Assertion") {
    my $saml_ns = ${$$root_node->getNamespace}->getValue;

    $tokenInfo{ROOT_NODE_NS} = $saml_ns;
    $tokenInfo{MAJOR_VERSION} = ${$root_node}->getAttribute('MajorVersion');
    $tokenInfo{MINOR_VERSION} = ${$root_node}->getAttribute('MinorVersion');
    $tokenInfo{ASSERTION_ID} = ${$root_node}->getAttribute('AssertionID');

    my $strptime = DateTime::Format::Strptime->new(pattern => '%Y-%m-%dT%H:%M:%S');

    $tokenInfo{ISSUE_INSTANT} = $strptime->parse_datetime(${$root_node}->getAttribute('IssueInstant')); 
    $tokenInfo{ISSUER} = ${$root_node}->getAttribute('Issuer'); 

    foreach my $c(${$root_node}->getChildNodes) {
      if(${$c}->getLocalName eq "Conditions") {
        if(${${$c}->getNamespace}->getValue eq $saml_ns) {
          $tokenInfo{NOT_BEFORE} = $strptime->parse_datetime(${$c}->getAttribute('NotBefore'));
          $tokenInfo{NOT_ON_OR_AFTER} = $strptime->parse_datetime(${$c}->getAttribute('NotOnOrAfter'));
          foreach my $c2(${$c}->getChildNodes) {
            if(${$c2}->getLocalName eq "AudienceRestrictionCondition" && ${${$c2}->getNamespace}->getValue eq $saml_ns) {
              foreach my $c3(${$c2}->getChildNodes) {
                if(${$c3}->getLocalName eq "Audience" && ${${$c3}->getNamespace}->getValue eq $saml_ns) {
                  $tokenInfo{AUDIENCE} = ${${$c3}->getFirstChild}->getValue;
                }
              }
            }
          }
        }
      }
      elsif(${$c}->getLocalName eq "Signature" and ${${$c}->getNamespace}->getValue eq $DSIG_NS) {
        foreach my $c2(${$c}->getChildNodes) {
          if(${$c2}->getLocalName eq "SignedInfo" && ${${$c2}->getNamespace}->getValue eq $DSIG_NS) {
            foreach my $c3(${$c2}->getChildNodes) {
              if(${$c3}->getLocalName eq "SignatureMethod" && ${${$c3}->getNamespace}->getValue eq $DSIG_NS) {
                $tokenInfo{DSIG_RSA_SHA1_ALGO} = ${$c3}->getAttribute('Algorithm');
              }
              elsif(${$c3}->getLocalName eq "CanonicalizationMethod" && ${${$c3}->getNamespace}->getValue eq $DSIG_NS) {
                $tokenInfo{CANON_EXCLUSIVE_ALGO} = ${$c3}->getAttribute('Algorithm');
              }
              elsif(${$c3}->getLocalName eq "Reference" && ${${$c3}->getNamespace}->getValue eq $DSIG_NS) {
                my $uri = ${$c3}->getAttribute('URI');
                my ($scheme, $auth, $path, $query, $frag) = URI::Split::uri_split($uri);
                my $expected_assertion_id;
                if($scheme and lc($scheme) ne "uri") {
                  $expected_assertion_id = $uri; 
                }
                elsif($uri =~ /^\#/) {
                  $expected_assertion_id = $frag;
                }
                $tokenInfo{EXPECTED_ASSERTION_ID} = $expected_assertion_id if $expected_assertion_id;

                foreach my $c4(${$c3}->getChildNodes) {
                  if(${$c4}->getLocalName eq "Transforms" && ${${$c4}->getNamespace}->getValue eq $DSIG_NS) {
                    my @transforms = ();
                    foreach my $c5(${$c4}->getChildNodes) {
                      if(${$c5}->getLocalName eq "Transform" && ${${$c5}->getNamespace}->getValue eq $DSIG_NS) {
                        push @transforms, ${$c5}->getAttribute('Algorithm');
                      }
                    }
                    $tokenInfo{TRANSFORMS} = \@transforms;
                  }
                  elsif(${$c4}->getLocalName eq "DigestMethod" && ${${$c4}->getNamespace}->getValue eq $DSIG_NS) {
                    $tokenInfo{DIGEST_METHOD} = ${$c4}->getAttribute('Algorithm');
                  }
                }
              }
            }
          }
          elsif(${$c2}->getLocalName eq "KeyInfo" && ${${$c2}->getNamespace}->getValue eq $DSIG_NS) {
            foreach my $c3(${$c2}->getChildNodes) {
              if(${$c3}->getLocalName eq "KeyValue" && ${${$c3}->getNamespace}->getValue eq $DSIG_NS) {
                foreach my $c4(${$c3}->getChildNodes) {
                  if(${$c4}->getLocalName eq "RSAKeyValue" && ${${$c4}->getNamespace}->getValue eq $DSIG_NS) {
                    foreach my $c5(${$c4}->getChildNodes) {
                      if(${$c5}->getLocalName eq "Modulus" && ${${$c5}->getNamespace}->getValue eq $DSIG_NS) {
                        my $modulus = ${${$c5}->getFirstChild}->getValue;
                        $modulus =~ s/\n//g;
                        $modulus =~ s/\r//g;
                        $tokenInfo{RSA_MODULUS} = $modulus;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
      elsif($saml_ns and ${$c}->getLocalName eq "AttributeStatement" and ${${$c}->getNamespace}->getValue eq $saml_ns) {
        my %attributes = ();
        foreach my $c2(${$c}->getChildNodes) {
          if(${$c2}->getLocalName eq "Attribute" && ${${$c2}->getNamespace}->getValue eq $saml_ns) {
            my @attr = ();
            my $attr_ns = ${$c2}->getAttribute('AttributeNamespace');
            my $attr_name = ${$c2}->getAttribute('AttributeName');
            my @attr_value = ();
            foreach my $c3(${$c2}->getChildNodes) {
              if(${$c3}->getLocalName eq "AttributeValue" && ${${$c3}->getNamespace}->getValue eq $saml_ns) {
                push @attr_value, ${${$c3}->getFirstChild}->getValue;
              } 
            }
            $attributes{"${attr_ns}/${attr_name}"} = [$attr_ns, $attr_name, @attr_value];
          }
        }
        $tokenInfo{ATTRIBUTES} = \%attributes;
      }
    }
  }

  verifyToken(\%tokenInfo);
  if($tokenInfo{ERROR}) {
    $tokenInfo{TOKEN_VERIFIED} = 0;
  }
  else {
    $tokenInfo{TOKEN_VERIFIED} = 1;
  }

  return \%tokenInfo;
}

sub verifyToken {
  my $tokenInfo = shift;

  #foreach my $k(keys %$tokenInfo) {
  #  print "$k -> $$tokenInfo{$k}\n";
  #}

  unless($$tokenInfo{ROOT_NODE_NAME} and $$tokenInfo{ROOT_NODE_NAME} eq "Assertion") {
    $$tokenInfo{ERROR} = "Root node is not Assertion"; return;
  }

  unless($$tokenInfo{ROOT_NODE_NS} and $$tokenInfo{ROOT_NODE_NS} eq $SAML_ASSERTION_1_0_NS or $$tokenInfo{ROOT_NODE_NS} eq $SAML_ASSERTION_1_1_NS) {
    $$tokenInfo{ERROR} = "Unsupported SAML Assertion: $$tokenInfo{ROOT_NODE_NS}"; return;
  }

  unless($$tokenInfo{MAJOR_VERSION} and $$tokenInfo{MAJOR_VERSION} eq "1") {
    $$tokenInfo{ERROR} = "Invalid MajorVersion: $$tokenInfo{MAJOR_VERSION}"; return;
  }

  unless($$tokenInfo{MINOR_VERSION} and $$tokenInfo{MINOR_VERSION} eq "1") {
    $$tokenInfo{ERROR} = "Invalid MinorVersion: $$tokenInfo{MINOR_VERSION}"; return;
  }

  unless($$tokenInfo{ASSERTION_ID}) {
    $$tokenInfo{ERROR} = "Missing AssertionID Attribute"; return;
  }

  #unless($$tokenInfo{ISSUE_INSTANT}) {
  #  $$tokenInfo{ERROR} = "Missing IssueInstant Attribute"; return;
  #}

  unless($$tokenInfo{ISSUER}) {
    $$tokenInfo{ERROR} = "Missing Issuer Attribute"; return;
  }

  unless($$tokenInfo{NOT_BEFORE}) {
    $$tokenInfo{ERROR} = "Missing NotBefore Attribute"; return;
  }

  unless($$tokenInfo{NOT_ON_OR_AFTER}) {
    $$tokenInfo{ERROR} = "Missing NotOnOrAfter Attribute"; return;
  }

  if(!$$tokenInfo{AUDIENCE} and $$tokenInfo{ISSUER} eq $XMLSOAP_SELF_ISSUED) {
    $$tokenInfo{ERROR} = "Missing Audience node"; return;
  }

  unless($$tokenInfo{DSIG_RSA_SHA1_ALGO} and $$tokenInfo{DSIG_RSA_SHA1_ALGO} eq $DSIG_RSA_SHA1) {
    $$tokenInfo{ERROR} = "Invalid SignatureMethod Algorithm: expected $DSIG_RSA_SHA1, got $$tokenInfo{DSIG_RSA_SHA1_ALGO}"; return;
  }

  unless($$tokenInfo{CANON_EXCLUSIVE_ALGO} and $$tokenInfo{CANON_EXCLUSIVE_ALGO} eq $CANON_EXCLUSIVE) {
    $$tokenInfo{ERROR} = "Invalid CanonicalizationMethod Algorithm: expected $CANON_EXCLUSIVE, got $$tokenInfo{CANON_EXCLUSIVE_ALGO}"; return;
  }

  unless($$tokenInfo{EXPECTED_ASSERTION_ID} and $$tokenInfo{EXPECTED_ASSERTION_ID} eq $$tokenInfo{ASSERTION_ID}) {
    $$tokenInfo{ERROR} = "Signature does not refer to the root node: expected $$$tokenInfo{ASSERTION_ID}, got $$tokenInfo{EXPECTED_ASSERTION_ID}"; return;
  }

  my @all_transforms = sort @{$$tokenInfo{TRANSFORMS}};
  my @expected_transforms = sort ($CANON_EXCLUSIVE, $DSIG_ENVELOPED_SIG);
  unless(compare_arrays(\@all_transforms, \@expected_transforms)) {
    $$tokenInfo{ERROR} = "Signature did not use expected transforms: expected @expected_transforms, got @all_transforms"; return;
  }
  
  unless($$tokenInfo{DIGEST_METHOD} and $$tokenInfo{DIGEST_METHOD} eq $DSIG_SHA1) {
    $$tokenInfo{ERROR} = "Invalid DigestMethod Algorithm: expected $DSIG_RSA_SHA1, got $$tokenInfo{DIGEST_METHOD}"; return;
  }
  
  unless($$tokenInfo{RSA_MODULUS}) {
    $$tokenInfo{ERROR} = "Invalid RSA Key:"; return;
  }

  my %attribs = %{$$tokenInfo{ATTRIBUTES}};
  unless(%attribs and keys(%attribs) > 0) {
    $$tokenInfo{ERROR} = "No attributes returned"; return;
  }

  unless(checkAudience($$tokenInfo{AUDIENCE}, \$$tokenInfo{ERROR}, $$tokenInfo{ISSUER})) {
    return;
  }

  unless(isExpired($$tokenInfo{NOT_BEFORE}, $$tokenInfo{NOT_ON_OR_AFTER}, \$$tokenInfo{ERROR})) {
    return;
  }
}

sub checkAudience {
  my $uri = shift;
  my $err = shift;
  my $issuer = shift;

  return 1 if(!$uri and $issuer ne $XMLSOAP_SELF_ISSUED);

  my ($scheme, $host) = URI::Split::uri_split($uri);
  if($scheme ne "https") {
    $$err = "Specified audience is not SSL"; return 0;
  }

  $host =~ s/\:.*$//;
  my $cn = getCommonName();
  if($cn =~ /^\*\./) {
    $cn =~ s/^\*//;
    unless($host =~ /${cn}$/) {
      $$err = "${cn} is not under ${host}"; return 0;
    } 
  }
  elsif($host ne $cn) {
      $$err = "${cn} is not under ${host}"; return 0;
  }

  return 1;
}

sub isExpired {
  my $not_before = shift;
  my $not_on_or_after = shift;
  my $err = shift;

  my $now = DateTime->now;
  my $slop = DateTime::Duration->new(minutes => 5);
  my $expired = DateTime->compare($now, $not_on_or_after + $slop) == 1 || DateTime->compare($now, $not_before - $slop) == -1; 

  if($expired) {
    $$err = "Got expired token: now=$now, not_before=$not_before, not_after=$not_on_or_after";
  }

  return $expired;
}

sub compare_arrays {
  my ($first, $second) = @_;
  no warnings;  # silence spurious -w undef complaints
  return 0 unless @$first == @$second;
  for (my $i = 0; $i < @$first; $i++) {
    return 0 if $first->[$i] ne $second->[$i];
  }
  return 1;
}  

sub verifyArguments {
  unless($PRIV_KEY_PATH) {
    print STDERR "Private key path is not specified";
  }

  unless($PUB_KEY_PATH) {
    print STDERR "Public key path is not specified";
  }

  return;
}

sub getCommonName {
  my $cmd = opensslCmdPrefix() .
            "x509 -noout " .
            "-in $PUB_KEY_PATH " .
            "-subject";
  my $sub = `$cmd`;
  $sub =~ s/\n//; $sub =~ s/\r//;
  my %h = ();
  map {my($k, $v) = split(/=/); $h{$k} = $v if $k and $v;} split(/\//, $sub);
  return $h{CN};
}



1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

InfoCard - Perl extension for validating, decrypting, verifying and extracting claims from encrypted Information Card SAML token submitted by an Identity Selector.

=head1 SYNOPSIS

  use CGI;
  use InfoCard;

  my $cgi = new CGI();
  .....
  my $infoCard = new InfoCard({PUB_KEY_PATH => "/etc/ssl/certs/server.crt", PRIV_KEY_PATH => "/etc/ssl/private/server.key"}); 
  $infoCard->process($cgi->param('xmlToken'));
  print $cgi->p("Token is valid") if $infoCard->valid;
  my %claims = %{$infoCard->claims};
  foreach my $c(keys %claims) {
    print $cgi->p("$c, $claims{$c}->[1], $claims{$c}->[2]");
  }
  ....

=head1 DESCRIPTION

This module is a PERL port of Python implementaion at http://code.google.com/p/py-self-issued-rp/. So all credit goes to 
developers of py-self-issued-rp.

This module uses the following native libraries:

1. xmlsec library from http://www.aleksey.com/xmlsec/

2. openssl library from http://www.openssl.org/

and the following PERL modules and it's dependencies:

1. File::Temp

2. XML::XPath

3. XML::XPath::NodeSet

4. XML::XPath::XMLParser

5. DateTime::Format::Strptime

6. URI::Split

=head1 CONSTRUCTOR

=over 4

=item * new(

		{

			PRIV_KEY_PATH => '/path/to/private_key',

			PUB_KEY_PATH => '/path/to/public_key',

			XMLSEC_PATH => '/path/to/xmlsec1', # optional

			OPENSSL_PATH => '/path/to/openssl', # optional

			LD_LIB_PATH => '/path/to/addtional/libs' #optional

             	}

	   )

=back

=head1 METHODS

This class offers the following methods:

=over 4

=item * libPath($LD_LIB_PATH)

=item * xmlsecPath($XMLSEC_PATH)

=item * openSSLPath($OPENSSL_PATH)

=item * pubKeyPath($PUB_KEY_PATH)

=item * privKeyPath($PRIV_KEY_PATH)

=item * process($encryptedXMLToken)

=item * valid()

=item * error()

=item * decryptedToken()

=item * signatureVerified()

=item * tokenVerified()

=item * dump()

=item * availableKeys()

=item * keyValue($key)

=item * claims()

=back

=head1 SEE ALSO

http://code.google.com/p/py-self-issued-rp/

=head1 AUTHOR

Jeesmon Jacob, E<lt>jeesmon at gmail dot comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008 by Jeesmon Jacob

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut
