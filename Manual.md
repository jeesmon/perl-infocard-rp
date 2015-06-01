
```
InfoCard(3)           User Contributed Perl Documentation          InfoCard(3)



NAME
       InfoCard − Perl extension for validating, decrypting, verifying and
       extracting claims from encrypted Information Card SAML token submitted
       by an Identity Selector.

SYNOPSIS
         use CGI;
         use InfoCard;

         my $cgi = new CGI();
         .....
         my $infoCard = new InfoCard({PUB_KEY_PATH => "/etc/ssl/certs/server.crt", PRIV_KEY_PATH => "/etc/ssl/private/server.key"});
         $infoCard−>process($cgi−>param(’xmlToken’));
         print $cgi−>p("Token is valid") if $infoCard−>valid;
         my %claims = %{$infoCard−>claims};
         foreach my $c(keys %claims) {
           print $cgi−>p("$c, $claims{$c}−>[1], $claims{$c}−>[2]");
         }
         ....

DESCRIPTION
       This module is a PERL port of Python implementaion at
       http://code.google.com/p/py−self−issued−rp/. So all credit goes to
       developers of py‐self‐issued‐rp.

       This module uses the following native libraries:

       1. xmlsec library from http://www.aleksey.com/xmlsec/

       2. openssl library from http://www.openssl.org/

       and the following PERL modules and it’s dependencies:

       1. File::Temp

       2. XML::XPath

       3. XML::XPath::NodeSet

       4. XML::XPath::XMLParser

       5. DateTime

       6. URI::Split

CONSTRUCTOR
       ·   new(

                           {

                                   PRIV_KEY_PATH => ’/path/to/private_key’,

                                   PUB_KEY_PATH => ’/path/to/public_key’,

                                   XMLSEC_PATH => ’/path/to/xmlsec1’, # optional

                                   OPENSSL_PATH => ’/path/to/openssl’, # optional

                                   LD_LIB_PATH => ’/path/to/addtional/libs’ #optional

                           }

                      )

METHODS
       This class offers the following methods:

       ·   libPath($LD_LIB_PATH)

       ·   xmlsecPath($XMLSEC_PATH)

       ·   openSSLPath($OPENSSL_PATH)

       ·   pubKeyPath($PUB_KEY_PATH)

       ·   privKeyPath($PRIV_KEY_PATH)

       ·   process($encryptedXMLToken)

       ·   valid()

       ·   error()

       ·   decryptedToken()

       ·   signatureValid()

       ·   tokenVerified()

       ·   dump()

       ·   availableKeys()

       ·   keyValue($key)

       ·   claims()

       ·   issuer()

SEE ALSO
       http://code.google.com/p/py−self−issued−rp/

AUTHOR
       Jeesmon Jacob, <jeesmon at gmail dot com>

COPYRIGHT AND LICENSE
       Copyright (C) 2008 by Jeesmon Jacob

       This library is free software; you can redistribute it and/or modify it
       under the same terms as Perl itself, either Perl version 5.8.8 or, at
       your option, any later version of Perl 5 you may have available.



perl v5.8.8                       2008‐10‐07                       InfoCard(3)
```