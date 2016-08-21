# PHPSAML-Verification
Verification of SAML Response

This piece of code can be used to verify the SAML response from an IDP like OKTA, OneLogin. Users who do not wish to use libraries like SimpleSAMLPHP can use this to verify the digital signature contained within a SAML response. 

The code performs:
1. Verifies the Digital Signature
2. Verifies the IDP and SP URL. 

NOTE: We can also include reference validation (http://massimilianosciacco.com/validate-saml-assertion-signature) in addition to the digital signature validation. 
