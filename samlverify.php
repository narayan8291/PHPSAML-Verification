<?php

$verify = verifySiganture($_POST['SAMLResponse']);
$issuer = getIssuer($_POST['SAMLResponse']);
$consumer = getAudienceRestriction($_POST['SAMLResponse']);
$userdetails = explode(",", $consumer);
$useremail = $userdetails[0]; // User's email address
$audience = $userdetails[1]; // SAML Assertion - Receiver

if (strcmp($audience, <SP URL>) != 0) {
  exit("Invalid Audience");
}

else if (strcmp($issuer, <IDP URL>) != 0) {
  exit("Invalid Issuer");
}

if ($verify == 1) {
  // Set cookie or create a session 
}
else {
  exit ("Signature verification failed");
}

function verifySiganture($samlassertion) {
  $saml_response = base64_decode($samlassertion);
  $xmlDoc = new DOMDocument();
  $xmlDoc->loadXML($saml_response);
  $xpath = new DOMXPath($xmlDoc);
  $xpath->registerNamespace('secdsig', 'http://www.w3.org/2000/09/xmldsig#');

  // fetch Signature node from XML
  $query = ".//secdsig:Signature";
  $nodeset = $xpath->query($query, $xmlDoc);
  $signatureNode = $nodeset->item(0);

  // fetch SignedInfo node from XML
  $query = "./secdsig:SignedInfo";
  $nodeset = $xpath->query($query, $signatureNode);
  $signedInfoNode = $nodeset->item(0);

  // canonicalize SignedInfo using the method descried in secdsig:SignedInfo/secdsig:CanonicalizationMethod/@Algorithm
  $signedInfoNodeCanonicalized = $signedInfoNode->C14N(true, false);
  $query = 'string(./secdsig:KeyInfo/secdsig:X509Data/secdsig:X509Certificate)';
  $x509cert = $xpath->evaluate($query, $signatureNode);

  // Re-wrap the certificate from XML to respect the PEM standard
  $x509cert = "-----BEGIN CERTIFICATE-----\n" . $x509cert . "\n" . "-----END CERTIFICATE-----";

  // Get public key from x509 certificate

  $publicKey = openssl_get_publickey($x509cert);

  // Get Signature from XML

  $query = 'string(./secdsig:SignatureValue)';
  $signature = base64_decode($xpath->evaluate($query, $signatureNode));

  // Verify using php openssl library
  $ok = openssl_verify($signedInfoNodeCanonicalized, $signature, $publicKey);
  return $ok;

  // Free key from memory

  openssl_free_key($publicKey);
  }

function getAudienceRestriction($samlassertion) {
  $saml_response = base64_decode($samlassertion);
  $xml = simplexml_load_string($saml_response, 'SimpleXMLElement', 0, "urn:oasis:names:tc:SAML:2.0:assertion");
  $email_address = $xml->Assertion->Subject->NameID;
  $audience = $xml->Assertion->Conditions->AudienceRestriction->Audience;
  return $email_address . "," . $audience;
  }

function getIssuer($samlassertion) {
  $saml_response = base64_decode($samlassertion);
  $xml = simplexml_load_string($saml_response, 'SimpleXMLElement', 0, "urn:oasis:names:tc:SAML:2.0:assertion");
  $issuer = $xml->Assertion->Issuer;
  return $issuer;
  }
  
?>
