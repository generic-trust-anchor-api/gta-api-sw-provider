# com.github.generic-trust-anchor-api.basic.tls

## Description
The profile com.github.generic-trust-anchor-api.basic.tls supports the signature creation for authentication during a TLS handshake.

The same profile name com.github.generic-trust-anchor-api.basic.tls is used for a enrollment and a usage profile.

## Enrollment
The following table specifies the behaviour of the function **gta_personality_enroll()**. <br>The function gta_personality_enroll_auth() is not defined in this profile and any calls to it shall result in GTA_ERROR_PROFILE_UNSUPPORTED.

The enrollment function for profile com.github.generic-trust-anchor-api.basic.tls allows an application to get the public key of a personality, corresponding to its private key.

| **Property** | **Description** |
| ------------ | ----------------|
| Profile Dependencies | Shall be usable with any personality that is created with com.github.generic-trust-anchor-api.basic.ec and com.github.generic-trust-anchor-api.basic.dilithium |
| Enrollment Attributes | N/A |
| Enrollment Artifact | PEM encoded public key |

## Usage
Usage of the profile with any other function than those functions listed in the table shall result in GTA_ERROR_PROFILE_UNSUPPORTED.

| **Property** | **Description** |
| ------------ | ----------------|
| Profile Dependencies | Shall be usable with any personality that is created with com.github.generic-trust-anchor-api.basic.ec and com.github.generic-trust-anchor-api.basic.dilithium |
| Supported Functions | **gta_personality_get_attribute()**<br><blockquote>Allows personality attributes of the following types to be retrieved:<ul><li> <u>ch.iec.30168.trustlist.certificate.self.x509</u> - Public key certificate for the personalities end entity in X.509 ASN.1 DER coding.</li><li> <u>ch.iec.30168.trustlist.certificate.trusted.x509v3</u> - Trusted public key certificate in X.509 ASN.1 DER coding; Validation of a public key certificate chain can stop at this certificate. The public key certificate can be a self-signed root certificate or any other certificate that is directly trusted by the personality.</li><li> <u>com.github.generic-trust-anchor-api.keytype.openssl</u> - A string specifying the type of the secret attribute (e.g., private key) of the personality.</li></ul></blockquote><br>**gta_authenticate_data_detached()**<br><blockquote>computes a digital signature for the data provided as input data.</blockquote> |
| Usage Attributes | N/A |
| Usage Artifact | digital signature as raw bytes. todo: describe details depending on supported algorithms |
