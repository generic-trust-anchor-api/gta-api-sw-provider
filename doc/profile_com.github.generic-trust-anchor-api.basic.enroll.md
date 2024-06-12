# com.github.generic-trust-anchor-api.basic.enroll

## Description
The profile com.github.generic-trust-anchor-api.basic.enroll supports the generation of a Certificate Signing Request (CSR) as PKCS#10 in PEM.

The same profile name com.github.generic-trust-anchor-api.basic.enroll is used for a enrollment and usage profile:
- Generation of a certificate signing request (CSR) [see [Enrollment](#enrollment)]
- Adding personality attributes as part of the enrollment process (e.g. the issued certificate from the PKI) [see [Usage](#usage)]

## Enrollment
The following table specifies the behaviour of the function **gta_personality_enroll()**. <br>The function gta_personality_enroll_auth() is not defined in this profile and any calls to it shall result in GTA_ERROR_PROFILE_UNSUPPORTED.

| **Property** | **Description** |
| ------------ | ----------------|
| Profile Dependencies | Shall be usable with any personality that is created with com.github.generic-trust-anchor-api.basic.rsa and com.github.generic-trust-anchor-api.basic.ec |
| Enrollment Attributes | Context Attributes:<br>**com.github.generic-trust-anchor-api.enroll.subject_rdn** (optional)<br><blockquote>Subject RDN String  as defined in RFC4514.</blockquote> |
| Enrollment Artifact | The enrollment artifact is a Certificate Signing Request (CSR) as PKCS#10 in PEM. |

## Usage
Usage of the profile with any other function than those functions listed in the table shall result in GTA_ERROR_PROFILE_UNSUPPORTED.

| **Property** | **Description** |
| ------------ | ----------------|
| Profile Dependencies | Shall be usable with any personality that is created with com.github.generic-trust-anchor-api.basic.rsa and com.github.generic-trust-anchor-api.basic.ec |
| Supported Functions | **gta_personality_add_attribute()**<br>**gta_personality_add_trusted_attribute()**<br><blockquote>Allows personality attributes of the following types to be added to a personality: <ul><li> <u>ch.iec.30168.trustlist.certificate.self.x509</u> - Public key certificate for the personalities end entity in X.509 ASN.1 DER coding. </li><li> <u>ch.iec.30168.trustlist.certificate.trusted.x509v3</u> - Trusted public key certificate in X.509 ASN.1 DER coding; Validation of a public key certificate chain can stop at this certificate. The public key certificate can be a self-signed root certificate or any other certificate that is directly trusted by the personality.</li></ul></blockquote> |
| Usage Attributes | N/A |
| Usage Artifact | N/A |


*Fingerprinting: description under discussion; may be changed in the future<br>
**Attribute type/name: under discussion; may be changed in the future
