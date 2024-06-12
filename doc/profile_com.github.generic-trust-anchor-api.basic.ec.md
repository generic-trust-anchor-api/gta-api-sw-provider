# com.github.generic-trust-anchor-api.basic.ec

## Description
The profile com.github.generic-trust-anchor-api.basic.ec supports the creation of a Elliptic Curve based personality.

The profile name com.github.generic-trust-anchor-api.basic.ec is used for a creation profile only.

## Creation
The following table specifies the behaviour of the function **gta_personality_create()**.

| **Property** | **Description** |
| ------------ | ----------------|
| Security Mechanism | secp256r1 |
| Fingerprinting* | The fingerprint is the SHA512 value of the DER encoded private key. |
| Attributes | **com.github.generic-trust-anchor-api.keytype.openssl****<BR><blockquote>An attribute of type “com.github.generic-trust-anchor-api.keytype.openssl” and with name ”com.github.generic-trust-anchor-api.keytype.openssl” is created, specifying the type of the secret attribute (“EC” in this case) of the personality.</blockquote> |
| Usage Info | Intended for use with com.github.generic-trust-anchor-api.basic.jwt and com.github.generic-trust-anchor-api.basic.tls |


*Fingerprinting: description under discussion; may be changed in the future<br>
**Attribute type/name: under discussion; may be changed in the future
