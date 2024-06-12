# com.github.generic-trust-anchor-api.basic.dilithium

## Description
The profile com.github.generic-trust-anchor-api.basic.dilithium supports the creation of a Dilithium based personality.

The profile name com.github.generic-trust-anchor-api.basic.dilithium is used for a creation profile only.

## Creation
The following table specifies the behaviour of the function **gta_personality_create()**.

| **Property** | **Description** |
| ------------ | ----------------|
| Security Mechanism | Dilithium2 |
| Fingerprinting* | The fingerprint is the SHA512 value of the concatenation (raw private key \| raw public key). |
| Attributes | **com.github.generic-trust-anchor-api.keytype.openssl****<BR><blockquote>An attribute of type “com.github.generic-trust-anchor-api.keytype.openssl” and with name ”com.github.generic-trust-anchor-api.keytype.openssl” is created, specifying the type of the secret attribute (“dilithium2” in this case) of the personality. </blockquote>|
| Usage Info | Intended for use with com.github.generic-trust-anchor-api.basic.tls |


*Fingerprinting: description under discussion; may be changed in the future<br>
**Attribute type/name: under discussion; may be changed in the future

## FURTHER TODO:
- Dilithium to be renamed to NIST final standard (ML-DSA)
- Dilithium2 security level to be renamed to ML-DSA-44

