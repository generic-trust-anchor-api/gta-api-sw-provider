# com.github.generic-trust-anchor-api.basic.rsa

## Description
The profile com.github.generic-trust-anchor-api.basic.rsa supports the creation of a RSA based personality.

The profile name com.github.generic-trust-anchor-api.basic.rsa is used for a creation profile only.

## Creation
The following table specifies the behaviour of the function **gta_personality_create()**.

| **Property** | **Description** |
| ------------ | ----------------|
| Security Mechanism | RSA2048 |
| Fingerprinting* | The fingerprint is the SHA512 value of the DER encoded private key. |
| Attributes | N/A |
| Usage Info | Intended for use with com.github.generic-trust-anchor-api.basic.jwt |

*Fingerprinting: description under discussion; may be changed in the future<br>

## FURTHER TODO:
- Attributes: no attribute vs. RSA?
