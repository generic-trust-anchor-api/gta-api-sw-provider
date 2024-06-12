# com.github.generic-trust-anchor-api.basic.jwt

## Description
The profile com.github.generic-trust-anchor-api.basic.jwt supports the creation of a signed JWT.

The same profile name com.github.generic-trust-anchor-api.basic.jwt is used for a enrollment and a usage profile.

## Enrollment
The following table specifies the behaviour of the function **gta_personality_enroll()**. <br>The function gta_personality_enroll_auth() is not defined in this profile and any calls to it shall result in GTA_ERROR_PROFILE_UNSUPPORTED.

| **Property** | **Description** |
| ------------ | ----------------|
| Profile Dependencies | Shall be usable with any personality that is created with com.github.generic-trust-anchor-api.basic.rsa and com.github.generic-trust-anchor-api.basic.ec |
| Enrollment Attributes | N/A |
| Enrollment Artifact | PEM encoded public key |

## Usage
Usage of the profile with any other function than those functions listed in the table shall result in GTA_ERROR_PROFILE_UNSUPPORTED.

| **Property** | **Description** |
| ------------ | ----------------|
| Profile Dependencies | Shall be usable with any personality that is created with com.github.generic-trust-anchor-api.basic.rsa and com.github.generic-trust-anchor-api.basic.ec |
| Supported Functions | **gta_seal_data()**<br><blockquote>Gets base64 encoded JWT payload and creates signed JWT (header.payload.signature). </blockquote>|
| Usage Attributes | N/A |
| Usage Artifact | Encoded JWT |
