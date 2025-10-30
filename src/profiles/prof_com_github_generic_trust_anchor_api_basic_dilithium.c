/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#include <gta_api/gta_api.h>
#include "../gta_sw_provider.h"
#include "../helper_functions.h"

#define PERS_ATTR_NAME_KEYTYPE          "com.github.generic-trust-anchor-api.keytype.openssl"
#define PERS_ATTR_KEYTYPE_DILITHIUM2    "dilithium2"

#ifdef ENABLE_PQC

#define OQS_SIGN_ALGORITHM OQS_SIG_alg_dilithium_2

GTA_SWP_DEFINE_FUNCTION(bool, personality_create,
(
    struct gta_sw_provider_params_t * p_provider_params,
    gta_personality_name_t personality_name,
    personality_secret_type_t * p_pers_secret_type,
    unsigned char ** p_pers_secret_buffer,
    size_t * p_pers_secret_length,
    gta_personality_fingerprint_t pers_fingerprint,
    struct personality_attribute_t ** p_pers_attribute,
    gta_errinfo_t * p_errinfo
))
{
    OQS_SIG *signer = NULL;
    OQS_STATUS rc = OQS_ERROR;
    bool ret = false;

    OQS_init();
    signer = OQS_SIG_new(OQS_SIGN_ALGORITHM);
    if (signer == NULL) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    /*
    * SECRET_TYPE_DILITHIUM2 is a concatenation of the private key and
    * the public key.
    */
   *p_pers_secret_length = signer->length_secret_key + signer->length_public_key;
   *p_pers_secret_buffer = OPENSSL_zalloc(*p_pers_secret_length);
    if (NULL == *p_pers_secret_buffer) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    rc = OQS_SIG_keypair(signer, (*p_pers_secret_buffer + signer->length_secret_key), *p_pers_secret_buffer);
    if (rc != OQS_SUCCESS) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    *p_pers_secret_type = SECRET_TYPE_DILITHIUM2;
    /* Calculate personality fingerprint */
    SHA512(*p_pers_secret_buffer, *p_pers_secret_length, (unsigned char *)pers_fingerprint);

    /* Add profile specific personality attribute */
    if (!add_personality_attribute_list_item(p_provider_params,
        p_pers_attribute, PAT_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_KEYTYPE_OPENSSL,
        (unsigned char *)PERS_ATTR_NAME_KEYTYPE, sizeof(PERS_ATTR_NAME_KEYTYPE),
        (unsigned char *)PERS_ATTR_KEYTYPE_DILITHIUM2, sizeof(PERS_ATTR_KEYTYPE_DILITHIUM2),
        true, p_errinfo)) {

        goto err;
    }

    ret = true;
err:
    OQS_SIG_free(signer);
    return ret;
}

const struct profile_function_list_t fl_prof_com_github_generic_trust_anchor_api_basic_dilithium = {
    .personality_create = personality_create,
};
#endif