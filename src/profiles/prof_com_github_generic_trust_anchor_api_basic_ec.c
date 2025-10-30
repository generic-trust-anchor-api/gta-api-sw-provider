/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../gta_sw_provider.h"
#include <gta_api/gta_api.h>

#define PERS_ATTR_NAME_KEYTYPE "com.github.generic-trust-anchor-api.keytype.openssl"
#define PERS_ATTR_KEYTYPE_EC "EC"

GTA_SWP_DEFINE_FUNCTION(
    bool,
    personality_create,
    (struct gta_sw_provider_params_t * p_provider_params,
     gta_personality_name_t personality_name,
     personality_secret_type_t * p_pers_secret_type,
     unsigned char ** p_pers_secret_buffer,
     size_t * p_pers_secret_length,
     gta_personality_fingerprint_t pers_fingerprint,
     struct personality_attribute_t ** p_pers_attribute,
     gta_errinfo_t * p_errinfo))
{
    EVP_PKEY * p_key = NULL;
    p_key = EVP_EC_gen("P-256");
    *p_pers_secret_length = i2d_PrivateKey(p_key, p_pers_secret_buffer);
    EVP_PKEY_free(p_key);
    *p_pers_secret_type = SECRET_TYPE_DER;
    /* Calculate personality fingerprint */
    SHA512(*p_pers_secret_buffer, *p_pers_secret_length, (unsigned char *)pers_fingerprint);

    /* Add profile specific personality attribute */
    if (!add_personality_attribute_list_item(
            p_provider_params,
            p_pers_attribute,
            PAT_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_KEYTYPE_OPENSSL,
            (unsigned char *)PERS_ATTR_NAME_KEYTYPE,
            sizeof(PERS_ATTR_NAME_KEYTYPE),
            (unsigned char *)PERS_ATTR_KEYTYPE_EC,
            sizeof(PERS_ATTR_KEYTYPE_EC),
            true,
            p_errinfo)) {

        return false;
    }

    return true;
}

const struct profile_function_list_t fl_prof_com_github_generic_trust_anchor_api_basic_ec = {
    .personality_create = personality_create,
};
