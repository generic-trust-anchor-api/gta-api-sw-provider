/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#include <gta_api/gta_api.h>
#include "../gta_sw_provider.h"

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
    EVP_PKEY * p_key = NULL;
    p_key = EVP_RSA_gen(2048);
    *p_pers_secret_length = i2d_PrivateKey(p_key, p_pers_secret_buffer);
    EVP_PKEY_free(p_key);
    *p_pers_secret_type = SECRET_TYPE_DER;
    /* Calculate personality fingerprint */
    SHA512(*p_pers_secret_buffer, *p_pers_secret_length, (unsigned char *)pers_fingerprint);

    /* No profile specific personality attributes */
    *p_pers_attribute = NULL;

    return true;
}

const struct profile_function_list_t fl_prof_com_github_generic_trust_anchor_api_basic_rsa = {
    .personality_create = personality_create,
};
