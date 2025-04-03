/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#include <gta_api/gta_api.h>
#include <gta_api/util/gta_memset.h>
#include "../gta_sw_provider.h"

#define PROFILE_MIN_PASSCODE_LEN 16

const char * allowed_passcode_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ()[]{}%*&-+<>!?=$#";

GTA_SWP_DEFINE_FUNCTION(bool, context_open,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gta_errinfo_t * p_errinfo
))
{
    return true;
}

GTA_SWP_DEFINE_FUNCTION(bool, personality_deploy,
(
    struct gta_sw_provider_params_t * p_provider_params,
    gta_personality_name_t personality_name,
    gtaio_istream_t * personality_content,
    personality_secret_type_t * p_pers_secret_type,
    unsigned char ** p_pers_secret_buffer,
    size_t * p_pers_secret_length,
    gta_personality_fingerprint_t pers_fingerprint,
    struct personality_attribute_t ** p_pers_attribute,
    gta_errinfo_t * p_errinfo
))
{
    EVP_MD_CTX * ctx = NULL;
    unsigned char digest[SHA256_DIGEST_LENGTH] = { 0 };

    /* Read personality content into buffer */
    unsigned char * data = NULL;
    size_t len = 0;
    if (!read_input_buffer(personality_content, &data, &len, p_errinfo)) {
        return false;
    }

    /* Check min length */
    if (PROFILE_MIN_PASSCODE_LEN > len) {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        goto err;
    }

    /* Check if passcode contains only valid characters and is terminated with '\0' */
    if (('\0' != data[len-1]) || ((len-1) != strspn((char *)data, allowed_passcode_chars))) {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        goto err;
    }

    *p_pers_secret_type = SECRET_TYPE_PASSCODE;
    *p_pers_secret_buffer = data;
    *p_pers_secret_length = len;

    /* Calculate personality fingerprint as specified in profile */
    memset(pers_fingerprint, 0x00, sizeof(gta_personality_fingerprint_t));

    /*
     * This should be set to 0x01 in case the fingerprinting is done as
     * specified. As the TS doesn't state clearly which hash function should
     * be used, we define our own way here.
     */
    pers_fingerprint[0] = 0x01;
    if (!RAND_bytes((unsigned char*)&pers_fingerprint[1], 32)) {
        goto internal_err;
    }

    /* Compute hash */
    ctx = EVP_MD_CTX_new();
    if (NULL == ctx) {
        goto internal_err;
    }
    if (1 != EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL)) {
        goto internal_err;
    }
    /* Hash the first 40 bytes of the fingerprint */
    if (1 != EVP_DigestUpdate(ctx, pers_fingerprint, 40)) {
        goto internal_err;
    }
    /* Hash the personality name w/o the terminating '\0' */
    if (1 != EVP_DigestUpdate(ctx, personality_name, strnlen(personality_name, PERSONALITY_NAME_LENGTH_MAX))) {
        goto internal_err;
    }
    /* Hash the passcode w/o the terminating '\0' */
    if (1 != EVP_DigestUpdate(ctx, data, len-1)) {
        goto internal_err;
    }

    if (1 != EVP_DigestFinal_ex(ctx, digest, NULL)) {
        goto internal_err;
    }

    /* Copy the first 24 bytes of digest to the fingerprint */
    memcpy(&pers_fingerprint[40], digest, 24);
    EVP_MD_CTX_free(ctx);

    /* No profile specific personality attributes */
    *p_pers_attribute = NULL;

    return true;

internal_err:
    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
err:
    OPENSSL_clear_free(data, len);
    *p_pers_secret_buffer = NULL;
    *p_pers_secret_length = 0;
    EVP_MD_CTX_free(ctx);
    return false;
}

GTA_SWP_DEFINE_FUNCTION(bool, verify,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gtaio_istream_t * claim,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;
    const struct personality_t * p_personality_content = NULL;
    char p_buffer[CHUNK_LEN] = { 0 };
    size_t buffer_idx = 0;
    size_t len = 0;

    /* get personality of the context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    /*
     * read input in chunks and compare chunk-wise.
     * Note: This comparison is not done in constant time and may lead to side-
     * channel attacks. (todo)
     */
    while (!claim->eof(claim, p_errinfo)) {
        len = claim->read(claim, p_buffer, CHUNK_LEN, p_errinfo);
        if ((0 == len)
            || (p_personality_content->secret_data_size < (len + buffer_idx))
            || (0 != memcmp(p_personality_content->secret_data + buffer_idx, p_buffer, len))) {

            *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
            goto err;
        }
        buffer_idx += len;
    }

    /* Check if passcode check was successful */
    if (p_personality_content->secret_data_size != buffer_idx) {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        goto err;
    }

    /* If passcode verification is successful, we set the condition in the ctx to true */
    p_context_params->b_pers_derived_access_token_condition_fulfilled = true;
    ret = true;

err:
    /* Clear memory */
    gta_memset(p_buffer, CHUNK_LEN, 0, CHUNK_LEN);

    return ret;
}

const struct profile_function_list_t fl_prof_ch_iec_30168_basic_passcode = {
    .context_open = context_open,
    .personality_deploy = personality_deploy,
    .personality_attribute_functions_supported = true,
    .verify = verify,
};
