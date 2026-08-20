/*
 * SPDX-FileCopyrightText: Copyright 2025-2026 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../gta_sw_provider.h"
#include "prof_helper_functions.h"
#include <gta_api/gta_api.h>

GTA_SWP_DEFINE_FUNCTION(
    bool,
    context_open,
    (struct gta_sw_provider_context_params_t * p_context_params, gta_errinfo_t * p_errinfo))
{
    bool ret = false;
    const struct personality_t * p_personality_content = NULL;
    EVP_PKEY * evp_private_key = NULL;

    if (SECRET_TYPE_DER == p_context_params->p_personality_item->p_personality_content->secret_type) {
        /* get the private key from the personality */
        p_personality_content = p_context_params->p_personality_item->p_personality_content;
        evp_private_key =
            get_pkey_from_der(p_personality_content->secret_data, p_personality_content->secret_data_size, p_errinfo);
        if (NULL == evp_private_key) {
            goto err;
        }

        int key_id = EVP_PKEY_base_id(evp_private_key);

        /*
         * Check profile restrictions on personality:
         * RSA 2048, ECC P-256, and ML-DSA-44 are allowed.
         */
        if (!(((EVP_PKEY_RSA == key_id) && (2048 == pkey_bits(evp_private_key))) ||
              ((EVP_PKEY_EC == key_id) && (NID_X9_62_prime256v1 == pkey_ec_nid(evp_private_key))) ||
              (EVP_PKEY_is_a(evp_private_key, "ML-DSA-44")))) {

            DEBUG_PRINT(("gta_sw_provider_gta_context_open: Profile requirements not fulfilled \n"));
            *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
            goto err;
        }
        ret = true;
    } else {
        DEBUG_PRINT(("gta_sw_provider_gta_context_open: Personality type not as expected\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
    }

err:
    EVP_PKEY_free(evp_private_key);
    return ret;
}

GTA_SWP_DEFINE_FUNCTION(
    bool,
    personality_enroll,
    (struct gta_sw_provider_context_params_t * p_context_params,
     gtaio_ostream_t * p_personality_enrollment_info,
     gta_errinfo_t * p_errinfo))
{
    bool ret = false;
    BIO * bio = NULL;
    long len = 0;
    char * pem_data = NULL;
    EVP_PKEY * p_key = NULL;
    struct personality_t * p_personality_content = NULL;

    /* get personality of the context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    if (SECRET_TYPE_DER != p_personality_content->secret_type) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    p_key = get_pkey_from_der(p_personality_content->secret_data, p_personality_content->secret_data_size, p_errinfo);
    if (NULL == p_key) {
        goto err;
    }

    /* get public key in PEM */
    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, p_key);
    len = BIO_get_mem_data(bio, &pem_data);

    /* len always >= 0 */
    if ((size_t)len !=
        p_personality_enrollment_info->write(p_personality_enrollment_info, pem_data, (size_t)len, p_errinfo)) {
        goto err;
    }
    p_personality_enrollment_info->finish(p_personality_enrollment_info, 0, p_errinfo);
    ret = true;

err:
    EVP_PKEY_free(p_key);
    if (NULL != bio) {
        BIO_free_all(bio);
    }
    return ret;
}

GTA_SWP_DEFINE_FUNCTION(
    bool,
    authenticate_data_detached,
    (struct gta_sw_provider_context_params_t * p_context_params,
     gtaio_istream_t * data,
     gtaio_ostream_t * seal,
     gta_errinfo_t * p_errinfo))
{
    bool ret = false;
    char payload_chunk[CHUNK_LEN];
    unsigned char * signature = NULL;
    size_t signature_len = 0;

    EVP_MD_CTX * mdctx = NULL;
    EVP_PKEY * evp_private_key = NULL;
    unsigned char * p_buffer_in = NULL;
    size_t buffer_idx_in = 0;

    struct personality_t * p_personality_content = NULL;

    /* get Personality of the Context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    if (SECRET_TYPE_DER != p_personality_content->secret_type) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    evp_private_key =
        get_pkey_from_der(p_personality_content->secret_data, p_personality_content->secret_data_size, p_errinfo);
    if (NULL == evp_private_key) {
        goto err;
    }

    /* Create the Message Digest Context */
    if (!(mdctx = EVP_MD_CTX_new())) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    if (EVP_PKEY_is_a(evp_private_key, "ML-DSA-44")) {
        /* ML-DSA requires one-shot EVP_DigestSign (no streaming support) */
        if (1 != EVP_DigestSignInit(mdctx, NULL, NULL, NULL, evp_private_key)) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        if (!read_input_buffer(data, &p_buffer_in, &buffer_idx_in, p_errinfo)) {
            goto err;
        }

        /* Get signature length */
        if (1 != EVP_DigestSign(mdctx, NULL, &signature_len, p_buffer_in, buffer_idx_in)) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        if (!(signature = OPENSSL_malloc(signature_len))) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        if (1 != EVP_DigestSign(mdctx, signature, &signature_len, p_buffer_in, buffer_idx_in)) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }
    } else {
        /* RSA/EC: streaming DigestSign with SHA-256 */
        if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, evp_private_key)) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        /* get Data to sign */
        while (!data->eof(data, p_errinfo)) {
            size_t read_len = data->read(data, payload_chunk, CHUNK_LEN, p_errinfo);
            /* Update with the data chunck */
            if (1 != EVP_DigestSignUpdate(mdctx, payload_chunk, read_len)) {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                goto err;
            }
        }

        /* Obtain the length of the signature before being calculated */
        if (1 != EVP_DigestSignFinal(mdctx, NULL, &signature_len)) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        /* Allocate memory for the signature based on size in signature_len */
        if (!(signature = OPENSSL_malloc(sizeof(unsigned char) * (signature_len)))) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        /* Obtain the signature */
        if (1 != EVP_DigestSignFinal(mdctx, signature, &signature_len)) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }
    }

    seal->write(seal, (const char *)signature, signature_len, p_errinfo);
    seal->finish(seal, 0, p_errinfo);

    ret = true;

err:
    OPENSSL_free(signature);
    OPENSSL_clear_free(p_buffer_in, buffer_idx_in);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(evp_private_key);

    return ret;
}

const struct profile_function_list_t fl_prof_com_github_generic_trust_anchor_api_basic_signature = {
    .context_open = context_open,
    .personality_enroll = personality_enroll,
    .personality_activate_deactivate_supported = true,
    .personality_attribute_functions_supported = true,
    .authenticate_data_detached = authenticate_data_detached,
};
