/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#include <gta_api/gta_api.h>
#include "../gta_sw_provider.h"

#define P256_COORDINATE_LEN 32

GTA_SWP_DEFINE_FUNCTION(bool, context_open,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gta_errinfo_t * p_errinfo
))
{
    struct personality_t * p_personality_content = NULL;
    EVP_PKEY *evp_private_key = NULL;
    bool ret = false;

    if (SECRET_TYPE_DER != p_context_params->p_personality_item->p_personality_content->secret_type)
    {
        DEBUG_PRINT(("gta_sw_provider_gta_context_open: Personality type not as expected\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }
    /* further checks required by profile: such as algorithms and minimum key length */

    /* get the Private Key from the Personality */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;
    evp_private_key = get_pkey_from_der(p_personality_content->secret_data, p_personality_content->secret_data_size, p_errinfo);
    if (NULL == evp_private_key) {
        goto err;
    }

    int key_id = EVP_PKEY_base_id(evp_private_key);

    if ((EVP_PKEY_RSA == key_id) && (2048 <= pkey_bits(evp_private_key))) {
        ret = true;
    } else if ((EVP_PKEY_EC == key_id) && (NID_X9_62_prime256v1 == pkey_ec_nid(evp_private_key))) {
        ret = true;
    } else {
        DEBUG_PRINT(("gta_sw_provider_gta_context_open: Profile requirements not fulfilled \n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }

err:
    EVP_PKEY_free(evp_private_key);

    return ret;
}

GTA_SWP_DEFINE_FUNCTION(bool, personality_enroll,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gtaio_ostream_t * p_personality_enrollment_info,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;
    BIO* bio = NULL;
    long len = 0;
    char* pem_data = NULL;
    EVP_PKEY *p_key = NULL;
    struct personality_t * p_personality_content = NULL;

    /* get personality of the context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    if (SECRET_TYPE_DER == p_personality_content->secret_type) {
        p_key = get_pkey_from_der(p_personality_content->secret_data, p_personality_content->secret_data_size, p_errinfo);
        if (NULL == p_key) {
            goto err;
        }
        /* get public key in PEM */
        bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bio, p_key);
        len = BIO_get_mem_data(bio, &pem_data);
    }
    else {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    /* len always >= 0 */
    if ((size_t)len != p_personality_enrollment_info->write(p_personality_enrollment_info, pem_data, (size_t)len, p_errinfo)) {
        goto err;
    }
    p_personality_enrollment_info->finish(p_personality_enrollment_info, 0, p_errinfo);
    ret = true;

err:
    EVP_PKEY_free(p_key);
    BIO_free_all(bio);

    return ret;
}

/**
 * @brief Encodes binary data into base64_url (memory has to be freed by the caller)
 *
 */
char* base64url_encode(gta_context_handle_t h_ctx, const unsigned char* data, size_t data_len) {
    const size_t trail_len = 2;
    gta_errinfo_t errinfo;

    if ((0 == data_len) || (data_len>INT_MAX)) {
        return NULL;
    }

    size_t encoded_size = (4 * ((data_len +2) / 3)) + 1;
    char* encoded_data = gta_secmem_calloc(h_ctx, 1, encoded_size, &errinfo);
    if (NULL == encoded_data) {
        return NULL;
    }

    /* Range checks on data_len already done */
    int32_t result = EVP_EncodeBlock((unsigned char*)encoded_data, data, (int) data_len);

    if (0 == result)
    {
        gta_secmem_free(h_ctx, encoded_data, &errinfo);
        encoded_data = NULL;
        return NULL;
    }

    /* Replace '+' and '/' characters */
    for (size_t i = 0; i < encoded_size; i++) {
        if ('+' == encoded_data[i]) {
            encoded_data[i] = '-';
        } else if ('/' == encoded_data[i]) {
            encoded_data[i] = '_';
        } else {
            /* nothing to do */
        }
    }

    /* Remove any trailing '=' */
    while ((trail_len <= encoded_size) && ('=' == encoded_data[encoded_size - trail_len])) {
        --encoded_size;
    }
    encoded_data[encoded_size-1] = '\0';

    return encoded_data;
}

GTA_SWP_DEFINE_FUNCTION(bool, seal_data,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gtaio_istream_t * data,
    gtaio_ostream_t * protected_data,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;
    gta_errinfo_t errinfo_tmp;

    /* Currently only static JWT headers, hardcoded for algs RS256 & ES256 */
    const char *jwt_header_rs256 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9";
    const char *jwt_header_es256 = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";

    struct personality_t * p_personality_content = NULL;

    char payload_chunk[CHUNK_LEN];
    const char* header_base64 = NULL;
    char* signature_base64url = NULL;
    unsigned char* signature = NULL;
    size_t signature_len = 0;

    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *evp_private_key = NULL;
    int32_t key_type = EVP_PKEY_NONE;
    ECDSA_SIG * signatureRaw = NULL;

    /* get Personality of the Context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    evp_private_key = get_pkey_from_der(p_personality_content->secret_data, p_personality_content->secret_data_size, p_errinfo);
    if (NULL == evp_private_key) {
        goto err;
    }

    /* get key type & config accordingly */
    key_type = EVP_PKEY_base_id(evp_private_key);
    if (EVP_PKEY_RSA == key_type) {
        header_base64 = jwt_header_rs256;
    } else if (EVP_PKEY_EC == key_type) {
        header_base64 = jwt_header_es256;
    } else {
        goto err;
    }

    /* Create the Message Digest Context */
    if (!(mdctx = EVP_MD_CTX_new()))
    {
        goto err;
    }

    /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
    if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, evp_private_key))
    {
        goto err;
    }

    /* add JWT Header */
    if (1 != EVP_DigestSignUpdate(mdctx, header_base64, strlen(header_base64)))
    {
        goto err;
    }
    protected_data->write(protected_data, header_base64, strlen(header_base64), p_errinfo);

    /* add "." JWT separator */
    if (1 != EVP_DigestSignUpdate(mdctx, ".", 1))
    {
        goto err;
    }
    protected_data->write(protected_data, ".", 1, p_errinfo);

    /* add JWT Payload */
    while (!data->eof(data, p_errinfo)) {
        size_t read_len = data->read(data, payload_chunk, CHUNK_LEN, p_errinfo);
        /* Update with the data chunk */
        if(1 != EVP_DigestSignUpdate(mdctx, payload_chunk, read_len))
        {
            goto err;
        }
        /* Add data chunk as JWT payload */
        protected_data->write(protected_data, payload_chunk, read_len, p_errinfo);
    }

    /* Obtain the length of the signature before being calculated */
    if (1 != EVP_DigestSignFinal(mdctx, NULL, &signature_len))
    {
        goto err;
    }

    /* Allocate memory for the signature based on size in signature_len */
    if (!(signature = OPENSSL_malloc(sizeof(unsigned char) * (signature_len))))
    {
        goto err;
    }

    /* Obtain the signature */
    if (1 != EVP_DigestSignFinal(mdctx, signature, &signature_len))
    {
        goto err;
    }

    /* In case of EC, we need to convert the signature */
    if (EVP_PKEY_EC == key_type) {
        const unsigned char * ptmpData = signature;
        const BIGNUM * pr = NULL;
        const BIGNUM * ps = NULL;

        signatureRaw = d2i_ECDSA_SIG(NULL, &ptmpData, signature_len);
        if (NULL == signatureRaw) {
            goto err;
        }

        ECDSA_SIG_get0(signatureRaw, &pr, &ps);
        if ((NULL == pr) || (NULL == ps) || ((P256_COORDINATE_LEN * 2) > signature_len)) {
            goto err;
        }

        if (P256_COORDINATE_LEN != BN_bn2binpad(pr, signature, P256_COORDINATE_LEN)) {
            goto err;
        }

        if (P256_COORDINATE_LEN != BN_bn2binpad(ps, signature + P256_COORDINATE_LEN, P256_COORDINATE_LEN)) {
            goto err;
        }
        signature_len = P256_COORDINATE_LEN * 2;
    }

    signature_base64url = base64url_encode(p_context_params->h_ctx, signature, signature_len);
    if (NULL == signature_base64url)
    {
        goto err;
    }

    /* add "." JWT separator & Signature */
    protected_data->write(protected_data, ".", 1, p_errinfo);
    protected_data->write(protected_data, signature_base64url, strlen(signature_base64url), p_errinfo);
    protected_data->finish(protected_data, 0, p_errinfo);

    ret = true;
    goto cleanup;

err:
    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
cleanup:
    gta_secmem_free(p_context_params->h_ctx, signature_base64url, &errinfo_tmp);
    OPENSSL_free(signature);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(evp_private_key);
    ECDSA_SIG_free(signatureRaw);

    return ret;
}

const struct profile_function_list_t fl_prof_com_github_generic_trust_anchor_api_basic_jwt = {
    .context_open = context_open,
    .personality_enroll = personality_enroll,
    .personality_activate_deactivate_supported = true,
    .personality_attribute_functions_supported = true,
    .seal_data = seal_data,
};
