/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#include "prof_helper_functions.h"

/*
 * Helper function, returning the number of bits of a private key.
 * It is intended to be used in order to check if the properties
 * of a personality matches the expectations of a profile.
 */
int pkey_bits(const EVP_PKEY *evp_private_key) {
    return EVP_PKEY_bits(evp_private_key);
}

/*
 * Helper function, returning the OpenSSL curve NID of an EC private key.
 * It is intended to be used in order to check if the properties
 * of a personality matches the expectations of a profile.
 * Returns 0 in case of error.
 */
int pkey_ec_nid(const EVP_PKEY *evp_private_key) {
    char curve_name[CURVENAME_LENGTH_MAX] = { 0 };
    size_t len = 0;

    if (!EVP_PKEY_get_utf8_string_param(evp_private_key, OSSL_PKEY_PARAM_GROUP_NAME,
        curve_name, sizeof(curve_name), &len)) {
            return 0;
    }

    return OBJ_sn2nid(curve_name);
}

/* Helper function, returning an OpenSSL EVP_PKEY from DER encoded buffer. */
EVP_PKEY * get_pkey_from_der(unsigned char * p_der_content, const size_t der_size, gta_errinfo_t * p_errinfo) {
    EVP_PKEY * evp_private_key = NULL;

    unsigned char * p_secret_buffer = p_der_content;
    /* Range check on p_personality_content->content_data_size */
    if (der_size > LONG_MAX) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return NULL;
    }
    evp_private_key = d2i_AutoPrivateKey(NULL,
                                        (const unsigned char **) &p_secret_buffer,
                                        (long)der_size);
    /* clear pointer */
    p_secret_buffer = NULL;
    if (NULL == evp_private_key) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
    }
    return evp_private_key;
}


/* Helper function to read the whole input from gtaio_istream_t into a buffer */
bool read_input_buffer
(
    gtaio_istream_t * data,
    unsigned char ** pp_data,
    size_t * p_data_size,
    gta_errinfo_t * p_errinfo
)
{
    *pp_data = NULL;
    *p_data_size = 0;

    unsigned char * p_buffer = NULL;
    size_t buffer_idx = 0;

    p_buffer = OPENSSL_zalloc(CHUNK_LEN);
    if(NULL != p_buffer) {
        size_t chunk_len = CHUNK_LEN;
        while (!data->eof(data, p_errinfo)) {
            chunk_len = data->read(data, (char *)p_buffer + buffer_idx, chunk_len, p_errinfo);
            buffer_idx += chunk_len;
            if (!data->eof(data, p_errinfo)) {
                chunk_len = CHUNK_LEN;
                p_buffer = OPENSSL_clear_realloc(p_buffer, buffer_idx, buffer_idx + CHUNK_LEN);
                if (NULL == p_buffer) {
                    *p_errinfo = GTA_ERROR_MEMORY;
                    return false;
                }
            }
        }
    }
    else {
        *p_errinfo = GTA_ERROR_MEMORY;
        return false;
    }

    *pp_data = p_buffer;
    *p_data_size = buffer_idx;
    return true;
}

