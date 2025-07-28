/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#include <gta_api/gta_api.h>
#include "../gta_sw_provider.h"

#define LOCAL_DATA_PROTECTION_SECRET_LEN 32
#define LOCAL_DATA_PROTECTION_KEY_DERIVATION_LEN 32
#define LOCAL_DATA_PROTECTION_IV_LEN 12
#define LOCAL_DATA_PROTECTION_TAG_LEN 16

GTA_SWP_DEFINE_FUNCTION(bool, context_open,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;

    if (SECRET_TYPE_RAW_BYTES != p_context_params->p_personality_item->p_personality_content->secret_type)
    {
        DEBUG_PRINT(("gta_sw_provider_gta_context_open: Personality type not as expected\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }
    /* Check secret length */
    if (LOCAL_DATA_PROTECTION_SECRET_LEN != p_context_params->p_personality_item->p_personality_content->secret_data_size) {
        DEBUG_PRINT(("gta_sw_provider_gta_context_open: Profile requirements not fulfilled \n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }
    ret = true;

err:
    return ret;
}

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
    *p_pers_secret_length = LOCAL_DATA_PROTECTION_SECRET_LEN;
    *p_pers_secret_buffer = OPENSSL_zalloc(*p_pers_secret_length);
    if ((NULL == *p_pers_secret_buffer) || (1 != RAND_bytes(*p_pers_secret_buffer, (int)*p_pers_secret_length))) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }
    *p_pers_secret_type = SECRET_TYPE_RAW_BYTES;
    /* Calculate personality fingerprint */
    SHA512(*p_pers_secret_buffer, *p_pers_secret_length, (unsigned char *)pers_fingerprint);

    /* No profile specific personality attributes */
    *p_pers_attribute = NULL;

    return true;
}

typedef struct {
    ASN1_OCTET_STRING *key;
    ASN1_OCTET_STRING *iv;
    ASN1_OCTET_STRING *tag;
    ASN1_OCTET_STRING *data;
} ProtectedData;

ASN1_SEQUENCE(ProtectedData) = {
    ASN1_SIMPLE(ProtectedData, key, ASN1_OCTET_STRING),
    ASN1_SIMPLE(ProtectedData, iv, ASN1_OCTET_STRING),
    ASN1_SIMPLE(ProtectedData, tag, ASN1_OCTET_STRING),
    ASN1_SIMPLE(ProtectedData, data, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(ProtectedData)

IMPLEMENT_ASN1_FUNCTIONS(ProtectedData)

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
    const struct personality_t * p_personality_content = NULL;

    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *evp_private_key = NULL;

    ProtectedData p_data = { NULL };
    unsigned int size = 0;
    int len = 0;
    unsigned char * p_buffer_in = NULL;
    size_t buffer_idx_in = 0;
    unsigned char * p_buffer_out = NULL;
    size_t buffer_idx_out = 0;
    unsigned char *encoded_data = NULL;
    int encoded_len = 0;
    EVP_CIPHER_CTX *gcmctx = NULL;
    unsigned char key_derivation[LOCAL_DATA_PROTECTION_KEY_DERIVATION_LEN] = { 0 };
    unsigned char iv[LOCAL_DATA_PROTECTION_IV_LEN] = { 0 };
    unsigned char tag[LOCAL_DATA_PROTECTION_TAG_LEN] = { 0 };
    unsigned char *key = NULL;

    /* get personality of the context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    /* Read whole input into buffer */
    if (!read_input_buffer(data, &p_buffer_in, &buffer_idx_in, p_errinfo)) {
        goto err;
    }

    /* Initialize data structure */
    p_data.key = ASN1_OCTET_STRING_new();
    p_data.iv = ASN1_OCTET_STRING_new();
    p_data.tag = ASN1_OCTET_STRING_new();
    p_data.data = ASN1_OCTET_STRING_new();

    /* Generate a random input for the key derivation */
    if (1 != RAND_bytes(key_derivation, LOCAL_DATA_PROTECTION_KEY_DERIVATION_LEN)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    ASN1_OCTET_STRING_set(p_data.key, key_derivation, LOCAL_DATA_PROTECTION_KEY_DERIVATION_LEN);

    /* Allocate memory for the key to be derived (return value of
        * EVP_CIPHER_get_key_length always >= 0) */
    key = gta_secmem_calloc(p_context_params->h_ctx, (size_t)EVP_CIPHER_get_key_length(EVP_aes_256_gcm()), sizeof(unsigned char), p_errinfo);
    if (NULL == key) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Range check on p_personality_content->content_data_size */
    if (p_personality_content->secret_data_size > INT_MAX) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    /* Derive a key from the personality secret */
    HMAC(EVP_sha256(), p_personality_content->secret_data,
        (int)p_personality_content->secret_data_size, key_derivation,
        LOCAL_DATA_PROTECTION_KEY_DERIVATION_LEN, key, &size);

    /* EVP_CIPHER_get_key_length always >= 0 */
    if (size < (unsigned int)EVP_CIPHER_get_key_length(EVP_aes_256_gcm())) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Generate a random IV */
    if (1 != RAND_bytes(iv, LOCAL_DATA_PROTECTION_IV_LEN)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    ASN1_OCTET_STRING_set(p_data.iv, iv, LOCAL_DATA_PROTECTION_IV_LEN);

    /* Initialize the cipher context */
    gcmctx = EVP_CIPHER_CTX_new();
    if (1 != EVP_EncryptInit_ex2(gcmctx, EVP_aes_256_gcm(), key, iv, NULL)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    EVP_CIPHER_CTX_ctrl(gcmctx, EVP_CTRL_AEAD_SET_IVLEN, LOCAL_DATA_PROTECTION_IV_LEN, NULL);

    /* Allocate memory for the encrypted data */
    p_buffer_out = gta_secmem_calloc(p_context_params->h_ctx, buffer_idx_in, sizeof(unsigned char), p_errinfo);
    if (NULL == p_buffer_out) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Range check on buffer_idx_in */
    if (buffer_idx_in > INT_MAX) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    /* Encrypt input data */
    if(1 != EVP_EncryptUpdate(gcmctx, p_buffer_out, &len, p_buffer_in, (int)buffer_idx_in))
    {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    /* len is always >= 0 */
    buffer_idx_out = (size_t)len;

    if (1 != EVP_EncryptFinal_ex(gcmctx, p_buffer_out + buffer_idx_out, &len)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    /* len is always >= 0 */
    buffer_idx_out += (size_t)len;

    /* Check length */
    if (buffer_idx_out != buffer_idx_in) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Range check on buffer_idx_out */
    if (buffer_idx_out > INT_MAX) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    /* Encode payload */
    ASN1_OCTET_STRING_set(p_data.data, p_buffer_out, (int)buffer_idx_out);

    /* Get and encode cipher tag */
    EVP_CIPHER_CTX_ctrl(gcmctx, EVP_CTRL_AEAD_GET_TAG, LOCAL_DATA_PROTECTION_TAG_LEN, tag);
    ASN1_OCTET_STRING_set(p_data.tag, tag, LOCAL_DATA_PROTECTION_TAG_LEN);

    /* Encode the ProtectedData */
    encoded_len = i2d_ProtectedData(&p_data, &encoded_data);
    if (encoded_len <= 0) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Write output stream (encoded_len > 0 already checked) */
    protected_data->write(protected_data, (char *)encoded_data, (size_t)encoded_len, p_errinfo);
    protected_data->finish(protected_data, 0, p_errinfo);

    ret = true;

err:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(evp_private_key);
    EVP_CIPHER_CTX_free(gcmctx);
    OPENSSL_clear_free(p_buffer_in, buffer_idx_in);
    gta_secmem_free(p_context_params->h_ctx, p_buffer_out, &errinfo_tmp);
    gta_secmem_free(p_context_params->h_ctx, key, &errinfo_tmp);
    ASN1_OCTET_STRING_free(p_data.key);
    ASN1_OCTET_STRING_free(p_data.iv);
    ASN1_OCTET_STRING_free(p_data.tag);
    ASN1_OCTET_STRING_free(p_data.data);
    OPENSSL_free(encoded_data);

    return ret;
}

GTA_SWP_DEFINE_FUNCTION(bool, unseal_data,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gtaio_istream_t * protected_data,
    gtaio_ostream_t * data,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;
    gta_errinfo_t errinfo_tmp;
    const struct personality_t * p_personality_content = NULL;
    ProtectedData *p_data = NULL;
    unsigned int size = 0;
    int len = 0;
    unsigned char * p_buffer_in = NULL;
    size_t buffer_idx_in = 0;
    unsigned char * p_buffer_out = NULL;
    size_t buffer_idx_out = 0;
    EVP_CIPHER_CTX *gcmctx = NULL;
    unsigned char *key = NULL;

    /* get personality of the context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    /* Read whole input into buffer */
    if (!read_input_buffer(protected_data, &p_buffer_in, &buffer_idx_in, p_errinfo)) {
        goto err;
    }

    /* Range check on buffer_idx_in */
    if (buffer_idx_in > LONG_MAX) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    /* Decode ProtectedData */
    const unsigned char *p = p_buffer_in;
    p_data = d2i_ProtectedData(NULL, &p, (long)buffer_idx_in);
    if (NULL == p_data) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Check if sizes are supported */
    if ((LOCAL_DATA_PROTECTION_KEY_DERIVATION_LEN != p_data->key->length) ||
        (LOCAL_DATA_PROTECTION_IV_LEN != p_data->iv->length) ||
        (LOCAL_DATA_PROTECTION_TAG_LEN != p_data->tag->length)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Allocate memory for the key to be derived (return value of
        * EVP_CIPHER_get_key_length always >= 0) */
    key = gta_secmem_calloc(p_context_params->h_ctx, (size_t)EVP_CIPHER_get_key_length(EVP_aes_256_gcm()), sizeof(unsigned char), p_errinfo);
    if (NULL == key) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Range check on p_personality_content->content_data_size */
    if (p_personality_content->secret_data_size > INT_MAX) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    /* Derive a key from the personality secret */
    HMAC(EVP_sha256(), p_personality_content->secret_data,
        (int)p_personality_content->secret_data_size, p_data->key->data,
        LOCAL_DATA_PROTECTION_KEY_DERIVATION_LEN, key, &size);

    /* EVP_CIPHER_get_key_length always >= 0 */
    if (size < (unsigned int)EVP_CIPHER_get_key_length(EVP_aes_256_gcm())) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Initialize the cipher context */
    gcmctx = EVP_CIPHER_CTX_new();
    if (1 != EVP_DecryptInit_ex2(gcmctx, EVP_aes_256_gcm(), key, p_data->iv->data, NULL)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    EVP_CIPHER_CTX_ctrl(gcmctx, EVP_CTRL_AEAD_SET_IVLEN, LOCAL_DATA_PROTECTION_IV_LEN, NULL);
    EVP_CIPHER_CTX_ctrl(gcmctx, EVP_CTRL_AEAD_SET_TAG, LOCAL_DATA_PROTECTION_TAG_LEN, p_data->tag->data);

    /* Allocate memory for the decrypted data */
    p_buffer_out = gta_secmem_calloc(p_context_params->h_ctx, buffer_idx_in, sizeof(unsigned char), p_errinfo);
    if (NULL == p_buffer_out) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Decrypt input data */
    if(1 != EVP_DecryptUpdate(gcmctx, p_buffer_out, &len, p_data->data->data, p_data->data->length))
    {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    /* len is always >= 0 */
    buffer_idx_out = (size_t)len;

    if (1 != EVP_DecryptFinal_ex(gcmctx, p_buffer_out + buffer_idx_out, &len)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    /* len is always >= 0 */
    buffer_idx_out += (size_t)len;

    /* Check length */
    if ((p_data->data->length < 0) ||
        (buffer_idx_out != (size_t)p_data->data->length)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Write output stream */
    if (buffer_idx_out != data->write(data, (char *)p_buffer_out, buffer_idx_out, p_errinfo)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    data->finish(data, 0, p_errinfo);

    ret = true;

err:
    EVP_CIPHER_CTX_free(gcmctx);
    OPENSSL_clear_free(p_buffer_in, buffer_idx_in);
    gta_secmem_free(p_context_params->h_ctx, p_buffer_out, &errinfo_tmp);
    gta_secmem_free(p_context_params->h_ctx, key, &errinfo_tmp);

    if (NULL != p_data) {
        ASN1_OCTET_STRING_free(p_data->key);
        ASN1_OCTET_STRING_free(p_data->iv);
        ASN1_OCTET_STRING_free(p_data->tag);
        ASN1_OCTET_STRING_free(p_data->data);
        OPENSSL_free(p_data);
    }

    return ret;
}

const struct profile_function_list_t fl_prof_ch_iec_30168_basic_local_data_protection = {
    .context_open = context_open,
    .personality_create = personality_create,
    .seal_data = seal_data,
    .unseal_data = unseal_data,
};
