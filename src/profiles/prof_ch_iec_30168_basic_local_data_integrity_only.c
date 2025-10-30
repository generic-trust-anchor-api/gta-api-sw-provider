/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#include <gta_api/gta_api.h>
#include "../gta_sw_provider.h"
#include "prof_helper_functions.h"
#include <gta_api/util/gta_memset.h>

#define LOCAL_DATA_INTEGRITY_ONLY_SECRET_LEN 32
#define LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN 32
#define KEY_DERIVATION_STRING_VALUE "ch.iec.30168.basic.local_data_integrity_only"

GTA_SWP_DEFINE_FUNCTION(bool, context_open,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;

    if (SECRET_TYPE_RAW_BYTES != p_context_params->p_personality_item->p_personality_content->secret_type)
    {
        DEBUG_PRINT(("gta_sw_provider_gta_context_open: personality secret type not as expected\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }
    /* Check secret length */
    if (LOCAL_DATA_INTEGRITY_ONLY_SECRET_LEN != p_context_params->p_personality_item->p_personality_content->secret_data_size) {
        DEBUG_PRINT(("gta_sw_provider_gta_context_open: personality secret data size not as expected \n"));
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
    *p_pers_secret_length = LOCAL_DATA_INTEGRITY_ONLY_SECRET_LEN;
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

static bool calculate_icv(
    const struct gta_sw_provider_context_params_t * p_context_params,
    const unsigned char * data,
    size_t data_len,
    unsigned char * icv,
    gta_errinfo_t * p_errinfo
)
{
    bool ret = false;
    const struct personality_t * p_personality_content = NULL;
    unsigned int md_len = 0;
    unsigned int key_len = 0;
    const EVP_MD * md_type = EVP_sha256();
    unsigned char key[EVP_MD_size(md_type)];
    unsigned char md[EVP_MD_size(md_type)];
    
    /* get personality of the context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;
    
    /* Range checks */
    if ((INT_MAX < p_personality_content->secret_data_size) ||
        (LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN > EVP_MD_size(md_type))) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }    

    /* Derive a key from the personality secret */
    if ((NULL == HMAC(md_type, p_personality_content->secret_data,
        (int)p_personality_content->secret_data_size, (unsigned char *) KEY_DERIVATION_STRING_VALUE,
        strlen(KEY_DERIVATION_STRING_VALUE), key, &key_len)) ||
        (INT_MAX < key_len) ||
        (EVP_MD_size(md_type) != (int)key_len)){
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Calculate ICV over data and the derived HMAC key */
    if ((NULL == HMAC(md_type, key,
                     (int)key_len, data,
                     data_len, md, &md_len)) ||
        (INT_MAX < md_len) ||
        (EVP_MD_size(md_type) != (int)md_len)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    memcpy(icv, md, LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN);

    ret = true;

err:
    gta_memset(key, EVP_MD_size(md_type), 0, EVP_MD_size(md_type));
    return ret;
}

typedef struct {
    ASN1_OCTET_STRING *data;
    ASN1_OCTET_STRING *icv;  /* HMAC-SHA256 result */
} IntegrityProtectedData;

ASN1_SEQUENCE(IntegrityProtectedData) = {
    ASN1_SIMPLE(IntegrityProtectedData, data, ASN1_OCTET_STRING),
    ASN1_SIMPLE(IntegrityProtectedData, icv, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(IntegrityProtectedData)

IMPLEMENT_ASN1_FUNCTIONS(IntegrityProtectedData)

GTA_SWP_DEFINE_FUNCTION(bool, seal_data,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gtaio_istream_t * data,
    gtaio_ostream_t * protected_data,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;

    IntegrityProtectedData asn1_data = { NULL };
    unsigned char icv[LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN] = { 0 };

    unsigned char * p_buffer_in = NULL;
    size_t buffer_idx_in = 0;
    unsigned char * p_encoded_data = NULL;
    int encoded_len = 0;

    /* Read whole input into buffer */
    if (!read_input_buffer(data, &p_buffer_in, &buffer_idx_in, p_errinfo)) {
        goto err;
    }

    /* Initialize data structure */
    asn1_data.data = ASN1_OCTET_STRING_new();
    asn1_data.icv = ASN1_OCTET_STRING_new();    

    if ((NULL == asn1_data.data) ||
        (NULL == asn1_data.icv)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err; 
    }
    
    /* Range checks */
    if (INT_MAX < buffer_idx_in) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }    

    /* Encode data */
    ASN1_OCTET_STRING_set(asn1_data.data, p_buffer_in, (int)buffer_idx_in);

    /* Calculate ICV */
    if (!calculate_icv(p_context_params, p_buffer_in, buffer_idx_in, icv, p_errinfo)) {
        goto err;
    }

    /* Encode icv */
    ASN1_OCTET_STRING_set(asn1_data.icv, icv, LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN);
    
    /* Encode the ProtectedData */
    encoded_len = i2d_IntegrityProtectedData(&asn1_data, &p_encoded_data);
    if (0 >= encoded_len) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Write output stream (encoded_len > 0 already checked) */
    protected_data->write(protected_data, (char *)p_encoded_data, (size_t)encoded_len, p_errinfo);
    protected_data->finish(protected_data, 0, p_errinfo);

    ret = true;

err:
    OPENSSL_free(p_buffer_in);
    ASN1_OCTET_STRING_free(asn1_data.data);
    ASN1_OCTET_STRING_free(asn1_data.icv);
    OPENSSL_free(p_encoded_data);

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

    IntegrityProtectedData * p_asn1_data = NULL;   
    unsigned char icv[LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN] = { 0 };

    unsigned char * p_buffer_in = NULL;
    size_t buffer_idx_in = 0;

    /* Read whole input into buffer */
    if (!read_input_buffer(protected_data, &p_buffer_in, &buffer_idx_in, p_errinfo)) {
        goto err;
    }

    /* Range check on buffer_idx_in */
    if (LONG_MAX < buffer_idx_in) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    /* Decode IntegrityProtectedData */
    const unsigned char * p = p_buffer_in;
    p_asn1_data = d2i_IntegrityProtectedData(NULL, &p, (long)buffer_idx_in);
    if (NULL == p_asn1_data) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Calculate ICV */
    if (!calculate_icv(p_context_params, p_asn1_data->data->data, p_asn1_data->data->length, icv, p_errinfo)) {
        goto err;
    }

    /* Check icv by comparing new calculated icv with reference icv */
    if ((LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN != p_asn1_data->icv->length) ||
        (0 != CRYPTO_memcmp(icv, p_asn1_data->icv->data, LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN))) {
        *p_errinfo = GTA_ERROR_INTEGRITY;
        goto err;
    }    

    /* Write output stream */
    if (p_asn1_data->data->length != (int) data->write(data, (const char *)p_asn1_data->data->data, p_asn1_data->data->length, p_errinfo)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    data->finish(data, 0, p_errinfo);

    ret = true;

err:
    OPENSSL_free(p_buffer_in);
    if (NULL != p_asn1_data) {
        ASN1_OCTET_STRING_free(p_asn1_data->data);
        ASN1_OCTET_STRING_free(p_asn1_data->icv);
    }
    OPENSSL_free(p_asn1_data);

    return ret;
}

GTA_SWP_DEFINE_FUNCTION(bool, authenticate_data_detached,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gtaio_istream_t * data,
    gtaio_ostream_t * seal,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;

    unsigned char icv[LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN] = { 0 };

    unsigned char * p_buffer_in = NULL;
    size_t buffer_idx_in = 0;

    /* Read whole input into buffer */
    if (!read_input_buffer(data, &p_buffer_in, &buffer_idx_in, p_errinfo)) {
        goto err;
    }

    /* Calculate ICV */
    if (!calculate_icv(p_context_params, p_buffer_in, buffer_idx_in, icv, p_errinfo)) {
        goto err;
    }

    /* Write output stream */
    seal->write(seal, (char *)icv, LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN, p_errinfo);
    seal->finish(seal, 0, p_errinfo);

    ret = true;

err:
    OPENSSL_free(p_buffer_in);

    return ret;    
}

GTA_SWP_DEFINE_FUNCTION(bool, verify_data_detached,
(    
    struct gta_sw_provider_context_params_t * p_context_params,
    gtaio_istream_t * data,
    gtaio_istream_t * seal,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;
 
    unsigned char icv[LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN] = { 0 };

    unsigned char * p_buffer_in = NULL;
    size_t buffer_idx_in = 0;
    unsigned char * p_icv_ref = NULL;
    size_t icv_ref_len = 0;

    /* Read whole input into buffer */
    if ((!read_input_buffer(data, &p_buffer_in, &buffer_idx_in, p_errinfo)) || 
        (!read_input_buffer(seal, &p_icv_ref, &icv_ref_len, p_errinfo))) {
        goto err;
    }    

    /* Calculate ICV */
    if (!calculate_icv(p_context_params, p_buffer_in, buffer_idx_in, icv, p_errinfo)) {
        goto err;
    }
    
    /* Check icv by comparing new calculated icv with reference icv */
    if ((LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN != icv_ref_len) ||
        (0 != CRYPTO_memcmp(icv, p_icv_ref, LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN))) {
        *p_errinfo = GTA_ERROR_INTEGRITY;
        goto err;
    }    

    ret = true;

err:
    OPENSSL_free(p_buffer_in);
    OPENSSL_free(p_icv_ref);

    return ret;
}

const struct profile_function_list_t fl_prof_ch_iec_30168_basic_local_data_integrity_only = {
    .context_open = context_open,
    .personality_create = personality_create,
    .seal_data = seal_data,
    .unseal_data = unseal_data,
    .authenticate_data_detached = authenticate_data_detached,
    .verify_data_detached = verify_data_detached,    
};
