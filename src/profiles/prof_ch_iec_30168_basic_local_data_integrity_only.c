/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#include <gta_api/gta_api.h>
#include "../gta_sw_provider.h"
#include "prof_helper_functions.h"

#define LOCAL_DATA_INTEGRITY_ONLY_SECRET_LEN 32
#define LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN 32

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
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    /* Check secret length */
    if (LOCAL_DATA_INTEGRITY_ONLY_SECRET_LEN != p_context_params->p_personality_item->p_personality_content->secret_data_size) {
        DEBUG_PRINT(("gta_sw_provider_gta_context_open: personality secret size not as expected\n"));
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
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
    
    const struct personality_t * p_personality_content = NULL;

    IntegrityProtectedData asn1_data = { NULL };
    unsigned int md_len = 0;
    unsigned char icv[LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN] = { 0 };

    unsigned char * p_buffer_in = NULL;
    size_t buffer_idx_in = 0;
    unsigned char *p_encoded_data = NULL;
    int encoded_len = 0;
    
    /* get personality of the context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    /* Read whole input into buffer */
    if (!read_input_buffer(data, &p_buffer_in, &buffer_idx_in, p_errinfo)) {
        goto err;
    }

    /* Initialize data structure */
    asn1_data.data = ASN1_OCTET_STRING_new();
    asn1_data.icv = ASN1_OCTET_STRING_new();
    
    /* Encode data */
    ASN1_OCTET_STRING_set(asn1_data.data, p_buffer_in, (int)buffer_idx_in);

    /* Range check on p_personality_content->content_data_size */
    if (p_personality_content->secret_data_size > INT_MAX) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    
    /* check size of icv */    
    if (LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN < EVP_MD_size(EVP_sha256())) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Calculate ICV over data with HMAC SHA256 and the personality secret */
    if ((NULL == HMAC(EVP_sha256(), p_personality_content->secret_data,
                     (int)p_personality_content->secret_data_size, p_buffer_in,
                     buffer_idx_in, icv, &md_len)) ||
         (md_len != LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Encode icv */
    ASN1_OCTET_STRING_set(asn1_data.icv, icv, LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN);
    
    /* Encode the ProtectedData */
    encoded_len = i2d_IntegrityProtectedData(&asn1_data, &p_encoded_data);
    if (encoded_len <= 0) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Write output stream (encoded_len > 0 already checked) */
    protected_data->write(protected_data, (char *)p_encoded_data, (size_t)encoded_len, p_errinfo);
    protected_data->finish(protected_data, 0, p_errinfo);

    ret = true;

err:
    OPENSSL_clear_free(p_buffer_in, buffer_idx_in);
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

    const struct personality_t * p_personality_content = NULL;

    IntegrityProtectedData *p_asn1_data = NULL;
    unsigned int md_len = 0;    
    unsigned char icv[LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN] = { 0 };

    unsigned char * p_buffer_in = NULL;
    size_t buffer_idx_in = 0;
            
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
    /* Decode IntegrityProtectedData */
    const unsigned char *p = p_buffer_in;
    p_asn1_data = d2i_IntegrityProtectedData(NULL, &p, (long)buffer_idx_in);
    if (NULL == p_asn1_data) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    const unsigned char * p_data = ASN1_STRING_get0_data(p_asn1_data->data);
    int data_len = ASN1_STRING_length(p_asn1_data->data);
    const unsigned char * p_icv_ref = ASN1_STRING_get0_data(p_asn1_data->icv);
    int icv_ref_len = ASN1_STRING_length(p_asn1_data->icv);

    /* Range check on p_personality_content->content_data_size */
    if (p_personality_content->secret_data_size > INT_MAX) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

     /* check size of icv */    
    if (LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN < EVP_MD_size(EVP_sha256())) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Calculate ICV over data with HMAC SHA256 and the personality secret */
    if ((NULL == HMAC(EVP_sha256(), p_personality_content->secret_data,
                     (int)p_personality_content->secret_data_size, p_data,
                     data_len, icv, &md_len)) ||
        (md_len != LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err; 
    }

    /* Check icv by comparing new calculated icv with reference icv */
    if ((icv_ref_len != LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN) ||
        (0 != memcmp(icv, p_icv_ref, LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN))) {
        *p_errinfo = GTA_ERROR_INTEGRITY;
        goto err;
    }    

    /* Write output stream */
    if (p_asn1_data->data->length != (int) data->write(data, (const char *)p_data, data_len, p_errinfo)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    data->finish(data, 0, p_errinfo);

    ret = true;

err:
   
    OPENSSL_clear_free(p_buffer_in, buffer_idx_in);
    
    if (NULL != p_asn1_data) {
        ASN1_OCTET_STRING_free(p_asn1_data->data);
        ASN1_OCTET_STRING_free(p_asn1_data->icv);
        OPENSSL_free(p_asn1_data);
    }

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

    const struct personality_t * p_personality_content = NULL;

    unsigned int md_len = 0;
    unsigned char icv[LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN] = { 0 };

    unsigned char * p_buffer_in = NULL;
    size_t buffer_idx_in = 0;
    
    /* get personality of the context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    /* Read whole input into buffer */
    if (!read_input_buffer(data, &p_buffer_in, &buffer_idx_in, p_errinfo)) {
        goto err;
    }

    /* Range check on p_personality_content->content_data_size */
    if (p_personality_content->secret_data_size > INT_MAX) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    
    /* check size of icv */    
    if (LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN < EVP_MD_size(EVP_sha256())) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Calculate ICV over data with HMAC SHA256 and the personality secret */
    if ((NULL == HMAC(EVP_sha256(), p_personality_content->secret_data,
                     (int)p_personality_content->secret_data_size, p_buffer_in,
                     buffer_idx_in, icv, &md_len)) ||
         (md_len != LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Write output stream (encoded_len > 0 already checked) */
    seal->write(seal, (char *)icv, (size_t)md_len, p_errinfo);
    seal->finish(seal, 0, p_errinfo);

    ret = true;

err:
    OPENSSL_clear_free(p_buffer_in, buffer_idx_in);

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

    const struct personality_t * p_personality_content = NULL;
    
    unsigned int md_len = 0;    
    unsigned char icv[LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN] = { 0 };

    unsigned char * p_buffer_in = NULL;
    size_t buffer_idx_in = 0;
    unsigned char * p_icv_ref = NULL;
    size_t icv_ref_len = 0;
            
    /* get personality of the context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    /* Read whole input into buffer */
    if ((!read_input_buffer(data, &p_buffer_in, &buffer_idx_in, p_errinfo)) || 
        (!read_input_buffer(seal, &p_icv_ref, &icv_ref_len, p_errinfo))) {
        goto err;
    }    

    /* Range checks */
    if ((buffer_idx_in > LONG_MAX) ||
        (p_personality_content->secret_data_size > INT_MAX) ||
        (LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN < EVP_MD_size(EVP_sha256()))) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }    

    /* Calculate ICV over data with HMAC SHA256 and the personality secret */
    if ((NULL == HMAC(EVP_sha256(), p_personality_content->secret_data,
                     (int)p_personality_content->secret_data_size, p_buffer_in,
                     buffer_idx_in, icv, &md_len)) ||
        (md_len != LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err; 
    }
    
    /* Check icv by comparing new calculated icv with reference icv */
    if ((icv_ref_len != LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN) ||
        (0 != memcmp(icv, p_icv_ref, LOCAL_DATA_INTEGRITY_ONLY_ICV_LEN))) {
        *p_errinfo = GTA_ERROR_INTEGRITY;
        goto err;
    }    

    ret = true;

err:
    OPENSSL_clear_free(p_buffer_in, buffer_idx_in);
    OPENSSL_clear_free(p_icv_ref, icv_ref_len);

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
