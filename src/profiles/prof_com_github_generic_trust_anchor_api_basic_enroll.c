/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#include "../gta_sw_provider.h"
#include "prof_helper_functions.h"
#include <gta_api/gta_api.h>

#define CTX_ATTR_TYPE_SUBJECT_RDN "com.github.generic-trust-anchor-api.enroll.subject_rdn"

struct pers_enroll_attributes_t {
    char * subject_rdn;
    X509_NAME * x509_name;
};

static bool parse_rdn_pair(char * rdn_pair, X509_NAME * name)
{
    const char * delimiter_pos = strchr(rdn_pair, '=');
    const char * value = delimiter_pos + 1;
    /* Only one delimiter is allowed for each key value pair */
    if (delimiter_pos != strrchr(rdn_pair, '=')) {
        return false;
    }
    rdn_pair[delimiter_pos - rdn_pair] = '\0';
    if (1 != X509_NAME_add_entry_by_txt(
                 name,
                 rdn_pair,
                 MBSTRING_UTF8,
                 (const unsigned char *)value,
                 (int)strnlen(value, MAXLEN_CTX_ATTRIBUTE_VALUE),
                 -1,
                 0)) {
        return false;
    }
    return true;
}

/*
 * Helper function to parse a Subject RDN as described in RFC4514 and construct
 * a OpenSSL x509_name. Todo: May not be fully compliant to the RFC yet!
 */
static X509_NAME * parse_rdn(const char * subject_rdn)
{
    X509_NAME * name = NULL;
    char * work = NULL;
    char * key_value_pair = NULL;
    char * saveptr = NULL;
    size_t len = strnlen(subject_rdn, MAXLEN_CTX_ATTRIBUTE_VALUE);

    /* subject_rdn string must not end with a delimiter */
    if ((',' == subject_rdn[len - 1]) || ('+' == subject_rdn[len - 1]) || ('=' == subject_rdn[len - 1])) {
        return NULL;
    }

    name = X509_NAME_new();
    work = OPENSSL_strdup(subject_rdn);
    if ((work == NULL) || (name == NULL)) {
        goto err;
    }

    key_value_pair = strtok_r(work, ",+", &saveptr);
    while (NULL != key_value_pair) {
        if (!parse_rdn_pair(key_value_pair, name)) {
            goto err;
        }
        key_value_pair = strtok_r(NULL, ",", &saveptr);
    }

    OPENSSL_free(work);
    return name;

err:
    X509_NAME_free(name);
    OPENSSL_free(work);
    return NULL;
}

GTA_SWP_DEFINE_FUNCTION(
    bool,
    context_open,
    (struct gta_sw_provider_context_params_t * p_context_params, gta_errinfo_t * p_errinfo))
{
    bool ret = false;
    struct personality_t * p_personality_content = NULL;
    EVP_PKEY * evp_private_key = NULL;

    if (SECRET_TYPE_DER != p_context_params->p_personality_item->p_personality_content->secret_type) {
        DEBUG_PRINT(("gta_sw_provider_gta_context_open: Personality type not as expected\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }

    /* get the private key from the personality */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;
    unsigned char * p_secret_buffer = p_personality_content->secret_data;
    /* Range check on p_personality_content->content_data_size */
    if (p_personality_content->secret_data_size > LONG_MAX) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    evp_private_key = d2i_AutoPrivateKey(
        NULL, (const unsigned char **)&p_secret_buffer, (long)p_personality_content->secret_data_size);
    /* clear pointer */
    p_secret_buffer = NULL;
    if (NULL == evp_private_key) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    int key_id = EVP_PKEY_base_id(evp_private_key);

    /*
     * Check profile restrictions on personality:
     * Only RSA 2048 and ECC P-256 are allowed.
     */
    if (!(((EVP_PKEY_RSA == key_id) && (2048 == pkey_bits(evp_private_key))) ||
          ((EVP_PKEY_EC == key_id) && (NID_X9_62_prime256v1 == pkey_ec_nid(evp_private_key))))) {

        DEBUG_PRINT(("gta_sw_provider_gta_context_open: Profile requirements not fulfilled \n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }

    /* Allocate memory for context attributes */
    p_context_params->context_attributes =
        gta_secmem_calloc(p_context_params->h_ctx, 1, sizeof(struct pers_enroll_attributes_t), p_errinfo);
    if (NULL == p_context_params->context_attributes) {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    struct pers_enroll_attributes_t * pers_enroll_attributes =
        (struct pers_enroll_attributes_t *)p_context_params->context_attributes;
    pers_enroll_attributes->x509_name = NULL;
    pers_enroll_attributes->subject_rdn = NULL;
    ret = true;

err:
    EVP_PKEY_free(evp_private_key);
    return ret;
}

GTA_SWP_DEFINE_FUNCTION(
    bool,
    context_close,
    (struct gta_sw_provider_context_params_t * p_context_params, gta_errinfo_t * p_errinfo))
{
    struct pers_enroll_attributes_t * pers_enroll_attributes =
        (struct pers_enroll_attributes_t *)p_context_params->context_attributes;
    X509_NAME_free(pers_enroll_attributes->x509_name);
    return true;
}

GTA_SWP_DEFINE_FUNCTION(
    bool,
    context_get_attribute,
    (struct gta_sw_provider_context_params_t * p_context_params,
     gta_context_attribute_type_t attrtype,
     gtaio_ostream_t * p_attrvalue,
     gta_errinfo_t * p_errinfo))
{
    const struct pers_enroll_attributes_t * pers_enroll_attributes =
        (struct pers_enroll_attributes_t *)p_context_params->context_attributes;

    /* check whether attribute type is supported by profile */
    if (0 != strcmp(attrtype, CTX_ATTR_TYPE_SUBJECT_RDN)) {
        /* attribute not supported by profile */
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        return false;
    }

    /* check whether attribute has been set */
    if (NULL == pers_enroll_attributes->subject_rdn) {
        /* attribute not available */
        *p_errinfo = GTA_ERROR_ITEM_NOT_FOUND;
        return false;
    }

    /* write subject rdn */
    size_t len = strnlen(pers_enroll_attributes->subject_rdn, MAXLEN_CTX_ATTRIBUTE_VALUE);
    if (len != p_attrvalue->write(p_attrvalue, pers_enroll_attributes->subject_rdn, len, p_errinfo)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }
    if (1 != p_attrvalue->write(p_attrvalue, "", 1, p_errinfo)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }
    p_attrvalue->finish(p_attrvalue, 0, p_errinfo);

    return true;
}

GTA_SWP_DEFINE_FUNCTION(
    bool,
    context_set_attribute,
    (struct gta_sw_provider_context_params_t * p_context_params,
     gta_context_attribute_type_t attrtype,
     gtaio_istream_t * p_attrvalue,
     gta_errinfo_t * p_errinfo))
{
    struct pers_enroll_attributes_t * pers_enroll_attributes =
        (struct pers_enroll_attributes_t *)p_context_params->context_attributes;
    char attrval[MAXLEN_CTX_ATTRIBUTE_VALUE] = {0};
    X509_NAME * x509_name = NULL;
    size_t read = 0;

    /* check whether attribute type is supported by profile and not already set */
    if (!((0 == strcmp(attrtype, CTX_ATTR_TYPE_SUBJECT_RDN)) && (NULL == pers_enroll_attributes->x509_name))) {

        /* attribute not supported by profile or already set */
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        return false;
    }

    /* read context attribute value into buffer */
    read = p_attrvalue->read(p_attrvalue, attrval, MAXLEN_CTX_ATTRIBUTE_VALUE, p_errinfo);
    if ((MAXLEN_CTX_ATTRIBUTE_VALUE == read) || ('\0' != attrval[read - 1])) {
        /* attribute too long or not Null-terminated*/
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        return false;
    }

    /* parse subject_rdn */
    x509_name = parse_rdn(attrval);
    if (NULL == x509_name) {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        return false;
    }

    /* allocate memory for subject rdn */
    pers_enroll_attributes->subject_rdn = gta_secmem_calloc(p_context_params->h_ctx, 1, read, p_errinfo);
    if (NULL == pers_enroll_attributes->subject_rdn) {
        *p_errinfo = GTA_ERROR_MEMORY;
        X509_NAME_free(x509_name);
        return false;
    }

    memcpy(pers_enroll_attributes->subject_rdn, attrval, read);
    pers_enroll_attributes->x509_name = x509_name;

    return true;
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
    char * pem_data = NULL;
    EVP_PKEY * p_key = NULL;
    X509_REQ * x509_req = NULL;
    struct personality_t * p_personality_content = NULL;

    const struct pers_enroll_attributes_t * pers_enroll_attributes =
        (struct pers_enroll_attributes_t *)p_context_params->context_attributes;

    /* get personality of the context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    /* range check on p_personality_content->content_data_size */
    if (p_personality_content->secret_data_size > LONG_MAX) {
        goto internal_err;
    }
    /* get the key from the personality */
    unsigned char * p_secret_buffer = p_personality_content->secret_data;
    p_key = d2i_AutoPrivateKey(
        NULL, (const unsigned char **)&p_secret_buffer, (long)p_personality_content->secret_data_size);

    p_secret_buffer = NULL;
    if (!p_key) {
        goto internal_err;
    }

    int ret_val = 0;
    x509_req = X509_REQ_new();
    ret_val = X509_REQ_set_version(x509_req, 0);
    if (1 != ret_val) {
        goto internal_err;
    }

    /* This is optional */
    if ((NULL != pers_enroll_attributes->x509_name) &&
        (!X509_REQ_set_subject_name(x509_req, pers_enroll_attributes->x509_name))) {

        goto internal_err;
    }

    ret_val = X509_REQ_set_pubkey(x509_req, p_key);
    if (1 != ret_val) {
        goto internal_err;
    }

    // set sign key of x509 req
    ret_val = X509_REQ_sign(x509_req, p_key, EVP_sha256());
    if (0 >= ret_val) {
        goto internal_err;
    }

    size_t length = 0;

    bio = BIO_new(BIO_s_mem());
    ret_val = PEM_write_bio_X509_REQ(bio, x509_req);
    if (0 >= ret_val) {
        goto internal_err;
    }
    length = BIO_get_mem_data(bio, &pem_data);

    if (length != p_personality_enrollment_info->write(p_personality_enrollment_info, pem_data, length, p_errinfo)) {
        goto internal_err;
    }
    p_personality_enrollment_info->finish(p_personality_enrollment_info, 0, p_errinfo);
    ret = true;

    goto cleanup;

internal_err:
    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
cleanup:
    EVP_PKEY_free(p_key);
    BIO_free_all(bio);
    X509_REQ_free(x509_req);

    return ret;
}

const struct profile_function_list_t fl_prof_com_github_generic_trust_anchor_api_basic_enroll = {
    .context_open = context_open,
    .context_close = context_close,
    .context_get_attribute = context_get_attribute,
    .context_set_attribute = context_set_attribute,
    .personality_enroll = personality_enroll,
    .personality_attribute_functions_supported = true,
};
