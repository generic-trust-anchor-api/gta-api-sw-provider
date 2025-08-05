/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#include <gta_api/gta_api.h>
#include "../gta_sw_provider.h"
#include <openssl/x509v3.h>

#define CTX_ATTR_TYPE_CSR_SUBJECT_DER           "org.opcfoundation.csr.subject"
#define CTX_ATTR_TYPE_CSR_SUBJECTALTNAME_DER    "org.opcfoundation.csr.subjectAltName"
#define P256_COORDINATE_LEN                     32

struct pers_enroll_attributes_t {    
    X509_NAME * x509_name;
    STACK_OF(GENERAL_NAME) *san_names;
};

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
    p_key = EVP_EC_gen("P-256");
    *p_pers_secret_length = i2d_PrivateKey(p_key, p_pers_secret_buffer);
    EVP_PKEY_free(p_key);
    *p_pers_secret_type = SECRET_TYPE_DER;
    /* Calculate personality fingerprint */
    SHA512(*p_pers_secret_buffer, *p_pers_secret_length, (unsigned char *)pers_fingerprint);

    /* No profile specific personality attributes */
    *p_pers_attribute = NULL;

    return true;
}

GTA_SWP_DEFINE_FUNCTION(bool, context_open,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;
    struct personality_t * p_personality_content = NULL;
    EVP_PKEY * evp_private_key = NULL;

    if (SECRET_TYPE_DER != p_context_params->p_personality_item->p_personality_content->secret_type)
    {
        DEBUG_PRINT(("gta_sw_provider_gta_context_open: Personality type not as expected\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto cleanup;
    }

    /* get the private key from the personality */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;
    unsigned char * p_secret_buffer  = p_personality_content->secret_data;
    /* Range check on p_personality_content->content_data_size */
    if (p_personality_content->secret_data_size > LONG_MAX) {
        goto internal_err;
    }
    evp_private_key = d2i_AutoPrivateKey(NULL,
                                         (const unsigned char **) &p_secret_buffer,
                                         (long)p_personality_content->secret_data_size);
    /* clear pointer */
    p_secret_buffer = NULL;
    if (NULL == evp_private_key) {
        goto internal_err;
    }

    int key_id = EVP_PKEY_base_id(evp_private_key);

    /*
     * Check profile restrictions on personality:
     * Only ECC P-256 is allowed.
     */
    if (!((EVP_PKEY_EC == key_id) && (NID_X9_62_prime256v1 == pkey_ec_nid(evp_private_key)))) {

        DEBUG_PRINT(("gta_sw_provider_gta_context_open: Profile requirements not fulfilled \n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto cleanup;
    }

    /* Allocate memory for context attributes */
    p_context_params->context_attributes = gta_secmem_calloc(p_context_params->h_ctx, 1, sizeof(struct pers_enroll_attributes_t), p_errinfo);
    if (NULL == p_context_params->context_attributes) {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto cleanup;
    }
    struct pers_enroll_attributes_t * pers_enroll_attributes = (struct pers_enroll_attributes_t *) p_context_params->context_attributes;
    pers_enroll_attributes->x509_name = NULL;
    pers_enroll_attributes->san_names = NULL;
    ret = true;
    goto cleanup;

internal_err: 
     *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

cleanup:
    EVP_PKEY_free(evp_private_key);
    return ret;
}

GTA_SWP_DEFINE_FUNCTION(bool, context_close,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gta_errinfo_t * p_errinfo
))
{
    struct pers_enroll_attributes_t * pers_enroll_attributes = (struct pers_enroll_attributes_t *) p_context_params->context_attributes;
    X509_NAME_free(pers_enroll_attributes->x509_name);
    sk_GENERAL_NAME_pop_free(pers_enroll_attributes->san_names, GENERAL_NAME_free);
    return true;
}

GTA_SWP_DEFINE_FUNCTION(bool, context_get_attribute,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gta_context_attribute_type_t attrtype,
    gtaio_ostream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
))
{
    const struct pers_enroll_attributes_t * pers_enroll_attributes = (struct pers_enroll_attributes_t *) p_context_params->context_attributes;
    bool ret = false;
    unsigned char * p_buffer_out = NULL; 
    int len = 0;   

    /* check whether attribute type is supported by profile */
    if (0 == strcmp(attrtype, CTX_ATTR_TYPE_CSR_SUBJECT_DER)) {
        /* check whether attribute has been set */
        if (NULL == pers_enroll_attributes->x509_name) {
            /* attribute not available */
            *p_errinfo = GTA_ERROR_ITEM_NOT_FOUND;
            return false;
        }
        /* serialize subjectname in DER */
        len = i2d_X509_NAME(pers_enroll_attributes->x509_name, &p_buffer_out);
        if (len < 0) {
            goto internal_err;
        }
    } else if (0 == strcmp(attrtype, CTX_ATTR_TYPE_CSR_SUBJECTALTNAME_DER)) {
        /* check whether attribute has been set */
        if (NULL == pers_enroll_attributes->san_names) {
            /* attribute not available */
            *p_errinfo = GTA_ERROR_ITEM_NOT_FOUND;
            return false;
        }
        /* serialize subjectAltName in DER */
        len = i2d_GENERAL_NAMES(pers_enroll_attributes->san_names, &p_buffer_out);
        if (len < 0) {
            goto internal_err;
        }
    } else {
        /* attribute not supported by profile */
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        return false;
    }

    size_t buffer_idx_out = (size_t)len;
    if (buffer_idx_out != p_attrvalue->write(p_attrvalue, (char *)p_buffer_out, buffer_idx_out, p_errinfo)) {
        goto internal_err;
    }
    p_attrvalue->finish(p_attrvalue, 0, p_errinfo);

    ret = true;
    goto cleanup;

internal_err: 
    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
cleanup:
    OPENSSL_free(p_buffer_out);

    return ret;
}

GTA_SWP_DEFINE_FUNCTION(bool, context_set_attribute,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gta_context_attribute_type_t attrtype,
    gtaio_istream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
))
{
    struct pers_enroll_attributes_t * pers_enroll_attributes = (struct pers_enroll_attributes_t *) p_context_params->context_attributes;
    unsigned char attrval[MAXLEN_CTX_ATTRIBUTE_VALUE] = { 0 };    
    size_t read = 0;

    /* read context attribute value into buffer */
    /* todo: should this be read in chunks? */
    read = p_attrvalue->read(p_attrvalue, (char*) attrval, MAXLEN_CTX_ATTRIBUTE_VALUE, p_errinfo);    
    if (MAXLEN_CTX_ATTRIBUTE_VALUE == read)  {
        /* attribute too long */
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        return false;
    }

    const unsigned char *p = attrval;

    /* check whether attribute type is supported by profile and not already set */
    if ((0 == strcmp(attrtype, CTX_ATTR_TYPE_CSR_SUBJECT_DER)) && (NULL == pers_enroll_attributes->x509_name)) {   
        /* set subjectname as an x509 object to enrollment attribute */
        pers_enroll_attributes->x509_name = d2i_X509_NAME(&pers_enroll_attributes->x509_name, &p, read); 
        if (NULL == pers_enroll_attributes->x509_name) {        
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            return false;
        }
    } else if ((0 == strcmp(attrtype, CTX_ATTR_TYPE_CSR_SUBJECTALTNAME_DER)) && (NULL == pers_enroll_attributes->san_names)) {
        /* set subjectAltName as GENERAL_NAMES to enrollment attribute */
        pers_enroll_attributes->san_names = d2i_GENERAL_NAMES(&pers_enroll_attributes->san_names, &p, read); 
        if (NULL == pers_enroll_attributes->san_names) {        
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            return false;
        }
    }
    else {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        return false;
    }

    return true;
}

GTA_SWP_DEFINE_FUNCTION(bool, personality_enroll,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gtaio_ostream_t * p_personality_enrollment_info,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;    
    EVP_PKEY *p_key = NULL;
    X509_REQ * x509_req = NULL;
    struct personality_t * p_personality_content = NULL;

    const struct pers_enroll_attributes_t * pers_enroll_attributes = (struct pers_enroll_attributes_t *) p_context_params->context_attributes;
    unsigned char *p_buffer_out= NULL;

    /* get personality of the context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    /* range check on p_personality_content->content_data_size */
    if (p_personality_content->secret_data_size > LONG_MAX) {
        goto internal_err;
    }
    /* get the key from the personality */
    unsigned char * p_secret_buffer  = p_personality_content->secret_data;
    p_key = d2i_AutoPrivateKey(NULL,
        (const unsigned char **) &p_secret_buffer,
        (long)p_personality_content->secret_data_size);

    p_secret_buffer = NULL;
    if (!p_key) {
        goto internal_err;
    }

    int ret_val = 0;
    x509_req = X509_REQ_new();
    ret_val = X509_REQ_set_version(x509_req, 0);
    if (1 != ret_val){
        goto internal_err;
    }

    /* Enrollment attribute x509_name is optional */       
   if ((NULL != pers_enroll_attributes->x509_name) && (!X509_REQ_set_subject_name(x509_req, pers_enroll_attributes->x509_name))) {
            goto internal_err;
    }
       
    X509_EXTENSION *ext = NULL;
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    
    if (NULL != pers_enroll_attributes->san_names) {
        /* Create X509 extension with subjectAltNames from enrollment attributes */        
        ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, pers_enroll_attributes->san_names);                
    } else {
        /* default behaviour if subjectAltName wasn't set by the enrollment attributes */
        /* Create X509 extension with subjectAltNames set to the identifier that relates to the personality */
        STACK_OF(GENERAL_NAME) *san_names = sk_GENERAL_NAME_new_null();
        GENERAL_NAME *gen_name = GENERAL_NAME_new();
        ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();

        /* todo: check if identifier has the type PERS_ATTR_NAME_IDENTIFIER*/
        ASN1_STRING_set(ia5, p_context_params->p_personality_item->p_identifier_list_item->name, -1);
        GENERAL_NAME_set0_value(gen_name, GEN_DNS, ia5);
        sk_GENERAL_NAME_push(san_names, gen_name);        
        
        ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, san_names);   
        
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free); 

    }

    sk_X509_EXTENSION_push(exts, ext);   
    X509_REQ_add_extensions(x509_req, exts);

    /* set pub key of x509 req */
    /* set sign key of x509 req */
    if ((1 != X509_REQ_set_pubkey(x509_req, p_key)) ||
        (0 >= X509_REQ_sign(x509_req, p_key, EVP_sha256()))) {
        goto internal_err;
    }      
    
    int len = i2d_X509_REQ(x509_req, &p_buffer_out); 
    size_t buffer_idx_out = (size_t)len;
    if ((len < 0) ||
        (buffer_idx_out != p_personality_enrollment_info->write(p_personality_enrollment_info, (char *)p_buffer_out, buffer_idx_out, p_errinfo))) {
        goto internal_err;
    }
    
    p_personality_enrollment_info->finish(p_personality_enrollment_info, 0, p_errinfo);    

    ret = true;

    goto cleanup;

internal_err:
    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
cleanup:
    EVP_PKEY_free(p_key);
    X509_REQ_free(x509_req);    
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);     
    OPENSSL_free(p_buffer_out);         

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
    char payload_chunk[CHUNK_LEN];
    unsigned char* signature = NULL;
    size_t signature_len = 0;

    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *evp_private_key = NULL;

    struct personality_t * p_personality_content = NULL;
    ECDSA_SIG * signatureRaw = NULL;

    /* get Personality of the Context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    evp_private_key = get_pkey_from_der(p_personality_content->secret_data, p_personality_content->secret_data_size, p_errinfo);
    if (NULL == evp_private_key) {            
        goto cleanup;
    }

    /* Create the Message Digest Context */
    /* Initialise the DigestSign operation - SHA-256 */
    if ((!(mdctx = EVP_MD_CTX_new())) ||
        (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, evp_private_key)))
    {
        goto internal_err;
    }    

    /* get Data to sign */
    while (!data->eof(data, p_errinfo)) {
        size_t read_len = data->read(data, payload_chunk, CHUNK_LEN, p_errinfo);
        /* Update with the data chunck */
        if(1 != EVP_DigestSignUpdate(mdctx, payload_chunk, read_len)) {
            goto internal_err;
        }
    }

    /* Obtain the length of the signature before being calculated */
    /* Allocate memory for the signature based on size in signature_len */
    /* Obtain the signature */
    if ((1 != EVP_DigestSignFinal(mdctx, NULL, &signature_len)) ||
        (!(signature = OPENSSL_malloc(sizeof(unsigned char) * (signature_len)))) ||
        (1 != EVP_DigestSignFinal(mdctx, signature, &signature_len))) {
        goto internal_err;
    }
    
    const unsigned char * ptmpData = signature;
    const BIGNUM * pr = NULL;
    const BIGNUM * ps = NULL;

    signatureRaw = d2i_ECDSA_SIG(NULL, &ptmpData, signature_len);
    if (NULL == signatureRaw) {
        goto internal_err;
    }

    ECDSA_SIG_get0(signatureRaw, &pr, &ps);
    if ((NULL == pr) || (NULL == ps) || ((P256_COORDINATE_LEN * 2) > signature_len)) {
        goto internal_err;
    }

    if ((P256_COORDINATE_LEN != BN_bn2binpad(pr, signature, P256_COORDINATE_LEN)) ||
        (P256_COORDINATE_LEN != BN_bn2binpad(ps, signature + P256_COORDINATE_LEN, P256_COORDINATE_LEN))) {
        goto internal_err;
    }

    signature_len = P256_COORDINATE_LEN * 2;

    seal->write(seal, (const char*)signature, signature_len, p_errinfo);
    seal->finish(seal, 0, p_errinfo);

    ret = true;
    goto cleanup;

internal_err:
    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
cleanup:
    OPENSSL_free(signature);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(evp_private_key);
    ECDSA_SIG_free(signatureRaw);

    return ret;
}

const struct profile_function_list_t fl_prof_org_opcfoundation_ecc_nistp256 = {
    .context_open = context_open,
    .context_close = context_close,
    .personality_create = personality_create,
    .personality_enroll = personality_enroll,
    .personality_activate_deactivate_supported = false,
    .personality_attribute_functions_supported = true,
    .context_get_attribute = context_get_attribute,
    .context_set_attribute = context_set_attribute,
    .authenticate_data_detached = authenticate_data_detached,
};
