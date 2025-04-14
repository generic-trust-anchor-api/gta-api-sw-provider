/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#ifndef GTA_SW_PROVIDER_H
#define GTA_SW_PROVIDER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef ENABLE_PQC
#include <oqs/oqs.h>
#endif

#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/types.h>
#include <openssl/x509.h>

#include <gta_api/gta_api.h>
#include <gta_api/util/gta_list.h>

#include "gta_debug.h"
#include "provider_data_model.h"


#define GTA_SWP_DEFINE_FUNCTION(return_type, function_name, argument_list) \
    static return_type function_name argument_list

#define SIZEOF(x) sizeof(x)/sizeof(x[0])

/* Implementation specific boundary of profile name length */
#define MAXLEN_PROFILE 160
#define MAXLEN_CTX_ATTRIBUTE_VALUE 2000
#define PERSONALITY_NAME_LENGTH_MAX 1024
#define CURVENAME_LENGTH_MAX 64
#define CHUNK_LEN 512
#define SERIALIZE_PATH_LEN_MAX 200

/* Supported profiles */
enum profile_t {
    PROF_INVALID = 0,
    PROF_CH_IEC_30168_BASIC_PASSCODE,
    PROF_CH_IEC_30168_BASIC_LOCAL_DATA_INTEGRITY_ONLY,
    PROF_CH_IEC_30168_BASIC_LOCAL_DATA_PROTECTION,
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_RSA,
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_EC,
#ifdef ENABLE_PQC
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_DILITHIUM,
#endif
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_JWT,
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_SIGNATURE,
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_ENROLL,
};

/*
 * Personality Attribute Types
 * Todo: The list only needs to contain personality attribute types which are
 * defined by at least one profile supported by the provider. As a starting
 * point, some types from TS 30168 are listed here.
 *
 * Note: Changing the order / numbering of the existing entries breaks the
 * compatibility with previously serialized personalities.
 */
enum pers_attr_type_t {
    PAT_INVALID = 0,
    PAT_CH_IEC_30168_IDENTIFIER,
    PAT_CH_IEC_30168_FINGERPRINT,
    PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_SELF_X509,
    PAT_CH_IEC_30168_TRUSTLIST_CRL_X509V3,
    PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_TRUSTED_X509V3,
    PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_AUXILIARY_X509,
    PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_LIST_RFC8446,
    PAT_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_KEYTYPE_OPENSSL,
};

/* provider instance global data */
struct gta_sw_provider_params_t {

    gta_context_handle_t h_ctx;

    /* This is the entry pointer to the device stack */
    /* The runtime device stack is initialized or de-serialized during provider init */
    struct devicestate_stack_item_t * p_devicestate_stack;

    /* This struct stores a list of tokens associated with this instance */
    struct provider_instance_auth_token_t * p_auth_token_list;
    /* Struct to track metainfo for auth tokens */
    struct provider_instance_auth_token_info_t {
        gta_access_token_t issuing_token;
        bool issuing_token_issued;
        bool issuing_token_revoked;
        bool physical_presence_token_issued;
    } provider_instance_auth_token_info;

    /* Path used for Serialization files */
    char p_serializ_path[SERIALIZE_PATH_LEN_MAX + 2];
};

/* provider local context specific data */
struct gta_sw_provider_context_params_t {
    gta_context_handle_t h_ctx;
    struct personality_name_list_item_t * p_personality_item;
    struct gta_access_token_list_t * p_access_token_list;
    /* Profile specific condition to be fulfilled before a personality derived access token is issued */
    bool b_pers_derived_access_token_condition_fulfilled;
    enum profile_t profile;
    void * context_attributes;
};

/*
 * Helper function to create and add a new list item for a personality attribute
 * (personality_attribute_t). Input validation and range checks are done by
 * caller.
 */
bool add_personality_attribute_list_item
(
    struct gta_sw_provider_params_t * p_provider_params,
    struct personality_attribute_t ** p_pers_attribute_list,
    const enum pers_attr_type_t attrtype,
    const unsigned char * attrname,
    const size_t attrname_len,
    const unsigned char * attrval,
    const size_t attrval_len,
    const bool b_trusted,
    gta_errinfo_t * p_errinfo
);

/*
 * Helper function, returning the number of bits of a private key.
 * It is intended to be used in order to check if the properties
 * of a personality matches the expectations of a profile.
 */
int pkey_bits(const EVP_PKEY *evp_private_key);

/*
 * Helper function, returning the OpenSSL curve NID of an EC private key.
 * It is intended to be used in order to check if the properties
 * of a personality matches the expectations of a profile.
 * Returns 0 in case of error.
 */
int pkey_ec_nid(const EVP_PKEY *evp_private_key);

/* Helper function to read the whole input from gtaio_istream_t into a buffer */
bool read_input_buffer (gtaio_istream_t * data, unsigned char ** pp_data, size_t * p_data_size, gta_errinfo_t * p_errinfo);

struct profile_function_list_t {
    bool (*context_open)(struct gta_sw_provider_context_params_t *, gta_errinfo_t *);
    bool (*context_close)(struct gta_sw_provider_context_params_t *, gta_errinfo_t *);
    bool (*context_get_attribute)(struct gta_sw_provider_context_params_t *, gta_context_attribute_type_t, gtaio_ostream_t *, gta_errinfo_t *);
    bool (*context_set_attribute)(struct gta_sw_provider_context_params_t *, gta_context_attribute_type_t, gtaio_istream_t *, gta_errinfo_t *);
    bool (*personality_deploy)(struct gta_sw_provider_params_t *, gta_personality_name_t, gtaio_istream_t *, personality_secret_type_t *,unsigned char **, size_t *, gta_personality_fingerprint_t, struct personality_attribute_t **, gta_errinfo_t *);
    bool (*personality_create)(struct gta_sw_provider_params_t *, gta_personality_name_t, personality_secret_type_t *,unsigned char **, size_t *, gta_personality_fingerprint_t, struct personality_attribute_t **, gta_errinfo_t *);
    bool (*personality_enroll)(struct gta_sw_provider_context_params_t *, gtaio_ostream_t *, gta_errinfo_t *);
    bool personality_attribute_functions_supported;
    bool (*seal_data)(struct gta_sw_provider_context_params_t *, gtaio_istream_t *, gtaio_ostream_t *, gta_errinfo_t *);
    bool (*unseal_data)(struct gta_sw_provider_context_params_t *, gtaio_istream_t *, gtaio_ostream_t *, gta_errinfo_t *);
    bool (*verify)(struct gta_sw_provider_context_params_t *, gtaio_istream_t *, gta_errinfo_t *);
    bool (*authenticate_data_detached)(struct gta_sw_provider_context_params_t *, gtaio_istream_t *, gtaio_ostream_t *, gta_errinfo_t *);
};

#endif //GTA_SW_PROVIDER_H
