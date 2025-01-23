/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2024-2025, Siemens AG
 **********************************************************************/

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
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
#include "persistent_storage.h"

#ifdef WINDOWS
#include <openssl\applink.c>
#endif /* WINDOWS */

#ifdef ENABLE_PQC
#include <oqs/oqs.h>

/* TODO this has to be reworked, naming of varaible is confusing */
typedef struct EncryptionAlgorithm_st {
      ASN1_OBJECT* algorithm;
} EncryptionAlgorithm;
DECLARE_ASN1_FUNCTIONS(EncryptionAlgorithm)

typedef struct PublicKeyInfo_st {
    EncryptionAlgorithm* encryptionAlgorithm;
    ASN1_BIT_STRING *public_key_data;
} PublicKeyInfo;
DECLARE_ASN1_FUNCTIONS(PublicKeyInfo)

ASN1_SEQUENCE(EncryptionAlgorithm) = {
    ASN1_SIMPLE(EncryptionAlgorithm, algorithm, ASN1_OBJECT),
} ASN1_SEQUENCE_END(EncryptionAlgorithm)

IMPLEMENT_ASN1_FUNCTIONS(EncryptionAlgorithm)

ASN1_SEQUENCE(PublicKeyInfo) = {
    ASN1_SIMPLE(PublicKeyInfo, encryptionAlgorithm, EncryptionAlgorithm),
    ASN1_SIMPLE(PublicKeyInfo, public_key_data, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(PublicKeyInfo)

IMPLEMENT_ASN1_FUNCTIONS(PublicKeyInfo)

#define OQS_SIGN_ALGORITHM OQS_SIG_alg_dilithium_2
#define OQS_ALG_ID_DILITHIUM_2 "1.3.6.1.4.1.2.267.7.4.4"
#define OQS_ALG_ID_DILITHIUM_3 "1.3.6.1.4.1.2.267.7.6.5"
#define OQS_ALG_ID_DEFAULT OQS_ALG_ID_DILITHIUM_2
#endif

/* Implementation specific boundary of profile name length */
#define MAXLEN_PROFILE 160
#define PERSONALITY_NAME_LENGTH_MAX 1024
#define CHUNK_LEN 512
#define SERIALIZE_PATH_LEN_MAX 200

/* Define for profile ch.iec.30168.basic.local_data_protection */
#define LOCAL_DATA_PROTECTION_SECRET_LEN 32
#define LOCAL_DATA_PROTECTION_KEY_DERIVATION_LEN 32
#define LOCAL_DATA_PROTECTION_IV_LEN 12
#define LOCAL_DATA_PROTECTION_TAG_LEN 16

/* TODO: The following conversion functions have some issues and need
 * improvement in future releases. Due to definitions in the ISO/IEC 30168
 * standard, the pre-defined handle values are not optimal that the handle can
 * safely store the actual counter values for the list enumeration. Therefore, we
 * have to make sure that a undefined handle or a handle with some error
 * condition gets not converted. We only convert GTA_HANDLE_ENUM_FIRST (== -1)
 * to the counter value 0. All other values are kept the same. Converting back
 * and forth this could lead to problems when not done with caution.
 */

#define ENUM_CNT_FROM_HANDLE(p_handle) (size_t)(*p_handle)== (size_t)GTA_HANDLE_ENUM_FIRST ? 0 : (size_t)(*p_handle)
#define ENUM_CNT_TO_HANDLE(enum_cnt) (gta_enum_handle_t)( enum_cnt==0 ? (size_t)GTA_HANDLE_ENUM_FIRST : (size_t)enum_cnt )

static const struct gta_function_list_t g_my_function_list;

/* provider instance global data */
struct gta_sw_provider_params_t {

    gta_context_handle_t h_ctx;

    /* This is the entry pointer to the device stack */
    /* The runtime device stack is initialized or de-serialized during provider init */
    struct devicestate_stack_item_t * p_devicestate_stack;

    /* This struct stores a list of tokens associated with with this instance */
    struct provider_instance_auth_token_t * p_auth_token_list;

    /* Path used for Serialization files */
    char p_serializ_path[SERIALIZE_PATH_LEN_MAX + 2];
};

struct provider_instance_auth_token_t {
    struct provider_instance_auth_token_t * p_next;

    /*
     * Mandatory token attributes
     */

    /* Object reference scope */
    gta_personality_name_t personality_name;

    /* enum: initial, basic, personality derived, physical presence */
    gta_access_descriptor_type_t type;

    /* enum: use, admin, recede */
    gta_access_token_usage_t usage;

    /* Nonce for freshness of token */
    uint32_t freshness;

    /*
     * Optional attributes
     */
    gta_personality_fingerprint_t pers_fingerprint;
    uint32_t profile;  /* Note: stores unnamed enum declared in gta_sw_provider_context_params_t */

    /* Actual token value (binary string) */
    gta_access_token_t access_token;
};


/* Supported profiles */
enum profile_t {
    PROF_INVALID = 0,
    PROF_CH_IEC_30168_BASIC_PASSCODE,
    PROF_CH_IEC_30168_BASIC_LOCAL_DATA_INTEGRITY_ONLY,
    PROF_CH_IEC_30168_BASIC_LOCAL_DATA_PROTECTION,
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_RSA,
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_EC,
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_DILITHIUM,
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_JWT,
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_TLS,
};
#define NUM_PROFILES 9
static char supported_profiles[NUM_PROFILES][MAXLEN_PROFILE] = {
    [PROF_INVALID] = "INVALID",
    [PROF_CH_IEC_30168_BASIC_PASSCODE] = "ch.iec.30168.basic.passcode",
    [PROF_CH_IEC_30168_BASIC_LOCAL_DATA_INTEGRITY_ONLY] = "ch.iec.30168.basic.local_data_integrity_only",
    [PROF_CH_IEC_30168_BASIC_LOCAL_DATA_PROTECTION] = "ch.iec.30168.basic.local_data_protection",
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_RSA] = "com.github.generic-trust-anchor-api.basic.rsa",
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_EC] = "com.github.generic-trust-anchor-api.basic.ec",
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_DILITHIUM] = "com.github.generic-trust-anchor-api.basic.dilithium",
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_JWT] = "com.github.generic-trust-anchor-api.basic.jwt",
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_TLS] = "com.github.generic-trust-anchor-api.basic.tls",
};

/*
 * Helper function to get enum value of a profile string. In case the string is
 * not found, 0 (PROF_INVALID) is returned.
 */
static enum profile_t get_profile_enum(const char * profile)
{
    for (uint32_t i=0; i < NUM_PROFILES; ++i) {
        if (0 == strcmp(profile, supported_profiles[i])) {
            return i;
        }
    }
    return PROF_INVALID;
}

/* provider local context specific data */
struct gta_sw_provider_context_params_t {
    struct personality_name_list_item_t * p_personality_item;
    gta_access_token_t access_token;
    enum profile_t profile;

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
#define NUM_PERSONALITY_ATTRIBUTE_TYPE 9
static char pers_attr_type_strings[NUM_PERSONALITY_ATTRIBUTE_TYPE][MAXLEN_PERSONALITY_ATTRIBUTE_TYPE] = {
    [PAT_INVALID] = "INVALID",
    [PAT_CH_IEC_30168_IDENTIFIER] = "ch.iec.30168.identifier",
    [PAT_CH_IEC_30168_FINGERPRINT] = "ch.iec.30168.fingerprint",
    [PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_SELF_X509] = "ch.iec.30168.trustlist.certificate.self.x509",
    [PAT_CH_IEC_30168_TRUSTLIST_CRL_X509V3] = "ch.iec.30168.trustlist.crl.x509v3",
    [PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_TRUSTED_X509V3] = "ch.iec.30168.trustlist.certificate.trusted.x509v3",
    [PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_AUXILIARY_X509] = "ch.iec.30168.trustlist.certificate.auxiliary.x509",
    [PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_LIST_RFC8446] = "ch.iec.30168.trustlist.certificate_list.rfc8446",
    [PAT_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_KEYTYPE_OPENSSL] = "com.github.generic-trust-anchor-api.keytype.openssl",
};

static bool pers_attr_type_trusted[NUM_PERSONALITY_ATTRIBUTE_TYPE] = {
    [PAT_INVALID] = false,
    [PAT_CH_IEC_30168_IDENTIFIER] = true, /* it is an internal attribute, anyway not allowed to be changed */
    [PAT_CH_IEC_30168_FINGERPRINT] = true, /* it is an internal attribute, anyway not allowed to be changed */
    [PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_SELF_X509] = false,
    [PAT_CH_IEC_30168_TRUSTLIST_CRL_X509V3] = false,
    [PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_TRUSTED_X509V3] = true,
    // TODO: check the implications of: "are only trusted if additional evidence is provided"
    [PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_AUXILIARY_X509] = true,
    [PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_LIST_RFC8446] = false,
    [PAT_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_KEYTYPE_OPENSSL] = true, /* it is an internal attribute, anyway not allowed to be changed */
};

/* attribute related defines */
#define PERS_ATTR_NAME_IDENTIFIER       "ch.iec.30168.identifier_value"
#define PERS_ATTR_NAME_FINGERPRINT      "ch.iec.30168.fingerprint"
#define PERS_ATTR_NAME_KEYTYPE          "com.github.generic-trust-anchor-api.keytype.openssl"
#define PERS_ATTR_KEYTYPE_EC            "EC"
#define PERS_ATTR_KEYTYPE_DILITHIUM2    "dilithium2"

/*
 * Helper function to get enum value of personality attribute type string. In
 * case the string is not found, 0 (PAT_INVALID) is returned.
 */
static enum pers_attr_type_t get_pers_attr_type_enum(const char * attrtype)
{
    for (uint32_t i=0; i < NUM_PERSONALITY_ATTRIBUTE_TYPE; ++i) {
        if (0 == strcmp(attrtype, pers_attr_type_strings[i])) {
            return i;
        }
    }
    return PAT_INVALID;
}

void
gta_sw_provider_free_params(void * p_params)
{
    /* p_params have been allocated using gta_secmem_calloc() an
       are released automatically.
       Since there are no additional resources there's nothing
       to do at the moment. */
}

/* used with list_find() to find a identifier list item by the identifier name */
bool identifier_list_item_cmp_name(void * p_list_item, void * p_item_crit)
{
    struct identifier_list_item_t * p_identifier_list_item = p_list_item;
    gta_identifier_value_t identifier_value = p_item_crit;

    if (0 == strcmp(p_identifier_list_item->name, identifier_value)) {
        return true;
    }

    return false;
}

/* used with list_find() to find a personality list item by the personality name */
bool personality_list_item_cmp_name(void * p_list_item, void * p_item_crit)
{
    struct personality_name_list_item_t * p_personality_name_list_item = p_list_item;
    gta_personality_name_t personality_name = p_item_crit;

    if (0 == strcmp(p_personality_name_list_item->personality_name, personality_name)) {
        return true;
    }

    return false;
}

/* used with list_find() to find an attribute list item by the attribute name */
bool attribute_list_item_cmp_name(void * p_list_item, void * p_item_crit)
{
    struct personality_attribute_t * p_personality_attribute = p_list_item;
    char * p_attribute_name = p_item_crit;

    if (0 == strcmp(p_personality_attribute->p_name, p_attribute_name)) {
        return true;
    }

    return false;
}

/*
 * Helper function to check whether all provider params are valid.
 * - returns true, if provider params are valid
 * - returns false, if provider params are NULL or device state stack is NULL
 */
static bool check_provider_params
(
    const struct gta_sw_provider_params_t * p_provider_params,
    gta_errinfo_t * p_errinfo
)
{
    bool ret = true;

    if ((NULL == p_provider_params) || (NULL == p_provider_params->p_devicestate_stack)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        ret = false;
    }

    return ret;
}

GTA_DECLARE_FUNCTION(const struct gta_function_list_t *, gta_sw_provider_init, ());
GTA_DEFINE_FUNCTION(const struct gta_function_list_t *, gta_sw_provider_init,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * provider_init_config,
    gtaio_ostream_t * logging,
    void ** pp_params,
    void (** ppf_free_params)(void * p_params),
    gta_errinfo_t * p_errinfo
))
{
    struct gta_sw_provider_params_t * p_provider_params = NULL;

    p_provider_params = gta_secmem_calloc(h_ctx, 1, sizeof(struct gta_sw_provider_params_t), p_errinfo);
    if (NULL != p_provider_params) {
        *pp_params = p_provider_params;
        p_provider_params->p_devicestate_stack = NULL;
    }
    else {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* assign the cleanup function */
    *ppf_free_params = gta_sw_provider_free_params;

    /* save context for later use */
    p_provider_params->h_ctx = h_ctx;

    /* configure provider */
    if (provider_init_config->read(provider_init_config, p_provider_params->p_serializ_path, SERIALIZE_PATH_LEN_MAX, p_errinfo)
        > SERIALIZE_PATH_LEN_MAX) {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        goto err;
    }
    DEBUG_PRINT(("CONFIG: Serialization path = %s\n", p_provider_params->p_serializ_path));


#if 1 /* internal test */
    if (gta_context_get_provider_params(h_ctx, p_errinfo) != p_provider_params)
    {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
#endif

    /* de-serialize the persisted device state */
    if (serialized_file_exists(p_provider_params->p_serializ_path)) {
        DEBUG_PRINT(("Performing DESERIALIZATION.\n"));
        if (!provider_deserialize(p_provider_params->p_serializ_path, &(p_provider_params->p_devicestate_stack), p_provider_params->h_ctx)) {
            DEBUG_PRINT(("Error while DESERIALIZATION. Cleaning up.\n"));
            devicestate_stack_list_destroy(h_ctx, p_provider_params->p_devicestate_stack, p_errinfo);
            /* Fail when Deserialization error. In order to start just remove existing serialization files */
            goto err;
        }
    }

    /* If no Serialization data found, simply start with an empty device stack which is filled during runtime */
    if (NULL == p_provider_params->p_devicestate_stack) {
        p_provider_params->p_devicestate_stack =
            gta_secmem_calloc(h_ctx, 1, sizeof(struct devicestate_stack_item_t), p_errinfo);
        if (NULL == p_provider_params->p_devicestate_stack) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        p_provider_params->p_devicestate_stack->p_next = NULL;
        p_provider_params->p_devicestate_stack->owner_lock_count = 0;
        p_provider_params->p_devicestate_stack->p_identifier_list = NULL;
        p_provider_params->p_devicestate_stack->p_personality_name_list = NULL;
    }

    return &g_my_function_list;

err:
    /* clean up */
    if (NULL != p_provider_params) {
        gta_secmem_free(h_ctx, p_provider_params, p_errinfo);
    }

    return NULL;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_access_token_get_physical_presence,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t physical_presence_token,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_access_token_get_issuing,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t granting_token,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_access_token_get_basic,
(
    gta_instance_handle_t h_inst,
    const gta_access_token_t granting_token,
    const gta_personality_name_t personality_name,
    gta_access_token_usage_t usage,
    gta_access_token_t basic_access_token,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;
    struct gta_sw_provider_params_t * p_provider_params = NULL;
    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
    struct provider_instance_auth_token_t * p_auth_token_list_item = NULL;

    p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (NULL == p_provider_params) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* TODO: For now we ignore the granting token (set to NULL) and accept
     * any request */

    /* Create a new access token object */
    p_auth_token_list_item =
       gta_secmem_calloc(p_provider_params->h_ctx,
       1, sizeof(struct provider_instance_auth_token_t ), p_errinfo);
    if (NULL == p_auth_token_list_item) {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    p_auth_token_list_item->p_next = NULL;
    p_auth_token_list_item->personality_name =
       gta_secmem_calloc(p_provider_params->h_ctx, 1,
       strnlen(personality_name, PERSONALITY_NAME_LENGTH_MAX)+1, p_errinfo);
    if (NULL == p_auth_token_list_item->personality_name) {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    strcpy(p_auth_token_list_item->personality_name, personality_name);
    p_auth_token_list_item->type = GTA_ACCESS_DESCRIPTOR_TYPE_BASIC_TOKEN;
    p_auth_token_list_item->usage = usage;

    /* Get random number from OpenSSL for freshness */
    if (1 != RAND_bytes((unsigned char *)&p_auth_token_list_item->freshness,
             sizeof(p_auth_token_list_item->freshness)))
    {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Set optional attributes to undefined */
    p_auth_token_list_item->profile = PROF_INVALID;
    memset(p_auth_token_list_item->pers_fingerprint, 0, PERS_FINGERPRINT_LEN);

    /* Compute and set basic_access_token (256 bit value) */
    /* TODO SHA256 error handling */
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    /*
     * todo: hashing of p_auth_token_list_item needs to be refactored as the
     * current approach causes valgrind errors. We should hash (sha update) the
     * content of each struct element independently.
     */
    /*
    SHA256_Update(&sha256, p_auth_token_list_item + sizeof(p_auth_token_list_item->p_next),
               sizeof(struct provider_instance_auth_token_t ) - sizeof(p_auth_token_list_item->p_next));
    */
                /* Note: do not include "p_auth_token_list_item->p_next", as the pointer can change */
    SHA256_Update(&sha256, p_auth_token_list_item->personality_name,
                   strnlen(p_auth_token_list_item->personality_name, PERSONALITY_NAME_LENGTH_MAX)+1 );
#if (GTA_ACCESS_TOKEN_LEN != 32)
#error Size of access_token does not match used hash function
#endif
    SHA256_Final((unsigned char *)p_auth_token_list_item->access_token, &sha256);
    memcpy(basic_access_token, p_auth_token_list_item->access_token, GTA_ACCESS_TOKEN_LEN);

    /* Append item to list */
    list_append((struct list_t **) &p_provider_params->p_auth_token_list, (void *) p_auth_token_list_item);
    ret = true;

err:
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_access_token_get_pers_derived,
(
    gta_context_handle_t h_ctx,
    const gta_personality_name_t target_personality_name,
    gta_access_token_usage_t usage,
    gta_access_token_t * p_pers_derived_access_token,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;
    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct provider_instance_auth_token_t * p_auth_token_list_item = NULL;
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    const struct personality_attribute_t * p_attribute = NULL;

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (NULL == p_provider_params) {
        goto err;
    }

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (NULL == p_context_params) {
        goto err;
    }

    /* TODO: in order to generate a personality derived token we have to check whether
    * a certain condition is met. But how do we know the what condition has to be met?
    */

    p_auth_token_list_item =
       gta_secmem_calloc(h_ctx,
       1, sizeof(struct provider_instance_auth_token_t ), p_errinfo);
    if (NULL == p_auth_token_list_item) {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    p_auth_token_list_item->p_next = NULL;
    p_auth_token_list_item->personality_name =
       gta_secmem_calloc(p_provider_params->h_ctx, 1,
       strnlen(target_personality_name, PERSONALITY_NAME_LENGTH_MAX)+1, p_errinfo);
    if (NULL == p_auth_token_list_item->personality_name) {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    strcpy(p_auth_token_list_item->personality_name, target_personality_name);
    p_auth_token_list_item->type = GTA_ACCESS_DESCRIPTOR_TYPE_PERS_DERIVED_TOKEN;
    p_auth_token_list_item->usage = usage;

    /* Get random number from OpenSSL for freshness */
    if (1 != RAND_bytes((unsigned char *)&p_auth_token_list_item->freshness,
             sizeof(p_auth_token_list_item->freshness)))
    {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Find attribute_list_item with requested name */
    p_attribute = list_find((struct list_t *)(p_context_params->p_personality_item->p_personality_content->p_attribute_list),
                            PERS_ATTR_NAME_FINGERPRINT, attribute_list_item_cmp_name);
    if (NULL == p_attribute) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    memcpy(p_auth_token_list_item->pers_fingerprint, p_attribute->p_data, p_attribute->data_size);

    p_auth_token_list_item->profile = (uint32_t)p_context_params->profile;
    memset(p_auth_token_list_item->access_token, 0, GTA_ACCESS_TOKEN_LEN);

    /* Compute and set pers_derived_access_token (256 bit value) */
    /* TODO SHA256 error handling */
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, (char*)p_auth_token_list_item + sizeof(p_auth_token_list_item->p_next),
               sizeof(struct provider_instance_auth_token_t ) - sizeof(p_auth_token_list_item->p_next));
               /* Note: do not include "p_auth_token_list_item->p_next", as the pointer can change */
    SHA256_Update(&sha256, p_auth_token_list_item->personality_name,
                   strnlen(p_auth_token_list_item->personality_name, PERSONALITY_NAME_LENGTH_MAX)+1 );
    SHA256_Update(&sha256, p_auth_token_list_item->pers_fingerprint, PERS_FINGERPRINT_LEN);
#if (GTA_ACCESS_TOKEN_LEN != 32)
#error Size of access_token does not match used hash function
#endif
    SHA256_Final((unsigned char *)p_auth_token_list_item->access_token, &sha256);
    memcpy(*p_pers_derived_access_token, p_auth_token_list_item->access_token, GTA_ACCESS_TOKEN_LEN);

    /* Append item to list */
    list_append((struct list_t **) &(p_provider_params->p_auth_token_list), (void *) p_auth_token_list_item);
    ret = true;

err:
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_access_token_revoke,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t access_token_tbr,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}

GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_context_auth_set_access_token,
(
    gta_context_handle_t h_ctx,
    const gta_access_token_t access_token,
    gta_errinfo_t * p_errinfo
    ))
{
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (NULL == p_context_params) {
        goto err;
    }

    /* Here we set the token in the context parameters,
     * currently only one token per context is allowed */
    memcpy(p_context_params->access_token, access_token, GTA_ACCESS_TOKEN_LEN);
    ret = true;

err:
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_context_auth_get_challenge,
(
    gta_context_handle_t h_ctx,
    gtaio_ostream_t * challenge,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_context_auth_set_random,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * random,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_context_get_attribute,
(
    gta_context_handle_t h_ctx,
    const gta_context_attribute_type_t attrtype,
    gtaio_ostream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_context_set_attribute,
(
    gta_context_handle_t h_ctx,
    const gta_context_attribute_type_t attrtype,
    gtaio_istream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


/*
 * Helper function, returning the number of bits of a private key.
 * It is intended to be used in order to check if the properties
 * of a personality matches the expectations of a profile.
 */
static int pkey_bits(const EVP_PKEY *evp_private_key) {
    return EVP_PKEY_bits(evp_private_key);
}


/*
 * Helper function, returning the OpenSSL curve NID of an EC private key.
 * It is intended to be used in order to check if the properties
 * of a personality matches the expectations of a profile.
 * Returns 0 in case of error.
 */

static int pkey_ec_name(const EVP_PKEY *evp_private_key) {
    const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(evp_private_key);
    if (NULL == ec_key) {
        return 0;
    }
    const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);

    return EC_GROUP_get_curve_name(ec_group);
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_provider_context_open,
(
    gta_context_handle_t h_ctx,
    const gta_personality_name_t personality,
    const gta_profile_name_t profile,
    void ** pp_params,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct devicestate_stack_item_t * p_devicestate_stack_item = NULL;
    struct personality_name_list_item_t * p_personality_item = NULL;

    struct personality_t * p_personality_content = NULL;
    EVP_PKEY *evp_private_key = NULL;

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /* iterate device states to find requested personality */
    p_devicestate_stack_item = p_provider_params->p_devicestate_stack;
    while (NULL != p_devicestate_stack_item) {
        p_personality_item = list_find((struct list_t *)p_devicestate_stack_item->p_personality_name_list, personality, personality_list_item_cmp_name);
        if (NULL == p_personality_item ) {
            p_devicestate_stack_item = p_devicestate_stack_item->p_next;
        } else {
            /* Personality found, exit the Loop */
            p_devicestate_stack_item = NULL;
        }
    }

    if (NULL == p_personality_item ) {
        *p_errinfo = GTA_ERROR_ITEM_NOT_FOUND;
        goto err;
    }

    /* TODO: load / initialize personality -- something to do here? */

    /* initialize context parameters */
    p_context_params = gta_secmem_calloc(h_ctx, 1, sizeof(struct gta_sw_provider_context_params_t), p_errinfo);
    if (NULL != p_context_params) {
        *pp_params = p_context_params;
    }
    else {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    p_context_params->p_personality_item = p_personality_item;

    p_context_params->profile = get_profile_enum(profile);

    /* check whether provider and personality support requested profile */
    if (PROF_CH_IEC_30168_BASIC_PASSCODE == p_context_params->profile) {
        ret = true;
    } else if (PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_JWT == p_context_params->profile) {

        if (SECRET_TYPE_DER != p_personality_item->p_personality_content->secret_type)
        {
            DEBUG_PRINT(("gta_sw_provider_gta_context_open: Personality type not as expected\n"));
            *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
            goto err;
        }
        /* further checks required by profile: such as algorithms and minimum key length */

        /* get the Private Key from the Personality */
        p_personality_content = p_context_params->p_personality_item->p_personality_content;
        unsigned char * p_secret_buffer  = p_personality_content->secret_data;
        /* Range check on p_personality_content->content_data_size */
        if (p_personality_content->secret_data_size > LONG_MAX) {
            goto err;
        }
        evp_private_key = d2i_AutoPrivateKey(NULL,
                                             (const unsigned char **) &p_secret_buffer,
                                             (long)p_personality_content->secret_data_size);
        /* clear pointer */
        p_secret_buffer = NULL;
        if (!evp_private_key)
        {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        int key_id = EVP_PKEY_base_id(evp_private_key);

        if ((EVP_PKEY_RSA == key_id) && (2048 <= pkey_bits(evp_private_key))) {
            ret = true;
        } else if ((EVP_PKEY_EC == key_id) && (NID_X9_62_prime256v1 == pkey_ec_name(evp_private_key))) {
            ret = true;
        } else {
            DEBUG_PRINT(("gta_sw_provider_gta_context_open: Profile requirements not fulfilled \n"));
            *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
            goto err;
        }

    } else if (PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_TLS == p_context_params->profile) {
        if (SECRET_TYPE_DER == p_personality_item->p_personality_content->secret_type)
        {
            /* here add further checks if required by profile: such as algorithms and minimum key length */
            ret = true;
        }
#ifdef ENABLE_PQC
        else if (SECRET_TYPE_DILITHIUM2 == p_personality_item->p_personality_content->secret_type) {
            /* here add further checks if required by profile: such as algorithms and minimum key length */
            ret = true;
        }
#endif
        else {
            DEBUG_PRINT(("gta_sw_provider_gta_context_open: Personality type not as expected\n"));
            *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
            goto err;
        }
    } else if (PROF_CH_IEC_30168_BASIC_LOCAL_DATA_PROTECTION == p_context_params->profile) {
        if (SECRET_TYPE_RAW_BYTES != p_personality_item->p_personality_content->secret_type)
        {
            DEBUG_PRINT(("gta_sw_provider_gta_context_open: Personality type not as expected\n"));
            *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
            goto err;
        }
        /* Check secret length */
        if (LOCAL_DATA_PROTECTION_SECRET_LEN != p_personality_item->p_personality_content->secret_data_size) {
            DEBUG_PRINT(("gta_sw_provider_gta_context_open: Profile requirements not fulfilled \n"));
            *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
            goto err;
        }
        ret = true;

    } else {
        DEBUG_PRINT(("gta_sw_provider_gta_context_open: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }


#if 0 /* internal test */
    if (gta_context_get_params(h_ctx, p_errinfo) != p_context_params)
    {
        /* p_provider_params is not cleaned up */
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }
#endif

    if (NULL != evp_private_key) {
        EVP_PKEY_free(evp_private_key);
        evp_private_key = NULL;
    }

    return ret;

err:
    if (NULL != p_context_params) {
        gta_secmem_free(h_ctx, p_context_params, p_errinfo);
        p_context_params = NULL;
    }

    if (NULL != evp_private_key) {
        EVP_PKEY_free(evp_private_key);
        evp_private_key = NULL;
    }

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_provider_context_close,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = true;

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_devicestate_transition,
(
    gta_instance_handle_t h_inst,
    gta_access_policy_handle_t h_auth_recede,
    size_t owner_lock_count,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_devicestate_recede,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t access_token,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_devicestate_attestate,
(
    gta_context_handle_t h_context,
    gtaio_istream_t * nonce,
    gtaio_ostream_t * attestation,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_identifier_assign,
(
    gta_instance_handle_t h_inst,
    const gta_identifier_type_t identifier_type,
    const gta_identifier_value_t identifier_value,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;
    size_t identifier_type_length = 0;
    size_t identifier_value_length = 0;
    gta_errinfo_t errinfo_tmp = GTA_ERROR_INTERNAL_ERROR;

    const struct gta_sw_provider_params_t * p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    struct identifier_list_item_t * p_identifier_list_item = NULL;

    /* From here we attach the new identifier to internal data structures */
    if (NULL != (p_identifier_list_item = gta_secmem_calloc(p_provider_params->h_ctx,
        1, sizeof(struct identifier_list_item_t), p_errinfo))) {

        identifier_type_length = strnlen(identifier_type, IDENTIFIER_TYPE_MAXLEN);
        identifier_value_length = strnlen(identifier_value, IDENTIFIER_VALUE_MAXLEN);
        if ((0 != identifier_type_length) && (IDENTIFIER_TYPE_MAXLEN != identifier_type_length)
            && (0 != identifier_value_length) && (IDENTIFIER_VALUE_MAXLEN != identifier_value_length)) {

            if ((NULL != (p_identifier_list_item->type = gta_secmem_calloc(p_provider_params->h_ctx,
                1, (identifier_type_length + 1), p_errinfo)))
                && (NULL != (p_identifier_list_item->name = gta_secmem_calloc(p_provider_params->h_ctx,
                1, (identifier_value_length + 1), p_errinfo)))) {

                memcpy((char*)p_identifier_list_item->type, identifier_type, identifier_type_length + 1);
                *((char *)p_identifier_list_item->type+identifier_type_length) = 0;
                memcpy(p_identifier_list_item->name, identifier_value, identifier_value_length + 1);
                *(p_identifier_list_item->name+identifier_value_length) = 0;

                list_append_front(
                    (struct list_t **)(&(p_provider_params->p_devicestate_stack->p_identifier_list)),
                    p_identifier_list_item);
                p_provider_params->p_devicestate_stack->p_identifier_list = p_identifier_list_item;

                ret = provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack);
                if (false == ret) {
                    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                    identifier_list_item_free(p_provider_params->h_ctx, p_identifier_list_item, &errinfo_tmp);
                }
            }
            else {
                /* TODO add proper error handling */
                *p_errinfo = GTA_ERROR_MEMORY;
                identifier_list_item_free(p_provider_params->h_ctx, p_identifier_list_item, &errinfo_tmp);
            }
        }
        else {
            /* TODO add proper error handling */
            *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
            identifier_list_item_free(p_provider_params->h_ctx, p_identifier_list_item, &errinfo_tmp);
        }
    }
    else {
        /* TODO add proper error handling */
        *p_errinfo = GTA_ERROR_MEMORY;
    }
err:
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_identifier_enumerate,
(
    gta_instance_handle_t h_inst,
    gta_enum_handle_t * ph_enum,
    gtaio_ostream_t * identifier_type,
    gtaio_ostream_t * identifier_value,
    gta_errinfo_t * p_errinfo
    ))
{
     /* @todo The direct exposure of an internal pointer through ph_enum
             is not ideal. Using a handle map as in the GTA API framework
             implementation would improve robustness.
             Use of magic values (GTA_HANDLE_ENUM_FINISHED) to distinguish
             different kinds of invalid handles is a hack. */

    bool ret = false;

    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct identifier_list_item_t * p_identifier_list_item = NULL;
    struct devicestate_stack_item_t * p_devicestate_stack_item = NULL;
    size_t enum_cnt = 0;

    p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /*
     * Find the current list element based on ph_enum. ph_enum stores the index
     * number of the element starting at 0
     */
    enum_cnt = ENUM_CNT_FROM_HANDLE(ph_enum);

    p_devicestate_stack_item = p_provider_params->p_devicestate_stack;
    p_identifier_list_item = p_devicestate_stack_item->p_identifier_list;

    /*
     * Walk through the list to find element with index enum_cnt or break
     * early if p_devicestate_stack_item is NULL
     */
    size_t count = 0;
    while (NULL != p_devicestate_stack_item) {
        /*
         * If we have a valid identifier_list_item:
         * - in case count == enum_cnt, we are done and break
         * - otherwise, we increment count and walk to the next
         *   identifier_list_item
         */
        if (NULL != p_identifier_list_item) {
            if (enum_cnt == count) {
                break;
            }
            else {
                ++count;
                p_identifier_list_item = p_identifier_list_item->p_next;
            }
        }
        /*
         * We are at the end of the current identifier_list and need to proceed
         * with the next device state
         */
        else {
            if (NULL != (p_devicestate_stack_item = p_devicestate_stack_item->p_next)) {
                p_identifier_list_item = p_devicestate_stack_item->p_identifier_list;
            }
        }
    }

    if (NULL != p_identifier_list_item) {
        gta_errinfo_t errinfo = 0;

        identifier_type->write(identifier_type, p_identifier_list_item->type, strnlen(p_identifier_list_item->type, IDENTIFIER_TYPE_MAXLEN), &errinfo);
        identifier_type->write(identifier_type, "", 1, &errinfo);
        identifier_value->write(identifier_value, p_identifier_list_item->name, strnlen(p_identifier_list_item->name, IDENTIFIER_VALUE_MAXLEN), &errinfo);
        identifier_value->write(identifier_value, "", 1, &errinfo);

        if (0 == errinfo) {
            ++enum_cnt;
            ret = true;
        }
        else {
           *p_errinfo = errinfo;
        }

    }
    else {
        *ph_enum = GTA_HANDLE_INVALID;
        *p_errinfo = GTA_ERROR_ENUM_NO_MORE_ITEMS;
    }
    if(*ph_enum != GTA_HANDLE_INVALID) {
        *ph_enum = ENUM_CNT_TO_HANDLE(enum_cnt);
    }
err:
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_enumerate,
(
    gta_instance_handle_t h_inst,
    const gta_identifier_value_t identifier_value,
    gta_enum_handle_t * ph_enum,
    gta_personality_enum_flags_t flags,
    gtaio_ostream_t * personality_name,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct personality_name_list_item_t * p_personality_name_list_item = NULL;
    struct devicestate_stack_item_t * p_devicestate_stack_item = NULL;
    size_t enum_cnt = 0;

    p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /*
     * Find the current list element based on ph_enum. ph_enum stores the index
     * number of the element starting at 0
     */
    enum_cnt = ENUM_CNT_FROM_HANDLE(ph_enum);

    p_devicestate_stack_item = p_provider_params->p_devicestate_stack;
    p_personality_name_list_item = p_devicestate_stack_item->p_personality_name_list;

    /*
     * Walk through the list to find element with index enum_cnt or break
     * early if p_devicestate_stack_item is NULL
     */
    size_t count = 0;
    while (NULL != p_devicestate_stack_item) {
        /*
         * If we have a valid personality_name_list_item, which should be
         * enumerated based on identifier_value and flags:
         * - in case count == enum_cnt, we are done and break
         * - otherwise, we increment count and walk to the next
         *   personality_name_list_item
         * If we have a valid personality_name_list_item, which should not be
         * enumerated, we proceed with the next item w/o incrementing count.
         */
        if (NULL != p_personality_name_list_item) {
            if ((0 != strncmp(p_personality_name_list_item->p_identifier_list_item->name, identifier_value, IDENTIFIER_VALUE_MAXLEN))
                || (((GTA_PERSONALITY_ENUM_ACTIVE == flags) && (!p_personality_name_list_item->activated))
                    || ((GTA_PERSONALITY_ENUM_INACTIVE == flags) && (p_personality_name_list_item->activated)))) {
                /* We go to the next item w/o incrementing count */
                p_personality_name_list_item = p_personality_name_list_item->p_next;
            }
            else if (enum_cnt == count) {
                break;
            }
            else {
                ++count;
                p_personality_name_list_item = p_personality_name_list_item->p_next;
            }
        }
        /*
         * We are at the end of the current personality_name_list and need to
         * proceed with the next device state
         */
        else {
            if (NULL != (p_devicestate_stack_item = p_devicestate_stack_item->p_next)) {
                p_personality_name_list_item = p_devicestate_stack_item->p_personality_name_list;
            }
        }
    }

    if (NULL != p_personality_name_list_item) {
        gta_errinfo_t errinfo = 0;

        personality_name->write(personality_name, p_personality_name_list_item->personality_name, strnlen(p_personality_name_list_item->personality_name, PERSONALITY_NAME_LENGTH_MAX), &errinfo);
        personality_name->write(personality_name, "", 1, &errinfo);

        if (0 == errinfo) {
            ++enum_cnt;
            ret = true;
        }
        else {
           *p_errinfo = errinfo;
        }
    }
    else {
        *ph_enum = GTA_HANDLE_INVALID;
        *p_errinfo = GTA_ERROR_ENUM_NO_MORE_ITEMS;
    }
    if(*ph_enum != GTA_HANDLE_INVALID) {
        *ph_enum = ENUM_CNT_TO_HANDLE(enum_cnt);
    }
err:
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_enumerate_application,
(
    gta_instance_handle_t h_inst,
    const gta_application_name_t application_name,
    gta_enum_handle_t * ph_enum,
    gta_personality_enum_flags_t flags,
    gtaio_ostream_t * personality_name,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct personality_name_list_item_t * p_personality_name_list_item = NULL;
    struct devicestate_stack_item_t * p_devicestate_stack_item = NULL;
    size_t enum_cnt = 0;

    p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /*
     * Find the current list element based on ph_enum. ph_enum stores the index
     * number of the element starting at 0
     */
    enum_cnt = ENUM_CNT_FROM_HANDLE(ph_enum);

    p_devicestate_stack_item = p_provider_params->p_devicestate_stack;
    p_personality_name_list_item = p_devicestate_stack_item->p_personality_name_list;

    /*
     * Walk through the list to find element with index enum_cnt or break
     * early if p_devicestate_stack_item is NULL
     */
    size_t count = 0;
    while (NULL != p_devicestate_stack_item) {
        /*
         * If we have a valid personality_name_list_item, which should be
         * enumerated based on identifier_value and flags:
         * - in case count == enum_cnt, we are done and break
         * - otherwise, we increment count and walk to the next
         *   personality_name_list_item
         * If we have a valid personality_name_list_item, which should not be
         * enumerated, we proceed with the next item w/o incrementing count.
         */
        if (NULL != p_personality_name_list_item) {
            if ((0 != strncmp(p_personality_name_list_item->application_name, application_name, MAXLEN_APPLICATION_NAME))
                || (((GTA_PERSONALITY_ENUM_ACTIVE == flags) && (!p_personality_name_list_item->activated))
                    || ((GTA_PERSONALITY_ENUM_INACTIVE == flags) && (p_personality_name_list_item->activated)))) {
                /* We go to the next item w/o incrementing count */
                p_personality_name_list_item = p_personality_name_list_item->p_next;
            }
            else if (enum_cnt == count) {
                break;
            }
            else {
                ++count;
                p_personality_name_list_item = p_personality_name_list_item->p_next;
            }
        }
        /*
         * We are at the end of the current personality_name_list and need to
         * proceed with the next device state
         */
        else {
            if (NULL != (p_devicestate_stack_item = p_devicestate_stack_item->p_next)) {
                p_personality_name_list_item = p_devicestate_stack_item->p_personality_name_list;
            }
        }
    }

    if (NULL != p_personality_name_list_item) {
        gta_errinfo_t errinfo = 0;

        personality_name->write(personality_name, p_personality_name_list_item->personality_name, strnlen(p_personality_name_list_item->personality_name, PERSONALITY_NAME_LENGTH_MAX), &errinfo);
        personality_name->write(personality_name, "", 1, &errinfo);

        if (0 == errinfo) {
            ++enum_cnt;
            ret = true;
        }
        else {
           *p_errinfo = errinfo;
        }
    }
    else {
        *ph_enum = GTA_HANDLE_INVALID;
        *p_errinfo = GTA_ERROR_ENUM_NO_MORE_ITEMS;
    }
    if(*ph_enum != GTA_HANDLE_INVALID) {
        *ph_enum = ENUM_CNT_TO_HANDLE(enum_cnt);
    }
err:
    return ret;
}

/*
 * Helper function to create and add a new list item for a personality attribute
 * (personality_attribute_t). Input validation and range checks are done by
 * caller.
 */
bool add_personality_attribute_list_item(
    struct gta_sw_provider_params_t * p_provider_params,
    struct personality_name_list_item_t * p_personality_name_list_item,
    const enum pers_attr_type_t attrtype,
    const unsigned char * attrname,
    const size_t attrname_len,
    const unsigned char * attrval,
    const size_t attrval_len,
    gta_errinfo_t * p_errinfo
    )
{
    struct personality_attribute_t * p_personality_attribute = NULL;
    gta_errinfo_t errinfo_tmp = GTA_ERROR_INTERNAL_ERROR;

    /* allocate memory for personality attribute list item */
    if (!(p_personality_attribute = gta_secmem_calloc(p_provider_params->h_ctx,
        1, sizeof(struct personality_attribute_t), p_errinfo))) {

        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    p_personality_attribute->p_next = NULL;
    p_personality_attribute->type = attrtype;
    p_personality_attribute->activated = true;

    /* allocate memory for attribute value (and additional null-terminator) */
    p_personality_attribute->data_size = attrval_len;
    if (!(p_personality_attribute->p_data = gta_secmem_calloc(p_provider_params->h_ctx, 1, attrval_len + 1, p_errinfo))) {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    /* copy attribute value */
    memcpy(p_personality_attribute->p_data, attrval, attrval_len);
    /* add null-terminator explicitly */
    p_personality_attribute->p_data[attrval_len] = '\0';

    /* allocate memory for attribute name (and additional null-terminator) */
    if (!(p_personality_attribute->p_name = gta_secmem_calloc(p_provider_params->h_ctx, 1, attrname_len + 1, p_errinfo))) {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    memcpy(p_personality_attribute->p_name, attrname, attrname_len);
    /* add null-terminator explicitly */
    p_personality_attribute->p_name[attrname_len] = '\0';

    /* add the attribute */
    list_append_front(
            (struct list_t **)(&(p_personality_name_list_item->p_personality_content->p_attribute_list)),
            p_personality_attribute);

    return true;
err:
    personality_attribute_list_item_free(p_provider_params->h_ctx, p_personality_attribute, &errinfo_tmp);
    return false;
}

/* Helper routine that performs the copy operation of authentication information to
 * the access policy data structure. Memory allocation and error checks are performed. */
bool policy_copy_helper(gta_context_handle_t h_ctx,
                            gta_access_policy_handle_t h_auth,
                            struct auth_info_list_item_t ** p_auth_info_list,
                            gta_errinfo_t * p_errinfo
          ) {
    gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;
    gta_access_descriptor_handle_t h_access_descriptor = GTA_HANDLE_INVALID;
    struct auth_info_list_item_t * p_auth_info_list_current = NULL;
    gta_access_descriptor_type_t access_descriptor_type;
    const char * p_attr = NULL;
    size_t attr_len;

    /* Enumerate access policies */
    while (gta_access_policy_enumerate(h_auth, &h_enum, &h_access_descriptor, p_errinfo)) {

        /* Try to get access descriptor type, proceed when successful */
        if (gta_access_policy_get_access_descriptor_type(h_auth,
                h_access_descriptor, &access_descriptor_type, p_errinfo)) {
            /* Now we allocate memory for the new list element and append it to the list */
            if (NULL != (p_auth_info_list_current = gta_secmem_calloc(h_ctx,
                          1, sizeof(struct auth_info_list_item_t), p_errinfo))) {
                p_auth_info_list_current->p_next = NULL;
                p_auth_info_list_current->type = access_descriptor_type;

                switch (access_descriptor_type) {
                    case GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL:
                    case GTA_ACCESS_DESCRIPTOR_TYPE_BASIC_TOKEN:
                    case GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN:
                        /* Nothing to do */
                        break;
                    case GTA_ACCESS_DESCRIPTOR_TYPE_PERS_DERIVED_TOKEN:
                        /* Copy fingerprint */
                        if (gta_access_policy_get_access_descriptor_attribute(
                            h_access_descriptor, GTA_ACCESS_DESCRIPTOR_ATTR_PERS_FINGERPRINT,
                            &p_attr, &attr_len, p_errinfo )) {
                            if (PERS_FINGERPRINT_LEN == attr_len) {
                                memcpy( p_auth_info_list_current->pers_fingerprint,
                                    p_attr, attr_len );
                            }
                            else {
                                /* Cleanup memory */
                                gta_secmem_free(h_ctx, p_auth_info_list_current, p_errinfo);
                                p_auth_info_list_current = NULL;
                                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                                goto err;
                            }
                        }
                        else {
                            /* Cleanup memory */
                            gta_secmem_free(h_ctx, p_auth_info_list_current, p_errinfo);
                            p_auth_info_list_current = NULL;
                            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                            goto err;
                        }

                        /* Copy profile name */
                        if (gta_access_policy_get_access_descriptor_attribute(
                            h_access_descriptor, GTA_ACCESS_DESCRIPTOR_ATTR_PROFILE_NAME,
                            &p_attr, &attr_len, p_errinfo )) {
                            /* NOTE: attr_len does not include the string termination! */
                            if (NULL != (
                                p_auth_info_list_current->profile_name =
                                gta_secmem_calloc(h_ctx, 1, attr_len + 1, p_errinfo)
                            )){
                               strncpy( p_auth_info_list_current->profile_name,
                                        p_attr, attr_len + 1 );
                            }
                            else {
                                /* Cleanup memory */
                                gta_secmem_free(h_ctx, p_auth_info_list_current, p_errinfo);
                                p_auth_info_list_current = NULL;
                                *p_errinfo = GTA_ERROR_MEMORY;
                                goto err;
                            }
                        }
                        else {
                            /* Cleanup memory */
                            gta_secmem_free(h_ctx, p_auth_info_list_current, p_errinfo);
                            p_auth_info_list_current = NULL;
                            *p_errinfo = GTA_ERROR_MEMORY;
                            goto err;
                        }
                        break;
                    default:
                        break;
               }
               list_append((struct list_t **)p_auth_info_list, p_auth_info_list_current);
            }
            else {
                /* List element allocation failed, therefore, no cleanup required */
                *p_errinfo = GTA_ERROR_MEMORY;
                goto err;
            }
        }
    }
    return true;
err:
    return false;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_deploy,
(
    gta_instance_handle_t h_inst,
    const gta_identifier_value_t identifier_value,
    const gta_personality_name_t personality_name,
    const gta_application_name_t application,
    const gta_profile_name_t profile,
    gtaio_istream_t * personality_content,
    gta_access_policy_handle_t h_auth_use,
    gta_access_policy_handle_t h_auth_admin,
    struct gta_protection_properties_t requested_protection_properties,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct identifier_list_item_t * p_identifier_list_item = NULL;
    struct personality_name_list_item_t * p_personality_name_list_item = NULL;
    size_t buffer_idx = 0;
    char * p_buffer = NULL;
    size_t personality_name_length = 0;
    size_t application_name_length = 0;
    gta_personality_fingerprint_t personality_fingerprint = { 0 };
    gta_errinfo_t errinfo_tmp = GTA_ERROR_INTERNAL_ERROR;

    /* TODO do we need now h_access_token_descriptor OR p_auth_use_info ?
    gta_access_token_descriptor_handle_t h_access_token_descriptor = GTA_HANDLE_INVALID;
    struct auth_info_list_item_t * p_auth_use_info = NULL;
     */

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /* Find identifier_list_item with specific name */
    p_identifier_list_item = list_find((struct list_t *)(p_provider_params->p_devicestate_stack->p_identifier_list),
                                 identifier_value, identifier_list_item_cmp_name);
    if (NULL == p_identifier_list_item)
    {
        *p_errinfo = GTA_ERROR_ITEM_NOT_FOUND;
        goto err;
    }

    /* setup personality reference */
    if (NULL != (p_personality_name_list_item = gta_secmem_calloc(p_provider_params->h_ctx,
        1, sizeof(struct personality_name_list_item_t), p_errinfo))) {

        personality_name_length = strnlen(personality_name, PERSONALITY_NAME_LENGTH_MAX);
        if ((0 != personality_name_length) && (PERSONALITY_NAME_LENGTH_MAX > personality_name_length)) {
            if ((NULL != (p_personality_name_list_item->personality_name = gta_secmem_calloc(p_provider_params->h_ctx,
                1, (personality_name_length + 1), p_errinfo)))
                && (NULL != (p_personality_name_list_item->p_personality_content =
                gta_secmem_calloc(p_provider_params->h_ctx, 1, sizeof(struct personality_t), p_errinfo)))) {

                memcpy(p_personality_name_list_item->personality_name, personality_name, personality_name_length + 1);
                p_personality_name_list_item->p_identifier_list_item = p_identifier_list_item;
                /* TODO: here we probably need to copy */
            }
            else {
                *p_errinfo = GTA_ERROR_MEMORY;
                goto err;
            }
        }
        else {
            *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
            goto err;
        }
        /* application name */
        p_personality_name_list_item->application_name = NULL;
        application_name_length = strnlen(application, MAXLEN_APPLICATION_NAME);
        if ((0 != application_name_length) && (PERSONALITY_NAME_LENGTH_MAX > application_name_length)) {
            if (NULL != (p_personality_name_list_item->application_name = gta_secmem_calloc(p_provider_params->h_ctx,
                1, (application_name_length + 1), p_errinfo))) {

                memcpy(p_personality_name_list_item->application_name, application, application_name_length + 1);
            }
            else {
                *p_errinfo = GTA_ERROR_MEMORY;
                goto err;
            }
        }
        else {
            *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
            goto err;
        }
    }
    else {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }

    /* personality activation status */
    p_personality_name_list_item->activated = true;

    /* Access policy management: get policy information from policy handle and copy to personality */
    p_personality_name_list_item->p_personality_content->p_auth_use_info_list = NULL;
    p_personality_name_list_item->p_personality_content->p_auth_admin_info_list = NULL;

    if(false == policy_copy_helper(p_provider_params->h_ctx,
                        h_auth_use,
                        &(p_personality_name_list_item->p_personality_content->p_auth_use_info_list),
                        p_errinfo)) {
        goto err;
    }

    if(false == policy_copy_helper(p_provider_params->h_ctx,
                        h_auth_admin,
                        &(p_personality_name_list_item->p_personality_content->p_auth_admin_info_list),
                        p_errinfo)) {
        goto err;
    }

    enum profile_t prof = get_profile_enum(profile);

    /* Read data from stream, reserve and fill temporary buffer */
    if (PROF_CH_IEC_30168_BASIC_PASSCODE == prof) {

        p_buffer = OPENSSL_zalloc(CHUNK_LEN);
        if(NULL != p_buffer) {
            size_t chunk_len = CHUNK_LEN;
            while (!personality_content->eof(personality_content, p_errinfo)) {
                chunk_len = personality_content->read(personality_content, p_buffer+buffer_idx, chunk_len, p_errinfo);
                buffer_idx += chunk_len;
                if (!personality_content->eof(personality_content, p_errinfo)) {
                    chunk_len = CHUNK_LEN;
                    p_buffer = OPENSSL_clear_realloc(p_buffer, buffer_idx, buffer_idx+CHUNK_LEN);
                    if(NULL == p_buffer) {
                        /* TODO is there a potential memory leak? */
                        *p_errinfo = GTA_ERROR_MEMORY;
                        goto err;
                    }
                }
            }
        }
        else {
            *p_errinfo = GTA_ERROR_MEMORY;
            goto err;
        }
    } else {
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }

    /* Handle Passcode data */
    if (PROF_CH_IEC_30168_BASIC_PASSCODE == prof) {
        if(NULL != (p_personality_name_list_item->p_personality_content->secret_data = \
            gta_secmem_calloc(p_provider_params->h_ctx, 1, buffer_idx, p_errinfo))) {
            memcpy(p_personality_name_list_item->p_personality_content->secret_data, p_buffer, buffer_idx);
            p_personality_name_list_item->p_personality_content->secret_data_size = buffer_idx;
            p_personality_name_list_item->p_personality_content->secret_type = SECRET_TYPE_PASSCODE;
            p_personality_name_list_item->p_personality_content->p_attribute_list = NULL;
            /* Calculate personality fingerprint */
            SHA512((unsigned char *)p_buffer, buffer_idx, (unsigned char *)personality_fingerprint);
        }
        else {
            *p_errinfo = GTA_ERROR_MEMORY;
            goto err;
        }
    }

    /* add default attributes to personality */
    if (!add_personality_attribute_list_item(p_provider_params,
        p_personality_name_list_item, PAT_CH_IEC_30168_IDENTIFIER,
        (unsigned char *)PERS_ATTR_NAME_IDENTIFIER, sizeof(PERS_ATTR_NAME_IDENTIFIER),
        (unsigned char *)identifier_value, strnlen(identifier_value, IDENTIFIER_VALUE_MAXLEN),
        p_errinfo)) {

        goto err;
    }
    if (!add_personality_attribute_list_item(p_provider_params,
        p_personality_name_list_item, PAT_CH_IEC_30168_FINGERPRINT,
        (unsigned char *)PERS_ATTR_NAME_FINGERPRINT, sizeof(PERS_ATTR_NAME_FINGERPRINT),
        (unsigned char *)personality_fingerprint, sizeof(personality_fingerprint),
        p_errinfo)) {

        goto err;
    }

    /* If we reach this point we are correctly finished reading the personality content */
    /* Now we can add the personality data strature ad the beginning of the personality list */
    list_append_front(
            (struct list_t **)(&(p_provider_params->p_devicestate_stack->p_personality_name_list)),
            p_personality_name_list_item);
    p_provider_params->p_devicestate_stack->p_personality_name_list = p_personality_name_list_item;

    ret = provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack);
    if (ret) {
        goto cleanup;
    }
    /* TODO: which value should be set for *p_errinfo in case of no error */

err:
    /* cleanup personality */
    personality_name_list_item_free(p_provider_params->h_ctx, p_personality_name_list_item, &errinfo_tmp);

cleanup:
    /* Cleanup buffer memory */
    if(NULL != p_buffer) {
        OPENSSL_clear_free(p_buffer, buffer_idx);
        p_buffer = NULL;
    }

    /* unsigned long e = ERR_get_error();
             * char buf[120];
             * ERR_error_string_n(e, buf, 120);
             * printf("e=%ld\nbuf=%s\n", e, buf);
            gta_secmem_free(p_provider_params->h_ctx, p_personality_name_list_item->p_personality_content, p_errinfo);
            p_personality_name_list_item->p_personality_content = NULL;
*/
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_create,
(
    gta_instance_handle_t h_inst,
    const gta_identifier_value_t identifier_value,
    const gta_personality_name_t personality_name,
    const gta_application_name_t application,
    const gta_profile_name_t profile,
    gta_access_policy_handle_t h_auth_use,
    gta_access_policy_handle_t h_auth_admin,
    struct gta_protection_properties_t requested_protection_properies,
    gta_errinfo_t * p_errinfo
    ))
{
    /* bool ret = false; */
    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct identifier_list_item_t * p_identifier_list_item = NULL;
    struct devicestate_stack_item_t * p_devicestate_stack_item = NULL;
    struct personality_name_list_item_t * p_personality_name_list_item = NULL;
    personality_secret_type_t personality_secret_type;
    size_t personality_name_length = 0;
    size_t application_name_length = 0;
    gta_personality_fingerprint_t personality_fingerprint = { 0 };
    gta_errinfo_t errinfo_tmp = GTA_ERROR_INTERNAL_ERROR;

    EVP_PKEY *p_key = NULL;
    unsigned char * p_secret_buffer = NULL;
    long len = 0;

#ifdef ENABLE_PQC
    OQS_SIG *signer = NULL;
#endif

    p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /* TODO: what about the other params (mandatory vs. optional) */

    /* iterate device states to find requested identifier */
    p_devicestate_stack_item = p_provider_params->p_devicestate_stack;
    while (NULL != p_devicestate_stack_item) {
        p_identifier_list_item = list_find((struct list_t *)p_devicestate_stack_item->p_identifier_list,
                                    identifier_value, identifier_list_item_cmp_name);
        if (NULL == p_identifier_list_item ) {
            p_devicestate_stack_item = p_devicestate_stack_item->p_next;
        } else {
            /* Identifier found, exit the Loop */
            p_devicestate_stack_item = NULL;
        }
    }

    if (NULL == p_identifier_list_item)
    {
        *p_errinfo = GTA_ERROR_ITEM_NOT_FOUND;
        goto err;
    }

    /*
     * Check requested Profile & do the specifics.
     * The profile specific part should return the following information:
     * - personality_secret_type_t personality_secret_type
     * - unsigned char * p_secret_buffer containing the secret data of type
     *   personality_secret_type. The memory needs to be allocated by callee
     *   using OpenSSL_zalloc or similar. It is freed by caller using
     *   OPENSSL_clear_free.
     * - long len with the length of the data in p_secret_buffer
     * - gta_personality_fingerprint_t personality_fingerprint
     */
    enum profile_t prof = get_profile_enum(profile);
    if (PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_RSA == prof) {
        p_key = EVP_RSA_gen(2048);
        len = i2d_PrivateKey(p_key, &p_secret_buffer);
        EVP_PKEY_free(p_key);
        personality_secret_type = SECRET_TYPE_DER;
        /* Calculate personality fingerprint */
        SHA512(p_secret_buffer, (size_t)len, (unsigned char *)personality_fingerprint);
    }
    else if (PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_EC == prof) {
        p_key = EVP_EC_gen("P-256");
        len = i2d_PrivateKey(p_key, &p_secret_buffer);
        EVP_PKEY_free(p_key);
        personality_secret_type = SECRET_TYPE_DER;
        /* Calculate personality fingerprint */
        SHA512(p_secret_buffer, (size_t)len, (unsigned char *)personality_fingerprint);
    }
    else if (PROF_CH_IEC_30168_BASIC_LOCAL_DATA_PROTECTION == prof) {
        len = LOCAL_DATA_PROTECTION_SECRET_LEN;
        p_secret_buffer = OPENSSL_zalloc(len);
        if ((NULL == p_secret_buffer) || (1 != RAND_bytes(p_secret_buffer, (int)len))) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }
        personality_secret_type = SECRET_TYPE_RAW_BYTES;
        /* Calculate personality fingerprint */
        SHA512(p_secret_buffer, (size_t)len, (unsigned char *)personality_fingerprint);
    }
#ifdef ENABLE_PQC
    else if (PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_DILITHIUM == prof) {
        OQS_STATUS rc;

        OQS_init();

        signer = OQS_SIG_new(OQS_SIGN_ALGORITHM);

        if (signer == NULL) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }
        /*
         * SECRET_TYPE_DILITHIUM2 is a concatenation of the private key and
         * the public key.
         */
        len = signer->length_secret_key + signer->length_public_key;
        p_secret_buffer = OPENSSL_zalloc(len);
        if (NULL == p_secret_buffer) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        rc = OQS_SIG_keypair(signer, (p_secret_buffer + signer->length_secret_key), p_secret_buffer);
        if (rc != OQS_SUCCESS) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        OQS_SIG_free(signer);

        personality_secret_type = SECRET_TYPE_DILITHIUM2;
        /* Calculate personality fingerprint */
        SHA512(p_secret_buffer, (size_t)len, (unsigned char *)personality_fingerprint);
    }
#endif
    else {
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }

    if (len <= 0) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* setup personality_name list item reference */
    if (!(p_personality_name_list_item = gta_secmem_calloc(p_provider_params->h_ctx,
        1, sizeof(struct personality_name_list_item_t), p_errinfo)))
    {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }

    /* personality identifier */
    p_personality_name_list_item->p_identifier_list_item = p_identifier_list_item;

    /* personality activation status */
    p_personality_name_list_item->activated = true;

    /* personality name */
    p_personality_name_list_item->personality_name = NULL;
    personality_name_length = strnlen(personality_name, PERSONALITY_NAME_LENGTH_MAX);
    if ((0 != personality_name_length) && (PERSONALITY_NAME_LENGTH_MAX > personality_name_length)) {
        if (NULL != (p_personality_name_list_item->personality_name = gta_secmem_calloc(p_provider_params->h_ctx,
            1, (personality_name_length + 1), p_errinfo))) {

            memcpy(p_personality_name_list_item->personality_name, personality_name, personality_name_length + 1);
        }
        else {
            *p_errinfo = GTA_ERROR_MEMORY;
            goto err;
        }
    }
    else {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        goto err;
    }

    /* application name */
    p_personality_name_list_item->application_name = NULL;
    application_name_length = strnlen(application, MAXLEN_APPLICATION_NAME);
    if ((0 != application_name_length) && (PERSONALITY_NAME_LENGTH_MAX > application_name_length)) {
        if (NULL != (p_personality_name_list_item->application_name = gta_secmem_calloc(p_provider_params->h_ctx,
            1, (application_name_length + 1), p_errinfo))) {

            memcpy(p_personality_name_list_item->application_name, application, application_name_length + 1);
        }
        else {
            *p_errinfo = GTA_ERROR_MEMORY;
            goto err;
        }
    }
    else {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        goto err;
    }

    /* personality content */
    p_personality_name_list_item->p_personality_content = NULL;
    if (!(p_personality_name_list_item->p_personality_content = gta_secmem_calloc(p_provider_params->h_ctx,
      1, sizeof(struct personality_t), p_errinfo)))
    {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    p_personality_name_list_item->p_personality_content->p_attribute_list = NULL;
    p_personality_name_list_item->p_personality_content->p_auth_use_info_list = NULL;
    p_personality_name_list_item->p_personality_content->p_auth_admin_info_list = NULL;
    p_personality_name_list_item->p_personality_content->secret_data = NULL;
    p_personality_name_list_item->p_personality_content->secret_type = personality_secret_type;

    errinfo_tmp = *p_errinfo;
    /* Access policy management: get policy information from policy handle and copy to personality */
    if(false == policy_copy_helper(p_provider_params->h_ctx,
                        h_auth_use,
                        &(p_personality_name_list_item->p_personality_content->p_auth_use_info_list),
                        p_errinfo)) {
        goto err;
    }

    if(false == policy_copy_helper(p_provider_params->h_ctx,
                        h_auth_admin,
                        &(p_personality_name_list_item->p_personality_content->p_auth_admin_info_list),
                        p_errinfo)) {
        goto err;
    }

    if((GTA_ERROR_ENUM_NO_MORE_ITEMS == *p_errinfo) ||
       (GTA_ERROR_HANDLE_INVALID == *p_errinfo)) {
       /* Note: In this case it could mean that there was nothing
          to copy or the iteration has been finished.
          Therefore, we recover errinfo */
        /* TODO: This "solution" has to be double checked! */
          *p_errinfo = errinfo_tmp;
       }

    /* Store private key / secret in personality content data */
    if (!(p_personality_name_list_item->p_personality_content->secret_data =
        gta_secmem_calloc(p_provider_params->h_ctx, 1, len, p_errinfo)))
    {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    memcpy(p_personality_name_list_item->p_personality_content->secret_data, p_secret_buffer, len);
    p_personality_name_list_item->p_personality_content->secret_data_size = len;

    OPENSSL_clear_free(p_secret_buffer, len);
    p_secret_buffer = NULL;

    /* add default attributes to personality */
    if (!add_personality_attribute_list_item(p_provider_params,
        p_personality_name_list_item, PAT_CH_IEC_30168_IDENTIFIER,
        (unsigned char *)PERS_ATTR_NAME_IDENTIFIER, sizeof(PERS_ATTR_NAME_IDENTIFIER),
        (unsigned char *)identifier_value, strnlen(identifier_value, IDENTIFIER_VALUE_MAXLEN),
        p_errinfo)) {

        goto err;
    }
    if (!add_personality_attribute_list_item(p_provider_params,
        p_personality_name_list_item, PAT_CH_IEC_30168_FINGERPRINT,
        (unsigned char *)PERS_ATTR_NAME_FINGERPRINT, sizeof(PERS_ATTR_NAME_FINGERPRINT),
        (unsigned char *)personality_fingerprint, sizeof(personality_fingerprint),
        p_errinfo)) {

        goto err;
    }

    /* Add additional / profile dependent attributes */
    if (PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_EC == prof) {
        if (!add_personality_attribute_list_item(p_provider_params,
            p_personality_name_list_item, PAT_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_KEYTYPE_OPENSSL,
            (unsigned char *)PERS_ATTR_NAME_KEYTYPE, sizeof(PERS_ATTR_NAME_KEYTYPE),
            (unsigned char *)PERS_ATTR_KEYTYPE_EC, sizeof(PERS_ATTR_KEYTYPE_EC),
            p_errinfo)) {

            goto err;
        }
    }
#ifdef ENABLE_PQC
    else if (PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_DILITHIUM == prof) {
        if (!add_personality_attribute_list_item(p_provider_params,
            p_personality_name_list_item, PAT_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_KEYTYPE_OPENSSL,
            (unsigned char *)PERS_ATTR_NAME_KEYTYPE, sizeof(PERS_ATTR_NAME_KEYTYPE),
            (unsigned char *)PERS_ATTR_KEYTYPE_DILITHIUM2, sizeof(PERS_ATTR_KEYTYPE_DILITHIUM2),
            p_errinfo)) {

            goto err;
        }
    }
#endif

    /* add the personality */
    list_append_front(
            (struct list_t **)(&(p_provider_params->p_devicestate_stack->p_personality_name_list)),
            p_personality_name_list_item);

    if (provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack)) {
        return true;
    }

err:
    if (NULL != p_secret_buffer) {
        OPENSSL_clear_free(p_secret_buffer, len);
        p_secret_buffer = NULL;
    }

#ifdef ENABLE_PQC
    if (NULL != signer) {
        OQS_SIG_free(signer);
    }
#endif

    /* cleanup personality */
    personality_name_list_item_free(p_provider_params->h_ctx, p_personality_name_list_item, &errinfo_tmp);
    return false;
}

GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_enroll,
(
    gta_context_handle_t h_ctx,
    gtaio_ostream_t * p_personality_enrollment_info,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;
    BIO* bio = NULL;
    long len = 0;
    char* pem_data = NULL;
    EVP_PKEY *p_key = NULL;
#ifdef ENABLE_PQC
    OQS_SIG *signer = NULL;
    char *base64EncodedKey = NULL;
    PublicKeyInfo *pub_key = NULL;
    unsigned char *publicKeyInfoString = NULL;
    BIO *bio_sink = NULL;
    BIO *bio_base64_converter = NULL;
    FILE* stream = NULL;
    gta_errinfo_t errinfo_tmp = GTA_ERROR_INTERNAL_ERROR;
#endif

    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct personality_t * p_personality_content = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (NULL == p_context_params) {
        goto err;
    }

    if ((PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_JWT == p_context_params->profile)
        || (PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_TLS == p_context_params->profile)) {
        /* get personality of the context */
        p_personality_content = p_context_params->p_personality_item->p_personality_content;

        if (SECRET_TYPE_DER == p_personality_content->secret_type) {
            /* range check on p_personality_content->content_data_size */
            if (p_personality_content->secret_data_size > LONG_MAX) {
                goto err;
            }
            /* get the key from the personality */
            unsigned char * p_secret_buffer  = p_personality_content->secret_data;
            p_key = d2i_AutoPrivateKey(NULL,
                (const unsigned char **) &p_secret_buffer,
                (long)p_personality_content->secret_data_size);

            p_secret_buffer = NULL;
            if (!p_key) {
                goto err;
            }
            /* get public key in PEM */
            bio = BIO_new(BIO_s_mem());
            PEM_write_bio_PUBKEY(bio, p_key);
            len = BIO_get_mem_data(bio, &pem_data);
        }
#ifdef ENABLE_PQC
        else if (SECRET_TYPE_DILITHIUM2 == p_personality_content->secret_type) {
            OQS_init();
            signer = OQS_SIG_new(OQS_SIGN_ALGORITHM);

            pub_key = PublicKeyInfo_new();
            if (NULL == pub_key) {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                goto err;
            }

            /* Step 1: Create ASN.1 data structures containing the key */
            /*
            enc_alg = EncryptionAlgorithm_new();
            if (NULL == enc_alg) {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                goto err;
            }
            */
            pub_key->encryptionAlgorithm->algorithm = OBJ_txt2obj(OQS_ALG_ID_DEFAULT, 1);
            if (NULL == pub_key->encryptionAlgorithm->algorithm) {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                goto err;
            }
            if (0 == ASN1_BIT_STRING_set(pub_key->public_key_data, (p_personality_content->secret_data + signer->length_secret_key), signer->length_public_key)) {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                goto err;
            }
            int publicKeyInfoStringLen = i2d_PublicKeyInfo(pub_key, &publicKeyInfoString);
            /* Step 2: Initialize BIO based base64 converter */
            /* TODO: double check length calculations */
            int encodedSize = (4 * ((publicKeyInfoStringLen + 2) / 3)) + 2;
            base64EncodedKey = gta_secmem_calloc(h_ctx, 1, encodedSize, p_errinfo);
            if (NULL == base64EncodedKey) {
                *p_errinfo = GTA_ERROR_MEMORY;
                goto err;
            }
            stream = fmemopen(base64EncodedKey, encodedSize, "w");
            if (NULL == stream) {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                goto err;
            }
            bio_base64_converter = BIO_new(BIO_f_base64());
            if (NULL == bio_base64_converter) {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                goto err;
            }
            bio_sink = BIO_new_fp(stream, BIO_NOCLOSE);
            if (NULL == bio_sink) {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                goto err;
            }
            bio_sink = BIO_push(bio_base64_converter, bio_sink);
            BIO_set_flags(bio_sink, BIO_FLAGS_BASE64_NO_NL);

            /* Step 3: Perform base64 encoding of key data */
            if (BIO_write(bio_sink, publicKeyInfoString, publicKeyInfoStringLen) <= 0) {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                goto err;
            }
            if (1 != BIO_flush(bio_sink)) {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                goto err;
            }

            /* Step 4: Add PEM header and footer and write the result to pem_data */
            char* pub_key_begin = "-----BEGIN PUBLIC KEY-----";
            char* pub_key_end = "-----END PUBLIC KEY-----";

            /* Note: Size is incremented by 4 as we add 3 '\n' and the 0-termination */
            size_t pem_size_calculated = strlen(pub_key_begin) + strlen(base64EncodedKey) + strlen(pub_key_end) + 4 ;

            pem_data = OPENSSL_zalloc(pem_size_calculated);
            if (NULL == pem_data) {
                *p_errinfo = GTA_ERROR_MEMORY;
                goto err;
            }
            if ((pem_size_calculated-1) != (size_t)snprintf(pem_data, pem_size_calculated,
                        "%s\n%s\n%s\n", pub_key_begin, base64EncodedKey, pub_key_end)) {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                goto err;
            }
            len = strlen(pem_data);
        }
#endif
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
    }
    else {
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
    }

err:
    if (NULL != p_key) {
        EVP_PKEY_free(p_key);
        p_key = NULL;
    }
    if (NULL != bio) {
        BIO_free_all(bio);
        pem_data = NULL;
    }

#ifdef ENABLE_PQC
    if (NULL != base64EncodedKey) {
        gta_secmem_free(h_ctx, base64EncodedKey, &errinfo_tmp);
    }
    if (NULL != signer) {
        OQS_SIG_free(signer);
    }
    if (NULL != bio_sink) {
        BIO_free_all(bio_sink);
    }
    if (NULL != stream) {
        fclose(stream);
    }
    if (NULL != pub_key) {
        PublicKeyInfo_free(pub_key); /* Note enc_alg is also freed here */
    }
    if (NULL != publicKeyInfoString) {
        OPENSSL_free(publicKeyInfoString);
    }
    if (NULL != pem_data) {
        OPENSSL_free(pem_data);
    }
#endif
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_enroll_auth,
(
    gta_context_handle_t h_ctx,
    gta_context_handle_t h_auth_ctx,
    gtaio_ostream_t * p_personality_enrollment_info,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_attestate,
(
    gta_context_handle_t h_ctx,
    const gta_personality_name_t personality_name,
    gtaio_istream_t * nonce,
    gtaio_ostream_t * p_attestation_data,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_remove,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_deactivate,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_activate,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}

/*
 * Helper function for gta_sw_provider_gta_personality_add_trusted_attribute
 * and gta_sw_provider_gta_personality_add_attribute
 */
bool personality_add_attribute(
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_type_t attrtype,
    const gta_personality_attribute_name_t attrname,
    gtaio_istream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
    )
{
    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    unsigned char attrval[MAXLEN_PERSONALITY_ATTRIBUTE_VALUE] = { 0 };
    size_t attrval_len = 0;
    size_t attrname_len = 0;
    bool ret = false;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (NULL == p_context_params) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    enum pers_attr_type_t pers_attr_type = get_pers_attr_type_enum(attrtype);

    /* Default attribute types are not allowed */
    if ((PAT_CH_IEC_30168_FINGERPRINT == pers_attr_type) || (PAT_CH_IEC_30168_IDENTIFIER == pers_attr_type)) {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        goto err;
    }

    /* Check if attribute with the same name already exists */
    if (NULL != list_find((struct list_t *)(p_context_params->p_personality_item->p_personality_content->p_attribute_list),
                            attrname, attribute_list_item_cmp_name)) {

        *p_errinfo = GTA_ERROR_NAME_ALREADY_EXISTS;
        goto err;
    }

    /* Check whether profile defines support for the requested attribute type */
    if ((PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_TLS == p_context_params->profile) && (PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_SELF_X509 == pers_attr_type)) {
        /* read personality attribute value into buffer */
        attrval_len = p_attrvalue->read(p_attrvalue, (char *)attrval, MAXLEN_PERSONALITY_ATTRIBUTE_VALUE, p_errinfo);
        if ((MAXLEN_PERSONALITY_ATTRIBUTE_VALUE <= attrval_len) || (0 == attrval_len)) {
            /* attribute too long */
            *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
            goto err;
        }
        /* basic input validation for attrname */
        attrname_len = strnlen(attrname, MAXLEN_PERSONALITY_ATTRIBUTE_NAME);
        if ((MAXLEN_PERSONALITY_ATTRIBUTE_NAME <= attrname_len) || (0 == attrname_len)) {
            /* attribute name too long */
            *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
            goto err;
        }
        /* add attribute to personality specific attribute list */
        if (add_personality_attribute_list_item(p_provider_params,
            p_context_params->p_personality_item, pers_attr_type,
            (unsigned char *)attrname, attrname_len, attrval, attrval_len,
            p_errinfo)) {

            /* Serialize the new device state */
            if (!provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack)) {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                goto err;
            }
            ret = true;
        }
    }
    else {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
    }
err:
    return ret;
}

GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_add_trusted_attribute,
(
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_type_t attrtype,
    const gta_personality_attribute_name_t attrname,
    gtaio_istream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
    ))
{
    /* todo: check access condition */

    enum pers_attr_type_t pers_attr_type = get_pers_attr_type_enum(attrtype);
    /* Generic attribute types are not allowed */
    if (false == pers_attr_type_trusted[pers_attr_type]) {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        return false;
    }

    return personality_add_attribute(h_ctx, attrtype, attrname, p_attrvalue, p_errinfo);
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_add_attribute,
(
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_type_t attrtype,
    const gta_personality_attribute_name_t attrname,
    gtaio_istream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
    ))
{
    enum pers_attr_type_t pers_attr_type = get_pers_attr_type_enum(attrtype);
    /* Trusted attribute types are not allowed */
    if (true == pers_attr_type_trusted[pers_attr_type]) {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        return false;
    }

    return personality_add_attribute(h_ctx, attrtype, attrname, p_attrvalue, p_errinfo);
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_get_attribute, (
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_name_t attrname,
    gtaio_ostream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    const struct personality_attribute_t * p_attribute = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (NULL == p_context_params) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Find attribute_list_item with requested name and check whether it is activated */
    p_attribute = list_find((struct list_t *)(p_context_params->p_personality_item->p_personality_content->p_attribute_list),
                            attrname, attribute_list_item_cmp_name);
    if ((NULL == p_attribute) || (!p_attribute->activated)) {
        *p_errinfo = GTA_ERROR_ITEM_NOT_FOUND;
        goto err;
    }

    /*
     * Check whether profile defines support for the requested attribute type.
     * Default attributes need to be supported by all profiles.
     */
    if ((PAT_CH_IEC_30168_FINGERPRINT == p_attribute->type) || (PAT_CH_IEC_30168_IDENTIFIER == p_attribute->type)
        || ((PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_TLS == p_context_params->profile) && ((PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_SELF_X509 == p_attribute->type) || (PAT_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_KEYTYPE_OPENSSL == p_attribute->type)))) {

        if (p_attribute->data_size != p_attrvalue->write(p_attrvalue, p_attribute->p_data, p_attribute->data_size, p_errinfo)) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }
        p_attrvalue->finish(p_attrvalue, 0, p_errinfo);
        ret = true;
    }
    else {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
    }
err:
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_remove_attribute,
(
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_name_t attrname,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct personality_attribute_t * p_attribute = NULL;
    gta_errinfo_t errinfo_tmp = GTA_ERROR_INTERNAL_ERROR;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (NULL == p_context_params) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /* Default attributes must not be removed */
    if ((0 == strcmp(attrname, PERS_ATTR_NAME_FINGERPRINT)) || (0 == strcmp(attrname, PERS_ATTR_NAME_IDENTIFIER))) {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        goto err;
    }

    /* Find attribute_list_item with requested name and check whether it is activated */
    p_attribute = list_find((struct list_t *)(p_context_params->p_personality_item->p_personality_content->p_attribute_list),
                            attrname, attribute_list_item_cmp_name);
    if ((NULL == p_attribute) || (!p_attribute->activated)) {
        *p_errinfo = GTA_ERROR_ITEM_NOT_FOUND;
        goto err;
    }

    /* Check whether profile defines support for this attribute type */
    if ((PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_TLS == p_context_params->profile) && (PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_SELF_X509 == p_attribute->type)) {
        /*
         * Remove the attribute from attribute list. Note that this function
         * searches again for the attribute in the list. This is not necessary
         * and could be optimized in the future.
         */
        p_attribute = list_remove((struct list_t **)(&p_context_params->p_personality_item->p_personality_content->p_attribute_list),
                                attrname, attribute_list_item_cmp_name);
        if (NULL == p_attribute) {
            *p_errinfo = GTA_ERROR_ITEM_NOT_FOUND;
            goto err;
        }
        /* Remove attribute (this function cannot fail) */
        personality_attribute_list_item_free(p_provider_params->h_ctx, p_attribute, &errinfo_tmp);

        /* Serialize the new device state */
        if (!provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack)) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }
        ret = true;
    }
    else {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
    }
err:
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_deactivate_attribute,
(
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_name_t attrname,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct personality_attribute_t * p_attribute = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (NULL == p_context_params) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /* Default attributes must not be deactivated */
    if ((0 == strcmp(attrname, PERS_ATTR_NAME_FINGERPRINT)) || (0 == strcmp(attrname, PERS_ATTR_NAME_IDENTIFIER))) {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        goto err;
    }

    /* Find attribute_list_item with requested name and check whether it is activated */
    p_attribute = list_find((struct list_t *)(p_context_params->p_personality_item->p_personality_content->p_attribute_list),
                            attrname, attribute_list_item_cmp_name);
    if ((NULL == p_attribute) || (!p_attribute->activated)) {
        *p_errinfo = GTA_ERROR_ITEM_NOT_FOUND;
        goto err;
    }

    /* Check whether profile defines support for this attribute type */
    if ((PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_TLS == p_context_params->profile) && (PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_SELF_X509 == p_attribute->type)) {

        /* todo: check access condition */
        p_attribute->activated = false;

        /* Serialize the new device state */
        if (!provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack)) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }
        ret = true;
    }
    else {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
    }
err:
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_activate_attribute,
(
    gta_context_handle_t h_ctx,
    gta_personality_attribute_name_t attrname,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct personality_attribute_t * p_attribute = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (NULL == p_context_params) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /* Find attribute_list_item with requested name */
    p_attribute = list_find((struct list_t *)(p_context_params->p_personality_item->p_personality_content->p_attribute_list),
                            attrname, attribute_list_item_cmp_name);
    if (NULL == p_attribute) {
        *p_errinfo = GTA_ERROR_ITEM_NOT_FOUND;
        goto err;
    }

    /* Check whether attribute is already activated */
    if (p_attribute->activated) {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        goto err;
    }

    /* Check whether profile defines support for this attribute type */
    if ((PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_TLS == p_context_params->profile) && (PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_SELF_X509 == p_attribute->type)) {

        /* todo: check access condition */
        p_attribute->activated = true;

        /* Serialize the new device state */
        if (!provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack)) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }
        ret = true;
    }
    else {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
    }
err:
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_attributes_enumerate,
(
    gta_instance_handle_t h_inst,
    const gta_personality_name_t personality_name,
    gta_enum_handle_t * ph_enum,
    gtaio_ostream_t * attribute_type,
    gtaio_ostream_t * attribute_name,
    gta_errinfo_t * p_errinfo
    ))
{
     /* @todo The direct exposure of an internal pointer through ph_enum
             is not ideal. Using a handle map as in the GTA API framework
             implementation would improve robustness.
             Use of magic values (GTA_HANDLE_ENUM_FINISHED) to distinguish
             different kinds of invalid handles is a hack. */

    bool ret = false;

    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct personality_name_list_item_t * p_personality_name_list_item = NULL;
    struct devicestate_stack_item_t * p_devicestate_stack_item = NULL;
    struct personality_attribute_t * p_personality_attribute = NULL;
    size_t enum_cnt = 0;

    enum_cnt = ENUM_CNT_FROM_HANDLE(ph_enum);
    p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /* iterate device states to find requested personality */
    p_devicestate_stack_item = p_provider_params->p_devicestate_stack;
    while (NULL != p_devicestate_stack_item) {
        p_personality_name_list_item = list_find((struct list_t *)p_devicestate_stack_item->p_personality_name_list, personality_name, personality_list_item_cmp_name);
        if (NULL == p_personality_name_list_item ) {
            p_devicestate_stack_item = p_devicestate_stack_item->p_next;
        } else {
            /* Personality found, exit the Loop */
            p_devicestate_stack_item = NULL;
        }
    }
    if (NULL == p_personality_name_list_item) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /*
     * Find the current list element based on ph_enum. ph_enum stores the index
     * number of the element starting at 0.
     * Walk through the list to find element with index enum_cnt or break early
     * if p_personality_attribute is NULL.
     * Note: Currently, there is no flag parameter, so we use the default
     * behaviour of gta_personality_enumerate() and enumerate all personality
     * attributes (activated and deactivated ones).
     */
    p_personality_attribute = p_personality_name_list_item->p_personality_content->p_attribute_list;
    for(size_t count=0; (NULL != p_personality_attribute) && (count < enum_cnt); ++count) {
        p_personality_attribute = p_personality_attribute->p_next;
    }

    if (NULL != p_personality_attribute) {
        gta_errinfo_t errinfo = 0;

        attribute_type->write(attribute_type, pers_attr_type_strings[p_personality_attribute->type], strnlen(pers_attr_type_strings[p_personality_attribute->type], MAXLEN_PERSONALITY_ATTRIBUTE_TYPE), &errinfo);
        attribute_type->finish(attribute_type, 0, &errinfo);
        attribute_name->write(attribute_name, p_personality_attribute->p_name, strnlen(p_personality_attribute->p_name, MAXLEN_PERSONALITY_ATTRIBUTE_NAME), &errinfo);
        attribute_name->finish(attribute_name, 0, &errinfo);

        if (0 == errinfo) {
            ++enum_cnt;
            ret = true;
        }
        else {
           *p_errinfo = errinfo;
        }

    }
    else {
        *ph_enum = GTA_HANDLE_INVALID;
        *p_errinfo = GTA_ERROR_ENUM_NO_MORE_ITEMS;
    }
    if(*ph_enum != GTA_HANDLE_INVALID) {
        *ph_enum = ENUM_CNT_TO_HANDLE(enum_cnt);
    }
err:
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


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_seal_data,
(
    gta_context_handle_t h_ctx,
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

    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct personality_t * p_personality_content = NULL;

    char payload_chunk[CHUNK_LEN];
    const char* header_base64url = NULL;
    char* signature_base64url = NULL;
    unsigned char* signature = NULL;
    size_t signature_len = 0;

    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *evp_private_key = NULL;
    int32_t key_type = EVP_PKEY_NONE;

    /* Variables for profile local_data_protection */
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

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!p_context_params)
    {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Check Profile */
    if (PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_JWT == p_context_params->profile)
    {
        /* get Personality of the Context */
        p_personality_content = p_context_params->p_personality_item->p_personality_content;

        /* get the Private Key from the Personality */
        unsigned char * p_secret_buffer  = p_personality_content->secret_data;
        evp_private_key = d2i_AutoPrivateKey(NULL,
                                            (const unsigned char **) &p_secret_buffer,
                                            p_personality_content->secret_data_size);
        /* clear pointer */
        p_secret_buffer = NULL;
        if (!evp_private_key)
        {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        /* get key type & config accordingly */
        key_type = EVP_PKEY_base_id(evp_private_key);
        if (EVP_PKEY_RSA == key_type) {
            header_base64url = jwt_header_rs256;
        } else if (EVP_PKEY_EC == key_type) {
            header_base64url = jwt_header_es256;
        } else {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        /* Create the Message Digest Context */
        if (!(mdctx = EVP_MD_CTX_new()))
        {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
        if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, evp_private_key))
        {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        /* add JWT Header */
        if (1 != EVP_DigestSignUpdate(mdctx, header_base64url, strlen(header_base64url)))
        {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }
        protected_data->write(protected_data, header_base64url, strlen(header_base64url), p_errinfo);

        /* add "." JWT separator */
        if (1 != EVP_DigestSignUpdate(mdctx, ".", 1))
        {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }
        protected_data->write(protected_data, ".", 1, p_errinfo);

        /* add JWT Payload */
        while (!data->eof(data, p_errinfo)) {
            size_t read_len = data->read(data, payload_chunk, CHUNK_LEN, p_errinfo);
            /* Update with the data chunck */
            if(1 != EVP_DigestSignUpdate(mdctx, payload_chunk, read_len))
            {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                goto err;
            }
            /* Add data chunck as JWT paylod */
            protected_data->write(protected_data, payload_chunk, read_len, p_errinfo);
        }

        /* Obtain the length of the signature before being calculated */
        if (1 != EVP_DigestSignFinal(mdctx, NULL, &signature_len))
        {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        /* Allocate memory for the signature based on size in signature_len */
        if (!(signature = OPENSSL_malloc(sizeof(unsigned char) * (signature_len))))
        {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        /* Obtain the signature */
        if (1 != EVP_DigestSignFinal(mdctx, signature, &signature_len))
        {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        signature_base64url = base64url_encode(h_ctx, signature, signature_len);
        if (!signature_base64url)
        {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        /* add "." JWT separator & Signature */
        protected_data->write(protected_data, ".", 1, p_errinfo);
        protected_data->write(protected_data, signature_base64url, strlen(signature_base64url), p_errinfo);
        protected_data->finish(protected_data, 0, p_errinfo);
    }
    else if (PROF_CH_IEC_30168_BASIC_LOCAL_DATA_PROTECTION == p_context_params->profile) {
        /* get personality of the context */
        p_personality_content = p_context_params->p_personality_item->p_personality_content;

        /* Read whole input into buffer */
        p_buffer_in = OPENSSL_zalloc(CHUNK_LEN);
        if(NULL != p_buffer_in) {
            size_t chunk_len = CHUNK_LEN;
            while (!data->eof(data, p_errinfo)) {
                chunk_len = data->read(data, (char *)p_buffer_in + buffer_idx_in, chunk_len, p_errinfo);
                buffer_idx_in += chunk_len;
                if (!data->eof(data, p_errinfo)) {
                    chunk_len = CHUNK_LEN;
                    p_buffer_in = OPENSSL_clear_realloc(p_buffer_in, buffer_idx_in, buffer_idx_in + CHUNK_LEN);
                    if(NULL == p_buffer_in) {
                        *p_errinfo = GTA_ERROR_MEMORY;
                        goto err;
                    }
                }
            }
        }
        else {
            *p_errinfo = GTA_ERROR_MEMORY;
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
        key = gta_secmem_calloc(h_ctx, (size_t)EVP_CIPHER_get_key_length(EVP_aes_256_gcm()), sizeof(unsigned char), p_errinfo);
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
        p_buffer_out = gta_secmem_calloc(h_ctx, buffer_idx_in, sizeof(unsigned char), p_errinfo);
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
    }
    else {
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }

    ret = true;

err:
    if (NULL != signature_base64url) {
        gta_secmem_free(h_ctx, signature_base64url, &errinfo_tmp);
        signature_base64url = NULL;
    }
    if (NULL != signature) {
        OPENSSL_free(signature);
        signature = NULL;
    }
    if (NULL != mdctx) {
        EVP_MD_CTX_free(mdctx);
        mdctx = NULL;
    }
    if (NULL != evp_private_key) {
        EVP_PKEY_free(evp_private_key);
        evp_private_key = NULL;
    }
    if (NULL != gcmctx) {
        EVP_CIPHER_CTX_free(gcmctx);
    }
    if (NULL != p_buffer_in) {
        OPENSSL_clear_free(p_buffer_in, buffer_idx_in);
    }
    if (NULL != p_buffer_out) {
        gta_secmem_free(h_ctx, p_buffer_out, &errinfo_tmp);
        p_buffer_out = NULL;
    }
    if (NULL != key) {
        gta_secmem_free(h_ctx, key, &errinfo_tmp);
        key = NULL;
    }
    if (NULL != p_data.key) {
        ASN1_OCTET_STRING_free(p_data.key);
    }
    if (NULL != p_data.iv) {
        ASN1_OCTET_STRING_free(p_data.iv);
    }
    if (NULL != p_data.tag) {
        ASN1_OCTET_STRING_free(p_data.tag);
    }
    if (NULL != p_data.data) {
        ASN1_OCTET_STRING_free(p_data.data);
    }
    if (NULL != encoded_data) {
        OPENSSL_free(encoded_data);
    }

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_unseal_data,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * protected_data,
    gtaio_ostream_t * data,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;
    gta_errinfo_t errinfo_tmp;

    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct personality_t * p_personality_content = NULL;

    /* Variables for profile local_data_protection */
    ProtectedData *p_data = NULL;
    unsigned int size = 0;
    int len = 0;
    unsigned char * p_buffer_in = NULL;
    size_t buffer_idx_in = 0;
    unsigned char * p_buffer_out = NULL;
    size_t buffer_idx_out = 0;
    EVP_CIPHER_CTX *gcmctx = NULL;
    unsigned char *key = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!p_context_params)
    {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Check Profile */
    if (PROF_CH_IEC_30168_BASIC_LOCAL_DATA_PROTECTION == p_context_params->profile) {
        /* get personality of the context */
        p_personality_content = p_context_params->p_personality_item->p_personality_content;

        /* Read whole input into buffer */
        p_buffer_in = OPENSSL_zalloc(CHUNK_LEN);
        if(NULL != p_buffer_in) {
            size_t chunk_len = CHUNK_LEN;
            while (!protected_data->eof(protected_data, p_errinfo)) {
                chunk_len = protected_data->read(protected_data, (char *)p_buffer_in + buffer_idx_in, chunk_len, p_errinfo);
                buffer_idx_in += chunk_len;
                if (!protected_data->eof(protected_data, p_errinfo)) {
                    chunk_len = CHUNK_LEN;
                    p_buffer_in = OPENSSL_clear_realloc(p_buffer_in, buffer_idx_in, buffer_idx_in + CHUNK_LEN);
                    if(NULL == p_buffer_in) {
                        *p_errinfo = GTA_ERROR_MEMORY;
                        goto err;
                    }
                }
            }
        }
        else {
            *p_errinfo = GTA_ERROR_MEMORY;
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
        key = gta_secmem_calloc(h_ctx, (size_t)EVP_CIPHER_get_key_length(EVP_aes_256_gcm()), sizeof(unsigned char), p_errinfo);
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
        p_buffer_out = gta_secmem_calloc(h_ctx, buffer_idx_in, sizeof(unsigned char), p_errinfo);
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
    }
    else {
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }

    ret = true;

err:
    if (NULL != gcmctx) {
        EVP_CIPHER_CTX_free(gcmctx);
    }
    if (NULL != p_buffer_in) {
        OPENSSL_clear_free(p_buffer_in, buffer_idx_in);
    }
    if (NULL != p_buffer_out) {
        gta_secmem_free(h_ctx, p_buffer_out, &errinfo_tmp);
        p_buffer_out = NULL;
    }
    if (NULL != key) {
        gta_secmem_free(h_ctx, key, &errinfo_tmp);
        key = NULL;
    }
    if (NULL != p_data) {
        if (NULL != p_data->key) {
            ASN1_OCTET_STRING_free(p_data->key);
        }
        if (NULL != p_data->iv) {
            ASN1_OCTET_STRING_free(p_data->iv);
        }
        if (NULL != p_data->tag) {
            ASN1_OCTET_STRING_free(p_data->tag);
        }
        if (NULL != p_data->data) {
            ASN1_OCTET_STRING_free(p_data->data);
        }
        OPENSSL_free(p_data);
    }

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_verify,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * claim,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_authenticate_data_detached,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * data,
    gtaio_ostream_t * seal,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;
    char payload_chunk[CHUNK_LEN];
    unsigned char* signature = NULL;
    size_t signature_len = 0;

#ifdef ENABLE_PQC
    OQS_SIG *signer = NULL;
    unsigned char * p_buffer_in = NULL;
    size_t buffer_idx_in = 0;
#endif

    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *evp_private_key = NULL;

    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct personality_t * p_personality_content = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (NULL == p_context_params) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Check Profile */
    if (PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_TLS != p_context_params->profile) {

        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }

    /* all that follows is the same for both supported profiles */

    /* get Personality of the Context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    /* get the Private Key from the Personality */
    unsigned char * p_secret_buffer  = p_personality_content->secret_data;

    /* Create the Message Digest Context */
    if (!(mdctx = EVP_MD_CTX_new()))
    {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    if (SECRET_TYPE_DER == p_personality_content->secret_type) {
        /* Range check on p_personality_content->content_data_size */
        if (p_personality_content->secret_data_size > LONG_MAX) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }
        evp_private_key = d2i_AutoPrivateKey(NULL,
                                            (const unsigned char **) &p_secret_buffer,
                                            (long)p_personality_content->secret_data_size);

        p_secret_buffer = NULL;
        if (!evp_private_key) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        /* Initialise the DigestSign operation - SHA-256 */
        if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, evp_private_key)) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        /* get Data to sign */
        while (!data->eof(data, p_errinfo)) {
            size_t read_len = data->read(data, payload_chunk, CHUNK_LEN, p_errinfo);
            /* Update with the data chunck */
            if(1 != EVP_DigestSignUpdate(mdctx, payload_chunk, read_len)) {
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
#ifdef ENABLE_PQC
    else if (SECRET_TYPE_DILITHIUM2 == p_personality_content->secret_type){
        OQS_STATUS rc;

        uint8_t *private_key = (unsigned char*)(p_personality_content->secret_data);

        OQS_init();
        signer = OQS_SIG_new(OQS_SIGN_ALGORITHM);

        if (NULL == signer) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }
        /* lengths need to match */
        if ((signer->length_secret_key + signer->length_public_key) != p_personality_content->secret_data_size) {
            /* Should this be profile unsupported or invalid parameter instead? */
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        /* Read whole input into buffer */
        p_buffer_in = OPENSSL_zalloc(CHUNK_LEN);
        if(NULL != p_buffer_in) {
            size_t chunk_len = CHUNK_LEN;
            while (!data->eof(data, p_errinfo)) {
                chunk_len = data->read(data, (char *)p_buffer_in + buffer_idx_in, chunk_len, p_errinfo);
                buffer_idx_in += chunk_len;
                if (!data->eof(data, p_errinfo)) {
                    chunk_len = CHUNK_LEN;
                    p_buffer_in = OPENSSL_clear_realloc(p_buffer_in, buffer_idx_in, buffer_idx_in + CHUNK_LEN);
                    if(NULL == p_buffer_in) {
                        *p_errinfo = GTA_ERROR_MEMORY;
                        goto err;
                    }
                }
            }
        }
        else {
            *p_errinfo = GTA_ERROR_MEMORY;
            goto err;
        }

        signature = OPENSSL_zalloc(signer->length_signature);

        if ((NULL == private_key) || (NULL == signature)) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        rc = OQS_SIG_sign(signer, signature, &signature_len, p_buffer_in, buffer_idx_in, private_key);
        if (OQS_SUCCESS != rc) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }
    }
#endif
    else {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    seal->write(seal, (const char*)signature, signature_len, p_errinfo);

    ret = true;

err:
    if (NULL != signature) {
        OPENSSL_free(signature);
        signature = NULL;
    }
    if (NULL != mdctx) {
        EVP_MD_CTX_free(mdctx);
        mdctx = NULL;
    }
    if (NULL != evp_private_key) {
        EVP_PKEY_free(evp_private_key);
        evp_private_key = NULL;
    }

#ifdef ENABLE_PQC
    OQS_SIG_free(signer);

    if (NULL != p_buffer_in) {
        OPENSSL_clear_free(p_buffer_in, buffer_idx_in);
    }
#endif

    return ret;
}

GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_verify_data_detached,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * data,
    gtaio_istream_t * seal,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_security_association_initialize,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * in,
    gtaio_ostream_t * out,
    bool * pb_finished,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_security_association_accept,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * in,
    gtaio_ostream_t * out,
    bool * pb_finished,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_security_association_destroy,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_seal_message,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * msg,
    gtaio_ostream_t * sealed_msg,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_unseal_message,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * sealed_msg,
    gtaio_ostream_t * msg,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_get_random_bytes,
(
    size_t num_bytes,
    gtaio_ostream_t * rnd_stream,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_attestate,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * nonce,
    gtaio_ostream_t * attestation_data,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_trustex_function_install,
(
    const char * function_name,
    gta_profile_name_t profile_name,
    gtaio_istream_t function,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_trustex_function_uninstall,
(
    const char * function_name,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_trustex_function_execute,
(
    const char * function_name,
    gta_handle_t function_handle,
    gtaio_istream_t input,
    gtaio_ostream_t output,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_trustex_function_terminate,
(
    gta_handle_t function_handle,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


static const struct gta_function_list_t g_my_function_list =
{
    gta_sw_provider_gta_access_token_get_physical_presence,
    gta_sw_provider_gta_access_token_get_issuing,
    gta_sw_provider_gta_access_token_get_basic,
    gta_sw_provider_gta_access_token_get_pers_derived,
    gta_sw_provider_gta_access_token_revoke,
    gta_sw_provider_gta_provider_context_open,
    gta_sw_provider_gta_provider_context_close,
    gta_sw_provider_gta_context_auth_set_access_token,
    gta_sw_provider_gta_context_auth_get_challenge,
    gta_sw_provider_gta_context_auth_set_random,
    gta_sw_provider_gta_context_get_attribute,
    gta_sw_provider_gta_context_set_attribute,
    gta_sw_provider_gta_devicestate_transition,
    gta_sw_provider_gta_devicestate_recede,
    gta_sw_provider_gta_devicestate_attestate,
    gta_sw_provider_gta_identifier_assign,
    gta_sw_provider_gta_identifier_enumerate,
    gta_sw_provider_gta_personality_enumerate,
    gta_sw_provider_gta_personality_enumerate_application,
    gta_sw_provider_gta_personality_deploy,
    gta_sw_provider_gta_personality_create,
    gta_sw_provider_gta_personality_enroll,
    gta_sw_provider_gta_personality_enroll_auth,
    gta_sw_provider_gta_personality_attestate,
    gta_sw_provider_gta_personality_remove,
    gta_sw_provider_gta_personality_deactivate,
    gta_sw_provider_gta_personality_activate,
    gta_sw_provider_gta_personality_add_trusted_attribute,
    gta_sw_provider_gta_personality_add_attribute,
    gta_sw_provider_gta_personality_get_attribute,
    gta_sw_provider_gta_personality_remove_attribute,
    gta_sw_provider_gta_personality_deactivate_attribute,
    gta_sw_provider_gta_personality_activate_attribute,
    gta_sw_provider_gta_personality_attributes_enumerate,
    gta_sw_provider_gta_seal_data,
    gta_sw_provider_gta_unseal_data,
    gta_sw_provider_gta_verify,
    gta_sw_provider_gta_authenticate_data_detached,
    gta_sw_provider_gta_verify_data_detached,
    gta_sw_provider_gta_security_association_initialize,
    gta_sw_provider_gta_security_association_accept,
    gta_sw_provider_gta_security_association_destroy,
    gta_sw_provider_gta_seal_message,
    gta_sw_provider_gta_unseal_message,
    gta_sw_provider_gta_get_random_bytes,
    gta_sw_provider_gta_attestate,
    gta_sw_provider_gta_trustex_function_install,
    gta_sw_provider_gta_trustex_function_uninstall,
    gta_sw_provider_gta_trustex_function_execute,
    gta_sw_provider_gta_trustex_function_terminate
};

/*** end of file ***/
