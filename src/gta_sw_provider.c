/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2024-2025, Siemens AG
 **********************************************************************/

#include "gta_sw_provider.h"
#include "persistent_storage.h"

#ifdef WINDOWS
#include <openssl\applink.c>
#endif /* WINDOWS */

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

const struct profile_function_list_t fl_null = {
    NULL
};

extern const struct profile_function_list_t fl_prof_ch_iec_30168_basic_passcode;
extern const struct profile_function_list_t fl_prof_ch_iec_30168_basic_local_data_integrity_only;
extern const struct profile_function_list_t fl_prof_ch_iec_30168_basic_local_data_protection;
extern const struct profile_function_list_t fl_prof_com_github_generic_trust_anchor_api_basic_rsa;
extern const struct profile_function_list_t fl_prof_com_github_generic_trust_anchor_api_basic_ec;
#ifdef ENABLE_PQC
extern const struct profile_function_list_t fl_prof_com_github_generic_trust_anchor_api_basic_dilithium;
#endif
extern const struct profile_function_list_t fl_prof_com_github_generic_trust_anchor_api_basic_jwt;
extern const struct profile_function_list_t fl_prof_com_github_generic_trust_anchor_api_basic_signature;
extern const struct profile_function_list_t fl_prof_com_github_generic_trust_anchor_api_basic_enroll;

struct profile_list_t {
    const char name[MAXLEN_PROFILE];
    const struct profile_function_list_t * pFunction;
};

/* Supported profiles */
#ifdef ENABLE_PQC
#define NUM_PROFILES 11
#else
#define NUM_PROFILES 10
#endif
static struct profile_list_t supported_profiles[NUM_PROFILES] = {
    [PROF_INVALID] = {"INVALID", &fl_null},
    [PROF_CH_IEC_30168_BASIC_PASSCODE] = {"ch.iec.30168.basic.passcode", &fl_prof_ch_iec_30168_basic_passcode},
    [PROF_CH_IEC_30168_BASIC_LOCAL_DATA_INTEGRITY_ONLY] = {"ch.iec.30168.basic.local_integrity_only", &fl_prof_ch_iec_30168_basic_local_data_integrity_only},
    [PROF_CH_IEC_30168_BASIC_LOCAL_DATA_PROTECTION] = {"ch.iec.30168.basic.local_data_protection", &fl_prof_ch_iec_30168_basic_local_data_protection},
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_RSA] = {"com.github.generic-trust-anchor-api.basic.rsa", &fl_prof_com_github_generic_trust_anchor_api_basic_rsa},
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_EC] = {"com.github.generic-trust-anchor-api.basic.ec", &fl_prof_com_github_generic_trust_anchor_api_basic_ec},
#ifdef ENABLE_PQC
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_DILITHIUM] = {"com.github.generic-trust-anchor-api.basic.dilithium", &fl_prof_com_github_generic_trust_anchor_api_basic_dilithium},
#endif
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_JWT] = {"com.github.generic-trust-anchor-api.basic.jwt", &fl_prof_com_github_generic_trust_anchor_api_basic_jwt},
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_SIGNATURE] = {"com.github.generic-trust-anchor-api.basic.signature", &fl_prof_com_github_generic_trust_anchor_api_basic_signature},
    /* The following is only an alias of com.github.generic-trust-anchor-api.basic.signature and does not have its own implementation. */
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_TLS] = {"com.github.generic-trust-anchor-api.basic.tls", &fl_prof_com_github_generic_trust_anchor_api_basic_signature},
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_ENROLL] = {"com.github.generic-trust-anchor-api.basic.enroll", &fl_prof_com_github_generic_trust_anchor_api_basic_enroll},
};

struct provider_instance_auth_token_t {
    struct provider_instance_auth_token_t * p_next;

    /*
     * Mandatory token attributes
     */

    /*
     * Object reference scope. For access tokens with
     * usage == GTA_ACCESS_TOKEN_USAGE_RECEDE this parameter is not used and set
     * to {0}.
     */
    gta_personality_fingerprint_t target_personality_fingerprint;

    /* enum: initial, basic, personality derived, physical presence */
    gta_access_descriptor_type_t type;

    /*
     * enum:
     * GTA_ACCESS_TOKEN_USAGE_USE, GTA_ACCESS_TOKEN_USAGE_ADMIN, GTA_ACCESS_TOKEN_USAGE_RECEDE
     */
    gta_access_token_usage_t usage;

    /* Nonce for freshness of token */
    uint8_t freshness[GTA_ACCESS_TOKEN_LEN];

    /*
     * Optional attributes required for personality derived tokens
     */
    /* Fingerprint of the personality used to derive this token */
    gta_personality_fingerprint_t binding_personality_fingerprint;
    /* Note: Stores unnamed enum declared in gta_sw_provider_context_params_t */
    uint32_t derivation_profile;

    /* Actual token value (binary string) */
    gta_access_token_t access_token;
};


/* List of access tokens */
struct gta_access_token_list_t {
    struct gta_access_token_list_t * p_next;
    gta_access_token_t access_token;
};


/*
 * Helper function to get enum value of a profile string. In case the string is
 * not found, 0 (PROF_INVALID) is returned.
 */
static enum profile_t get_profile_enum(const char * profile)
{
    for (uint32_t i=0; i < NUM_PROFILES; ++i) {
        if (0 == strcmp(profile, supported_profiles[i].name)) {
            return i;
        }
    }
    return PROF_INVALID;
}

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
    [PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_AUXILIARY_X509] = false,
    [PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_LIST_RFC8446] = false,
    [PAT_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_KEYTYPE_OPENSSL] = true, /* it is an internal attribute, anyway not allowed to be changed */
};

/*
 * This table defines which personality attribute types are not allowed
 * (restricted) to be added, deactivated and deleted by the respective GTA API
 * functions.
 */
static bool pers_attr_type_restricted[NUM_PERSONALITY_ATTRIBUTE_TYPE] = {
    [PAT_INVALID] = false,
    [PAT_CH_IEC_30168_IDENTIFIER] = true,
    [PAT_CH_IEC_30168_FINGERPRINT] = true,
    [PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_SELF_X509] = false,
    [PAT_CH_IEC_30168_TRUSTLIST_CRL_X509V3] = false,
    [PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_TRUSTED_X509V3] = false,
    [PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_AUXILIARY_X509] = false,
    [PAT_CH_IEC_30168_TRUSTLIST_CERTIFICATE_LIST_RFC8446] = false,
    [PAT_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_KEYTYPE_OPENSSL] = true,
};

/* attribute related defines */
#define PERS_ATTR_NAME_IDENTIFIER       "ch.iec.30168.identifier_value"
#define PERS_ATTR_NAME_FINGERPRINT      "ch.iec.30168.fingerprint"

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


/*
 * Helper function to check whether all context params are valid.
 * - returns true, if context params are valid (personality is available and activated)
 * - returns false, if context params are NULL or personality is missing (e.g.,
 *   because it has been removed) or personality is deactivated
 */
static bool check_context_params
(
    const struct gta_sw_provider_context_params_t * p_context_params,
    gta_errinfo_t * p_errinfo
)
{
    bool ret = false;

    if ((NULL == p_context_params) || (NULL == p_context_params->p_personality_item)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
    }
    else if((!p_context_params->p_personality_item->activated) || (NULL == p_context_params->p_personality_item->p_personality_content)) {
        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    }
    else {
        ret = true;
    }

    return ret;
}


/* Helper function to get the fingerprint of a personality specified by name */
static bool get_personality_fingerprint(
    struct personality_name_list_item_t * p_personality_name_list,
    const gta_personality_name_t personality_name,
    gta_personality_fingerprint_t * target_personality_fingerprint,
    gta_errinfo_t * p_errinfo
)
{
   struct personality_name_list_item_t * p_personality;
   const struct personality_attribute_t * p_personality_attribute;

    p_personality = list_find(  (struct list_t *)p_personality_name_list,
                                personality_name,
                                personality_list_item_cmp_name);
    if (NULL != p_personality) {
        p_personality_attribute = list_find((struct list_t *) p_personality->p_personality_content->p_attribute_list,
                                            (unsigned char *)PERS_ATTR_NAME_FINGERPRINT,
                                            attribute_list_item_cmp_name);
        if(NULL != p_personality_attribute) {
            memcpy (*target_personality_fingerprint, p_personality_attribute->p_data, p_personality_attribute->data_size);

        } else {
            *p_errinfo = GTA_ERROR_ATTRIBUTE_MISSING;
            return false;
        }
    } else {
        *p_errinfo = GTA_ERROR_ITEM_NOT_FOUND;
        return false;
    }
    return true;
}

bool find_access_token(void *p_item, void *p_item_crit) {
    /*
    *  ::: We search in the auth token list for a matching token:
    *  *p_item      : (struct provider_instance_auth_token_t *)
    *                 p_auth_token_list->access_token
    *
    *  ::: The access token to look for:
    *  *p_item_crit : (struct gta_access_token_t)
    *
    *   ::: Note: Here we do not test whether the policy allows a certain usage, profile, type, ...
    */

    if (0 == memcmp(((struct provider_instance_auth_token_t *)p_item)->access_token,
                    (struct gta_access_token_t *)p_item_crit,
                    GTA_ACCESS_TOKEN_LEN)) {
        return true;
    }
    else {
        return false;
    }
}

bool find_matching_access_policy(void *p_item, void *p_item_crit) {
    /*
    *  ::: We search for an item in the auth_*_info_list where the type matches,
    * and in case of personality derived access tokens, the additional
    * conditions match:
    *  *p_item      : (struct auth_info_list_item_t *)
    *                 p_auth_use_info_list->type
    *
    *  *p_item_crit : (struct provider_instance_auth_token_t *)
    *                 p_auth_token->type
    */
    const struct auth_info_list_item_t * p_auth_info_list_item = (struct auth_info_list_item_t *)p_item;
    const struct provider_instance_auth_token_t * p_provider_instance_auth_token = (struct provider_instance_auth_token_t *)p_item_crit;

    if (p_auth_info_list_item->type != p_provider_instance_auth_token->type) {
        return false;
    }
    if (GTA_ACCESS_DESCRIPTOR_TYPE_PERS_DERIVED_TOKEN == p_provider_instance_auth_token->type) {
        const enum profile_t profile = get_profile_enum(p_auth_info_list_item->derivation_profile_name);
        if (PROF_INVALID == profile) {
            return false;
        }
        if ((0 != memcmp(p_auth_info_list_item->binding_personality_fingerprint, p_provider_instance_auth_token->binding_personality_fingerprint, sizeof(gta_personality_fingerprint_t)))
            || (profile != p_provider_instance_auth_token->derivation_profile)) {
            return false;
        }
    }
    return true;
}

/* Helper function to check whether a valid access token is available and the policy allows access to the personality */
bool check_access_permission (
    struct gta_sw_provider_context_params_t * p_context_params,
    struct gta_sw_provider_params_t * p_provider_params,
    gta_access_token_usage_t usage,
    gta_errinfo_t * p_errinfo
)
{
    struct provider_instance_auth_token_t * p_auth_token = NULL;
    struct auth_info_list_item_t * p_auth_x_info_list = NULL;

    if(GTA_ACCESS_TOKEN_USAGE_USE == usage ) {
        p_auth_x_info_list = p_context_params->p_personality_item->p_personality_content->p_auth_use_info_list;
    }
    else if (GTA_ACCESS_TOKEN_USAGE_ADMIN == usage) {
        p_auth_x_info_list = p_context_params->p_personality_item->p_personality_content->p_auth_admin_info_list;
    }
    else {
        /* Todo: checks for recede here! */
        p_auth_x_info_list = NULL;
    }

    /* None of the policy lists are allowed to be empty */
    if (NULL == p_auth_x_info_list) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }

    /* If policy type is "initial", it is the only list element */
    if(GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL == p_auth_x_info_list->type) {
        /*
         * TODO: Infrastructure for initial access tokens to be defined.
         * Here we have to check a flag whether the condition for this policy is met.
         */
        return true;
    }

    /* Get the fingerprint of the current personality */
    const struct personality_attribute_t * p_personality_attribute = NULL;
    p_personality_attribute = list_find((struct list_t *) p_context_params->p_personality_item->p_personality_content->p_attribute_list,
                                (unsigned char *)PERS_ATTR_NAME_FINGERPRINT,
                                attribute_list_item_cmp_name);
    if (NULL == p_personality_attribute) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }

    /*
     * For all the other policy types, access tokens are needed. We loop over
     * all available access tokens in the context, until one meets the
     * requirements of the policy.
     */
    struct gta_access_token_list_t * access_token_list_item = p_context_params->p_access_token_list;
    while (NULL != access_token_list_item) {
        /* Find the auth token for the current access token */
        p_auth_token = list_find((struct list_t *)p_provider_params->p_auth_token_list, access_token_list_item->access_token, find_access_token);
        if ((NULL != p_auth_token) && (GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN != p_auth_token->type)
            /* Check if target personality and usage matches */
            && (0 == memcmp (p_personality_attribute->p_data, p_auth_token->target_personality_fingerprint, sizeof(gta_personality_fingerprint_t)))
            && (usage == p_auth_token->usage)
            /* Now we look for a policy which can be fulfilled by this token */
            && (NULL != list_find((struct list_t *)p_auth_x_info_list, p_auth_token, find_matching_access_policy))) {

            return true;
        }
        access_token_list_item = access_token_list_item->p_next;
    }
    *p_errinfo = GTA_ERROR_ACCESS;
    return false;
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

    /* init params */
    p_provider_params->p_auth_token_list = NULL;
    p_provider_params->provider_instance_auth_token_info.issuing_token_issued = false;
    p_provider_params->provider_instance_auth_token_info.issuing_token_revoked = false;
    p_provider_params->provider_instance_auth_token_info.physical_presence_token_issued = false;

    /* Create random token issuing token */
    if (1 != RAND_bytes((unsigned char *)(p_provider_params->provider_instance_auth_token_info.issuing_token), sizeof(gta_access_token_t))) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

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


/*
 * Helper function the generate an access token based on p_auth_token_list_item.
 * The caller is responsible to hand over a valid pointer to
 * p_auth_token_list_item.
 */
static bool generate_access_token (struct provider_instance_auth_token_t * p_auth_token_list_item)
{
    EVP_MD_CTX * ctx = NULL;
    bool ret = false;

    /* Compute and set basic_access_token (256 bit value) */
    ctx = EVP_MD_CTX_new();
    if (NULL == ctx) {
        goto err;
    }
    if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        goto err;
    }
    /* Note: do not include "p_auth_token_list_item->p_next", as this pointer can change */
    if (1 != EVP_DigestUpdate(ctx, p_auth_token_list_item->target_personality_fingerprint, sizeof(p_auth_token_list_item->target_personality_fingerprint))) {
        goto err;
    }
    if (1 != EVP_DigestUpdate(ctx, &(p_auth_token_list_item->type), sizeof(p_auth_token_list_item->type))) {
        goto err;
    }
    if (1 != EVP_DigestUpdate(ctx, &(p_auth_token_list_item->usage), sizeof(p_auth_token_list_item->usage))) {
        goto err;
    }
    if (1 != EVP_DigestUpdate(ctx, p_auth_token_list_item->freshness, sizeof(p_auth_token_list_item->freshness))) {
        goto err;
    }
    if (1 != EVP_DigestUpdate(ctx, p_auth_token_list_item->binding_personality_fingerprint, sizeof(p_auth_token_list_item->binding_personality_fingerprint))) {
        goto err;
    }
    if (1 != EVP_DigestUpdate(ctx, &(p_auth_token_list_item->derivation_profile), sizeof(p_auth_token_list_item->derivation_profile))) {
        goto err;
    }

#if (GTA_ACCESS_TOKEN_LEN != 32)
#error Size of access_token does not match used hash function
#endif

    if (1 != EVP_DigestFinal_ex(ctx, (unsigned char *)p_auth_token_list_item->access_token, NULL)) {
        goto err;
    }

    ret = true;

err:
    EVP_MD_CTX_free(ctx);
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_access_token_get_physical_presence,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t physical_presence_token,
    gta_errinfo_t * p_errinfo
    ))
{
    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct provider_instance_auth_token_t * p_auth_token_list_item = NULL;
    gta_errinfo_t errinfo_tmp = 0;

    p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /*
     * Check conditions - only allowed to be called once. If issuing token
     * already issued, physical presence token cannot be issued anymore.
     */
    if ((p_provider_params->provider_instance_auth_token_info.physical_presence_token_issued)
        || (p_provider_params->provider_instance_auth_token_info.issuing_token_issued)) {

        *p_errinfo = GTA_ERROR_ACCESS;
        return false;
    }

    /* Create a new access token object */
    p_auth_token_list_item =
        gta_secmem_calloc(p_provider_params->h_ctx,
        1, sizeof(struct provider_instance_auth_token_t ), p_errinfo);
    if (NULL == p_auth_token_list_item) {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    p_auth_token_list_item->p_next = NULL;
    p_auth_token_list_item->type = GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN;
    /* Physical presence access token only valid for devicestate recede */
    p_auth_token_list_item->usage = GTA_ACCESS_TOKEN_USAGE_RECEDE;

    /* Get random number from OpenSSL for freshness */
    if (1 != RAND_bytes((unsigned char *)&p_auth_token_list_item->freshness,
                sizeof(p_auth_token_list_item->freshness)))
    {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Set other attributes to undefined */
    p_auth_token_list_item->derivation_profile = PROF_INVALID;
    memset(p_auth_token_list_item->binding_personality_fingerprint, 0, PERS_FINGERPRINT_LEN);
    memset(p_auth_token_list_item->target_personality_fingerprint, 0, PERS_FINGERPRINT_LEN);

    /* Compute and set basic_access_token (256 bit value) */
    if (!generate_access_token(p_auth_token_list_item)) {
        goto err;
    }
    memcpy(physical_presence_token, p_auth_token_list_item->access_token, GTA_ACCESS_TOKEN_LEN);

    /* Append item to list */
    list_append((struct list_t **) &p_provider_params->p_auth_token_list, (void *) p_auth_token_list_item);
    p_provider_params->provider_instance_auth_token_info.physical_presence_token_issued = true;
    return true;

err:
    gta_secmem_free(p_provider_params->h_ctx, p_auth_token_list_item, &errinfo_tmp);
    return false;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_access_token_get_issuing,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t granting_token,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;
    struct gta_sw_provider_params_t * p_provider_params = NULL;

    p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /* Check condition - this function can only be called once */
    if (!p_provider_params->provider_instance_auth_token_info.issuing_token_issued) {
        memcpy(granting_token, p_provider_params->provider_instance_auth_token_info.issuing_token, sizeof(gta_access_token_t));
        p_provider_params->provider_instance_auth_token_info.issuing_token_issued = true;
        ret = true;
    }
    else {
        *p_errinfo = GTA_ERROR_ACCESS;
    }
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_access_token_get_basic,
(
    gta_instance_handle_t h_inst,
    const gta_access_token_t granting_token,
    const gta_personality_name_t target_personality_name,
    gta_access_token_usage_t usage,
    gta_access_token_t basic_access_token,
    gta_errinfo_t * p_errinfo
    ))
{
    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct provider_instance_auth_token_t * p_auth_token_list_item = NULL;
    gta_errinfo_t errinfo_tmp = 0;

    p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /*
     * Check granting token:
     * - Needs to be issued
     * - Must not be revoked
     * - Token must be valid (content check)
     */
    if ((!p_provider_params->provider_instance_auth_token_info.issuing_token_issued)
        || (p_provider_params->provider_instance_auth_token_info.issuing_token_revoked)
        || (0 != memcmp(p_provider_params->provider_instance_auth_token_info.issuing_token, granting_token, sizeof(gta_access_token_t)))) {
        
        *p_errinfo = GTA_ERROR_ACCESS;
        return false;
    }

    /* Create a new access token object */
    p_auth_token_list_item =
        gta_secmem_calloc(p_provider_params->h_ctx,
        1, sizeof(struct provider_instance_auth_token_t ), p_errinfo);
    if (NULL == p_auth_token_list_item) {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    p_auth_token_list_item->p_next = NULL;

    /* Get the personality fingerprint of the personality specified with "personality_name" */
    if (!get_personality_fingerprint(
                p_provider_params->p_devicestate_stack->p_personality_name_list,
                target_personality_name,
                &(p_auth_token_list_item->target_personality_fingerprint),
                p_errinfo)) {
        goto err;
    }

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
    p_auth_token_list_item->derivation_profile = PROF_INVALID;
    memset(p_auth_token_list_item->binding_personality_fingerprint, 0, PERS_FINGERPRINT_LEN);

    /* Compute and set basic_access_token (256 bit value) */
    if (!generate_access_token(p_auth_token_list_item)) {
        goto err;
    }
    memcpy(basic_access_token, p_auth_token_list_item->access_token, GTA_ACCESS_TOKEN_LEN);

    /* Append item to list */
    list_append((struct list_t **) &p_provider_params->p_auth_token_list, (void *) p_auth_token_list_item);
    return true;

err:
    gta_secmem_free(p_provider_params->h_ctx, p_auth_token_list_item, &errinfo_tmp);
    return false;
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
    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct provider_instance_auth_token_t * p_auth_token_list_item = NULL;
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    const struct personality_attribute_t * p_attribute = NULL;
    gta_errinfo_t errinfo_tmp = 0;

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!check_context_params(p_context_params, p_errinfo)) {
        goto err;
    }

    /* Check if condition is met allowing issue of pers derived access token */
    if (!p_context_params->b_pers_derived_access_token_condition_fulfilled) {
        *p_errinfo = GTA_ERROR_ACCESS;
        goto err;
    }

    p_auth_token_list_item =
        gta_secmem_calloc(p_provider_params->h_ctx,
        1, sizeof(struct provider_instance_auth_token_t ), p_errinfo);
    if (NULL == p_auth_token_list_item) {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    p_auth_token_list_item->p_next = NULL;

    /* Get the personality fingerprint of the personality specified with "personality_name" */
    if (!get_personality_fingerprint(
                p_provider_params->p_devicestate_stack->p_personality_name_list,
                target_personality_name,
                &(p_auth_token_list_item->target_personality_fingerprint),
                p_errinfo)) {
        goto err;
    }

    p_auth_token_list_item->type = GTA_ACCESS_DESCRIPTOR_TYPE_PERS_DERIVED_TOKEN;
    p_auth_token_list_item->usage = usage;

    /* Get random number from OpenSSL for freshness */
    if (1 != RAND_bytes((unsigned char *)&p_auth_token_list_item->freshness,
                sizeof(p_auth_token_list_item->freshness))) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* Set special attributes for personality derived tokens */
    /* Find attribute_list_item with requested name */
    p_attribute = list_find((struct list_t *)(p_context_params->p_personality_item->p_personality_content->p_attribute_list),
                            PERS_ATTR_NAME_FINGERPRINT, attribute_list_item_cmp_name);
    if (NULL == p_attribute) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    memcpy(p_auth_token_list_item->binding_personality_fingerprint, p_attribute->p_data, p_attribute->data_size);
    p_auth_token_list_item->derivation_profile = (uint32_t)p_context_params->profile;
    memset(p_auth_token_list_item->access_token, 0, GTA_ACCESS_TOKEN_LEN);

    /* Compute and set basic_access_token (256 bit value) */
    if (!generate_access_token(p_auth_token_list_item)) {
        goto err;
    }
    memcpy(*p_pers_derived_access_token, p_auth_token_list_item->access_token, GTA_ACCESS_TOKEN_LEN);

    /* Append item to list */
    list_append((struct list_t **) &(p_provider_params->p_auth_token_list), (void *) p_auth_token_list_item);
    return true;

err:
    gta_secmem_free(p_provider_params->h_ctx, p_auth_token_list_item, &errinfo_tmp);
    return false;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_access_token_revoke,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t access_token_tbr,
    gta_errinfo_t * p_errinfo
    ))
{
    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct provider_instance_auth_token_t * p_auth_token_list_item = NULL;

    p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /* Check if access_token_tbr is issuing token */
    if (0 == memcmp(p_provider_params->provider_instance_auth_token_info.issuing_token, access_token_tbr, sizeof(gta_access_token_t))) {
        if (p_provider_params->provider_instance_auth_token_info.issuing_token_revoked) {
            *p_errinfo = GTA_ERROR_ACCESS;
            return false;
        }
        else {
            p_provider_params->provider_instance_auth_token_info.issuing_token_revoked = true;
            return true;
        }
    }

    /* Remove item from list */
    p_auth_token_list_item = list_remove((struct list_t **) &p_provider_params->p_auth_token_list, access_token_tbr, find_access_token);
    if (NULL == p_auth_token_list_item) {
        *p_errinfo = GTA_ERROR_ACCESS;
        return false;
    }

    gta_secmem_free(p_provider_params->h_ctx, p_auth_token_list_item, p_errinfo);
    return true;
}

GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_context_auth_set_access_token,
(
    gta_context_handle_t h_ctx,
    const gta_access_token_t access_token,
    gta_errinfo_t * p_errinfo
    ))
{
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct gta_access_token_list_t * p_access_token_list_item = NULL;
    bool ret = false;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!check_context_params(p_context_params, p_errinfo)) {
        goto err;
    }

    /* Here we add the token to the list of tokens in the context */
    p_access_token_list_item = gta_secmem_calloc(h_ctx, 1, sizeof(struct gta_access_token_list_t), p_errinfo);
    if (NULL == p_access_token_list_item) {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    memcpy(p_access_token_list_item->access_token, access_token, GTA_ACCESS_TOKEN_LEN);
    list_append_front((struct list_t **)&(p_context_params->p_access_token_list), p_access_token_list_item);
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
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    const struct gta_sw_provider_params_t * p_provider_params = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!check_context_params(p_context_params, p_errinfo)) {
        return false;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /* check whether function is supported by profile */
    if (NULL == supported_profiles[p_context_params->profile].pFunction->context_get_attribute) {
        DEBUG_PRINT(("gta_sw_provider_gta_context_get_attribute: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        return false;
    }

    /* call profile specific implementation */
    return supported_profiles[p_context_params->profile].pFunction->context_get_attribute(p_context_params, attrtype, p_attrvalue, p_errinfo);
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_context_set_attribute,
(
    gta_context_handle_t h_ctx,
    const gta_context_attribute_type_t attrtype,
    gtaio_istream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
    ))
{
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    const struct gta_sw_provider_params_t * p_provider_params = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!check_context_params(p_context_params, p_errinfo)) {
        return false;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /* check whether function is supported by profile */
    if (NULL == supported_profiles[p_context_params->profile].pFunction->context_set_attribute) {
        DEBUG_PRINT(("gta_sw_provider_gta_context_set_attribute: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        return false;
    }

    /* call profile specific implementation */
    return supported_profiles[p_context_params->profile].pFunction->context_set_attribute(p_context_params, attrtype, p_attrvalue, p_errinfo);
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

    /*
     * Check if personality exists and its content has not been deleted. This
     * should already be checked by gta-api-core. In case it fails here, we
     * return GTA_ERROR_INTERNAL_ERROR.
     */
    if ((NULL == p_personality_item) || (NULL == p_personality_item->p_personality_content)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    /* initialize context parameters */
    p_context_params = gta_secmem_calloc(h_ctx, 1, sizeof(struct gta_sw_provider_context_params_t), p_errinfo);
    if (NULL != p_context_params) {
        *pp_params = p_context_params;
    }
    else {
        *p_errinfo = GTA_ERROR_MEMORY;
        goto err;
    }
    p_context_params->h_ctx = h_ctx;
    p_context_params->p_personality_item = p_personality_item;
    p_context_params->b_pers_derived_access_token_condition_fulfilled = false;
    p_context_params->profile = get_profile_enum(profile);
    p_context_params->p_access_token_list = NULL;
    p_context_params->context_attributes = NULL;

    /* check whether function is supported by profile */
    if (NULL == supported_profiles[p_context_params->profile].pFunction->context_open) {
        DEBUG_PRINT(("gta_sw_provider_gta_context_open: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }

    /* call profile specific implementation */
    if (!supported_profiles[p_context_params->profile].pFunction->context_open(p_context_params, p_errinfo)) {
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

    return true;

err:
    if (NULL != p_context_params) {
        gta_secmem_free(h_ctx, p_context_params, p_errinfo);
        p_context_params = NULL;
    }

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_provider_context_close,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
))
{
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    bool ret = true;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (NULL == p_context_params) {
        return false;
    }

    /*
     * Memory allocated with gta_secmem will be automatically freed. We only
     * need to call profile specific code in case there is something special
     * to do.
     */
    if (NULL != supported_profiles[p_context_params->profile].pFunction->context_close) {
        ret = supported_profiles[p_context_params->profile].pFunction->context_close(p_context_params, p_errinfo);
    }

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

    struct gta_sw_provider_params_t * p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
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
    struct personality_attribute_t ** p_pers_attribute_list,
    const enum pers_attr_type_t attrtype,
    const unsigned char * attrname,
    const size_t attrname_len,
    const unsigned char * attrval,
    const size_t attrval_len,
    const bool b_trusted,
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
    p_personality_attribute->trusted = b_trusted;

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
    list_append_front((struct list_t **)(p_pers_attribute_list),p_personality_attribute);

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
                        /* Nothing to do */
                        break;
                    case GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN:
                        /* Cleanup memory */
                        gta_secmem_free(h_ctx, p_auth_info_list_current, p_errinfo);
                        p_auth_info_list_current = NULL;
                        /* Access policy invalid */
                        *p_errinfo = GTA_ERROR_ACCESS_POLICY;
                        goto err;
                        break;
                    case GTA_ACCESS_DESCRIPTOR_TYPE_PERS_DERIVED_TOKEN:
                        /* Copy fingerprint */
                        if (gta_access_policy_get_access_descriptor_attribute(
                            h_access_descriptor, GTA_ACCESS_DESCRIPTOR_ATTR_PERS_FINGERPRINT,
                            &p_attr, &attr_len, p_errinfo )) {
                            if (PERS_FINGERPRINT_LEN == attr_len) {
                                memcpy( p_auth_info_list_current->binding_personality_fingerprint,
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
                                p_auth_info_list_current->derivation_profile_name =
                                gta_secmem_calloc(h_ctx, 1, attr_len + 1, p_errinfo)
                            )){
                                memcpy(p_auth_info_list_current->derivation_profile_name,
                                        p_attr, attr_len);
                                p_auth_info_list_current->derivation_profile_name[attr_len] = '\0';
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


/* Helper function for gta_personality_deploy and gta_personality_create */
static bool personality_deploy_create
(
    gta_instance_handle_t h_inst,
    const gta_identifier_value_t identifier_value,
    const gta_personality_name_t personality_name,
    const gta_application_name_t application,
    const gta_profile_name_t profile,
    gtaio_istream_t * personality_content,
    gta_access_policy_handle_t h_auth_use,
    gta_access_policy_handle_t h_auth_admin,
    const struct gta_protection_properties_t requested_protection_properties,
    gta_errinfo_t * p_errinfo
)
{
    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct identifier_list_item_t * p_identifier_list_item = NULL;
    struct devicestate_stack_item_t * p_devicestate_stack_item = NULL;
    struct personality_name_list_item_t * p_personality_name_list_item = NULL;
    personality_secret_type_t personality_secret_type;
    size_t personality_name_length = 0;
    size_t application_name_length = 0;
    gta_personality_fingerprint_t personality_fingerprint = { 0 };
    gta_errinfo_t errinfo_tmp = GTA_ERROR_INTERNAL_ERROR;
    struct personality_attribute_t * p_pers_specific_attributes = NULL;

    unsigned char * p_secret_buffer = NULL;
    size_t len = 0;

    p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

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
     * - size_t len with the length of the data in p_secret_buffer
     * - gta_personality_fingerprint_t personality_fingerprint
     * - p_pers_specific_attributes optional list of profile specific
     *   personality attributes
     */
    enum profile_t prof = get_profile_enum(profile);

    /*
     * Check personality_content:
     * - If NULL, call personality_create
     * - Otherwise call personality_deploy
     */
    if (NULL == personality_content) {
        /* check whether function is supported by profile */
        if (NULL == supported_profiles[prof].pFunction->personality_create) {
            DEBUG_PRINT(("gta_sw_provider_gta_personality_create: Profile not supported\n"));
            *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
            goto err;
        }

        /* call profile specific implementation */
        if (!supported_profiles[prof].pFunction->personality_create(p_provider_params, personality_name, &personality_secret_type, &p_secret_buffer, &len, personality_fingerprint, &p_pers_specific_attributes, p_errinfo)) {
            goto err;
        }
    }
    else {
        /* check whether function is supported by profile */
        if (NULL == supported_profiles[prof].pFunction->personality_deploy) {
            DEBUG_PRINT(("gta_sw_provider_gta_personality_deploy: Profile not supported\n"));
            *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
            goto err;
        }

        /* call profile specific implementation */
        if (!supported_profiles[prof].pFunction->personality_deploy(p_provider_params, personality_name, personality_content, &personality_secret_type, &p_secret_buffer, &len, personality_fingerprint, &p_pers_specific_attributes, p_errinfo)) {
            goto err;
        }
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
    if (!policy_copy_helper(p_provider_params->h_ctx, h_auth_use, &(p_personality_name_list_item->p_personality_content->p_auth_use_info_list), p_errinfo)) {
        goto err;
    }

    if (!policy_copy_helper(p_provider_params->h_ctx, h_auth_admin, &(p_personality_name_list_item->p_personality_content->p_auth_admin_info_list), p_errinfo)) {
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
        &p_personality_name_list_item->p_personality_content->p_attribute_list, PAT_CH_IEC_30168_IDENTIFIER,
        (unsigned char *)PERS_ATTR_NAME_IDENTIFIER, sizeof(PERS_ATTR_NAME_IDENTIFIER),
        (unsigned char *)identifier_value, strnlen(identifier_value, IDENTIFIER_VALUE_MAXLEN),
        true, p_errinfo)) {

        goto err;
    }
    if (!add_personality_attribute_list_item(p_provider_params,
        &p_personality_name_list_item->p_personality_content->p_attribute_list, PAT_CH_IEC_30168_FINGERPRINT,
        (unsigned char *)PERS_ATTR_NAME_FINGERPRINT, sizeof(PERS_ATTR_NAME_FINGERPRINT),
        (unsigned char *)personality_fingerprint, sizeof(personality_fingerprint),
        true, p_errinfo)) {

        goto err;
    }

    /*
     * Add additional / profile dependent attributes. We do the "append front"
     * manually, as p_pers_specific_attributes can be a list with multiple
     * elements
     */
    if (p_pers_specific_attributes != NULL) {
        /* Go to the last element of p_pers_specific_attributes */
        struct personality_attribute_t * p_attr = p_pers_specific_attributes;
        while (p_attr->p_next != NULL) {
            p_attr = p_attr->p_next;
        }
        /*
         * Change the p_next of the last p_pers_specific_attributes to first
         * element of existing list
         */
        p_attr->p_next = p_personality_name_list_item->p_personality_content->p_attribute_list;

        /* p_pers_specific_attributes is new start of the whole list */
        p_personality_name_list_item->p_personality_content->p_attribute_list = p_pers_specific_attributes;
    }

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

    /* cleanup personality */
    personality_name_list_item_free(p_provider_params->h_ctx, p_personality_name_list_item, &errinfo_tmp);
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
    return personality_deploy_create(
        h_inst,
        identifier_value,
        personality_name,
        application,
        profile,
        personality_content,
        h_auth_use,
        h_auth_admin,
        requested_protection_properties,
        p_errinfo
    );
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
    struct gta_protection_properties_t requested_protection_properties,
    gta_errinfo_t * p_errinfo
    ))
{
    return personality_deploy_create(
        h_inst,
        identifier_value,
        personality_name,
        application,
        profile,
        NULL,
        h_auth_use,
        h_auth_admin,
        requested_protection_properties,
        p_errinfo
    );
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_enroll,
(
    gta_context_handle_t h_ctx,
    gtaio_ostream_t * p_personality_enrollment_info,
    gta_errinfo_t * p_errinfo
    ))
{
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct gta_sw_provider_params_t * p_provider_params = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!check_context_params(p_context_params, p_errinfo)) {
        return false;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /* check whether function is supported by profile */
    if (NULL == supported_profiles[p_context_params->profile].pFunction->personality_enroll) {
        DEBUG_PRINT(("gta_sw_provider_gta_personality_enroll: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        return false;
    }

    /* check access condition */
    if (!check_access_permission(p_context_params, p_provider_params, GTA_ACCESS_TOKEN_USAGE_USE, p_errinfo)) {
        return false;
    }

    /* call profile specific implementation */
    return supported_profiles[p_context_params->profile].pFunction->personality_enroll(p_context_params, p_personality_enrollment_info, p_errinfo);
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
    struct gta_sw_provider_context_params_t * p_context_params,
    struct gta_sw_provider_params_t * p_provider_params,
    const gta_personality_attribute_type_t attrtype,
    const gta_personality_attribute_name_t attrname,
    gtaio_istream_t * p_attrvalue,
    const bool b_trusted,
    gta_errinfo_t * p_errinfo
    )
{
    unsigned char attrval[MAXLEN_PERSONALITY_ATTRIBUTE_VALUE] = { 0 };
    size_t attrval_len = 0;
    size_t attrname_len = 0;
    bool ret = false;

    enum pers_attr_type_t pers_attr_type = get_pers_attr_type_enum(attrtype);

    /* Restricted attribute types (default and internal) are not allowed */
    if (pers_attr_type_restricted[pers_attr_type]) {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        goto err;
    }

    /* Check if attribute with the same name already exists */
    if (NULL != list_find((struct list_t *)(p_context_params->p_personality_item->p_personality_content->p_attribute_list),
                            attrname, attribute_list_item_cmp_name)) {

        *p_errinfo = GTA_ERROR_NAME_ALREADY_EXISTS;
        goto err;
    }

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
        &p_context_params->p_personality_item->p_personality_content->p_attribute_list,
        pers_attr_type, (unsigned char *)attrname, attrname_len, attrval, attrval_len,
        b_trusted, p_errinfo)) {

        /* Serialize the new device state */
        if (!provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack)) {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }
        ret = true;
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
    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct gta_sw_provider_context_params_t * p_context_params = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!check_context_params(p_context_params, p_errinfo)) {
        return false;
    }
    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /* check whether function is supported by profile */
    if (!supported_profiles[p_context_params->profile].pFunction->personality_attribute_functions_supported) {
        DEBUG_PRINT(("gta_sw_provider_gta_personality_add_trusted_attribute: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        return false;
    }

    enum pers_attr_type_t pers_attr_type = get_pers_attr_type_enum(attrtype);
    /* Generic attribute types are not allowed */
    if ((PAT_INVALID == pers_attr_type) || (false == pers_attr_type_trusted[pers_attr_type])) {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        return false;
    }

    /* check access condition */
    if (!check_access_permission(p_context_params, p_provider_params, GTA_ACCESS_TOKEN_USAGE_ADMIN, p_errinfo)) {
        return false;
    }

    return personality_add_attribute(p_context_params, p_provider_params, attrtype, attrname, p_attrvalue, true, p_errinfo);
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
    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct gta_sw_provider_context_params_t * p_context_params = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!check_context_params(p_context_params, p_errinfo)) {
        return false;
    }
    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /* check whether function is supported by profile */
    if (!supported_profiles[p_context_params->profile].pFunction->personality_attribute_functions_supported) {
        DEBUG_PRINT(("gta_sw_provider_gta_personality_add_attribute: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        return false;
    }

    enum pers_attr_type_t pers_attr_type = get_pers_attr_type_enum(attrtype);
    /* Trusted attribute types are not allowed */
    if ((PAT_INVALID == pers_attr_type) || (true == pers_attr_type_trusted[pers_attr_type])) {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        return false;
    }

    return personality_add_attribute(p_context_params, p_provider_params, attrtype, attrname, p_attrvalue, false, p_errinfo);
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
    if (!check_context_params(p_context_params, p_errinfo)) {
        goto err;
    }

    /* check whether function is supported by profile */
    if (!supported_profiles[p_context_params->profile].pFunction->personality_attribute_functions_supported) {
        DEBUG_PRINT(("gta_sw_provider_gta_personality_get_attribute: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
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
     * For the time being we don't restrict attribute types for this function.
     * Open question: Is it ok that each profiles supports this function?
     */
    if (p_attribute->data_size != p_attrvalue->write(p_attrvalue, p_attribute->p_data, p_attribute->data_size, p_errinfo)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    p_attrvalue->finish(p_attrvalue, 0, p_errinfo);
    ret = true;
err:
    return ret;
}

/*
 * Helper function for gta_sw_provider_gta_personality_remove_attribute
 * and gta_sw_provider_gta_personality_deactivate_attribute to find a
 * personality attribute by name with two additional conditions: it has to be
 * activated and a non default attribute.
 */
bool find_activated_nondefault_attribute(
    struct gta_sw_provider_context_params_t * p_context_params,
    struct personality_attribute_t ** p_attribute,
    const gta_personality_attribute_name_t attrname,
    gta_errinfo_t * p_errinfo
)
{
    /* Find attribute_list_item with requested name and check whether it is activated */
    *p_attribute = list_find((struct list_t *)(p_context_params->p_personality_item->p_personality_content->p_attribute_list),
                            attrname, attribute_list_item_cmp_name);
    if ((NULL == *p_attribute) || (!(*p_attribute)->activated)) {
        *p_errinfo = GTA_ERROR_ITEM_NOT_FOUND;
        return false;
    }

    /* Restricted attributes (default and internal) are ignored */
    if (pers_attr_type_restricted[(*p_attribute)->type]) {
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        *p_attribute = NULL;
        return false;
    }

    return true;
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
    if (!check_context_params(p_context_params, p_errinfo)) {
        goto err;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /* check whether function is supported by profile */
    if (!supported_profiles[p_context_params->profile].pFunction->personality_attribute_functions_supported) {
        DEBUG_PRINT(("gta_sw_provider_gta_personality_remove_attribute: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }

    if (!find_activated_nondefault_attribute(p_context_params, &p_attribute, attrname, p_errinfo)) {
        goto err;
    }

    /* check access condition */
    if (!check_access_permission(p_context_params, p_provider_params, GTA_ACCESS_TOKEN_USAGE_ADMIN, p_errinfo)) {
        goto err;
    }

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
    if (!check_context_params(p_context_params, p_errinfo)) {
        goto err;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /* check whether function is supported by profile */
    if (!supported_profiles[p_context_params->profile].pFunction->personality_attribute_functions_supported) {
        DEBUG_PRINT(("gta_sw_provider_gta_personality_deactivate_attribute: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }

    if (!find_activated_nondefault_attribute(p_context_params, &p_attribute, attrname, p_errinfo)) {
        goto err;
    }

    /* check access condition */
    if (!check_access_permission(p_context_params, p_provider_params, GTA_ACCESS_TOKEN_USAGE_ADMIN, p_errinfo)) {
        goto err;
    }

    p_attribute->activated = false;

    /* Serialize the new device state */
    if (!provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    ret = true;

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
    if (!check_context_params(p_context_params, p_errinfo)) {
        goto err;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /* check whether function is supported by profile */
    if (!supported_profiles[p_context_params->profile].pFunction->personality_attribute_functions_supported) {
        DEBUG_PRINT(("gta_sw_provider_gta_personality_activate_attribute: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
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

    /* check access condition */
    if (!check_access_permission(p_context_params, p_provider_params, GTA_ACCESS_TOKEN_USAGE_ADMIN, p_errinfo)) {
        goto err;
    }

    p_attribute->activated = true;

    /* Serialize the new device state */
    if (!provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    ret = true;

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
        attribute_type->write(attribute_type, "", 1, &errinfo);
        attribute_type->finish(attribute_type, 0, &errinfo);
        attribute_name->write(attribute_name, p_personality_attribute->p_name, strnlen(p_personality_attribute->p_name, MAXLEN_PERSONALITY_ATTRIBUTE_NAME), &errinfo);
        attribute_name->write(attribute_name, "", 1, &errinfo);
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

GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_seal_data,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * data,
    gtaio_ostream_t * protected_data,
    gta_errinfo_t * p_errinfo
    ))
{
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct gta_sw_provider_params_t * p_provider_params = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!check_context_params(p_context_params, p_errinfo)) {
        return false;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /* check whether function is supported by profile */
    if (NULL == supported_profiles[p_context_params->profile].pFunction->seal_data) {
        DEBUG_PRINT(("gta_sw_provider_gta_seal_data: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        return false;
    }

    /* check access condition */
    if (!check_access_permission(p_context_params, p_provider_params, GTA_ACCESS_TOKEN_USAGE_USE, p_errinfo)) {
        return false;
    }

    /* call profile specific implementation */
    return supported_profiles[p_context_params->profile].pFunction->seal_data(p_context_params, data, protected_data, p_errinfo);
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_unseal_data,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * protected_data,
    gtaio_ostream_t * data,
    gta_errinfo_t * p_errinfo
    ))
{
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct gta_sw_provider_params_t * p_provider_params = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!check_context_params(p_context_params, p_errinfo)) {
        return false;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /* check whether function is supported by profile */
    if (NULL == supported_profiles[p_context_params->profile].pFunction->unseal_data) {
        DEBUG_PRINT(("gta_sw_provider_gta_unseal_data: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        return false;
    }

    /* check access condition */
    if (!check_access_permission(p_context_params, p_provider_params, GTA_ACCESS_TOKEN_USAGE_USE, p_errinfo)) {
        return false;
    }

    /* call profile specific implementation */
    return supported_profiles[p_context_params->profile].pFunction->unseal_data(p_context_params, protected_data, data, p_errinfo);
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_verify,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * claim,
    gta_errinfo_t * p_errinfo
    ))
{
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct gta_sw_provider_params_t * p_provider_params = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!check_context_params(p_context_params, p_errinfo)) {
        return false;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /* check whether function is supported by profile */
    if (NULL == supported_profiles[p_context_params->profile].pFunction->verify) {
        DEBUG_PRINT(("gta_sw_provider_gta_verify: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        return false;
    }

    /* check access condition */
    if (!check_access_permission(p_context_params, p_provider_params, GTA_ACCESS_TOKEN_USAGE_USE, p_errinfo)) {
        return false;
    }

    /* call profile specific implementation */
    return supported_profiles[p_context_params->profile].pFunction->verify(p_context_params, claim, p_errinfo);
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_authenticate_data_detached,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * data,
    gtaio_ostream_t * seal,
    gta_errinfo_t * p_errinfo
    ))
{
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct gta_sw_provider_params_t * p_provider_params = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!check_context_params(p_context_params, p_errinfo)) {
        return false;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /* check whether function is supported by profile */
    if (NULL == supported_profiles[p_context_params->profile].pFunction->authenticate_data_detached) {
        DEBUG_PRINT(("gta_sw_provider_gta_authenticate_data_detached: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        return false;
    }

    /* check access condition */
    if (!check_access_permission(p_context_params, p_provider_params, GTA_ACCESS_TOKEN_USAGE_USE, p_errinfo)) {
        return false;
    }

    /* call profile specific implementation */
    return supported_profiles[p_context_params->profile].pFunction->authenticate_data_detached(p_context_params, data, seal, p_errinfo);
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
