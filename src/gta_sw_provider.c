/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2024-2025, Siemens AG
 **********************************************************************/

#include "gta_sw_provider.h"
#include "helper_functions.h"
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
extern const struct profile_function_list_t fl_prof_org_opcfoundation_ecc_nistp256;

struct profile_list_t {
    const char name[MAXLEN_PROFILE];
    const struct profile_function_list_t * pFunction;
};

/* Supported profiles */
#ifdef ENABLE_PQC
#define NUM_PROFILES 12
#else
#define NUM_PROFILES 11
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
    [PROF_ORG_OPCFOUNDATION_ECC_NISTP256] = {"org.opcfoundation.ECC-nistP256", &fl_prof_org_opcfoundation_ecc_nistp256},
};

/*
 * Helper function to get enum value of a profile string. In case the string is
 * not found, 0 (PROF_INVALID) is returned.
 */
enum profile_t get_profile_enum(const char * profile)
{
    for (uint32_t i=0; i < NUM_PROFILES; ++i) {
        if (0 == strcmp(profile, supported_profiles[i].name)) {
            return i;
        }
    }
    return PROF_INVALID;
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
        p_provider_params->p_devicestate_stack->p_auth_recede_info_list = NULL;
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

    /* Increase reference count in personality if not max already */
    if (SIZE_MAX == p_personality_item->refcount) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    p_personality_item->refcount++;

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
    struct gta_sw_provider_params_t * p_provider_params = NULL;
    gta_errinfo_t errinfo_tmp = 0;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    /* We don't use the helper function here, and do checks manually */
    if (( NULL == p_context_params) || (NULL == p_context_params->p_personality_item)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /*
     * Memory allocated with gta_secmem will be automatically freed. We only
     * need to call profile specific code in case there is something special
     * to do.
     */
    if (NULL != supported_profiles[p_context_params->profile].pFunction->context_close) {
        /* Ignore the return code */
        supported_profiles[p_context_params->profile].pFunction->context_close(p_context_params, p_errinfo);
    }

    /* Decrease reference count in personality */
    p_context_params->p_personality_item->refcount--;

    /* In case refcount == 0 and personality content == NULL we free the memory */
    if ((NULL == p_context_params->p_personality_item->p_personality_content)
        && (0 == p_context_params->p_personality_item->refcount)) {

        personality_name_list_item_free(p_provider_params->h_ctx, p_context_params->p_personality_item, &errinfo_tmp);
    }

    return true;
}

GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_devicestate_transition,
(
    gta_instance_handle_t h_inst,
    gta_access_policy_handle_t h_auth_recede,
    size_t owner_lock_count,
    gta_errinfo_t * p_errinfo
))
{
    struct gta_sw_provider_params_t * p_provider_params = NULL;
    gta_errinfo_t errinfo_tmp = GTA_ERROR_INTERNAL_ERROR;

    p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /* Check if we are already in a transition state */
    if (NULL != p_provider_params->p_devicestate_stack->p_auth_recede_info_list) {
        /* return code? */
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        return false;
    }

    /* Implementation specific boundary for owner_lock_count */
    if (UINT8_MAX <= owner_lock_count) {
        *p_errinfo = GTA_ERROR_ACCESS_POLICY;
        goto err;
    }

    /* Assign recede policy to the device state */
    if (!policy_copy_helper(p_provider_params->h_ctx, h_auth_recede, &(p_provider_params->p_devicestate_stack->p_auth_recede_info_list), true, p_errinfo)) {
        goto err;
    }

    /* Check if h_auth_recede contains physical presence */
    struct auth_info_list_item_t * auth_info_list_item = p_provider_params->p_devicestate_stack->p_auth_recede_info_list;
    bool b_auth_recede_with_physical_presence = false;
    while (NULL != auth_info_list_item) {
        if (GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN == auth_info_list_item->type) {
            b_auth_recede_with_physical_presence = true;
            break;
        }
        auth_info_list_item = auth_info_list_item->p_next;
    }

    /* Check and assign owner lock count */
    /* Check if we are not in the first owner state */
    if (NULL != p_provider_params->p_devicestate_stack->p_next) {
        /*
         * If auth_recede contains physical presence condition, the new owner
         * lock count is allowed to be <= the previous one. Otherwise, it must
         * be < the previous one.
         */
        if (b_auth_recede_with_physical_presence) {
            if (owner_lock_count > (p_provider_params->p_devicestate_stack->p_next)->owner_lock_count)  {
                *p_errinfo = GTA_ERROR_ACCESS_POLICY;
                goto err;
            }
        }
        else {
            if(owner_lock_count >= (p_provider_params->p_devicestate_stack->p_next)->owner_lock_count) {
                *p_errinfo = GTA_ERROR_ACCESS_POLICY;
                goto err;
            }
        }
    }
    /* Range check already done */
    p_provider_params->p_devicestate_stack->owner_lock_count = (uint8_t)owner_lock_count;

    /* Serialize */
    if (!provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack)) {
        goto err;
    }
    return true;

err:
    /* Cleanup recede policy in p_devicestate_stack_item */
    auth_info_list_destroy(p_provider_params->h_ctx, p_provider_params->p_devicestate_stack->p_auth_recede_info_list, &errinfo_tmp);
    p_provider_params->p_devicestate_stack->p_auth_recede_info_list = NULL;
    p_provider_params->p_devicestate_stack->owner_lock_count = 0;
    return false;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_devicestate_recede,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t access_token,
    gta_errinfo_t * p_errinfo
))
{
    bool b_ret = false;
    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct devicestate_stack_item_t * p_devicestate_stack_item = NULL;
    struct personality_name_list_item_t * p_pers_list_item = NULL;
    gta_errinfo_t errinfo_tmp = GTA_ERROR_INTERNAL_ERROR;

    p_provider_params = gta_provider_get_params(h_inst, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        return false;
    }

    /* Check access token in case we are in a transition state */
    if (NULL != p_provider_params->p_devicestate_stack->p_auth_recede_info_list) {
        if (NULL == access_token) {
            *p_errinfo = GTA_ERROR_ACCESS;
            return false;
        }
        /* Find the auth token for the access token */
        struct provider_instance_auth_token_t * p_auth_token = NULL;
        p_auth_token = list_find((struct list_t *)p_provider_params->p_auth_token_list, access_token, find_access_token);
        if ((NULL == p_auth_token)
            /* Only physical presence and personality derived access tokens are allowed */
            || ((GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN != p_auth_token->type) && (GTA_ACCESS_DESCRIPTOR_TYPE_PERS_DERIVED_TOKEN != p_auth_token->type))
            /* Check if usage matches */
            || (GTA_ACCESS_TOKEN_USAGE_RECEDE != p_auth_token->usage)
            /* Now we look for a policy which can be fulfilled by this token */
            || (NULL == list_find((struct list_t *)&(p_provider_params->p_devicestate_stack->p_auth_recede_info_list), p_auth_token, find_matching_access_policy))) {

            *p_errinfo = GTA_ERROR_ACCESS;
            return false;
        }
    }

    /* Remove device state */
    p_devicestate_stack_item = list_remove_front((struct list_t **)(&(p_provider_params->p_devicestate_stack)));
    if (NULL == p_devicestate_stack_item) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }

    /*
     * Iterate over list of personalities in device state, free content for all
     * of them, but keep name list item for those with refcount != 0
     */
    p_pers_list_item = list_remove_front((struct list_t **)&(p_devicestate_stack_item->p_personality_name_list));
    while (NULL != p_pers_list_item) {
        if (0 == p_pers_list_item->refcount) {
            /* Free all */
            personality_name_list_item_free(p_provider_params->h_ctx, p_pers_list_item, &errinfo_tmp);
        }
        else {
            /* Free personality content */
            personality_content_free(p_provider_params->h_ctx, p_pers_list_item->p_personality_content, &errinfo_tmp);
            p_pers_list_item->p_personality_content = NULL;
        }

        /* Next item in list */
        p_pers_list_item = list_remove_front((struct list_t **)&(p_devicestate_stack_item->p_personality_name_list));
    }

    /* Free devicestate */
    devicestate_stack_list_item_free(p_provider_params->h_ctx, p_devicestate_stack_item, &errinfo_tmp);

    /* In case the first device state is removed, we need to create a new, empty one. */
    if ((NULL == p_provider_params->p_devicestate_stack)
        && (!create_new_devicestate(p_provider_params, p_errinfo))) {

        return false;
    }

    /* Serialize */
    b_ret = provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack);

    return b_ret;
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

    /* If we are in a transition state, we need to create a new device state */
    if ((NULL != p_provider_params->p_devicestate_stack->p_auth_recede_info_list)
        && (!create_new_devicestate(p_provider_params, p_errinfo))) {
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

    /* If we are in a transition state, we need to create a new device state */
    if ((NULL != p_provider_params->p_devicestate_stack->p_auth_recede_info_list)
        && (!create_new_devicestate(p_provider_params, p_errinfo))) {
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
    if (!policy_copy_helper(p_provider_params->h_ctx, h_auth_use, &(p_personality_name_list_item->p_personality_content->p_auth_use_info_list), false, p_errinfo)) {
        goto err;
    }

    if (!policy_copy_helper(p_provider_params->h_ctx, h_auth_admin, &(p_personality_name_list_item->p_personality_content->p_auth_admin_info_list), false, p_errinfo)) {
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
    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct gta_sw_provider_context_params_t * p_context_params = NULL;
    struct personality_name_list_item_t * p_personality_item = NULL;
    struct devicestate_stack_item_t * p_devicestate_stack_item = NULL;
    gta_errinfo_t errinfo_tmp = GTA_ERROR_INTERNAL_ERROR;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!check_context_params(p_context_params, p_errinfo)) {
        goto err;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /* check access condition */
    if (!check_access_permission(p_context_params, p_provider_params, GTA_ACCESS_TOKEN_USAGE_ADMIN, p_errinfo)) {
        goto err;
    }

    /* Remove the personality from device states personality list */
    p_devicestate_stack_item = p_provider_params->p_devicestate_stack;
    while (NULL != p_devicestate_stack_item) {
        /* Instead of searching by name, we could search by pointer... */
        p_personality_item = list_remove((struct list_t **)(&p_devicestate_stack_item->p_personality_name_list),
            p_context_params->p_personality_item->personality_name, personality_list_item_cmp_name);
        if (NULL == p_personality_item ) {
            p_devicestate_stack_item = p_devicestate_stack_item->p_next;
        } else {
            /* Personality found and unlinked from list. Free only the content as the refcount can never be zero */
            personality_content_free(p_provider_params->h_ctx, p_personality_item->p_personality_content, &errinfo_tmp);
            p_personality_item->p_personality_content = NULL;
            /* End the loop */
            p_devicestate_stack_item = NULL;
        }
    }

    /* Serialize the new device state */
    if (!provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    ret = true;
err:
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_deactivate,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;

    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct gta_sw_provider_context_params_t * p_context_params = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    if (!check_context_params(p_context_params, p_errinfo)) {
        goto err;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /* Check whether function is supported by profile */
    if (!supported_profiles[p_context_params->profile].pFunction->personality_activate_deactivate_supported) {
        DEBUG_PRINT(("gta_sw_provider_gta_personality_deactivate: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }

    /* Check access condition */
    if (!check_access_permission(p_context_params, p_provider_params, GTA_ACCESS_TOKEN_USAGE_ADMIN, p_errinfo)) {
        goto err;
    }

    p_context_params->p_personality_item->activated = false;

    /* Serialize the new device state */
    if (!provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    ret = true;

err:
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_sw_provider_gta_personality_activate,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;

    struct gta_sw_provider_params_t * p_provider_params = NULL;
    struct gta_sw_provider_context_params_t * p_context_params = NULL;

    p_context_params = gta_context_get_params(h_ctx, p_errinfo);
    /* We don't use the helper function here, but check the context params manually */
    if ((NULL == p_context_params) || (NULL == p_context_params->p_personality_item)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    else if (NULL == p_context_params->p_personality_item->p_personality_content) {
        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
        goto err;
    }

    p_provider_params = gta_context_get_provider_params(h_ctx, p_errinfo);
    if (!check_provider_params(p_provider_params, p_errinfo)) {
        goto err;
    }

    /* Check whether function is supported by profile */
    if (!supported_profiles[p_context_params->profile].pFunction->personality_activate_deactivate_supported) {
        DEBUG_PRINT(("gta_sw_provider_gta_personality_activate: Profile not supported\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
        goto err;
    }

    /* Check whether personality is already activated */
    if (p_context_params->p_personality_item->activated) {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        goto err;
    }

    /* Check access condition */
    if (!check_access_permission(p_context_params, p_provider_params, GTA_ACCESS_TOKEN_USAGE_ADMIN, p_errinfo)) {
        goto err;
    }

    p_context_params->p_personality_item->activated = true;

    /* Serialize the new device state */
    if (!provider_serialize(p_provider_params->p_serializ_path, p_provider_params->p_devicestate_stack)) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }
    ret = true;

err:
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
