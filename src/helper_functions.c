/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#include "helper_functions.h"

#define NUM_PERSONALITY_ATTRIBUTE_TYPE 9
char pers_attr_type_strings[NUM_PERSONALITY_ATTRIBUTE_TYPE][MAXLEN_PERSONALITY_ATTRIBUTE_TYPE] = {
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

bool pers_attr_type_trusted[NUM_PERSONALITY_ATTRIBUTE_TYPE] = {
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
bool pers_attr_type_restricted[NUM_PERSONALITY_ATTRIBUTE_TYPE] = {
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


/*
 * Helper function to get enum value of personality attribute type string. In
 * case the string is not found, 0 (PAT_INVALID) is returned.
 */
enum pers_attr_type_t get_pers_attr_type_enum(const char * attrtype)
{
    for (uint32_t i=0; i < NUM_PERSONALITY_ATTRIBUTE_TYPE; ++i) {
        if (0 == strcmp(attrtype, pers_attr_type_strings[i])) {
            return i;
        }
    }
    return PAT_INVALID;
}

void gta_sw_provider_free_params(void * p_params)
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
bool check_provider_params
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
bool check_context_params
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
bool get_personality_fingerprint(
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

/*
 * Helper function to check whether a valid access token is available and the
 * policy allows access to the personality. Must only be used for:
 * - GTA_ACCESS_TOKEN_USAGE_USE
 * - GTA_ACCESS_TOKEN_USAGE_ADMIN
 */
bool check_access_permission (
    struct gta_sw_provider_context_params_t * p_context_params,
    struct gta_sw_provider_params_t * p_provider_params,
    gta_access_token_usage_t usage,
    gta_errinfo_t * p_errinfo
)
{
    struct provider_instance_auth_token_t * p_auth_token = NULL;
    struct auth_info_list_item_t * p_auth_x_info_list = NULL;

    if (GTA_ACCESS_TOKEN_USAGE_USE == usage ) {
        p_auth_x_info_list = p_context_params->p_personality_item->p_personality_content->p_auth_use_info_list;
    }
    else if (GTA_ACCESS_TOKEN_USAGE_ADMIN == usage) {
        p_auth_x_info_list = p_context_params->p_personality_item->p_personality_content->p_auth_admin_info_list;
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

/*
 * Helper function the generate an access token based on p_auth_token_list_item.
 * The caller is responsible to hand over a valid pointer to
 * p_auth_token_list_item.
 */
bool generate_access_token (struct provider_instance_auth_token_t * p_auth_token_list_item)
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

/* Helper function to create a new device state. Serialization is done by caller */
bool create_new_devicestate(struct gta_sw_provider_params_t * p_provider_params, gta_errinfo_t * p_errinfo)
{
    struct devicestate_stack_item_t * p_devicestate_stack_item = NULL;

    p_devicestate_stack_item = gta_secmem_calloc(p_provider_params->h_ctx, 1, sizeof(struct devicestate_stack_item_t), p_errinfo);
    if (NULL == p_devicestate_stack_item) {
        *p_errinfo = GTA_ERROR_MEMORY;
        return false;
    }

    p_devicestate_stack_item->p_next = NULL;
    p_devicestate_stack_item->p_auth_recede_info_list = NULL;
    p_devicestate_stack_item->owner_lock_count = 0;
    p_devicestate_stack_item->p_identifier_list = NULL;
    p_devicestate_stack_item->p_personality_name_list = NULL;
    list_append_front((struct list_t **)(&(p_provider_params->p_devicestate_stack)), p_devicestate_stack_item);
    return true;
}


/*
 * Helper routine that performs the copy operation of authentication information to
 * the access policy data structure. Memory allocation and error checks are performed.
 */
bool policy_copy_helper(gta_context_handle_t h_ctx,
                            gta_access_policy_handle_t h_auth,
                            struct auth_info_list_item_t ** p_auth_info_list,
                            bool b_recede_policy,
                            gta_errinfo_t * p_errinfo
) {
    gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;
    gta_errinfo_t errinfo_tmp = 0;
    gta_access_descriptor_handle_t h_access_descriptor = GTA_HANDLE_INVALID;
    struct auth_info_list_item_t * p_auth_info_list_current = NULL;
    gta_access_descriptor_type_t access_descriptor_type;
    const char * p_attr = NULL;
    size_t attr_len;

    /* Enumerate access policies */
    while (gta_access_policy_enumerate(h_auth, &h_enum, &h_access_descriptor, &errinfo_tmp)) {

        /* Try to get access descriptor type, proceed when successful */
        if (!gta_access_policy_get_access_descriptor_type(h_auth, h_access_descriptor, &access_descriptor_type, p_errinfo)) {
            goto internal_err;
        }
        /* Now we allocate memory for the new list element and append it to the list */
        if (NULL == (p_auth_info_list_current = gta_secmem_calloc(h_ctx, 1, sizeof(struct auth_info_list_item_t), p_errinfo))) {
            *p_errinfo = GTA_ERROR_MEMORY;
            goto err;
        }
        p_auth_info_list_current->p_next = NULL;
        p_auth_info_list_current->type = access_descriptor_type;

        switch (access_descriptor_type) {
            case GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL:
            case GTA_ACCESS_DESCRIPTOR_TYPE_BASIC_TOKEN:
                if (b_recede_policy) {
                    /* initial and basic not allowed for recede */
                    *p_errinfo = GTA_ERROR_ACCESS_POLICY;
                    goto err;
                }
                /* all ok, nothing more to do */
                break;
            case GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN:
                if (!b_recede_policy) {
                    /* physical presence only allowed for recede */
                    *p_errinfo = GTA_ERROR_ACCESS_POLICY;
                    goto err;
                }
                /* all ok, nothing more to do */
                break;
            case GTA_ACCESS_DESCRIPTOR_TYPE_PERS_DERIVED_TOKEN:
                /* Copy fingerprint */
                if (!gta_access_policy_get_access_descriptor_attribute(h_access_descriptor, GTA_ACCESS_DESCRIPTOR_ATTR_PERS_FINGERPRINT, &p_attr, &attr_len, p_errinfo )) {
                    goto internal_err;
                }
                if (PERS_FINGERPRINT_LEN != attr_len) {
                    goto internal_err;
                }
                memcpy( p_auth_info_list_current->binding_personality_fingerprint, p_attr, attr_len );

                /* Copy profile name */
                if (!gta_access_policy_get_access_descriptor_attribute(h_access_descriptor, GTA_ACCESS_DESCRIPTOR_ATTR_PROFILE_NAME, &p_attr, &attr_len, p_errinfo )) {
                    goto internal_err;
                }
                /* NOTE: attr_len does not include the string termination! */
                if (NULL == (p_auth_info_list_current->derivation_profile_name = gta_secmem_calloc(h_ctx, 1, attr_len + 1, p_errinfo))){
                    *p_errinfo = GTA_ERROR_MEMORY;
                    goto err;
                }
                memcpy(p_auth_info_list_current->derivation_profile_name, p_attr, attr_len);
                p_auth_info_list_current->derivation_profile_name[attr_len] = '\0';
                break;
        }
        list_append((struct list_t **)p_auth_info_list, p_auth_info_list_current);
    }
    return true;

internal_err:
    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
err:
    gta_secmem_free(h_ctx, p_auth_info_list_current, &errinfo_tmp);
    return false;
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