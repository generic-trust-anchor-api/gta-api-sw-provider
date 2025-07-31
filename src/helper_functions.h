/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#ifndef HELPER_FUNCTIONS_H
#define HELPER_FUNCTIONS_H

#include <gta_api/gta_api.h>
#include "gta_sw_provider.h"
#include "provider_data_model.h"

#define NUM_PERSONALITY_ATTRIBUTE_TYPE 9

/* attribute related defines */
#define PERS_ATTR_NAME_IDENTIFIER       "ch.iec.30168.identifier_value"
#define PERS_ATTR_NAME_FINGERPRINT      "ch.iec.30168.fingerprint"

extern char pers_attr_type_strings[NUM_PERSONALITY_ATTRIBUTE_TYPE][MAXLEN_PERSONALITY_ATTRIBUTE_TYPE];
extern bool pers_attr_type_trusted[NUM_PERSONALITY_ATTRIBUTE_TYPE];
extern bool pers_attr_type_restricted[NUM_PERSONALITY_ATTRIBUTE_TYPE];

/*
 * Helper function to get enum value of personality attribute type string. In
 * case the string is not found, 0 (PAT_INVALID) is returned.
 */
enum pers_attr_type_t get_pers_attr_type_enum(const char * attrtype);

void gta_sw_provider_free_params(void * p_params);

/* used with list_find() to find a identifier list item by the identifier name */
bool identifier_list_item_cmp_name(void * p_list_item, void * p_item_crit);

/* used with list_find() to find a personality list item by the personality name */
bool personality_list_item_cmp_name(void * p_list_item, void * p_item_crit);

/* used with list_find() to find an attribute list item by the attribute name */
bool attribute_list_item_cmp_name(void * p_list_item, void * p_item_crit);

/*
 * Helper function to check whether all provider params are valid.
 * - returns true, if provider params are valid
 * - returns false, if provider params are NULL or device state stack is NULL
 */
bool check_provider_params(const struct gta_sw_provider_params_t * p_provider_params, gta_errinfo_t * p_errinfo);

/*
 * Helper function to check whether all context params are valid.
 * - returns true, if context params are valid (personality is available and activated)
 * - returns false, if context params are NULL or personality is missing (e.g.,
 *   because it has been removed) or personality is deactivated
 */
bool check_context_params(const struct gta_sw_provider_context_params_t * p_context_params, gta_errinfo_t * p_errinfo);

/* Helper function to get the fingerprint of a personality specified by name */
bool get_personality_fingerprint(
    struct personality_name_list_item_t * p_personality_name_list,
    const gta_personality_name_t personality_name,
    gta_personality_fingerprint_t * target_personality_fingerprint,
    gta_errinfo_t * p_errinfo
);

bool find_access_token(void *p_item, void *p_item_crit);

bool find_matching_access_policy(void *p_item, void *p_item_crit);

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
);

/*
 * Helper function the generate an access token based on p_auth_token_list_item.
 * The caller is responsible to hand over a valid pointer to
 * p_auth_token_list_item.
 */
bool generate_access_token (struct provider_instance_auth_token_t * p_auth_token_list_item);

/* Helper function to create a new device state. Serialization is done by caller */
bool create_new_devicestate(struct gta_sw_provider_params_t * p_provider_params, gta_errinfo_t * p_errinfo);

/*
 * Helper routine that performs the copy operation of authentication information to
 * the access policy data structure. Memory allocation and error checks are performed.
 */
bool policy_copy_helper(gta_context_handle_t h_ctx,
                            gta_access_policy_handle_t h_auth,
                            struct auth_info_list_item_t ** p_auth_info_list,
                            bool b_recede_policy,
                            gta_errinfo_t * p_errinfo
);

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
);

#endif //HELPER_FUNCTIONS_H
