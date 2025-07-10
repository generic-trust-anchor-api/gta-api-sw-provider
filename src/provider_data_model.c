/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2024-2025, Siemens AG
 **********************************************************************/

#include <gta_api/gta_api.h>
#include <gta_api/util/gta_list.h>
#include "provider_data_model.h"
#include "gta_debug.h"

/* free an Attribute of a Personality */
bool personality_attribute_list_item_free(gta_context_handle_t h_ctx,
                                          struct personality_attribute_t * p_attribute_item,
                                          gta_errinfo_t * p_errinfo
)
{
    if (NULL != p_attribute_item) {
        if (NULL != p_attribute_item->p_name) {
            gta_secmem_free(h_ctx, p_attribute_item->p_name, p_errinfo);
        }
        if (NULL != p_attribute_item->p_data) {
            gta_secmem_free(h_ctx, p_attribute_item->p_data, p_errinfo);
        }
        gta_secmem_free(h_ctx, p_attribute_item, p_errinfo);
    }

    return true;
}


/* free the list of Attributes of a Personality */
bool personality_attribute_list_destroy(gta_context_handle_t h_ctx,
                                        struct personality_attribute_t * p_attribute_list_head,
                                        gta_errinfo_t * p_errinfo
)
{
    struct personality_attribute_t * p_attribute_item = NULL;

    while (NULL != (p_attribute_item = list_remove_front((struct list_t **)(&p_attribute_list_head))))
    {
        personality_attribute_list_item_free(h_ctx, p_attribute_item, p_errinfo);
    }

    return true;
}


/* free an Auth Info */
bool auth_info_list_item_free(gta_context_handle_t h_ctx,
                              struct auth_info_list_item_t * p_auth_info_item,
                              gta_errinfo_t * p_errinfo
)
{
    if (NULL != p_auth_info_item) {
        if (NULL != p_auth_info_item->derivation_profile_name) {
            gta_secmem_free(h_ctx, p_auth_info_item->derivation_profile_name, p_errinfo);
        }
        gta_secmem_free(h_ctx, p_auth_info_item, p_errinfo);
    }

    return true;
}


/* free the list of Auth Info */
bool auth_info_list_destroy(gta_context_handle_t h_ctx,
                            struct auth_info_list_item_t * p_auth_info_list_head,
                            gta_errinfo_t * p_errinfo
)
{
    struct auth_info_list_item_t * p_auth_info_item = NULL;

    while (NULL != (p_auth_info_item = list_remove_front((struct list_t **)(&p_auth_info_list_head))))
    {
        auth_info_list_item_free(h_ctx, p_auth_info_item, p_errinfo);
    }

    return true;
}

/* free personality content */
bool personality_content_free(gta_context_handle_t h_ctx,
                              struct personality_t * p_personality_content,
                              gta_errinfo_t * p_errinfo
)
{
    if (NULL != p_personality_content) {
        /* free personality_t (personality content) */
        personality_attribute_list_destroy(h_ctx, p_personality_content->p_attribute_list, p_errinfo);
        auth_info_list_destroy(h_ctx, p_personality_content->p_auth_admin_info_list, p_errinfo);
        auth_info_list_destroy(h_ctx, p_personality_content->p_auth_use_info_list, p_errinfo);

        if (NULL != p_personality_content->secret_data) {
            gta_secmem_free(h_ctx, p_personality_content->secret_data, p_errinfo);
        }
        gta_secmem_free(h_ctx, p_personality_content, p_errinfo);
    }

    return true;
}

/* free a Personality */
bool personality_name_list_item_free(gta_context_handle_t h_ctx,
                                     struct personality_name_list_item_t * p_personality_name_item,
                                     gta_errinfo_t * p_errinfo
)
{
    if (NULL != p_personality_name_item) {
        /* free personality_t (personality content) */
        personality_content_free(h_ctx, p_personality_name_item->p_personality_content, p_errinfo);

        if (NULL != p_personality_name_item->personality_name) {
            gta_secmem_free(h_ctx, p_personality_name_item->personality_name, p_errinfo);
        }
        if (NULL != p_personality_name_item->application_name) {
            gta_secmem_free(h_ctx, p_personality_name_item->application_name, p_errinfo);
        }
        p_personality_name_item->p_identifier_list_item = NULL;

        gta_secmem_free(h_ctx, p_personality_name_item, p_errinfo);
    }

    return true;
}

/* free the list of Personalities */
bool personality_name_list_destroy(gta_context_handle_t h_ctx,
                                   struct personality_name_list_item_t * p_personality_name_list_head,
                                   gta_errinfo_t * p_errinfo
)
{
    struct personality_name_list_item_t * p_personality_name_list_item = NULL;

    while (NULL != (p_personality_name_list_item = list_remove_front((struct list_t **)(&p_personality_name_list_head))))
    {
        personality_name_list_item_free(h_ctx, p_personality_name_list_item, p_errinfo);
    }

    return true;
}

/* free an Identifier */
bool identifier_list_item_free(gta_context_handle_t h_ctx,
                               struct identifier_list_item_t * p_identifier_item,
                               gta_errinfo_t * p_errinfo
)
{
    if (NULL != p_identifier_item) {
        if (NULL != p_identifier_item->name) {
            gta_secmem_free(h_ctx, p_identifier_item->name, p_errinfo);
        }
        if (NULL != p_identifier_item->type) {
            /* Explicit cast to get rid of the const here */
            gta_secmem_free(h_ctx, (char *)p_identifier_item->type, p_errinfo);
        }
        gta_secmem_free(h_ctx, p_identifier_item, p_errinfo);
    }

    return true;
}

/* free the list of Identifiers */
bool identifier_list_destroy(gta_context_handle_t h_ctx,
                             struct identifier_list_item_t * p_identifier_list_head,
                             gta_errinfo_t * p_errinfo
)
{
    struct identifier_list_item_t * p_identifier_list_item = NULL;

    while (NULL != (p_identifier_list_item = list_remove_front((struct list_t **)(&p_identifier_list_head))))
    {
        identifier_list_item_free(h_ctx, p_identifier_list_item, p_errinfo);
    }

    return true;
}

/* free a Device State */
bool devicestate_stack_list_item_free(gta_context_handle_t h_ctx,
                                      struct devicestate_stack_item_t * p_devicestate_stack_item,
                                      gta_errinfo_t * p_errinfo
)
{
    if (NULL != p_devicestate_stack_item) {
        auth_info_list_destroy(h_ctx, p_devicestate_stack_item->p_auth_recede_info_list, p_errinfo);
        personality_name_list_destroy(h_ctx, p_devicestate_stack_item->p_personality_name_list, p_errinfo);
        identifier_list_destroy(h_ctx, p_devicestate_stack_item->p_identifier_list, p_errinfo);
        gta_secmem_free(h_ctx, p_devicestate_stack_item, p_errinfo);
    }

    return true;
}

/* free the list of Device States */
bool devicestate_stack_list_destroy(gta_context_handle_t h_ctx,
                                    struct devicestate_stack_item_t * p_devicestate_stack_head,
                                    gta_errinfo_t * p_errinfo
)
{
    struct devicestate_stack_item_t * p_devicestate_stack_item = NULL;

    while (NULL != (p_devicestate_stack_item = list_remove_front((struct list_t **)(&p_devicestate_stack_head))))
    {
        devicestate_stack_list_item_free(h_ctx, p_devicestate_stack_item, p_errinfo);
    }

    return true;
}
