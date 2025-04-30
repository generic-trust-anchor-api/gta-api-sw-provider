/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2024-2025, Siemens AG
 **********************************************************************/

#include <gta_api/gta_api.h>

#ifndef PROVIDER_DATA_MODEL_H
#define PROVIDER_DATA_MODEL_H

#define IDENTIFIER_TYPE_MAXLEN 160
#define IDENTIFIER_VALUE_MAXLEN 160
#define PERS_FINGERPRINT_LEN 64
#define MAXLEN_PERSONALITY_ATTRIBUTE_TYPE 160
#define MAXLEN_PERSONALITY_ATTRIBUTE_NAME 160
#define MAXLEN_PERSONALITY_ATTRIBUTE_VALUE 2000
#define MAXLEN_APPLICATION_NAME 160

/* internal representation of a device state */
struct devicestate_stack_item_t {
    struct devicestate_stack_item_t * p_next;

    struct auth_info_list_item_t * p_auth_recede_info_list;
    uint8_t owner_lock_count;

    /* List of identifiers and personalities related to this device state. */
    struct identifier_list_item_t * p_identifier_list;
    struct personality_name_list_item_t * p_personality_name_list;
};

/* single element of a linked list used to track personalities */
struct personality_name_list_item_t {
    struct personality_name_list_item_t * p_next;

    gta_personality_name_t personality_name;
    gta_application_name_t application_name;
    bool activated;
    struct personality_t * p_personality_content;
    struct identifier_list_item_t * p_identifier_list_item;

    /*
     * The `refcount` is a special variable, as it is not persisted and only
     * needed during runtime. It is used to track the number of opened GTA API
     * contexts referring to the personality. In case the personality is deleted
     * either by gta_personality_remove or gta_devicestate_recede the memory for
     * the corresponding personality_name_list_item_t is freed after the last
     * context referring to the personality is closed and the refcount becomes
     * zero.
     */
    size_t refcount;
};

/* single element of a linked list used for identifier management */
struct identifier_list_item_t {
    struct identifier_list_item_t * p_next;

    gta_identifier_type_t type;
    gta_identifier_value_t name;
};

/* internal representation of an attribute associated with a personality */
struct personality_attribute_t {
    struct personality_attribute_t * p_next;

    /*
     * store personality attribute type as unsigned integer
     * (enum pers_attr_type_t)
     */
    uint32_t type;

    char * p_name;
    bool activated;
    bool trusted;

    /* Here the attribute is stored as a byte array */
    size_t data_size;
    char * p_data;
};

typedef enum {
    /* DER encoded asymmetric key pair eg. the output of i2d_PrivateKey() */
    SECRET_TYPE_DER,
    /* Random bytes to be used eg. for Symmetric encryption, HMAC, ... */
    SECRET_TYPE_RAW_BYTES,
    /* Human readable characters (external input) */
    SECRET_TYPE_PASSCODE,
    /* Temporary, Dilithium2 raw key as raw bytes */
    SECRET_TYPE_DILITHIUM2,
} personality_secret_type_t;

/* internal representation of a personality */
struct personality_t {
    struct auth_info_list_item_t * p_auth_use_info_list;
    struct auth_info_list_item_t * p_auth_admin_info_list;
    struct personality_attribute_t * p_attribute_list;

    personality_secret_type_t secret_type;

    /* provider specific – TBD */
    size_t secret_data_size;
    unsigned char* secret_data;
};

/* authentication information */
struct auth_info_list_item_t {
    struct auth_info_list_item_t * p_next;

    gta_access_descriptor_type_t type;

    /* These two attributes are only checked for personality derived tokens */
    gta_personality_fingerprint_t binding_personality_fingerprint;
    gta_profile_name_t derivation_profile_name;
};

/* free an Attribute of a Personality */
bool personality_attribute_list_item_free(gta_context_handle_t h_ctx,
                                          struct personality_attribute_t * p_attribute_item,
                                          gta_errinfo_t * p_errinfo
);


/* free the list of Attributes of a Personality */
bool personality_attribute_list_destroy(gta_context_handle_t h_ctx,
                                        struct personality_attribute_t * p_attribute_list_head,
                                        gta_errinfo_t * p_errinfo
);

/* free personality content */
bool personality_content_free(gta_context_handle_t h_ctx,
                              struct personality_t * p_personality_content,
                              gta_errinfo_t * p_errinfo
);

/* free a Personality */
bool personality_name_list_item_free(gta_context_handle_t h_ctx,
                                     struct personality_name_list_item_t * p_personality_name_item,
                                     gta_errinfo_t * p_errinfo
);

/* free the list of Personalities */
bool personality_name_list_destroy(gta_context_handle_t h_ctx,
                                   struct personality_name_list_item_t * p_personality_name_list_head,
                                   gta_errinfo_t * p_errinfo
);

/* free an Identifier */
bool identifier_list_item_free(gta_context_handle_t h_ctx,
                               struct identifier_list_item_t * p_identifier_item,
                               gta_errinfo_t * p_errinfo
);

/* free the list of Identifiers */
bool identifier_list_destroy(gta_context_handle_t h_ctx,
                             struct identifier_list_item_t * p_identifier_list_head,
                             gta_errinfo_t * p_errinfo
);
/* free a Device State */
bool devicestate_stack_list_item_free(gta_context_handle_t h_ctx,
                                      struct devicestate_stack_item_t * p_devicestate_stack_item,
                                      gta_errinfo_t * p_errinfo
);

/* free the list of Device States */
bool devicestate_stack_list_destroy(gta_context_handle_t h_ctx,
                                    struct devicestate_stack_item_t * p_devicestate_stack_head,
                                    gta_errinfo_t * p_errinfo
);

/* free the list of auth info */
bool auth_info_list_destroy(gta_context_handle_t h_ctx,
                            struct auth_info_list_item_t * p_auth_info_list_head,
                            gta_errinfo_t * p_errinfo
);

#endif /* PROVIDER_DATA_MODEL_H */

