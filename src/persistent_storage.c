/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2024-2025, Siemens AG
 **********************************************************************/

#include <stdbool.h>
#include <stdlib.h>

#include <gta_api/gta_api.h>
#include <gta_api/util/gta_list.h>
#include <gta_api/util/gta_memset.h>
#include "gta_sw_provider.h"

#include "gta_debug.h"

#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor.h>
#include <qcbor/qcbor_spiffy_decode.h>

#include <t_cose/t_cose_common.h>
#include "t_cose/t_cose_mac_compute.h"
#include "t_cose/t_cose_mac_validate.h"
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_encrypt_dec.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "provider_data_model.h"
#include "persistent_storage.h"
#include "key_management.h"

/* File names for serialization */
#define FILE_PERSONALITY "PERS_"
#define FILE_DEVICESTATES_STACK "DEVICESTATES_STACK"

/* Labels used in CBOR Map - Device State */
#define LABEL_DEVICE_STATE_LOCK "LockCount"
#define LABEL_IDENTIFIERS "Identifiers"
#define LABEL_PERSONALITIES "Personalities"

/* Labels used in CBOR Map - Identifier */
#define LABEL_IDENTIFIER_NAME "Name"
#define LABEL_IDENTIFIER_TYPE "Type"

/* Labels used in CBOR Map - Personality Name */
#define LABEL_PERSONALITY_NAME "Name"
#define LABEL_APPLICATION_NAME "Application"
#define LABEL_PERSONALITY_IDENTIFIER "Identifier"
#define LABEL_PERSONALITY_ACTIVATED "Activated"
#define LABEL_PERSONALITY_PROTECTION "Hash"

/* Labels used in CBOR Map - Personality Content */
#define LABEL_PERSONALITY_ATTRIBUTES "Attributes"
#define LABEL_PERSONALITY_TYPE "Type"
#define LABEL_PERSONALITY_CONTENT "Content"

/* Labels used in CBOR Map - Auth Info Lists */
#define LABEL_AUTH_USE_LIST "AuthUseList"
#define LABEL_AUTH_ADMIN_LIST "AuthAdminList"
#define LABEL_AUTH_ITEM_TYPE "AuthItemType"
#define LABEL_AUTH_PERS_FINGERPRINT "AuthPersFingerprint"
#define LABEL_AUTH_DERIVATION_PROFILE_NAME "AuthDerivationProfileName"

/* Labels used in CBOR Map - Attribute */
#define LABEL_ATTRIBUTE_NAME "AttributeName"
#define LABEL_ATTRIBUTE_DATA "AttributeData"
#define LABEL_ATTRIBUTE_TYPE "AttributeType"
#define LABEL_ATTRIBUTE_ACTIVATED "Activated"
#define LABEL_ATTRIBUTE_TRUSTED "Trusted"

#define ENCODED_DATA_LEN 8192
#define COSE_DATA_LEN 8192
#define TMP_STR_BUF_LEN 256
#define TMP_SIGN_BUF_LEN 64

#define DERIVATION_KEY_LEN_MIN 32
#define AES_256_KEY_LEN 32
#define HMAC_256_KEY_LEN 32
#define SHA256_SIZE 32

typedef enum {
    SE_FILE_PERSONALITY,
    SE_FILE_DEVICESTATES_STACK
} se_file_type;


static bool get_se_filename(
        se_file_type type,
        char * name,
        const char * directory,
        char filepath[FILENAME_MAX]
        )
{
    char *type_str;

    /*  @todo take care of character encoding (personality_name may
              contain characters which do not work for file names) */

    switch (type) {
        case SE_FILE_PERSONALITY:
            type_str = FILE_PERSONALITY;
            break;
        case SE_FILE_DEVICESTATES_STACK:
            type_str = FILE_DEVICESTATES_STACK;
            break;
        default:
            return false;
    }

    if (snprintf(filepath, FILENAME_MAX, "%s/%s%s",
                 directory, type_str, name) > (FILENAME_MAX - 1)) {
        return false;
    }

    return true;
}

bool serialized_file_exists(const char * se_dir)
{
    bool ret = false;

    /* File Name */
    char filename[FILENAME_MAX] = { 0 };
    if (get_se_filename(SE_FILE_DEVICESTATES_STACK, "", se_dir, filename)) {
        /* File IO */
        FILE * fp = NULL;
        if (NULL != (fp = fopen(filename, "rb"))) {
            ret = true;
            fclose(fp);
        }
    }
    return ret;
}


#define INFO_KEY_MAC "Key for Device State protection"
#define INFO_KEY_ENC "Key for Personality protection"

bool get_derived_key(unsigned char *derived_key, size_t derived_key_len, char *info, size_t info_len) {
    struct hw_unique_key_32 master_key;
    bool ret = false;

    /* any larger output can be provided by the derivation, when requested */
    if ((NULL == derived_key) || (DERIVATION_KEY_LEN_MIN > derived_key_len)) {
        goto err1;
    }

    if (!get_hw_unique_key_32(&master_key)) {
        goto err1;
    }

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[5];
    OSSL_PARAM *p = params;

    if  (NULL == ctx) {
        goto err;
    }

    *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA-256", 0);
    *p++ = OSSL_PARAM_construct_octet_string("key", (unsigned char *)master_key.data, sizeof(master_key.data));
    *p++ = OSSL_PARAM_construct_octet_string("info", info, info_len);
    *p = OSSL_PARAM_construct_end();

    /* this will FAIL if requested size not supported */
    if (EVP_KDF_derive(ctx, derived_key, derived_key_len, params) > 0) {
        ret = true; /* Success */
    }


err:
    /* TODO: clean master key */

    if (NULL != ctx) {
        EVP_KDF_CTX_free(ctx);
        ctx = NULL;
    }

    if (NULL != kdf) {
        EVP_KDF_free(kdf);
        kdf = NULL;
    }

err1:
    return ret;
}


/* used with list_find() to find an identifier list item by the identifier name */
static bool identifier_list_item_cmp_name(void * p_list_item, void * p_item_crit)
{
    struct identifier_list_item_t * p_identifier_list_item = p_list_item;
    gta_identifier_value_t identifier_value = p_item_crit;

    if (0 == strcmp(p_identifier_list_item->name, identifier_value)) {
        return true;
    }

    return false;
}


static void auth_info_list_serialize(QCBOREncodeContext * p_encode_ctx,
                              const struct auth_info_list_item_t * p_auth_list)
{
    const struct auth_info_list_item_t * p_auth_item = p_auth_list;
    while(NULL != p_auth_item) {
        QCBOREncode_OpenMap(p_encode_ctx);
        /* This map encodes auth_info_list_item_t */
        QCBOREncode_AddUInt64ToMap(p_encode_ctx, LABEL_AUTH_ITEM_TYPE, p_auth_item->type);

        if ( GTA_ACCESS_DESCRIPTOR_TYPE_PERS_DERIVED_TOKEN == p_auth_item->type) {
            /* This map encodes pers_derived inside of auth_info_list_item_t */
            /* It is only included in case ofpersonality derived tokens */
            UsefulBufC fingerprint_data;
            fingerprint_data.ptr = p_auth_item->binding_personality_fingerprint;
            fingerprint_data.len = PERS_FINGERPRINT_LEN;
            QCBOREncode_AddBytesToMap(p_encode_ctx, LABEL_AUTH_PERS_FINGERPRINT, fingerprint_data);
            QCBOREncode_AddSZStringToMap(p_encode_ctx, LABEL_AUTH_DERIVATION_PROFILE_NAME, p_auth_item->derivation_profile_name);
        }
        QCBOREncode_CloseMap(p_encode_ctx);
        p_auth_item = p_auth_item->p_next;
    }
}


static bool personality_content_serialize(
        const char * se_dir,
        struct personality_t * p_personality,
        gta_personality_name_t personality_name,
        UsefulBuf * hash
        )
{
    bool ret = false;

    /* CBOR related stuff */
    QCBOREncodeContext encode_ctx;
    UsefulBuf_MAKE_STACK_UB(encode_buffer, ENCODED_DATA_LEN);
    UsefulBufC encoded_data;
    QCBORError qcbor_result;

    /* COSE related stuff */
    Q_USEFUL_BUF_MAKE_STACK_UB(enc_cose_buffer, COSE_DATA_LEN);
    struct q_useful_buf_c enc_cose;
    enum t_cose_err_t t_cose_result;


    QCBOREncode_Init(&encode_ctx, encode_buffer);

    /* Map of a Personality */
    QCBOREncode_OpenMap(&encode_ctx);

    /* Serialize Personality Type */
    QCBOREncode_AddUInt64ToMap(&encode_ctx, LABEL_PERSONALITY_TYPE, p_personality->secret_type);

    /* Serialize Content of the Personality - currently a blob */
    UsefulBufC personality_content_data;
    personality_content_data.ptr = p_personality->secret_data;
    personality_content_data.len = p_personality->secret_data_size;
    QCBOREncode_AddBytesToMap(&encode_ctx, LABEL_PERSONALITY_CONTENT, personality_content_data);

    /* Serialize attributes associated with personality */
    QCBOREncode_OpenArrayInMap(&encode_ctx, LABEL_PERSONALITY_ATTRIBUTES);
    struct personality_attribute_t * p_attribute = p_personality->p_attribute_list;
    while(NULL != p_attribute) {
        QCBOREncode_OpenMap(&encode_ctx);
        QCBOREncode_AddSZStringToMap(&encode_ctx, LABEL_ATTRIBUTE_NAME, p_attribute->p_name);
        QCBOREncode_AddBoolToMap(&encode_ctx, LABEL_ATTRIBUTE_ACTIVATED, p_attribute->activated);
        QCBOREncode_AddBoolToMap(&encode_ctx, LABEL_ATTRIBUTE_TRUSTED, p_attribute->trusted);

        UsefulBufC attribute_data;
        attribute_data.ptr = p_attribute->p_data;
        attribute_data.len = p_attribute->data_size;
        QCBOREncode_AddBytesToMap(&encode_ctx, LABEL_ATTRIBUTE_DATA, attribute_data);
        QCBOREncode_AddUInt64ToMap(&encode_ctx, LABEL_ATTRIBUTE_TYPE, p_attribute->type);
        QCBOREncode_CloseMap(&encode_ctx);
        p_attribute = p_attribute->p_next;
    }
    QCBOREncode_CloseArray(&encode_ctx);

    /* Serialize user authentication list */
    QCBOREncode_OpenArrayInMap(&encode_ctx, LABEL_AUTH_USE_LIST);
    auth_info_list_serialize(&encode_ctx, p_personality->p_auth_use_info_list);
    QCBOREncode_CloseArray(&encode_ctx);

    /* Serialize admin authentication list */
    QCBOREncode_OpenArrayInMap(&encode_ctx, LABEL_AUTH_ADMIN_LIST);
    auth_info_list_serialize(&encode_ctx, p_personality->p_auth_admin_info_list);
    QCBOREncode_CloseArray(&encode_ctx);

    /* Close map containing a Personality */
    QCBOREncode_CloseMap(&encode_ctx);
    qcbor_result = QCBOREncode_Finish(&encode_ctx, &encoded_data);
    if (QCBOR_SUCCESS != qcbor_result) {
        goto err;
    }

    /* Encode COSE Protection */

    struct t_cose_encrypt_enc enc_ctx;
    struct t_cose_key cek;
    unsigned char raw_key[AES_256_KEY_LEN];

    t_cose_encrypt_enc_init(&enc_ctx,
                            T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0,
                            T_COSE_ALGORITHM_A256GCM);


    /* get & set the COSE Key */
    get_derived_key(raw_key, AES_256_KEY_LEN, INFO_KEY_ENC, sizeof(INFO_KEY_ENC)-1);
    t_cose_key_init_symmetric(T_COSE_ALGORITHM_A256GCM,
                              Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(raw_key),
                              &cek);
    t_cose_encrypt_set_cek(&enc_ctx, cek);

    t_cose_result = t_cose_encrypt_enc(&enc_ctx,
                                       encoded_data,
                                       NULL_Q_USEFUL_BUF_C,
                                       enc_cose_buffer,
                                       &enc_cose);

    /* TODO clean Keys */

    if (T_COSE_SUCCESS != t_cose_result) {
        goto err;
    }

    /* File Name */
    char filename[FILENAME_MAX] = { 0 };
    if (!get_se_filename(SE_FILE_PERSONALITY, personality_name, se_dir, filename)) {
        goto err;
    }

    /* File IO */
    FILE * fp = NULL;
    if (NULL == (fp = fopen(filename, "wb"))) {
        goto err;
    }
    fwrite(enc_cose.ptr, enc_cose.len, 1, fp);
    fclose(fp);

    /* Get the Hash to be returned and stored in Device State */
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, enc_cose.ptr, enc_cose.len);
    EVP_DigestFinal_ex(ctx, hash->ptr, NULL);
    hash->len = SHA256_SIZE;
    EVP_MD_CTX_free(ctx);

    ret = true;

err:
    return ret;
}


bool provider_serialize(
        const char * se_dir,
        struct devicestate_stack_item_t * p_devicestate_stack
        )
{
    bool ret = false;
    struct devicestate_stack_item_t * p_devicestate_stack_item;

    /* CBOR related stuff */
    QCBOREncodeContext encode_ctx;
    UsefulBuf_MAKE_STACK_UB(perso_hash, TMP_SIGN_BUF_LEN);
    UsefulBuf_MAKE_STACK_UB(encode_buffer, ENCODED_DATA_LEN);
    UsefulBufC encoded_data;
    QCBORError qcbor_result;

    /* COSE related stuff */
    Q_USEFUL_BUF_MAKE_STACK_UB(signed_cose_buffer, COSE_DATA_LEN);
    struct q_useful_buf_c signed_cose;
    enum t_cose_err_t t_cose_result;


    QCBOREncode_Init(&encode_ctx, encode_buffer);

    /* TODO review all String Zero terminated assumed below */

    /* Array of all Device States */
    QCBOREncode_OpenArray(&encode_ctx);

    for (size_t i = list_cnt((struct list_t *) p_devicestate_stack); i >= 1 ; i--) {
        p_devicestate_stack_item = (struct devicestate_stack_item_t *)list_get((struct list_t *) p_devicestate_stack, i);

        /* Map of a Device State */
        QCBOREncode_OpenMap(&encode_ctx);

        /* Scalars of the Device State */
        QCBOREncode_AddUInt64ToMap(&encode_ctx, LABEL_DEVICE_STATE_LOCK, p_devicestate_stack_item->owner_lock_count);

        /* Array of Identifiers associated with the Device State */
        QCBOREncode_OpenArrayInMap(&encode_ctx, LABEL_IDENTIFIERS);
        struct identifier_list_item_t * p_identifier_list_item = p_devicestate_stack_item->p_identifier_list;
        while (NULL != p_identifier_list_item) {
            /* Map of an Identifier */
            QCBOREncode_OpenMap(&encode_ctx);

            QCBOREncode_AddSZStringToMap(&encode_ctx, LABEL_IDENTIFIER_NAME, p_identifier_list_item->name);
            QCBOREncode_AddSZStringToMap(&encode_ctx, LABEL_IDENTIFIER_TYPE, p_identifier_list_item->type);

            /* Close map containing an Identifier */
            QCBOREncode_CloseMap(&encode_ctx);
            p_identifier_list_item = p_identifier_list_item->p_next;
        }
        QCBOREncode_CloseArray(&encode_ctx);

        /* Array of Personalities associated with the Device State */
        QCBOREncode_OpenArrayInMap(&encode_ctx, LABEL_PERSONALITIES);
        struct personality_name_list_item_t * p_personality_name_list_item = p_devicestate_stack_item->p_personality_name_list;
        while (NULL != p_personality_name_list_item) {
            /* Map of a Personality */
            QCBOREncode_OpenMap(&encode_ctx);

            QCBOREncode_AddSZStringToMap(&encode_ctx, LABEL_PERSONALITY_NAME, p_personality_name_list_item->personality_name);
            QCBOREncode_AddSZStringToMap(&encode_ctx, LABEL_APPLICATION_NAME, p_personality_name_list_item->application_name);
            QCBOREncode_AddSZStringToMap(&encode_ctx, LABEL_PERSONALITY_IDENTIFIER, p_personality_name_list_item->p_identifier_list_item->name);
            QCBOREncode_AddBoolToMap(&encode_ctx, LABEL_PERSONALITY_ACTIVATED, p_personality_name_list_item->activated);

            /* Serialize Personality content & add the hash of it */
            if (!personality_content_serialize(se_dir, p_personality_name_list_item->p_personality_content,
                                               p_personality_name_list_item->personality_name, &perso_hash)) {
                goto err;
            }
            QCBOREncode_AddBytesToMap(&encode_ctx, LABEL_PERSONALITY_PROTECTION, UsefulBuf_Const(perso_hash));

            /* Close map containing a Personality */
            QCBOREncode_CloseMap(&encode_ctx);
            p_personality_name_list_item = p_personality_name_list_item->p_next;
        }
        QCBOREncode_CloseArray(&encode_ctx);

        /* Close map containing a Device State */
        QCBOREncode_CloseMap(&encode_ctx);
    }

    /* Close array of all Device States */
    QCBOREncode_CloseArray(&encode_ctx);
    qcbor_result = QCBOREncode_Finish(&encode_ctx, &encoded_data);
    if (QCBOR_SUCCESS != qcbor_result) {
        goto err;
    }

    /* Encode COSE Protection */
    struct t_cose_mac_calculate_ctx mac_ctx;
    struct t_cose_key key;
    unsigned char raw_key[HMAC_256_KEY_LEN];

    t_cose_mac_compute_init(&mac_ctx, 0, T_COSE_ALGORITHM_HMAC256);

    /* get & set the COSE Key */
    get_derived_key(raw_key, HMAC_256_KEY_LEN, INFO_KEY_MAC, sizeof(INFO_KEY_MAC)-1);
    t_cose_key_init_symmetric(T_COSE_ALGORITHM_HMAC256,
                              Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(raw_key),
                              &key);
    t_cose_mac_set_computing_key(&mac_ctx, key, NULL_Q_USEFUL_BUF_C);

    t_cose_result = t_cose_mac_compute(&mac_ctx,
                                  NULL_Q_USEFUL_BUF_C,
                                  encoded_data,
                                  signed_cose_buffer,
                                  &signed_cose);

    /* TODO clean Keys */

    if(T_COSE_SUCCESS != t_cose_result) {
        goto err;
    }

    /* File Name */
    char filename[FILENAME_MAX] = { 0 };
    if (!get_se_filename(SE_FILE_DEVICESTATES_STACK, "", se_dir, filename)) {
        goto err;
    }

    /* File IO */
    FILE * fp = NULL;
    if (NULL == (fp = fopen(filename, "wb"))) {
        goto err;
    }
    fwrite(signed_cose.ptr, signed_cose.len, 1, fp);
    fclose(fp);


    ret = true;

err:
    return ret;
}


static bool decode_attributes(
        QCBORDecodeContext *p_decode_ctx,
        struct personality_t * p_personality,
        gta_context_handle_t h_ctx
)
{
    bool ret = false;
    struct personality_attribute_t * p_attribute_list_item = NULL;
    gta_errinfo_t errinfo;

    /* CBOR related stuff */
    char tmp_str_buffer[TMP_STR_BUF_LEN];
    UsefulBufC tmp_str = {.ptr=(void*)tmp_str_buffer, .len=TMP_STR_BUF_LEN};
    QCBORItem Item;
    QCBORError qcbor_result;

    /* Assume that decoder has been entered into an array of Attributes */

    while(1) {
        /* Try to open new map containing an Attribute */
        QCBORDecode_EnterMap(p_decode_ctx, &Item);
        qcbor_result = QCBORDecode_GetError(p_decode_ctx);

        if (qcbor_result == QCBOR_ERR_NO_MORE_ITEMS) {
            QCBORDecode_GetAndResetError(p_decode_ctx);
            break;
        }
        if (qcbor_result != QCBOR_SUCCESS) {
            goto err;
        }

        p_attribute_list_item = gta_secmem_calloc(h_ctx, 1, sizeof(struct personality_attribute_t), &errinfo);
        if (NULL == p_attribute_list_item) {
            goto err;
        }

        list_append((struct list_t **)(&p_personality->p_attribute_list), p_attribute_list_item);

        /* Decode attribute name */
        QCBORDecode_GetTextStringInMapSZ(p_decode_ctx, LABEL_ATTRIBUTE_NAME, &tmp_str);
        p_attribute_list_item->p_name = gta_secmem_calloc(h_ctx, 1, tmp_str.len + 1, &errinfo);
        if (NULL == p_attribute_list_item->p_name) {
            goto err;
        }
        memcpy(p_attribute_list_item->p_name, tmp_str.ptr, tmp_str.len);
        p_attribute_list_item->p_name[tmp_str.len] = '\0';

        /* Decode if Activated or Trusted */
        QCBORDecode_GetBoolInMapSZ(p_decode_ctx, LABEL_ATTRIBUTE_ACTIVATED, &p_attribute_list_item->activated);
        QCBORDecode_GetBoolInMapSZ(p_decode_ctx, LABEL_ATTRIBUTE_TRUSTED, &p_attribute_list_item->trusted);

        /* Decode attribute type */
        QCBORDecode_GetUInt64InMapSZ(p_decode_ctx, LABEL_ATTRIBUTE_TYPE, (uint64_t *)&p_attribute_list_item->type);

        /* Decode attribute data */
        UsefulBufC tmp_bytes;
        QCBORDecode_GetByteStringInMapSZ(p_decode_ctx, LABEL_ATTRIBUTE_DATA, &tmp_bytes);
        p_attribute_list_item->data_size = tmp_bytes.len;
        p_attribute_list_item->p_data = gta_secmem_calloc(h_ctx, 1, tmp_bytes.len, &errinfo);
        if (NULL == p_attribute_list_item->p_data) {
            goto err;
        }
        memcpy(p_attribute_list_item->p_data, tmp_bytes.ptr, tmp_bytes.len);

        /* Close map containing Attribute */
        QCBORDecode_ExitMap(p_decode_ctx);

        qcbor_result = QCBORDecode_GetError(p_decode_ctx);
        if (QCBOR_SUCCESS != qcbor_result) {
            DEBUG_PRINT(("DESERIALIZATION Failed. QCBOR error: %d\n", qcbor_result));
            goto err;
        }
    }

    ret = true;

err:
    return ret;
}

static bool auth_info_list_deserialize(gta_context_handle_t h_ctx,
                                       QCBORDecodeContext * p_decode_ctx,
                                       struct auth_info_list_item_t ** p_auth_list,
                                       gta_errinfo_t * p_errinfo)
{
    bool ret = false;
    struct auth_info_list_item_t * p_auth_item;

    QCBORItem Item;
    QCBORError qcbor_result;
    char fingerprint_buffer[PERS_FINGERPRINT_LEN];
    UsefulBufC fingerprint_data = {.ptr=(void*)fingerprint_buffer, .len=PERS_FINGERPRINT_LEN};
    char profile_name_str_buffer[MAXLEN_PROFILE];
    UsefulBufC profile_name_str = {.ptr=(void*)profile_name_str_buffer, .len=MAXLEN_PROFILE};

    while(1) {
        QCBORDecode_EnterMap(p_decode_ctx, &Item);
        qcbor_result = QCBORDecode_GetError(p_decode_ctx);

        if (qcbor_result == QCBOR_ERR_NO_MORE_ITEMS) {
            QCBORDecode_GetAndResetError(p_decode_ctx);
            break;
        }
        if (qcbor_result != QCBOR_SUCCESS) {
            goto err;
        }
        if (NULL != (p_auth_item = gta_secmem_calloc(h_ctx,
                        1, sizeof(struct auth_info_list_item_t), p_errinfo))) {
            p_auth_item->p_next = NULL;
            QCBORDecode_GetUInt64InMapSZ(p_decode_ctx,
                LABEL_AUTH_ITEM_TYPE, (uint64_t *)&(p_auth_item->type));

            switch (p_auth_item->type) {
                case GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL:
                case GTA_ACCESS_DESCRIPTOR_TYPE_BASIC_TOKEN:
                case GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN:
                    /* Nothing to do */
                    break;
                case GTA_ACCESS_DESCRIPTOR_TYPE_PERS_DERIVED_TOKEN:
                    /* Deserialize LABEL_AUTH_PERS_FINGERPRINT */

                    QCBORDecode_GetByteStringInMapSZ(p_decode_ctx,
                        LABEL_AUTH_PERS_FINGERPRINT, &fingerprint_data);
                    if(PERS_FINGERPRINT_LEN != fingerprint_data.len) {
                        /* Cleanup memory */
                        gta_secmem_free(h_ctx, p_auth_item, p_errinfo);
                        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
                        goto err;
                    }
                    memcpy(p_auth_item->binding_personality_fingerprint,
                           fingerprint_data.ptr, fingerprint_data.len);

                    /* Deserialize LABEL_AUTH_DERIVATION_PROFILE_NAME */
                    QCBORDecode_GetTextStringInMapSZ(p_decode_ctx,
                        LABEL_AUTH_DERIVATION_PROFILE_NAME, &profile_name_str);
                    p_auth_item->derivation_profile_name = gta_secmem_calloc(h_ctx,
                        1, profile_name_str.len + 1, p_errinfo);
                    if (NULL == p_auth_item->derivation_profile_name) {
                        /* Cleanup memory */
                        gta_secmem_free(h_ctx, p_auth_item, p_errinfo);
                        *p_errinfo = GTA_ERROR_MEMORY;
                        goto err;
                    }
                    memcpy(p_auth_item->derivation_profile_name,
                        profile_name_str.ptr, profile_name_str.len);
                    p_auth_item->derivation_profile_name[profile_name_str.len] = '\0';

                    break;
                default:
                    break;
            }
        }
        else {
                /* List element allocation failed, therefore, no cleanup required */
                *p_errinfo = GTA_ERROR_MEMORY;
                goto err;
        }

        /* Close map containing auth object */
        QCBORDecode_ExitMap(p_decode_ctx);
        list_append((struct list_t **)p_auth_list, p_auth_item);
    }
    ret = true;
err:
    return ret;
}

static bool personality_content_deserialize(
        const char * se_dir,
        struct personality_t * p_personality,
        gta_personality_name_t personality_name,
        struct q_useful_buf_c * expected_hash,
        gta_context_handle_t h_ctx
        )
{
    bool ret = false;
    gta_errinfo_t errinfo;

    /* CBOR related stuff */
    QCBORDecodeContext perso_decode_ctx;
    QCBORItem Item;
    QCBORError qcbor_result;
    UsefulBuf_MAKE_STACK_UB(perso_file_hash, SHA256_SIZE);

    /* COSE related stuff */
    struct q_useful_buf_c returned_payload;
    enum t_cose_err_t t_cose_result;


    /* File Operations */
    char filename[FILENAME_MAX] = { 0 };
    char * file_buffer = NULL;
    size_t file_buffer_size = 0;
    FILE * fp = NULL;

    if (!get_se_filename(SE_FILE_PERSONALITY, personality_name, se_dir, filename)) {
        goto err;
    }

    if (NULL != (fp = fopen(filename, "rb"))) {
        fseek(fp, 0L, SEEK_END);
        size_t file_size = ftell(fp);
        rewind(fp);
        if(NULL != (file_buffer = gta_secmem_calloc(h_ctx, 1, file_size, &errinfo))) {
            file_buffer_size = fread(file_buffer, sizeof(char), file_size, fp);
        }
        else {
            goto err;
        }
        fclose(fp);
        fp = NULL;

    } else {
        goto err;
    }

    /* Calculate the Hash of the Personality file */
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, file_buffer, file_buffer_size);
    EVP_DigestFinal_ex(ctx, perso_file_hash.ptr, NULL);
    EVP_MD_CTX_free(ctx);

    /* Check if the hash matches the expected one in Device State */
    if (0 != UsefulBuf_Compare(UsefulBuf_Const(perso_file_hash), *expected_hash)) {
        DEBUG_PRINT(("DESERIALIZATION Failed. Personality Hash does not match the expected one\n"));
        goto err;
    }

    /* Verify COSE Protection */
    UsefulBufC encoded_data = {.ptr=(void *) file_buffer, .len=file_buffer_size};
    Q_USEFUL_BUF_MAKE_STACK_UB(dec_cose_buffer, COSE_DATA_LEN);
    struct t_cose_encrypt_dec_ctx dec_ctx;
    struct t_cose_key cek;
    unsigned char raw_key[AES_256_KEY_LEN];

    t_cose_encrypt_dec_init(&dec_ctx, T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0);

    /* get & set the COSE Key */
    get_derived_key(raw_key, AES_256_KEY_LEN, INFO_KEY_ENC, sizeof(INFO_KEY_ENC)-1);
    t_cose_key_init_symmetric(T_COSE_ALGORITHM_A256GCM,
                              Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(raw_key),
                              &cek);
    t_cose_encrypt_dec_set_cek(&dec_ctx, cek);

    /* decrypt and get COSE payload */
    t_cose_result = t_cose_encrypt_dec(&dec_ctx,
                                       encoded_data,
                                      NULL_Q_USEFUL_BUF_C,
                                       dec_cose_buffer,
                                      &returned_payload,
                                      NULL);

    /* TODO clean Keys */

    if (T_COSE_SUCCESS != t_cose_result) {
        DEBUG_PRINT(("DESERIALIZATION Failed. Personality content verification COSE Result: %d\n", t_cose_result));
        goto err;
    }


    /* CBOR decoding - Personality Content */
    QCBORDecode_Init(&perso_decode_ctx, returned_payload, QCBOR_DECODE_MODE_NORMAL);

    /* Map of a Personality */
    QCBORDecode_EnterMap(&perso_decode_ctx, &Item);

    /* Decode personality type */
    QCBORDecode_GetUInt64InMapSZ(&perso_decode_ctx, LABEL_PERSONALITY_TYPE, (uint64_t *)&p_personality->secret_type);

    /* Decode personality content */
    UsefulBufC tmp_bytes;
    QCBORDecode_GetByteStringInMapSZ(&perso_decode_ctx, LABEL_PERSONALITY_CONTENT, &tmp_bytes);
    p_personality->secret_data_size = tmp_bytes.len;
    p_personality->secret_data = gta_secmem_calloc(h_ctx, 1, tmp_bytes.len, &errinfo);
    if (NULL == p_personality->secret_data) {
        goto err;
    }
    memcpy(p_personality->secret_data, tmp_bytes.ptr, tmp_bytes.len);

    /* Decode personality attributes */
    QCBORDecode_EnterArrayFromMapSZ(&perso_decode_ctx, LABEL_PERSONALITY_ATTRIBUTES);
    if (!decode_attributes(&perso_decode_ctx, p_personality, h_ctx)) {
        DEBUG_PRINT(("DESERIALIZATION Failed. Error while decoding Personality Attributes\n"));
        goto err;
    }
    QCBORDecode_ExitArray(&perso_decode_ctx);

    /* Decode user authentication list */
    QCBORDecode_EnterArrayFromMapSZ(&perso_decode_ctx, LABEL_AUTH_USE_LIST);
    auth_info_list_deserialize(h_ctx, &perso_decode_ctx, &(p_personality->p_auth_use_info_list), &errinfo);
    QCBORDecode_ExitArray(&perso_decode_ctx);

    /* Decode admin authentication list */
    QCBORDecode_EnterArrayFromMapSZ(&perso_decode_ctx, LABEL_AUTH_ADMIN_LIST);
    auth_info_list_deserialize(h_ctx, &perso_decode_ctx, &(p_personality->p_auth_admin_info_list), &errinfo);
    QCBORDecode_ExitArray(&perso_decode_ctx);

    /* Close map containing the Personality */
    QCBORDecode_ExitMap(&perso_decode_ctx);

    qcbor_result = QCBORDecode_Finish(&perso_decode_ctx);
    if (QCBOR_SUCCESS != qcbor_result) {
        DEBUG_PRINT(("DESERIALIZATION Failed. QCBOR error: %d\n", qcbor_result));
        goto err;
    }

    ret = true;

err:
    if (NULL != fp) {
        fclose(fp);
        fp = NULL;
    }
    if (NULL != file_buffer) {
        gta_secmem_free(h_ctx, file_buffer, &errinfo);
        file_buffer = NULL;
    }

    return ret;
}


static bool decode_identifiers(
        QCBORDecodeContext *p_decode_ctx,
        struct devicestate_stack_item_t * p_devicestack_item,
        gta_context_handle_t h_ctx
        )
{
    bool ret = false;
    struct identifier_list_item_t * p_identifier_list_item = NULL;
    gta_errinfo_t errinfo;

    /* CBOR related stuff */
    char tmp_str_buffer[TMP_STR_BUF_LEN];
    UsefulBufC tmp_str = {.ptr=(void*)tmp_str_buffer, .len=TMP_STR_BUF_LEN};
    QCBORItem Item;
    QCBORError qcbor_result;

    /* Assume that decoder has been entered into an array of Identifiers */

    while(1) {
        /* Try to open new map containing an Identifier */
        QCBORDecode_EnterMap(p_decode_ctx, &Item);
        qcbor_result = QCBORDecode_GetError(p_decode_ctx);

        if (qcbor_result == QCBOR_ERR_NO_MORE_ITEMS) {
            QCBORDecode_GetAndResetError(p_decode_ctx);
            break;
        }
        if (qcbor_result != QCBOR_SUCCESS) {
            goto err;
        }

        p_identifier_list_item = gta_secmem_calloc(h_ctx, 1, sizeof(struct identifier_list_item_t), &errinfo);
        if (NULL == p_identifier_list_item) {
            goto err;
        }

        list_append((struct list_t **)(&p_devicestack_item->p_identifier_list), p_identifier_list_item);

        /* Decode identifier name */
        QCBORDecode_GetTextStringInMapSZ(p_decode_ctx, LABEL_IDENTIFIER_NAME, &tmp_str);
        p_identifier_list_item->name = gta_secmem_calloc(h_ctx, 1, tmp_str.len + 1, &errinfo);
        if (NULL == p_identifier_list_item->name) {
            goto err;
        }
        memcpy(p_identifier_list_item->name, tmp_str.ptr, tmp_str.len);
        p_identifier_list_item->name[tmp_str.len] = '\0';

        /* Decode identifier type */
        QCBORDecode_GetTextStringInMapSZ(p_decode_ctx, LABEL_IDENTIFIER_TYPE, &tmp_str);
        p_identifier_list_item->type = gta_secmem_calloc(h_ctx, 1, tmp_str.len + 1, &errinfo);
        if (NULL == p_identifier_list_item->type) {
            goto err;
        }
        memcpy((void *) p_identifier_list_item->type, tmp_str.ptr, tmp_str.len);
        gta_memset((void *) (p_identifier_list_item->type + tmp_str.len),1 , 0, 1);
        /* assigning value '\0' by memset, otherwise would fail because of const type */

        /* Close map containing Identifier */
        QCBORDecode_ExitMap(p_decode_ctx);

        qcbor_result = QCBORDecode_GetError(p_decode_ctx);
        if (QCBOR_SUCCESS != qcbor_result) {
            DEBUG_PRINT(("DESERIALIZATION Failed. QCBOR error: %d\n", qcbor_result));
            goto err;
        }
    }

    ret = true;

err:
    return ret;
}

static bool decode_personalities(
        const char * se_dir,
        QCBORDecodeContext *p_decode_ctx,
        struct devicestate_stack_item_t * p_devicestack_item,
        gta_context_handle_t h_ctx
        )
{
    bool ret = false;
    struct personality_name_list_item_t * p_personality_name_list_item = NULL;
    gta_errinfo_t errinfo;

    char* id_name = NULL;

    /* CBOR related stuff */
    char tmp_str_buffer[TMP_STR_BUF_LEN];
    UsefulBufC tmp_str = {.ptr=(void*)tmp_str_buffer, .len=TMP_STR_BUF_LEN};
    QCBORItem Item;
    QCBORError qcbor_result;

    /* Assume that decoder has been entered into an array of Personalities */

    while(1) {
        /* Try to open new map containing a Personality */
        QCBORDecode_EnterMap(p_decode_ctx, &Item);
        qcbor_result = QCBORDecode_GetError(p_decode_ctx);

        if (qcbor_result == QCBOR_ERR_NO_MORE_ITEMS) {
            QCBORDecode_GetAndResetError(p_decode_ctx);
            break;
        }
        if (qcbor_result != QCBOR_SUCCESS) {
            goto err;
        }

        p_personality_name_list_item = gta_secmem_calloc(h_ctx, 1, sizeof(struct personality_name_list_item_t), &errinfo);
        if (NULL == p_personality_name_list_item) {
            goto err;
        }

        list_append_front((struct list_t **)(&p_devicestack_item->p_personality_name_list), p_personality_name_list_item);

        /* Decode Personality name */
        QCBORDecode_GetTextStringInMapSZ(p_decode_ctx, LABEL_PERSONALITY_NAME, &tmp_str);
        p_personality_name_list_item->personality_name = gta_secmem_calloc(h_ctx, 1, tmp_str.len + 1, &errinfo);
        if (NULL == p_personality_name_list_item->personality_name) {
            goto err;
        }
        memcpy(p_personality_name_list_item->personality_name, tmp_str.ptr, tmp_str.len);
        p_personality_name_list_item->personality_name[tmp_str.len] = '\0';

        /* Decode Application name */
        QCBORDecode_GetTextStringInMapSZ(p_decode_ctx, LABEL_APPLICATION_NAME, &tmp_str);
        p_personality_name_list_item->application_name = gta_secmem_calloc(h_ctx, 1, tmp_str.len + 1, &errinfo);
        if (NULL == p_personality_name_list_item->application_name) {
            goto err;
        }
        memcpy(p_personality_name_list_item->application_name, tmp_str.ptr, tmp_str.len);
        p_personality_name_list_item->application_name[tmp_str.len] = '\0';

        /* Decode Activated status */
        QCBORDecode_GetBoolInMapSZ(p_decode_ctx, LABEL_PERSONALITY_ACTIVATED, &p_personality_name_list_item->activated);

        /* Decode Identifier name */
        QCBORDecode_GetTextStringInMapSZ(p_decode_ctx, LABEL_PERSONALITY_IDENTIFIER, &tmp_str);
        id_name = gta_secmem_calloc(h_ctx, 1, tmp_str.len + 1, &errinfo);
        if (NULL == id_name) {
            goto err;
        }
        memcpy(id_name, tmp_str.ptr, tmp_str.len);
        id_name[tmp_str.len] = '\0';

        /* Find the referenced identifier */
        struct identifier_list_item_t * p_identifier_list_item = NULL;
        struct devicestate_stack_item_t * p_devicestack_item_temp = p_devicestack_item;
        while (NULL != p_devicestack_item_temp) {
            p_identifier_list_item = list_find((struct list_t *)(p_devicestack_item_temp->p_identifier_list),
                                    id_name, identifier_list_item_cmp_name);
            if (NULL != p_identifier_list_item) {
                break;
            }
            p_devicestack_item_temp = p_devicestack_item_temp->p_next;
        }
        p_devicestack_item_temp = NULL;
        if (NULL == p_identifier_list_item) {
            DEBUG_PRINT(("DESERIALIZATION Failed. Identifier not found by name\n"));
            goto err;
        }
        p_personality_name_list_item->p_identifier_list_item = p_identifier_list_item;


        /* Deserialize personality content and add pointer to it */
        struct personality_t * p_personality = NULL;
        p_personality = gta_secmem_calloc(h_ctx, 1, sizeof(struct personality_t), &errinfo);
        if (NULL == p_personality) {
            goto err;
        }
        p_personality_name_list_item->p_personality_content = p_personality;
        /* expected Hash */
        QCBORDecode_GetByteStringInMapSZ(p_decode_ctx, LABEL_PERSONALITY_PROTECTION, &tmp_str);
        if (!personality_content_deserialize(se_dir, p_personality, p_personality_name_list_item->personality_name,
                                        &tmp_str, h_ctx)) {
            DEBUG_PRINT(("DESERIALIZATION Failed. Error while decoding Personality Content\n"));
            goto err;
        }

        /* Close map containing Personality */
        QCBORDecode_ExitMap(p_decode_ctx);

        qcbor_result = QCBORDecode_GetError(p_decode_ctx);
        if (QCBOR_SUCCESS != qcbor_result) {
            DEBUG_PRINT(("DESERIALIZATION Failed. QCBOR error: %d\n", qcbor_result));
            goto err;
        }

        /* Set reference counter to zero */
        p_personality_name_list_item->refcount = 0;
    }

    ret = true;

err:
    if (NULL != id_name) {
        gta_secmem_free(h_ctx, id_name, &errinfo);
    }

    return ret;
}

static bool decode_devicestates(
        const char * se_dir,
        QCBORDecodeContext *p_decode_ctx,
        struct devicestate_stack_item_t ** pp_devicestate_stack,
        gta_context_handle_t h_ctx
        )
{
    bool ret = false;
    struct devicestate_stack_item_t * p_devicestack_item = NULL;
    gta_errinfo_t errinfo;

    /* CBOR related stuff */
    QCBORItem Item;
    QCBORError qcbor_result;

    /* Assume that decoder has been entered into the array of Device States */

    while(1) {
        /* Try to open new map containing a Device State */
        QCBORDecode_EnterMap(p_decode_ctx, &Item);
        qcbor_result = QCBORDecode_GetError(p_decode_ctx);

        if (qcbor_result == QCBOR_ERR_NO_MORE_ITEMS) {
            break;
        }
        if (qcbor_result != QCBOR_SUCCESS) {
            goto err;
        }

        DEBUG_PRINT(("Device State Map --> Nesting: %d - Type: %d - Count: %d\n", Item.uNestingLevel, Item.uDataType, Item.val.uCount));

        p_devicestack_item = gta_secmem_calloc(h_ctx, 1, sizeof(struct devicestate_stack_item_t), &errinfo);
        if (NULL == p_devicestack_item) {
            goto err;
        }

        list_append_front((struct list_t **)(pp_devicestate_stack), p_devicestack_item);

        /* Decode Owner Lock Count */
        QCBORDecode_GetUInt64InMapSZ(p_decode_ctx, LABEL_DEVICE_STATE_LOCK, (uint64_t *)&p_devicestack_item->owner_lock_count);

        /* Decode Identifiers */
        QCBORDecode_EnterArrayFromMapSZ(p_decode_ctx, LABEL_IDENTIFIERS);
        if (!decode_identifiers(p_decode_ctx, p_devicestack_item, h_ctx)) {
            DEBUG_PRINT(("DESERIALIZATION Failed. Error while decoding Identifiers\n"));
            goto err;
        }
        QCBORDecode_ExitArray(p_decode_ctx);

        /* Decode Personalities */
        QCBORDecode_EnterArrayFromMapSZ(p_decode_ctx, LABEL_PERSONALITIES);
        if (!decode_personalities(se_dir, p_decode_ctx, p_devicestack_item, h_ctx)) {
            DEBUG_PRINT(("DESERIALIZATION Failed. Error while decoding Personalities\n"));
            goto err;
        }
        QCBORDecode_ExitArray(p_decode_ctx);

        /* Close map containing Device State */
        QCBORDecode_ExitMap(p_decode_ctx);

        qcbor_result = QCBORDecode_GetError(p_decode_ctx);
        if (QCBOR_SUCCESS != qcbor_result) {
            DEBUG_PRINT(("DESERIALIZATION Failed. QCBOR error: %d\n", qcbor_result));
            goto err;
        }
    }

    ret = true;

err:
    return ret;
}

bool provider_deserialize(
        const char * se_dir,
        struct devicestate_stack_item_t ** pp_devicestate_stack,
        gta_context_handle_t h_ctx
        )
{
    bool ret = false;
    gta_errinfo_t errinfo;

    char filename[FILENAME_MAX] = { 0 };
    char * file_buffer = NULL;
    size_t file_buffer_size = 0;

    /* CBOR related stuff */
    QCBORDecodeContext decode_ctx;
    QCBORItem Item;

    /* File Operations */
    if (get_se_filename(SE_FILE_DEVICESTATES_STACK, "", se_dir, filename)) {
        FILE * fp = NULL;
        if (NULL != (fp = fopen(filename, "rb"))) {
            fseek(fp, 0L, SEEK_END);
            size_t file_size = ftell(fp);
            rewind(fp);
            if(NULL != (file_buffer= gta_secmem_calloc(h_ctx, 1, file_size, &errinfo))) {
                file_buffer_size = fread(file_buffer, sizeof(char), file_size, fp);
            }
            fclose(fp);
        }
    }

    /* CBOR decoding */
    if ((NULL != file_buffer) && (0 != file_buffer_size)) {
        UsefulBufC DecodeStorage = {.ptr=(void *) file_buffer, .len=file_buffer_size};

        /* Decode COSE Protection */
        struct q_useful_buf_c returned_payload;
        enum t_cose_err_t t_cose_result;

        struct t_cose_mac_validate_ctx validate_ctx;
        struct t_cose_key key;
        unsigned char raw_key[HMAC_256_KEY_LEN];

        t_cose_mac_validate_init(&validate_ctx, 0);

        /* get & set the COSE Key */
        get_derived_key(raw_key, HMAC_256_KEY_LEN, INFO_KEY_MAC, sizeof(INFO_KEY_MAC)-1);
        t_cose_key_init_symmetric(T_COSE_ALGORITHM_HMAC256,
                                  Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(raw_key),
                                  &key);
        t_cose_mac_set_validate_key(&validate_ctx, key);

        t_cose_result = t_cose_mac_validate(&validate_ctx,
                                            DecodeStorage,  /* COSE to validate */
                                       NULL_Q_USEFUL_BUF_C,
                                       &returned_payload, /* Payload from maced_cose */
                                       NULL);

        /* TODO clean Keys */

        if (T_COSE_SUCCESS != t_cose_result){
            DEBUG_PRINT(("DESERIALIZATION Failed. Overall verification COSE Result: %d\n", t_cose_result));
            goto err;
        }

        QCBORDecode_Init(&decode_ctx, returned_payload, QCBOR_DECODE_MODE_NORMAL);

        /* Decode Device States */
        QCBORDecode_EnterArray(&decode_ctx, &Item);
        if (!decode_devicestates(se_dir, &decode_ctx, pp_devicestate_stack, h_ctx)) {
            DEBUG_PRINT(("DESERIALIZATION Failed. Error while decoding Device States\n"));
            goto err;
        }
        QCBORDecode_ExitArray(&decode_ctx);

        QCBORDecode_Finish(&decode_ctx);
    }

    ret = true;

err:
    if (NULL != file_buffer) {
        gta_secmem_free(h_ctx, file_buffer, &errinfo);
    }

    return ret;
}

