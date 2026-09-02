/*
 * SPDX-FileCopyrightText: Copyright 2024-2026 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "key_management.h"

#include "gta_debug.h"
#include <string.h>

#ifdef ENABLE_TPM2_BACKEND
#include <stdlib.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

/* Derivation value used to derive the hardware unique key (HUK) from the TPM primary key */
#define HUK_DERIVATION_VALUE "gta-api-sw-provider-tpm-huk"

/* TCTI_CONF is compiled from the (optional) tcti-conf Meson option. An empty string
   means "use the module default", which Tss2_TctiLdr_Initialize_Ex() expects as NULL. */
#define TCTI_CONF_OR_NULL (TCTI_CONF[0] != '\0' ? TCTI_CONF : NULL)
#endif

/*
 * This function can be implemented to provide a 32 byte hardware
 * unique key (huk) to the gta_sw_provider. The huk is then used
 * internally to protect the information objects of the
 * gta_sw_provider at rest and ensures, that the information objects
 * can only be used on the device which created it (device binding).
 *
 * The function should return:
 *   true, in case 32 byte hardware unique key are written to key->data
 *   false, on failure
 */
#ifndef ENABLE_TPM2_BACKEND
bool get_hw_unique_key_32(struct hw_unique_key_32 * key)
{
    static const unsigned char hardcoded_key[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03,
                                                  0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                                  0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    if (NULL == key) {
        return false;
    }

    memcpy(key->data, hardcoded_key, HUK_SIZE_32);

    return true;
}

#else

bool get_hw_unique_key_32(struct hw_unique_key_32 * key)
{

    bool b_ret = false;
    TSS2_RC tss2_ret = TSS2_TCTI_RC_GENERAL_FAILURE;
    ESYS_CONTEXT * p_esys_ctx = NULL;
    TSS2_TCTI_CONTEXT * p_tcti_ctx = NULL;
    ESYS_TR h_session = ESYS_TR_NONE;
    ESYS_TR h_salt_key = ESYS_TR_NONE;
    ESYS_TR h_primary_key = ESYS_TR_NONE;
    TPM2B_DIGEST * p_out_hmac = NULL;

    if (NULL == key) {
        goto err;
    }

    tss2_ret = Tss2_TctiLdr_Initialize_Ex(TCTI_MODULE, TCTI_CONF_OR_NULL, &p_tcti_ctx);

    if (TSS2_RC_SUCCESS != tss2_ret) {
        DEBUG_PRINT("Tss2_TctiLdr_Initialize_Ex failed\n");
        goto err;
    }

    tss2_ret = Esys_Initialize(&p_esys_ctx, p_tcti_ctx, NULL);

    if (TSS2_RC_SUCCESS != tss2_ret) {
        DEBUG_PRINT("Esys_Initialize failed\n");
        goto err;
    }

    /* Starting HMAC session */
    const TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES, .keyBits = {.aes = 128}, .mode = {.aes = TPM2_ALG_CFB}};

    /*
     * Create a restricted ECC decryption key to salt the HMAC session. Salting gives the
     * session a non-empty key, which is required for TPMA_SESSION_ENCRYPT/DECRYPT to actually
     * protect the derivation value and the returned HUK on the TPM bus.
     *
     * NOTE: The salt key's public part is created and returned by the TPM over the same bus,
     * so this defends against passive bus snooping but not against an active interposer that
     * substitutes its own key.
     */
    TPM2B_SENSITIVE_CREATE salt_sensitive = {.size = 0, .sensitive = {.userAuth = {.size = 0}, .data = {.size = 0}}};
    TPM2B_DATA salt_outside_info = {.size = 0};
    TPML_PCR_SELECTION salt_pcr = {.count = 0};

    TPM2B_PUBLIC salt_public = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |
                 TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT),
            .authPolicy = {.size = 0},
            .parameters.eccDetail =
                {
                    .symmetric = {.algorithm = TPM2_ALG_AES, .keyBits.aes = 128, .mode.aes = TPM2_ALG_CFB},
                    .scheme = {.scheme = TPM2_ALG_NULL},
                    .curveID = TPM2_ECC_NIST_P256,
                    .kdf = {.scheme = TPM2_ALG_NULL},
                },
            .unique.ecc = {.x = {.size = 0}, .y = {.size = 0}},
        }};

    tss2_ret = Esys_CreatePrimary(
        p_esys_ctx,
        ESYS_TR_RH_ENDORSEMENT,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &salt_sensitive,
        &salt_public,
        &salt_outside_info,
        &salt_pcr,
        &h_salt_key,
        NULL,
        NULL,
        NULL,
        NULL);

    if (TSS2_RC_SUCCESS != tss2_ret) {
        DEBUG_PRINT("Esys_CreatePrimary (salt key) failed\n");
        goto err;
    }

    tss2_ret = Esys_StartAuthSession(
        p_esys_ctx,
        h_salt_key,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        NULL,
        TPM2_SE_HMAC,
        &symmetric,
        TPM2_ALG_SHA256,
        &h_session);

    if (TSS2_RC_SUCCESS != tss2_ret) {
        DEBUG_PRINT("Esys_StartAuthSession failed\n");
        goto err;
    }

    TPMA_SESSION session_attributes = TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_ENCRYPT | TPMA_SESSION_DECRYPT;

    tss2_ret = Esys_TRSess_SetAttributes(p_esys_ctx, h_session, session_attributes, 0xff);

    if (TSS2_RC_SUCCESS != tss2_ret) {
        DEBUG_PRINT("Esys_TRSess_SetAttributes failed\n");
        goto err;
    }

    /*********************************/
    /* create primary and derive key */
    TPM2B_SENSITIVE_CREATE in_sensitive_primary = {
        .size = 0,
        .sensitive =
            {
                .userAuth =
                    {
                        .size = 0,
                        .buffer = {0},
                    },
                .data =
                    {
                        .size = 0,
                        .buffer = {0},
                    },
            },
    };

    TPM2B_PUBLIC in_public = {0};

    TPM2B_DATA outside_info = {
        .size = 0,
        .buffer = {0},
    };
    TPML_PCR_SELECTION creation_pcr = {
        .count = 0,
    };

    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    in_public.publicArea.type = TPM2_ALG_KEYEDHASH;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    in_public.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;
    in_public.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM2_ALG_SHA256;

    tss2_ret = Esys_CreatePrimary(
        p_esys_ctx,
        ESYS_TR_RH_ENDORSEMENT,
        ESYS_TR_PASSWORD,
        h_session,
        ESYS_TR_NONE,
        &in_sensitive_primary,
        &in_public,
        &outside_info,
        &creation_pcr,
        &h_primary_key,
        NULL,
        NULL,
        NULL,
        NULL);

    if (tss2_ret != TSS2_RC_SUCCESS) {
        DEBUG_PRINT("Esys_CreatePrimary failed\n");
        goto err;
    }

    TPM2B_MAX_BUFFER dv_buffer = {.size = sizeof(HUK_DERIVATION_VALUE) - 1, .buffer = HUK_DERIVATION_VALUE};

    session_attributes = TPMA_SESSION_ENCRYPT | TPMA_SESSION_DECRYPT;

    tss2_ret = Esys_TRSess_SetAttributes(p_esys_ctx, h_session, session_attributes, 0xff);

    if (TSS2_RC_SUCCESS != tss2_ret) {
        DEBUG_PRINT("Esys_TRSess_SetAttributes failed\n");
        goto err;
    }

    tss2_ret = Esys_HMAC(
        p_esys_ctx, h_primary_key, ESYS_TR_PASSWORD, h_session, ESYS_TR_NONE, &dv_buffer, TPM2_ALG_SHA256, &p_out_hmac);

    if (TSS2_RC_SUCCESS != tss2_ret) {
        DEBUG_PRINT("Esys_HMAC failed\n");
        goto err;
    }

    if (HUK_SIZE_32 > p_out_hmac->size) {
        DEBUG_PRINT("HUK_SIZE_32 > p_out_hmac->size\n");
        goto err;
    }

    /*********************************************************************/
    /* Copy 32 bytes of derived key to hardware unique key output buffer */
    memcpy(key->data, p_out_hmac->buffer, HUK_SIZE_32);

    b_ret = true;

err:

    /***********************/
    /* clean up everything */

    if (NULL != p_out_hmac) {
        Esys_Free(p_out_hmac);
    }

    /* Flush HMAC key */
    if (ESYS_TR_NONE != h_primary_key) {
        Esys_FlushContext(p_esys_ctx, h_primary_key);
    }

    /* Flush salt key */
    if (ESYS_TR_NONE != h_salt_key) {
        Esys_FlushContext(p_esys_ctx, h_salt_key);
    }

    /*************/
    /* tpm_close */

    /* Close open HMAC-Session */
    if (ESYS_TR_NONE != h_session) {
        Esys_FlushContext(p_esys_ctx, h_session);
    }

    /* Remove the TSS context */
    if (NULL != p_esys_ctx) {
        Esys_Finalize(&p_esys_ctx);
    }

    /* Remove the TSS context */
    if (NULL != p_tcti_ctx) {
        Tss2_TctiLdr_Finalize(&p_tcti_ctx);
    }

    return b_ret;
}
#endif

/*
 * The following three functions can be implemented to add support
 * for a monotonic counter to enhance the protection of the information
 * objects of the gta_sw_provider at rest.
 */

/*
 * This function initializes a monotonic counter. The function
 * can optionally use the parameters `metadata` and `metadata_len` to
 * store context information needed for the counter operation. The
 * memory for `metadata` must be allocated with `gta_secmem_calloc`.
 *
 * The function should return:
 *   true, in case the initialization was successful.
 *   false, on failure
 */
#ifndef ENABLE_TPM2_MONOTONIC_COUNTER
bool init_monotonic_counter(gta_context_handle_t h_ctx, unsigned char ** metadata, size_t * metadata_len)
{
    (void)h_ctx;
    *metadata = NULL;
    *metadata_len = 0;

    return true;
}

#else

bool init_monotonic_counter(gta_context_handle_t h_ctx, unsigned char ** metadata, size_t * metadata_len)
{
    bool ret = false;
    ESYS_CONTEXT * p_esys_ctx = NULL;
    TSS2_TCTI_CONTEXT * p_tcti_ctx = NULL;

    TSS2_RC r;
    ESYS_TR nvHandle = ESYS_TR_NONE;

    /* The NV index is accessed exclusively through the owner hierarchy
       (TPMA_NV_OWNERWRITE / TPMA_NV_OWNERREAD), so no index-specific
       authorization value is required and an empty auth is used. */
    TPM2B_AUTH auth = {.size = 0, .buffer = {0}};

    /* The NV index is a hardware monotonic counter (TPM2_NT_COUNTER) accessed via the owner
       hierarchy. Its value is not secret (it is stored in cleartext inside the COSE-signed
       provider state and only compared for freshness), so no read/write auth value and no
       write-lock (TPMA_NV_WRITE_STCLEAR) are needed. The monotonicity guarantee that the
       anti-rollback scheme relies on is provided by TPM2_NT_COUNTER itself. */
    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex = TPM2_NV_INDEX_FIRST, /* here the nv-index chosen is set
                                               TPM2_NV_INDEX_FIRST is 0x1000000
                                               to ensure that the chosen is not already
                                               assigned by the tpm perhaps a code like in handle_no_index_specified()
                                               in tpm2_nvdefine.c of tpm tools could be used? */
            .nameAlg = TPM2_ALG_SHA256,
            .attributes = (TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT),
            .authPolicy =
                {
                    .size = 0,
                    .buffer = {0},
                },
            .dataSize = 8,
        }};

    uint8_t * buffer = NULL;
    size_t buffer_size = 0;

    /************/
    /* tpm_open */
    r = Tss2_TctiLdr_Initialize_Ex(TCTI_MODULE, TCTI_CONF_OR_NULL, &p_tcti_ctx);

    if (TSS2_RC_SUCCESS != r) {
        DEBUG_PRINT("Tss2_TctiLdr_Initialize_Ex failed\n");
        goto error;
    }

    r = Esys_Initialize(&p_esys_ctx, p_tcti_ctx, NULL);

    if (TSS2_RC_SUCCESS != r) {
        DEBUG_PRINT("Esys_Initialize failed\n");
        goto error;
    }

    /*
     * Define the NV counter index. This only needs to happen once (the first time the
     * gta api is used on this device). On subsequent runs the index already exists, in
     * which case TPM2_RC_NV_DEFINED is returned and we simply obtain a handle to the
     * existing index instead of defining and initializing it again.
     */
    r = Esys_NV_DefineSpace(
        p_esys_ctx,
        ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD, /* password for the owner hierarchy */
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &auth, /* autorization value for the created nv index */
        &publicInfo,
        &nvHandle);

    if (TPM2_RC_NV_DEFINED == r) {
        /* Index already exists from a previous run: get its ESYS_TR handle. */
        r = Esys_TR_FromTPMPublic(
            p_esys_ctx, publicInfo.nvPublic.nvIndex, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nvHandle);

        if (TSS2_RC_SUCCESS != r) {
            DEBUG_PRINT("Esys_TR_FromTPMPublic failed\n");
            goto error;
        }
    } else if (TSS2_RC_SUCCESS != r) {
        DEBUG_PRINT("Esys_NV_DefineSpace failed\n");
        goto error;
    } else {
        /* A freshly defined counter index must be initialized with a single
           NV_Increment before it can be read. */
        r = Esys_NV_Increment(p_esys_ctx, ESYS_TR_RH_OWNER, nvHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);

        if (TSS2_RC_SUCCESS != r) {
            DEBUG_PRINT("Esys_NV_Increment failed\n");
            goto error;
        }
    }

    r = Esys_TR_Serialize(p_esys_ctx, nvHandle, &buffer, &buffer_size);
    if (TSS2_RC_SUCCESS != r) {
        DEBUG_PRINT("Esys_TR_Serialize failed\n");
        goto error;
    }

    /* Allocate Memory for buffer ... */
    gta_errinfo_t errinfo = GTA_ERROR_INTERNAL_ERROR;
    *metadata = gta_secmem_calloc(h_ctx, 1, buffer_size, &errinfo);
    if (NULL == *metadata) {
        DEBUG_PRINT("gta_secmem_calloc failed\n");
        goto error;
    }

    memcpy(*metadata, buffer, buffer_size);
    *metadata_len = buffer_size;

    ret = true;

error:

    if (buffer) {
        Esys_Free(buffer);
    }

    /*************/
    /* tpm_close */

    /* Remove the TSS context */
    if (NULL != p_esys_ctx) {
        Esys_Finalize(&p_esys_ctx);
    }

    /* Remove the TSS context */
    if (NULL != p_tcti_ctx) {
        Tss2_TctiLdr_Finalize(&p_tcti_ctx);
    }

    return ret;
}
#endif

/*
 * This function reads the current value of the monotonic counter and
 * returns it to the gta_sw_provider. The function gets access to the
 * metadata, which is optionally initialized during
 * `init_monotonic_counter`.
 *
 * The function should return:
 *   true, in case the current counter value was written to counter_value.
 *   false, on failure
 */
#ifndef ENABLE_TPM2_MONOTONIC_COUNTER
bool read_monotonic_counter(unsigned char * metadata, size_t metadata_len, uint64_t * counter_value)
{
    (void)metadata;
    (void)metadata_len;
    *counter_value = 0;

    return true;
}

#else

bool read_monotonic_counter(unsigned char * metadata, size_t metadata_len, uint64_t * counter_value)
{
    bool ret = false;
    ESYS_CONTEXT * p_esys_ctx = NULL;
    TSS2_TCTI_CONTEXT * p_tcti_ctx = NULL;

    TSS2_RC r;
    ESYS_TR nvHandle = ESYS_TR_NONE;

    TPM2B_MAX_NV_BUFFER * nv_counter = NULL;

    /************/
    /* tpm_open */

    r = Tss2_TctiLdr_Initialize_Ex(TCTI_MODULE, TCTI_CONF_OR_NULL, &p_tcti_ctx);

    if (TSS2_RC_SUCCESS != r) {
        DEBUG_PRINT("Tss2_TctiLdr_Initialize_Ex failed\n");
        goto error;
    }

    r = Esys_Initialize(&p_esys_ctx, p_tcti_ctx, NULL);

    if (TSS2_RC_SUCCESS != r) {
        DEBUG_PRINT("Esys_Initialize failed\n");
        goto error;
    }

    r = Esys_TR_Deserialize(p_esys_ctx, metadata, metadata_len, &nvHandle);

    if (TSS2_RC_SUCCESS != r) {
        DEBUG_PRINT("Esys_TR_Deserialize failed\n");
        goto error;
    }

    r = Esys_NV_Read(
        p_esys_ctx, ESYS_TR_RH_OWNER, nvHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, 8, 0, &nv_counter);

    if (TSS2_RC_SUCCESS != r) {
        DEBUG_PRINT("Esys_NV_Read failed\n");
        goto error;
    }

    /* NV counter data is returned big-endian (most significant byte first) */
    *counter_value = 0;
    for (int i = 0; i < 8; ++i) {
        *counter_value <<= 8;
        *counter_value |= nv_counter->buffer[i];
    }

    ret = true;

error:

    if (nv_counter) {
        Esys_Free(nv_counter);
    }

    /*************/
    /* tpm_close */

    /* Remove the TSS context */
    if (NULL != p_esys_ctx) {
        Esys_Finalize(&p_esys_ctx);
    }

    /* Remove the TSS context */
    if (NULL != p_tcti_ctx) {
        Tss2_TctiLdr_Finalize(&p_tcti_ctx);
    }

    return ret;
}
#endif

/*
 * This function increments the monotonic counter. The function gets access to the
 * metadata, which is optionally initialized during `init_monotonic_counter`.
 *
 * The function should return:
 *   true, in case the counter was successfully incremented.
 *   false, on failure
 */
#ifndef ENABLE_TPM2_MONOTONIC_COUNTER
bool increment_monotonic_counter(unsigned char * metadata, size_t metadata_len)
{
    (void)metadata;
    (void)metadata_len;

    return true;
}

#else

bool increment_monotonic_counter(unsigned char * metadata, size_t metadata_len)
{
    bool ret = false;
    ESYS_CONTEXT * p_esys_ctx = NULL;
    TSS2_TCTI_CONTEXT * p_tcti_ctx = NULL;

    TSS2_RC r;
    ESYS_TR nvHandle = ESYS_TR_NONE;

    /************/
    /* tpm_open */

    r = Tss2_TctiLdr_Initialize_Ex(TCTI_MODULE, TCTI_CONF_OR_NULL, &p_tcti_ctx);

    if (TSS2_RC_SUCCESS != r) {
        DEBUG_PRINT("Tss2_TctiLdr_Initialize_Ex failed\n");
        goto error;
    }

    r = Esys_Initialize(&p_esys_ctx, p_tcti_ctx, NULL);

    if (TSS2_RC_SUCCESS != r) {
        DEBUG_PRINT("Esys_Initialize failed\n");
        goto error;
    }

    r = Esys_TR_Deserialize(p_esys_ctx, metadata, metadata_len, &nvHandle);

    if (TSS2_RC_SUCCESS != r) {
        DEBUG_PRINT("Esys_TR_Deserialize failed\n");
        goto error;
    }

    r = Esys_NV_Increment(p_esys_ctx, ESYS_TR_RH_OWNER, nvHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);

    if (TSS2_RC_SUCCESS != r) {
        DEBUG_PRINT("Esys_NV_Increment failed\n");
        goto error;
    }

    ret = true;

error:

    /*************/
    /* tpm_close */

    /* Remove the TSS context */
    if (NULL != p_esys_ctx) {
        Esys_Finalize(&p_esys_ctx);
    }

    /* Remove the TSS context */
    if (NULL != p_tcti_ctx) {
        Tss2_TctiLdr_Finalize(&p_tcti_ctx);
    }

    return ret;
}
#endif