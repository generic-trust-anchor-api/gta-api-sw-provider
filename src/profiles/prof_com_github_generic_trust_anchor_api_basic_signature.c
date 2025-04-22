/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#include <gta_api/gta_api.h>
#include "../gta_sw_provider.h"

#ifdef ENABLE_PQC
#define OQS_SIGN_ALGORITHM OQS_SIG_alg_dilithium_2
#define OQS_ALG_ID_DEFAULT "1.3.6.1.4.1.2.267.7.4.4"

/* TODO this has to be reworked, naming of variable is confusing */
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
#endif

GTA_SWP_DEFINE_FUNCTION(bool, context_open,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;
    const struct personality_t * p_personality_content = NULL;
    EVP_PKEY * evp_private_key = NULL;

    if (SECRET_TYPE_DER == p_context_params->p_personality_item->p_personality_content->secret_type) {
        /* get the private key from the personality */
        p_personality_content = p_context_params->p_personality_item->p_personality_content;
        evp_private_key = get_pkey_from_der(p_personality_content->secret_data, p_personality_content->secret_data_size, p_errinfo);
        if (NULL == evp_private_key) {
            goto err;
        }

        int key_id = EVP_PKEY_base_id(evp_private_key);

        /*
        * Check profile restrictions on personality:
        * Only RSA 2048 and ECC P-256 are allowed.
        */
        if (!(((EVP_PKEY_RSA == key_id) && (2048 == pkey_bits(evp_private_key)))
            || ((EVP_PKEY_EC == key_id) && (NID_X9_62_prime256v1 == pkey_ec_nid(evp_private_key))))) {

            DEBUG_PRINT(("gta_sw_provider_gta_context_open: Profile requirements not fulfilled \n"));
            *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
            goto err;
        }
        ret = true;
    }
#ifdef ENABLE_PQC
    else if (SECRET_TYPE_DILITHIUM2 == p_context_params->p_personality_item->p_personality_content->secret_type) {
        /* here add further checks if required by profile: such as algorithms and minimum key length */
        ret = true;
    }
#endif
    else {
        DEBUG_PRINT(("gta_sw_provider_gta_context_open: Personality type not as expected\n"));
        *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
    }

err:
    EVP_PKEY_free(evp_private_key);
    return ret;
}

GTA_SWP_DEFINE_FUNCTION(bool, personality_enroll,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gtaio_ostream_t * p_personality_enrollment_info,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;
    BIO* bio = NULL;
    long len = 0;
    char* pem_data = NULL;
    EVP_PKEY *p_key = NULL;
    struct personality_t * p_personality_content = NULL;
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

    /* get personality of the context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    if (SECRET_TYPE_DER == p_personality_content->secret_type) {
        p_key = get_pkey_from_der(p_personality_content->secret_data, p_personality_content->secret_data_size, p_errinfo);
        if (NULL == p_key) {
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
        base64EncodedKey = gta_secmem_calloc(p_context_params->h_ctx, 1, encodedSize, p_errinfo);
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

err:
    EVP_PKEY_free(p_key);
    if (NULL != bio) {
        BIO_free_all(bio);
        pem_data = NULL;
    }

#ifdef ENABLE_PQC
    gta_secmem_free(p_context_params->h_ctx, base64EncodedKey, &errinfo_tmp);
    OQS_SIG_free(signer);
    BIO_free_all(bio_sink);
    if (NULL != stream) {
        fclose(stream);
    }
    PublicKeyInfo_free(pub_key); /* Note enc_alg is also freed here */
    OPENSSL_free(publicKeyInfoString);
    OPENSSL_free(pem_data);
#endif

    return ret;
}

GTA_SWP_DEFINE_FUNCTION(bool, authenticate_data_detached,
(
    struct gta_sw_provider_context_params_t * p_context_params,
    gtaio_istream_t * data,
    gtaio_ostream_t * seal,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;
    char payload_chunk[CHUNK_LEN];
    unsigned char* signature = NULL;
    size_t signature_len = 0;

    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *evp_private_key = NULL;

    struct personality_t * p_personality_content = NULL;

#ifdef ENABLE_PQC
    OQS_SIG *signer = NULL;
    unsigned char * p_buffer_in = NULL;
    size_t buffer_idx_in = 0;
#endif

    /* get Personality of the Context */
    p_personality_content = p_context_params->p_personality_item->p_personality_content;

    /* Create the Message Digest Context */
    if (!(mdctx = EVP_MD_CTX_new()))
    {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        goto err;
    }

    if (SECRET_TYPE_DER == p_personality_content->secret_type) {
        evp_private_key = get_pkey_from_der(p_personality_content->secret_data, p_personality_content->secret_data_size, p_errinfo);
        if (NULL == evp_private_key) {
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
        if (!read_input_buffer(data, &p_buffer_in, &buffer_idx_in, p_errinfo)) {
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
    seal->finish(seal, 0, p_errinfo);

    ret = true;

err:
    OPENSSL_free(signature);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(evp_private_key);

#ifdef ENABLE_PQC
    OQS_SIG_free(signer);
    OPENSSL_clear_free(p_buffer_in, buffer_idx_in);
#endif

    return ret;
}

const struct profile_function_list_t fl_prof_com_github_generic_trust_anchor_api_basic_signature = {
    .context_open = context_open,
    .personality_enroll = personality_enroll,
    .personality_attribute_functions_supported = true,
    .authenticate_data_detached = authenticate_data_detached,
};
