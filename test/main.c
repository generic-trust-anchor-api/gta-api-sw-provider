/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2024-2025, Siemens AG
 **********************************************************************/

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include <dirent.h>
#include <sys/stat.h>

#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>

#ifdef WINDOWS
/* The following define needs to be set for all subprojects which should be monitored. */
//#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif /* WINDOWS */

#include <gta_api/gta_api.h>
#include "myio_filestream.h"

#define MAXLEN_PROFILE 160
#define MAXLEN_IDENTIFIER_TYPE 160
#define MAXLEN_IDENTIFIER_VALUE 160
#define MAXLEN_PERSONALITY_NAME 160
#define MAXLEN_ATTRIBUTE_TYPE 160
#define MAXLEN_ATTRIBUTE_NAME 160
#define MAXLEN_ATTRIBUTE_VALUE 2000

const char * passcode = "zZ902()[]{}%*&-+<>!?=$#Ar";

#define IDENTIFIER1_TYPE "ch.iec.30168.identifier.mac_addr"
#define IDENTIFIER1_VALUE "DE-AD-BE-EF-FE-ED"

#define IDENTIFIER2_TYPE "ch.iec.30168.identifier.serial_number"
#define IDENTIFIER2_VALUE "0123456789"

#define TESTFILE_TXT "../test/testdata/testfile.txt"

#define TEST_JWT_INPUT "../test/testdata/test_jwt_input.txt"
#define TEST_DATA_PAYLOAD "../test/testdata/test_data_input.txt"

#define DIRECTORY_CLEAN_STATE "./serialized_data"

#define CHUNK_SIZE 256

#ifdef LOG_TEST_OUTPUT
#  define DEBUG_PRINT(msg) do { printf msg; } while(0)
#else
#  define DEBUG_PRINT(msg)
#endif


/* Supported profiles */
enum profile_t {
    PROF_INVALID = 0,
    PROF_CH_IEC_30168_BASIC_PASSCODE,
    PROF_CH_IEC_30168_BASIC_LOCAL_DATA_INTEGRITY_ONLY,
    PROF_CH_IEC_30168_BASIC_LOCAL_DATA_PROTECTION,
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_RSA,
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_EC,
#ifdef ENABLE_PQC
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_DILITHIUM,
#endif
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_JWT,
    PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_TLS,
};
#ifdef ENABLE_PQC
#define NUM_PROFILES 9
#else
#define NUM_PROFILES 8
#endif
static char supported_profiles[NUM_PROFILES][MAXLEN_PROFILE] = {
    [PROF_INVALID] = "INVALID",
    [PROF_CH_IEC_30168_BASIC_PASSCODE] = "ch.iec.30168.basic.passcode",
    [PROF_CH_IEC_30168_BASIC_LOCAL_DATA_INTEGRITY_ONLY] = "ch.iec.30168.basic.local_data_integrity_only",
    [PROF_CH_IEC_30168_BASIC_LOCAL_DATA_PROTECTION] = "ch.iec.30168.basic.local_data_protection",
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_RSA] = "com.github.generic-trust-anchor-api.basic.rsa",
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_EC] = "com.github.generic-trust-anchor-api.basic.ec",
#ifdef ENABLE_PQC
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_DILITHIUM] = "com.github.generic-trust-anchor-api.basic.dilithium",
#endif
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_JWT] = "com.github.generic-trust-anchor-api.basic.jwt",
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_TLS] = "com.github.generic-trust-anchor-api.basic.tls",
};

static bool profile_creation_supported[NUM_PROFILES] = {
    [PROF_INVALID] = false,
    [PROF_CH_IEC_30168_BASIC_PASSCODE] = false,
    [PROF_CH_IEC_30168_BASIC_LOCAL_DATA_INTEGRITY_ONLY] = false, // ToDo: to be changed to true after implementation
    [PROF_CH_IEC_30168_BASIC_LOCAL_DATA_PROTECTION] = true,
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_RSA] = true,
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_EC] = true,
#ifdef ENABLE_PQC
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_DILITHIUM] = true,
#endif
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_JWT] = false,
    [PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_TLS] = false,
};

extern const struct gta_function_list_t * gta_sw_provider_init(gta_context_handle_t, gtaio_istream_t *, gtaio_ostream_t *, void **, void(**)(void *),  gta_errinfo_t *);

struct test_params_t {
    gta_instance_handle_t h_inst;
    gta_access_token_t granting_token;
    gta_access_token_t physical_presence_token;
};

/* gtaio_istream implementation to read from a temporary buffer */
typedef struct istream_from_buf {
    /* public interface as defined for gtaio_istream */
    gtaio_stream_read_t read;
    gtaio_stream_eof_t eof;
    void * p_reserved2;
    void * p_reserved3;

    /* private implementation details */
    const char * buf; /* data buffer */
    size_t buf_size; /* data buffer size */
    size_t buf_pos; /* current position in data buffer */
} istream_from_buf_t;

static size_t istream_from_buf_read
(
    istream_from_buf_t * istream,
    char * data,
    size_t len,
    gta_errinfo_t * p_errinfo
)
{
    /* Check how many bytes are still available in data buffer */
    size_t bytes_available = istream->buf_size - istream->buf_pos;
    if (bytes_available < len) {
        /* Write only as many bytes as requested in case more are available */
        len = bytes_available;
    }

    /* Copy the bytes from the buffer */
    memcpy(data, &(istream->buf[istream->buf_pos]), len);
    /* Set new position in data buffer */
    istream->buf_pos += len;

    /* Return number of read bytes */
    return len;
}

static bool istream_from_buf_eof
(
    istream_from_buf_t * istream,
    gta_errinfo_t * p_errinfo
)
{
    /* Return true if we are at the end of the buffer */
    return (istream->buf_pos == istream->buf_size);
}

static void istream_from_buf_init
(
    istream_from_buf_t * istream,
    const char * buf,
    size_t buf_size
)
{
    istream->read = (gtaio_stream_read_t)istream_from_buf_read;
    istream->eof = (gtaio_stream_eof_t)istream_from_buf_eof;
    istream->buf = buf;
    istream->buf_size = buf_size;
    istream->buf_pos = 0;
}

bool gta_sw_provider_gta_register_provider(
    gta_instance_handle_t h_inst,
    gtaio_istream_t * init_config,
    gta_profile_name_t profile,
    gta_errinfo_t * p_errinfo)
{
    struct gta_provider_info_t provider_info = {
        .version = 0,
        .type = GTA_PROVIDER_INFO_CALLBACK,
        .provider_init = gta_sw_provider_init,
        .provider_init_config = init_config,
        .profile_info = {
            .profile_name = profile,
            .protection_properties = {0},
            .priority = 0
        }
    };

    return gta_register_provider(h_inst, &provider_info, p_errinfo);
}

void check_output(
    const char * reference_path,
    const char * out_buf,
    size_t out_size,
    bool unix_line_endings)
{
    FILE * testfile_output = NULL;
    size_t testfile_size = 0;
    unsigned char * reference_output = NULL;

    /* Open file with reference output */
#ifdef WINDOWS
    errno_t err = -1;
    if (unix_line_endings) {
        /* Open in text mode to convert line endings */
        err = fopen_s(&testfile_output, reference_path, "r");
    }
    else {
        err = fopen_s(&testfile_output, reference_path, "rb");
    }
    assert_int_equal(err, 0);
#else
    testfile_output = fopen(reference_path, "rb");
    assert_non_null(testfile_output);
#endif

    /* Get size of reference output */
    fseek(testfile_output, 0L, SEEK_END);
    testfile_size = ftell(testfile_output);
    fseek(testfile_output, 0L, SEEK_SET);

    /* Check sizes */
    assert_true((0 < out_size) && ((size_t)testfile_size >= out_size));

    /* Read reference output into buffer */
    reference_output = calloc(testfile_size, sizeof(unsigned char));
    assert_non_null(reference_output);
    fread(reference_output, sizeof(unsigned char), testfile_size, testfile_output);
    fclose(testfile_output);

    /* Compare the output */
    assert_memory_equal(reference_output, out_buf, out_size);
    free(reference_output);
}

/*
 * Folder utils
 */
static bool create_folder(const char *folder_path) {
    bool ret = false;
    DIR *dir = opendir(folder_path);

    if (NULL == dir) {
        if (0 != mkdir(folder_path, 0755)) {
            printf("ERROR creating serialization folder\n");
        } else {
            ret = true;
        }
    } else {
        closedir(dir);
        ret = true;
    }
    return ret;
}

static void remove_folder_files(const char *folder_path){
    DIR *dir = opendir(folder_path);

    if (NULL == dir) {
        return;
    }

    struct dirent *entry;
    while (NULL != (entry = readdir(dir))) {
        if(DT_REG == entry->d_type) {
            char file_path[1024];
            snprintf(file_path, sizeof(file_path), "%s/%s", folder_path, entry->d_name);
            if (0 != remove(file_path)) {
                printf("ERROR deleting file from serialization folder\n");
            }
        }
    }
    closedir(dir);
}

/*
 * Basic software provider test suite
 */

/* init provider, cleaning previously serialized data */
int init_suite_gta_sw_provider_clean_state(void **state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    struct test_params_t * test_params = NULL;
    gta_errinfo_t errinfo = 0;
    /* GTA instance used by the tests */
    struct gta_instance_params_t inst_params = {
        NULL,
        {
            .calloc = &calloc,
            .free = &free,
            .mutex_create  = NULL,
            .mutex_destroy = NULL,
            .mutex_lock    = NULL,
            .mutex_unlock  = NULL,
        },
        NULL
    };
    istream_from_buf_t init_config = { 0 };

    test_params = malloc(sizeof(struct test_params_t));
    assert_non_null(test_params);
    *state = test_params;

    create_folder(DIRECTORY_CLEAN_STATE);
    remove_folder_files(DIRECTORY_CLEAN_STATE);

    istream_from_buf_init(&init_config, DIRECTORY_CLEAN_STATE, sizeof(DIRECTORY_CLEAN_STATE) - 1);

    test_params->h_inst = gta_instance_init(&inst_params, &errinfo);
    assert_non_null(test_params->h_inst);

    /* register profiles for provider */
    for (size_t i=1; i<NUM_PROFILES; ++i) {
        assert_true(gta_sw_provider_gta_register_provider(test_params->h_inst, (gtaio_istream_t*)&init_config, supported_profiles[i], &errinfo));
        assert_int_equal(0, errinfo);
    }
    return 0;
}

int clean_suite_gta_sw_provider(void **state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    struct test_params_t * test_params = (struct test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;

    assert_true(gta_instance_final(test_params->h_inst, &errinfo));

    if (NULL != *state) {
        free(*state);
        *state = NULL;
    }

    return 0;
}

/*-----------------------------------------------------------------------------
 * helper functions for individual tests
 */
size_t ostream_null_write(
    gtaio_ostream_t * ostream,
    const char * data,
    size_t len,
    gta_errinfo_t * p_errinfo
    )
{
    return len;
}

size_t ostream_hex_write(
    myio_ofilestream_t * ostream,
    const char * data,
    size_t len,
    gta_errinfo_t * p_errinfo
    )
{
    for (size_t i=0; i<len; i++) {
        if (2 != fprintf(ostream->file, "%02x", *((unsigned char *)data + i))) {
            return i;
        }
    }
    return len;
}

bool ostream_finish(
    gtaio_ostream_t * ostream,
    gta_errinfo_t errinfo,
    gta_errinfo_t * p_errinfo
    )
{
    return true;
}

/* gtaio_ostream implementation to write the output to a temporary buffer */
typedef struct ostream_to_buf {
    /* public interface as defined for gtaio_ostream */
    void * p_reserved0;
    void * p_reserved1;
    gtaio_stream_write_t write;
    gtaio_stream_finish_t finish;

    /* private implementation details */
    char * buf; /* data buffer */
    size_t buf_size; /* data buffer size */
    size_t buf_pos; /* current position in data buffer */
} ostream_to_buf_t;

static size_t ostream_to_buf_write
(
    ostream_to_buf_t * ostream,
    const char * data,
    size_t len,
    gta_errinfo_t * p_errinfo
)
{
    /* Check how many bytes are still available in data buffer */
    size_t bytes_available = ostream->buf_size - ostream->buf_pos;
    if (bytes_available < len) {
        /* Write only as many bytes as are still available in data buffer */
        len = bytes_available;
    }
    /* Copy the bytes to the buffer */
    memcpy(&(ostream->buf[ostream->buf_pos]), data, len);
    /* Set new position in data buffer */
    ostream->buf_pos += len;

    /* Return number of written bytes */
    return len;
}

static void ostream_to_buf_init
(
    ostream_to_buf_t * ostream,
    char * buf,
    size_t buf_size
)
{
    ostream->write = (gtaio_stream_write_t)ostream_to_buf_write;
    ostream->finish = ostream_finish;
    ostream->buf = buf;
    ostream->buf_size = buf_size;
    ostream->buf_pos = 0;
}

static void get_pubkey(gta_context_handle_t h_ctx)
{
    gta_errinfo_t errinfo = 0;
    gtaio_ostream_t * ostream = NULL;

#ifdef LOG_TEST_OUTPUT
    myio_ofilestream_t ofilestream = { 0 };
    ofilestream.write = (gtaio_stream_write_t)myio_ofilestream_write;
    ofilestream.finish = (gtaio_stream_finish_t)myio_ofilestream_finish;
    ofilestream.file = stdout;
    ostream = (gtaio_ostream_t *)&ofilestream;
#else
    gtaio_ostream_t ostream_null = { 0 };
    ostream_null.write = (gtaio_stream_write_t)ostream_null_write;
    ostream_null.finish = (gtaio_stream_finish_t)ostream_finish;
    ostream = &ostream_null;
#endif
    DEBUG_PRINT(("\nPublic key:\n"));
    assert_true(gta_personality_enroll(h_ctx, ostream, &errinfo));
    assert_int_equal(0, errinfo);
    DEBUG_PRINT(("\n"));
}

static void pers_get_attribute(gta_context_handle_t h_ctx, gta_personality_attribute_name_t attrname, bool hex)
{
    gta_errinfo_t errinfo = 0;
    gtaio_ostream_t * ostream = NULL;

#ifdef LOG_TEST_OUTPUT
    myio_ofilestream_t ofilestream = { 0 };
    if (hex) {
        ofilestream.write = (gtaio_stream_write_t)ostream_hex_write;
    }
    else {
        ofilestream.write = (gtaio_stream_write_t)myio_ofilestream_write;
    }
    ofilestream.finish = (gtaio_stream_finish_t)ostream_finish;
    ofilestream.file = stdout;
    ostream = (gtaio_ostream_t *)&ofilestream;
#else
    gtaio_ostream_t ostream_null = { 0 };
    ostream_null.write = (gtaio_stream_write_t)ostream_null_write;
    ostream_null.finish = (gtaio_stream_finish_t)ostream_finish;
    ostream = &ostream_null;
#endif
    DEBUG_PRINT(("\nAttribute value of attribute \"%s\":\n", attrname));
    assert_true(gta_personality_get_attribute(h_ctx, attrname, ostream, &errinfo));
    assert_int_equal(0, errinfo);
    DEBUG_PRINT(("\n"));
}

static void pers_get_attribute_negative_tests(gta_context_handle_t h_ctx)
{
    gta_errinfo_t errinfo = 0;
    gtaio_ostream_t ostream = { 0 };
    ostream.write = (gtaio_stream_write_t)ostream_null_write;
    ostream.finish = (gtaio_stream_finish_t)ostream_finish;

    assert_false(gta_personality_get_attribute(h_ctx, "inexistent attribute", &ostream, &errinfo));
    assert_int_equal(GTA_ERROR_ITEM_NOT_FOUND, errinfo);
    errinfo = 0;
    //assert_false(gta_personality_get_attribute(h_ctx, "com.github.generic-trust-anchor-api.keytype.openssl", &ostream, &errinfo));
    //assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
}

static void pers_add_attribute_negative_tests(gta_context_handle_t h_ctx)
{
    gta_errinfo_t errinfo = 0;
    const char * dummy_ee_cert = "Dummy EE Certificate";
    const char * short_attribute_value = "";
    istream_from_buf_t istream = { 0 };
    char long_attribute_name[MAXLEN_ATTRIBUTE_NAME + 1] = { 0 };
    char long_attribute_value[MAXLEN_ATTRIBUTE_VALUE + 1] = { 0 };

    for (size_t i=0; i<sizeof(long_attribute_name); ++i) {
        long_attribute_name[i] = 'x';
    }
    for (size_t i=0; i<sizeof(long_attribute_value); ++i) {
        long_attribute_value[i] = 'x';
    }

    istream_from_buf_init(&istream, dummy_ee_cert, strlen(dummy_ee_cert));
    assert_false(gta_personality_add_attribute(h_ctx, "ch.iec.30168.trustlist.certificate.self.x509", "", (gtaio_istream_t *)&istream, &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;
    istream_from_buf_init(&istream, dummy_ee_cert, strlen(dummy_ee_cert));
    assert_false(gta_personality_add_attribute(h_ctx, "ch.iec.30168.trustlist.certificate.self.x509", long_attribute_name, (gtaio_istream_t *)&istream, &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;
    istream_from_buf_init(&istream, dummy_ee_cert, strlen(dummy_ee_cert));
    assert_false(gta_personality_add_attribute(h_ctx, "wrong.attribute.type", "Dummy EE Cert", (gtaio_istream_t *)&istream, &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;
    istream_from_buf_init(&istream, dummy_ee_cert, strlen(dummy_ee_cert));
    assert_false(gta_personality_add_attribute(h_ctx, "ch.iec.30168.fingerprint", "Dummy EE Cert", (gtaio_istream_t *)&istream, &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;
    istream_from_buf_init(&istream, dummy_ee_cert, strlen(dummy_ee_cert));
    assert_false(gta_personality_add_attribute(h_ctx, "ch.iec.30168.identifier", "Dummy EE Cert", (gtaio_istream_t *)&istream, &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;
    istream_from_buf_init(&istream, long_attribute_value, (MAXLEN_ATTRIBUTE_VALUE + 1));
    assert_false(gta_personality_add_attribute(h_ctx, "ch.iec.30168.trustlist.certificate.self.x509", "Dummy EE Cert", (gtaio_istream_t *)&istream, &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;
    istream_from_buf_init(&istream, short_attribute_value, strlen(short_attribute_value));
    assert_false(gta_personality_add_attribute(h_ctx, "ch.iec.30168.trustlist.certificate.self.x509", "Dummy EE Cert", (gtaio_istream_t *)&istream, &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
}

static void pers_attribute_functions_unsupported(gta_context_handle_t h_ctx)
{
    gta_errinfo_t errinfo = 0;
    gtaio_istream_t dummy_istream = { 0 };
    gtaio_ostream_t dummy_ostream = { 0 };

    assert_false(gta_personality_add_attribute(h_ctx, "test", "test", &dummy_istream, &errinfo));
    assert_int_equal(GTA_ERROR_PROFILE_UNSUPPORTED, errinfo);
    errinfo = 0;

    assert_false(gta_personality_add_trusted_attribute(h_ctx, "test", "test", &dummy_istream, &errinfo));
    assert_int_equal(GTA_ERROR_PROFILE_UNSUPPORTED, errinfo);
    errinfo = 0;

    assert_false(gta_personality_activate_attribute(h_ctx, "test", &errinfo));
    assert_int_equal(GTA_ERROR_PROFILE_UNSUPPORTED, errinfo);
    errinfo = 0;

    assert_false(gta_personality_deactivate_attribute(h_ctx, "test", &errinfo));
    assert_int_equal(GTA_ERROR_PROFILE_UNSUPPORTED, errinfo);
    errinfo = 0;

    assert_false(gta_personality_get_attribute(h_ctx, "test", &dummy_ostream, &errinfo));
    assert_int_equal(GTA_ERROR_PROFILE_UNSUPPORTED, errinfo);
    errinfo = 0;
}

static void pers_attr_enumerate(gta_instance_handle_t h_inst, gta_personality_name_t personality_name)
{
    DEBUG_PRINT(("\nEnumerate attributes for personality \"%s\"\n", personality_name));
    gta_errinfo_t errinfo = 0;
    gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;
    ostream_to_buf_t ostream_attribute_type = { 0 };
    ostream_to_buf_t ostream_attribute_name = { 0 };
    unsigned char attribute_type[MAXLEN_ATTRIBUTE_TYPE] = { 0 };
    unsigned char attribute_name[MAXLEN_ATTRIBUTE_NAME] = { 0 };
    size_t count = 0;
    bool b_loop = true;

    while(b_loop) {
        ostream_to_buf_init(&ostream_attribute_type, (char *)attribute_type, sizeof(attribute_type));
        ostream_to_buf_init(&ostream_attribute_name, (char *)attribute_name, sizeof(attribute_name));

        if (gta_personality_attributes_enumerate(h_inst, personality_name, &h_enum, (gtaio_ostream_t*)&ostream_attribute_type, (gtaio_ostream_t*)&ostream_attribute_name, &errinfo)) {
            assert_int_equal(0, errinfo);
            DEBUG_PRINT(("\n[%zu]\n", count));
            DEBUG_PRINT(("Attribute Type:   %s\n", attribute_type));
            DEBUG_PRINT(("Attribute Name:   %s\n", attribute_name));
            ++count;
        }
        else {
            DEBUG_PRINT(("\n"));
            assert_int_equal(GTA_ERROR_ENUM_NO_MORE_ITEMS, errinfo);
            b_loop = false;
        }
    }
}


char* get_personality_name(int i) {
    static char perso_name[100];

    sprintf(perso_name, "pers_test_%d", i);
    return perso_name;
}

/*-----------------------------------------------------------------------------
 * individual test functions
 */
static void get_physical_presence_and_issuing_token(void ** state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    struct test_params_t * test_params = (struct test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;

    assert_true(gta_access_token_get_physical_presence(test_params->h_inst, test_params->physical_presence_token, &errinfo));
    assert_int_equal(0, errinfo);

    assert_false(gta_access_token_get_physical_presence(test_params->h_inst, test_params->physical_presence_token, &errinfo));
    assert_int_equal(GTA_ERROR_ACCESS, errinfo);
    errinfo = 0;

    assert_true(gta_access_token_get_issuing(test_params->h_inst, test_params->granting_token, &errinfo));
    assert_int_equal(0, errinfo);

    assert_false(gta_access_token_get_issuing(test_params->h_inst, test_params->granting_token, &errinfo));
    assert_int_equal(GTA_ERROR_ACCESS, errinfo);
    errinfo = 0;
}

static void profile_spec_create(void ** state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    struct test_params_t * test_params = (struct test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;

    gta_access_policy_handle_t h_auth_use = GTA_HANDLE_INVALID;
    gta_access_policy_handle_t h_auth_admin = GTA_HANDLE_INVALID;
    struct gta_protection_properties_t protection_properties = { 0 };

    h_auth_use = gta_access_policy_simple(test_params->h_inst, GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL, &errinfo);
    h_auth_admin = h_auth_use;
    assert_int_not_equal(h_auth_use, GTA_HANDLE_INVALID);

    for (int profile_index = 1; profile_index < NUM_PROFILES; ++profile_index)
    {
        if (profile_creation_supported[profile_index])
        {
            assert_true(gta_personality_create(test_params->h_inst,
                                               IDENTIFIER1_VALUE,
                                               get_personality_name(profile_index),
                                               "provider_test",
                                               supported_profiles[profile_index],
                                               h_auth_use,
                                               h_auth_admin,
                                               protection_properties,
                                               &errinfo));
            assert_int_equal(0, errinfo);
        } else
        {
            assert_false(gta_personality_create(test_params->h_inst,
                                               IDENTIFIER1_VALUE,
                                                get_personality_name(profile_index),
                                               "provider_test",
                                               supported_profiles[profile_index],
                                               h_auth_use,
                                               h_auth_admin,
                                               protection_properties,
                                               &errinfo));
            // ToDo: check why failing (seems errinfo is 0 for: invalid, integrity_only & tls)
            assert_int_equal(GTA_ERROR_PROFILE_UNSUPPORTED, errinfo);
            errinfo = 0;
        }
    }

    /* Simple negative test to increase code coverage */
    gta_context_handle_t h_ctx = GTA_HANDLE_INVALID;
    gta_context_open(test_params->h_inst, get_personality_name(4), supported_profiles[4], &errinfo);
    assert_null(h_ctx);
    assert_int_equal(GTA_ERROR_PROFILE_UNSUPPORTED, errinfo);
}

static void identifier_assign(void ** state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    struct test_params_t * test_params = (struct test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    char long_identifier_type[MAXLEN_IDENTIFIER_TYPE + 1] = { 0 };
    char long_identifier_value[MAXLEN_IDENTIFIER_VALUE + 1] = { 0 };

    for (size_t i=0; i<sizeof(long_identifier_type); ++i) {
        long_identifier_type[i] = 'x';
    }
    for (size_t i=0; i<sizeof(long_identifier_value); ++i) {
        long_identifier_value[i] = 'x';
    }

    assert_false(gta_identifier_assign(test_params->h_inst, "", IDENTIFIER1_VALUE, &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_PARAMETER, errinfo);

    assert_false(gta_identifier_assign(test_params->h_inst, long_identifier_type, IDENTIFIER1_VALUE, &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_PARAMETER, errinfo);

    assert_false(gta_identifier_assign(test_params->h_inst, IDENTIFIER1_TYPE, "", &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_PARAMETER, errinfo);

    assert_false(gta_identifier_assign(test_params->h_inst, IDENTIFIER1_TYPE, long_identifier_value, &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_PARAMETER, errinfo);

    errinfo = 0;
    assert_true(gta_identifier_assign(test_params->h_inst, IDENTIFIER1_TYPE, IDENTIFIER1_VALUE, &errinfo));
    assert_int_equal(0, errinfo);
    assert_true(gta_identifier_assign(test_params->h_inst, IDENTIFIER2_TYPE, IDENTIFIER2_VALUE, &errinfo));
    assert_int_equal(0, errinfo);

    assert_false(gta_identifier_assign(test_params->h_inst, IDENTIFIER2_TYPE, IDENTIFIER2_VALUE, &errinfo));
    assert_int_equal(GTA_ERROR_NAME_ALREADY_EXISTS, errinfo);
}

static void profile_local_data_protection(void ** state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    struct test_params_t * test_params = (struct test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_context_handle_t h_ctx = GTA_HANDLE_INVALID;

    myio_ifilestream_t istream_data_to_seal = { 0 };
    ostream_to_buf_t ostream = { 0 };
    istream_from_buf_t istream = { 0 };

    char protected_data[3000] = { 0 };
    char data[3000] = { 0 };
    size_t protected_data_size = sizeof(protected_data) - 1;
    size_t data_size = sizeof(data) - 1;
    size_t len = 0;

    gta_access_policy_handle_t h_auth_use = GTA_HANDLE_INVALID;
    gta_access_policy_handle_t h_auth_admin = GTA_HANDLE_INVALID;
    struct gta_protection_properties_t protection_properties = { 0 };

    h_auth_use = gta_access_policy_simple(test_params->h_inst, GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL, &errinfo);
    assert_int_not_equal(h_auth_use, GTA_HANDLE_INVALID);
    assert_int_equal(0, errinfo);
    h_auth_admin = h_auth_use;

    /* Creating a personality with the same name should fail */
    assert_false(gta_personality_create(test_params->h_inst,
                                       IDENTIFIER2_VALUE,
                                       get_personality_name(PROF_CH_IEC_30168_BASIC_LOCAL_DATA_PROTECTION),
                                       "local_data_protection",
                                       "ch.iec.30168.basic.local_data_protection",
                                       h_auth_use,
                                       h_auth_admin,
                                       protection_properties,
                                       &errinfo));
    assert_int_equal(GTA_ERROR_NAME_ALREADY_EXISTS, errinfo);

    errinfo = 0;
    h_ctx = gta_context_open(test_params->h_inst,
                             get_personality_name(PROF_CH_IEC_30168_BASIC_LOCAL_DATA_PROTECTION),
                             "ch.iec.30168.basic.local_data_protection",
                             &errinfo);

    assert_non_null(h_ctx);
    assert_int_equal(0, errinfo);

    /* Negative tests for personality attribute functions */
    pers_attribute_functions_unsupported(h_ctx);

    assert_true(myio_open_ifilestream(&istream_data_to_seal, TEST_DATA_PAYLOAD, &errinfo));
    assert_int_equal(0, errinfo);
    ostream_to_buf_init(&ostream, protected_data, protected_data_size);
    assert_int_equal(0, errinfo);

    assert_true(gta_seal_data(h_ctx,
        (gtaio_istream_t*)&istream_data_to_seal,
        (gtaio_ostream_t*)&ostream,
        &errinfo));
    assert_int_equal(0, errinfo);
    len = ostream.buf_pos;

    assert_true(myio_close_ifilestream(&istream_data_to_seal, &errinfo));
    assert_int_equal(0, errinfo);

    /* Unseal */
    istream_from_buf_init(&istream, protected_data, len);
    assert_int_equal(0, errinfo);
    ostream_to_buf_init(&ostream, data, data_size);
    assert_int_equal(0, errinfo);

    assert_true(gta_unseal_data(h_ctx,
        (gtaio_istream_t*)&istream,
        (gtaio_ostream_t*)&ostream,
        &errinfo));
    assert_int_equal(0, errinfo);

    /* Compare input and output */
    check_output(TEST_DATA_PAYLOAD, data, ostream.buf_pos, false);

    assert_true(gta_context_close(h_ctx, &errinfo));
    assert_int_equal(0, errinfo);

    /* todo: negative tests for gta_context_open() */
}

static void profile_passcode(void ** state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    struct test_params_t * test_params = (struct test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;

    istream_from_buf_t istream_passcode = { 0 };
    gta_access_policy_handle_t h_auth = GTA_HANDLE_INVALID;
    struct gta_protection_properties_t protection_properties = { 0 };

    const char * short_passcode = "abcdefg1234";
    const char * invalid_passcode = "abcdefg=98!,/54Q";

    h_auth = gta_access_policy_simple(test_params->h_inst, GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL, &errinfo);
    assert_int_not_equal(h_auth, GTA_HANDLE_INVALID);

    /* Wrong identifier */
    istream_from_buf_init(&istream_passcode, short_passcode, strlen(short_passcode));
    assert_false(gta_personality_deploy(test_params->h_inst,
        "INVALID",
        "pers_passcode",
        "provider_test",
        "ch.iec.30168.basic.passcode",
        (gtaio_istream_t*)&istream_passcode,
        h_auth,
        h_auth,
        protection_properties,
        &errinfo));
    assert_int_equal(GTA_ERROR_ITEM_NOT_FOUND, errinfo);
    errinfo = 0;

    /* Wrong profile */
    istream_from_buf_init(&istream_passcode, short_passcode, strlen(short_passcode));
    assert_false(gta_personality_deploy(test_params->h_inst,
        IDENTIFIER1_VALUE,
        "pers_passcode",
        "provider_test",
        "ch.iec.30168.basic.local_data_protection",
        (gtaio_istream_t*)&istream_passcode,
        h_auth,
        h_auth,
        protection_properties,
        &errinfo));
    assert_int_equal(GTA_ERROR_PROFILE_UNSUPPORTED, errinfo);
    errinfo = 0;

    /* Too short passcode */
    istream_from_buf_init(&istream_passcode, short_passcode, strlen(short_passcode));
    assert_false(gta_personality_deploy(test_params->h_inst,
        IDENTIFIER1_VALUE,
        "pers_basic_passcode",
        "provider_test",
        "ch.iec.30168.basic.passcode",
        (gtaio_istream_t*)&istream_passcode,
        h_auth,
        h_auth,
        protection_properties,
        &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;

    /* Passcode with invalid characters */
    istream_from_buf_init(&istream_passcode, invalid_passcode, strlen(invalid_passcode));
    assert_false(gta_personality_deploy(test_params->h_inst,
        IDENTIFIER1_VALUE,
        "pers_basic_passcode",
        "provider_test",
        "ch.iec.30168.basic.passcode",
        (gtaio_istream_t*)&istream_passcode,
        h_auth,
        h_auth,
        protection_properties,
        &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;

    /* Passcode with missing NULL terminator */
    istream_from_buf_init(&istream_passcode, passcode, strlen(passcode));
    assert_false(gta_personality_deploy(test_params->h_inst,
        IDENTIFIER1_VALUE,
        get_personality_name(PROF_CH_IEC_30168_BASIC_PASSCODE),
        "provider_test",
        "ch.iec.30168.basic.passcode",
        (gtaio_istream_t*)&istream_passcode,
        h_auth,
        h_auth,
        protection_properties,
        &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;

    istream_from_buf_init(&istream_passcode, passcode, strlen(passcode)+1);
    assert_true(gta_personality_deploy(test_params->h_inst,
        IDENTIFIER1_VALUE,
        "pers_basic_passcode",
        "provider_test",
        "ch.iec.30168.basic.passcode",
        (gtaio_istream_t*)&istream_passcode,
        h_auth,
        h_auth,
        protection_properties,
        &errinfo));
    assert_int_equal(0, errinfo);
}

static void profile_jwt(void ** state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    struct test_params_t * test_params = (struct test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_context_handle_t h_ctx = GTA_HANDLE_INVALID;
    myio_ifilestream_t istream_data_to_seal = { 0 };
    gtaio_ostream_t * ostream = NULL;

#ifdef LOG_TEST_OUTPUT
    myio_ofilestream_t ofilestream = { 0 };
    ofilestream.write = (gtaio_stream_write_t)myio_ofilestream_write;
    ofilestream.finish = (gtaio_stream_finish_t)myio_ofilestream_finish;
    ofilestream.file = stdout;
    ostream = (gtaio_ostream_t *)&ofilestream;
#else
    gtaio_ostream_t ostream_null = { 0 };
    ostream_null.write = (gtaio_stream_write_t)ostream_null_write;
    ostream_null.finish = (gtaio_stream_finish_t)ostream_finish;
    ostream = &ostream_null;
#endif

    /* This profile is supposed to work with the following creation profiles: todo! */
    /* Test with first personality */
    h_ctx = gta_context_open(test_params->h_inst,
                             get_personality_name(PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_RSA),
                             "com.github.generic-trust-anchor-api.basic.jwt",
                             &errinfo);

    assert_non_null(h_ctx);
    assert_int_equal(0, errinfo);

    /* Read the public key */
    get_pubkey(h_ctx);

    pers_get_attribute(h_ctx, "ch.iec.30168.fingerprint", 1);
    pers_get_attribute(h_ctx, "ch.iec.30168.identifier_value", 0);
    DEBUG_PRINT(("\n"));

    assert_true(myio_open_ifilestream(&istream_data_to_seal, TEST_JWT_INPUT , &errinfo));
    assert_int_equal(0, errinfo);


    DEBUG_PRINT(("\nJWT with RSA:\n"));
    assert_true(gta_seal_data(h_ctx,
                              (gtaio_istream_t*)&istream_data_to_seal,
                              ostream,
                              &errinfo));
    assert_int_equal(0, errinfo);
    DEBUG_PRINT(("\n"));

    assert_true(gta_context_close(h_ctx, &errinfo));
    assert_int_equal(0, errinfo);
    assert_true(myio_close_ifilestream(&istream_data_to_seal, &errinfo));
    assert_int_equal(0, errinfo);

    /* Now test with second personality */
    h_ctx = gta_context_open(test_params->h_inst,
                             get_personality_name(PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_EC),
                             "com.github.generic-trust-anchor-api.basic.jwt",
                             &errinfo);

    assert_non_null(h_ctx);
    assert_int_equal(0, errinfo);

    /* Read the public key */
    get_pubkey(h_ctx);

    /* Negative test for gta_authenticate_data_detached */
    assert_false(gta_authenticate_data_detached(h_ctx, (gtaio_istream_t*)&istream_data_to_seal, ostream, &errinfo));
    assert_int_equal(GTA_ERROR_PROFILE_UNSUPPORTED, errinfo);
    errinfo = 0;

    pers_get_attribute_negative_tests(h_ctx);
    pers_get_attribute(h_ctx, "ch.iec.30168.fingerprint", 1);
    pers_get_attribute(h_ctx, "ch.iec.30168.identifier_value", 0);
    DEBUG_PRINT(("\n"));

    assert_true(myio_open_ifilestream(&istream_data_to_seal, TEST_JWT_INPUT , &errinfo));
    assert_int_equal(0, errinfo);

    assert_true(gta_seal_data(h_ctx,
                              (gtaio_istream_t*)&istream_data_to_seal,
                              ostream,
                              &errinfo));
    assert_int_equal(0, errinfo);
    DEBUG_PRINT(("\n\n"));

    assert_true(gta_context_close(h_ctx, &errinfo));
    assert_int_equal(0, errinfo);
    assert_true(myio_close_ifilestream(&istream_data_to_seal, &errinfo));
    assert_int_equal(0, errinfo);

    /* Negative test */
    h_ctx = gta_context_open(test_params->h_inst,
                             get_personality_name(PROF_CH_IEC_30168_BASIC_LOCAL_DATA_PROTECTION),
                             "com.github.generic-trust-anchor-api.basic.jwt",
                             &errinfo);

    assert_null(h_ctx);
    assert_int_equal(GTA_ERROR_PROFILE_UNSUPPORTED, errinfo);
}

static void profile_tls(void ** state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    struct test_params_t * test_params = (struct test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_context_handle_t h_ctx = GTA_HANDLE_INVALID;

    myio_ifilestream_t istream_data_to_seal = { 0 };
    gtaio_ostream_t * ostream = NULL;

#ifdef LOG_TEST_OUTPUT
    myio_ofilestream_t ostream_hex = { 0 };
    ostream_hex.write = (gtaio_stream_write_t)ostream_hex_write;
    ostream_hex.finish = (gtaio_stream_finish_t)ostream_finish;
    ostream_hex.file = stdout;
    ostream = (gtaio_ostream_t *)&ostream_hex;
#else
    gtaio_ostream_t ostream_null = { 0 };
    ostream_null.write = (gtaio_stream_write_t)ostream_null_write;
    ostream_null.finish = (gtaio_stream_finish_t)ostream_finish;
    ostream = &ostream_null;
#endif

    /* This profile is supposed to work with the following creation profiles: todo! */
    /* Test with first personality */
    h_ctx = gta_context_open(test_params->h_inst,
                             get_personality_name(PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_RSA),
                             "com.github.generic-trust-anchor-api.basic.tls",
                             &errinfo);

    assert_non_null(h_ctx);

    /* Some generic negative tests to increase code coverage */
    gtaio_istream_t dummy_istream = { 0 };
    assert_false(gta_seal_data(h_ctx, &dummy_istream, ostream, &errinfo));
    assert_int_equal(GTA_ERROR_PROFILE_UNSUPPORTED, errinfo);
    errinfo = 0;
    assert_false(gta_unseal_data(h_ctx, &dummy_istream, ostream, &errinfo));
    assert_int_equal(GTA_ERROR_PROFILE_UNSUPPORTED, errinfo);
    errinfo = 0;

    /* Read the public key */
    get_pubkey(h_ctx);

    /* Add a new attribute */
    const char * dummy_ee_cert = "Dummy EE Certificate";
    istream_from_buf_t istream = { 0 };

    pers_add_attribute_negative_tests(h_ctx);
    istream_from_buf_init(&istream, dummy_ee_cert, strlen(dummy_ee_cert));
    assert_true(gta_personality_add_attribute(h_ctx, "ch.iec.30168.trustlist.certificate.self.x509", "Dummy EE Cert", (gtaio_istream_t *)&istream, &errinfo));
    assert_int_equal(0, errinfo);
    istream_from_buf_init(&istream, dummy_ee_cert, strlen(dummy_ee_cert));
    assert_false(gta_personality_add_attribute(h_ctx, "ch.iec.30168.trustlist.certificate.self.x509", "Dummy EE Cert", (gtaio_istream_t *)&istream, &errinfo));
    assert_int_equal(GTA_ERROR_NAME_ALREADY_EXISTS, errinfo);
    errinfo = 0;

    /* Add another attribute */
    istream_from_buf_init(&istream, dummy_ee_cert, strlen(dummy_ee_cert));
    assert_true(gta_personality_add_attribute(h_ctx, "ch.iec.30168.trustlist.certificate.self.x509", "Dummy EE Cert 2", (gtaio_istream_t *)&istream, &errinfo));
    assert_int_equal(0, errinfo);

    /* Add generic attribute as trusted */
    istream_from_buf_init(&istream, dummy_ee_cert, strlen(dummy_ee_cert));
    assert_false(gta_personality_add_trusted_attribute(h_ctx, "ch.iec.30168.trustlist.certificate.self.x509", "Dummy EE Cert not trusted", (gtaio_istream_t *)&istream, &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;

    /* Add trusted attribute as trusted */
    istream_from_buf_init(&istream, dummy_ee_cert, strlen(dummy_ee_cert));
    assert_true(gta_personality_add_trusted_attribute(h_ctx, "ch.iec.30168.trustlist.certificate.trusted.x509v3", "Dummy EE Cert trusted", (gtaio_istream_t *)&istream, &errinfo));
    assert_int_equal(0, errinfo);

    /* Get generic attribute */
    assert_true(gta_personality_get_attribute(h_ctx, "Dummy EE Cert", ostream, &errinfo));

    /* Get trusted attribute */
    assert_true(gta_personality_get_attribute(h_ctx, "Dummy EE Cert trusted", ostream, &errinfo));

    /* Deactivate attribute */
    assert_false(gta_personality_deactivate_attribute(h_ctx, "ch.iec.30168.identifier_value", &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;
    assert_false(gta_personality_deactivate_attribute(h_ctx, "ch.iec.30168.fingerprint", &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;
    assert_false(gta_personality_deactivate_attribute(h_ctx, "inexistent attribute", &errinfo));
    assert_int_equal(GTA_ERROR_ITEM_NOT_FOUND, errinfo);
    errinfo = 0;
    assert_true(gta_personality_deactivate_attribute(h_ctx, "Dummy EE Cert 2", &errinfo));
    assert_int_equal(0, errinfo);
    assert_true(gta_personality_deactivate_attribute(h_ctx, "Dummy EE Cert trusted", &errinfo));
    assert_int_equal(0, errinfo);

    /* Enumerate attributes */
    pers_attr_enumerate(test_params->h_inst, get_personality_name(PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_RSA));

    /* Get attribute */
    pers_get_attribute(h_ctx, "Dummy EE Cert", 0);
    assert_false(gta_personality_get_attribute(h_ctx, "Dummy EE Cert 2", ostream, &errinfo));
    assert_int_equal(GTA_ERROR_ITEM_NOT_FOUND, errinfo);
    errinfo = 0;

    /* Get attribute */
    pers_get_attribute(h_ctx, "Dummy EE Cert", 0);
    assert_false(gta_personality_get_attribute(h_ctx, "Dummy EE Cert trusted", ostream, &errinfo));
    assert_int_equal(GTA_ERROR_ITEM_NOT_FOUND, errinfo);
    errinfo = 0;

    /* Remove attribute */
    assert_true(gta_personality_remove_attribute(h_ctx, "Dummy EE Cert", &errinfo));
    assert_int_equal(0, errinfo);
    assert_false(gta_personality_remove_attribute(h_ctx, "Dummy EE Cert", &errinfo));
    assert_int_equal(GTA_ERROR_ITEM_NOT_FOUND, errinfo);
    errinfo = 0;
    assert_false(gta_personality_remove_attribute(h_ctx, "Dummy EE Cert 2", &errinfo));
    assert_int_equal(GTA_ERROR_ITEM_NOT_FOUND, errinfo);
    errinfo = 0;
    assert_false(gta_personality_remove_attribute(h_ctx, "ch.iec.30168.identifier_value", &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;
    assert_false(gta_personality_remove_attribute(h_ctx, "ch.iec.30168.fingerprint", &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;

    /* Activate attribute */
    assert_true(gta_personality_activate_attribute(h_ctx, "Dummy EE Cert 2", &errinfo));
    assert_int_equal(0, errinfo);
    assert_false(gta_personality_activate_attribute(h_ctx, "Dummy EE Cert 2", &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_PARAMETER, errinfo);
    errinfo = 0;
    assert_false(gta_personality_activate_attribute(h_ctx, "inexistent attribute", &errinfo));
    assert_int_equal(GTA_ERROR_ITEM_NOT_FOUND, errinfo);
    errinfo = 0;
    assert_true(gta_personality_activate_attribute(h_ctx, "Dummy EE Cert trusted", &errinfo));
    assert_int_equal(0, errinfo);

    /* Remove attribute */
    assert_true(gta_personality_remove_attribute(h_ctx, "Dummy EE Cert trusted", &errinfo));
    assert_int_equal(0, errinfo);

    assert_true(myio_open_ifilestream(&istream_data_to_seal, TEST_DATA_PAYLOAD , &errinfo));

    DEBUG_PRINT(("\nSignature with RSA\n"));
    assert_true(gta_authenticate_data_detached(h_ctx,
                              (gtaio_istream_t*)&istream_data_to_seal,
                              ostream,
                              &errinfo));
    DEBUG_PRINT(("\n"));
    assert_int_equal(0, errinfo);

    assert_true(gta_context_close(h_ctx, &errinfo));
    assert_true(myio_close_ifilestream(&istream_data_to_seal, &errinfo));

    /* Test with second personality */
    h_ctx = gta_context_open(test_params->h_inst,
                             get_personality_name(PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_EC),
                             "com.github.generic-trust-anchor-api.basic.tls",
                             &errinfo);

    assert_non_null(h_ctx);

    /* Get openssl keytype attribute attribute */
    assert_true(gta_personality_get_attribute(h_ctx, "com.github.generic-trust-anchor-api.keytype.openssl", ostream, &errinfo));

    assert_true(myio_open_ifilestream(&istream_data_to_seal, TEST_DATA_PAYLOAD , &errinfo));

    DEBUG_PRINT(("\nSignature with EC\n"));
    assert_true(gta_authenticate_data_detached(h_ctx,
                              (gtaio_istream_t*)&istream_data_to_seal,
                              ostream,
                              &errinfo));
    DEBUG_PRINT(("\n"));
    assert_int_equal(0, errinfo);

    /* Try to deactivate attribute */
    assert_false(gta_personality_deactivate_attribute(h_ctx, "com.github.generic-trust-anchor-api.keytype.openssl", &errinfo));
    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
    errinfo = 0;

    get_pubkey(h_ctx);
    pers_get_attribute(h_ctx, "com.github.generic-trust-anchor-api.keytype.openssl", 0);
    DEBUG_PRINT(("\n"));
    assert_true(gta_context_close(h_ctx, &errinfo));
    assert_true(myio_close_ifilestream(&istream_data_to_seal, &errinfo));

    /* Test with third personality */
#ifdef ENABLE_PQC
    h_ctx = gta_context_open(test_params->h_inst,
                             get_personality_name(PROF_COM_GITHUB_GENERIC_TRUST_ANCHOR_API_BASIC_DILITHIUM),
                             "com.github.generic-trust-anchor-api.basic.tls",
                             &errinfo);

    assert_non_null(h_ctx);

    assert_true(myio_open_ifilestream(&istream_data_to_seal, TEST_DATA_PAYLOAD , &errinfo));

    DEBUG_PRINT(("\nSignature with Dilithium2\n"));
    assert_true(gta_authenticate_data_detached(h_ctx,
                              (gtaio_istream_t*)&istream_data_to_seal,
                              ostream,
                              &errinfo));
    DEBUG_PRINT(("\n"));
    assert_int_equal(0, errinfo);

    get_pubkey(h_ctx);
    pers_get_attribute(h_ctx, "com.github.generic-trust-anchor-api.keytype.openssl", 0);
    DEBUG_PRINT(("\n"));
    assert_true(gta_context_close(h_ctx, &errinfo));
    assert_true(myio_close_ifilestream(&istream_data_to_seal, &errinfo));

#endif
}

static void identifier_enumerate(void ** state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    struct test_params_t * test_params = (struct test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;
    ostream_to_buf_t ostream_identifier_type = { 0 };
    ostream_to_buf_t ostream_identifier_value = { 0 };
    unsigned char identifier_type[MAXLEN_IDENTIFIER_TYPE] = { 0 };
    unsigned char identifier_value[MAXLEN_IDENTIFIER_VALUE] = { 0 };
    size_t count = 0;
    bool b_loop = true;

    while(b_loop) {
        ostream_to_buf_init(&ostream_identifier_type, (char *)identifier_type, sizeof(identifier_type));
        ostream_to_buf_init(&ostream_identifier_value, (char *)identifier_value, sizeof(identifier_value));

        if (gta_identifier_enumerate(test_params->h_inst, &h_enum, (gtaio_ostream_t*)&ostream_identifier_type, (gtaio_ostream_t*)&ostream_identifier_value, &errinfo)) {
            DEBUG_PRINT(("\n[%zu]\n", count));
            DEBUG_PRINT(("Identifier Type:   %s\n", identifier_type));
            DEBUG_PRINT(("Identifier Value:  %s\n", identifier_value));
            ++count;
        }
        else {
            DEBUG_PRINT(("\n"));
            assert_int_equal(GTA_ERROR_ENUM_NO_MORE_ITEMS, errinfo);
            b_loop = false;
        }
    }
}

static void pers_enumerate(gta_instance_handle_t h_inst, gta_identifier_value_t identifier_value, gta_personality_enum_flags_t flags)
{
    gta_errinfo_t errinfo = 0;
    gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;
    ostream_to_buf_t ostream_personality_name = { 0 };
    unsigned char personality_name[MAXLEN_PERSONALITY_NAME] = { 0 };
    size_t count = 0;
    bool b_loop = true;

    while(b_loop) {
        ostream_to_buf_init(&ostream_personality_name, (char *)personality_name, sizeof(personality_name));

        if (gta_personality_enumerate(h_inst, identifier_value, &h_enum, flags, (gtaio_ostream_t*)&ostream_personality_name, &errinfo)) {
            DEBUG_PRINT(("\n[%zu]\n", count));
            DEBUG_PRINT(("Personality Name:   %s\n", personality_name));
            ++count;
        }
        else {
            DEBUG_PRINT(("\n"));
            assert_int_equal(GTA_ERROR_ENUM_NO_MORE_ITEMS, errinfo);
            b_loop = false;
        }
    }
}

static void personality_enumerate(void ** state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    struct test_params_t * test_params = (struct test_params_t *)(*state);

    DEBUG_PRINT(("\nEnumerate personalities with identifier \"%s\" and GTA_PERSONALITY_ENUM_ALL\n", IDENTIFIER1_VALUE));
    pers_enumerate(test_params->h_inst, IDENTIFIER1_VALUE, GTA_PERSONALITY_ENUM_ALL);

    DEBUG_PRINT(("\nEnumerate personalities with identifier \"%s\" and GTA_PERSONALITY_ENUM_ALL\n", IDENTIFIER2_VALUE));
    pers_enumerate(test_params->h_inst, IDENTIFIER2_VALUE, GTA_PERSONALITY_ENUM_ALL);

    DEBUG_PRINT(("\nEnumerate personalities with identifier \"%s\" and GTA_PERSONALITY_ENUM_ACTIVE\n", IDENTIFIER1_VALUE));
    pers_enumerate(test_params->h_inst, IDENTIFIER1_VALUE, GTA_PERSONALITY_ENUM_ACTIVE);

    DEBUG_PRINT(("\nEnumerate personalities with identifier \"%s\" and GTA_PERSONALITY_ENUM_INACTIVE\n", IDENTIFIER1_VALUE));
    pers_enumerate(test_params->h_inst, IDENTIFIER1_VALUE, GTA_PERSONALITY_ENUM_INACTIVE);
}

static void pers_enumerate_application(gta_instance_handle_t h_inst, gta_application_name_t application_name, gta_personality_enum_flags_t flags)
{
    gta_errinfo_t errinfo = 0;
    gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;
    ostream_to_buf_t ostream_personality_name = { 0 };
    unsigned char personality_name[MAXLEN_PERSONALITY_NAME] = { 0 };
    size_t count = 0;
    bool b_loop = true;

    while(b_loop) {
        ostream_to_buf_init(&ostream_personality_name, (char *)personality_name, sizeof(personality_name));

        if (gta_personality_enumerate_application(h_inst, application_name, &h_enum, flags, (gtaio_ostream_t*)&ostream_personality_name, &errinfo)) {
            DEBUG_PRINT(("\n[%zu]\n", count));
            DEBUG_PRINT(("Personality Name:   %s\n", personality_name));
            ++count;
        }
        else {
            DEBUG_PRINT(("\n"));
            assert_int_equal(GTA_ERROR_ENUM_NO_MORE_ITEMS, errinfo);
            b_loop = false;
        }
    }
}

static void personality_enumerate_application(void ** state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    struct test_params_t * test_params = (struct test_params_t *)(*state);

    DEBUG_PRINT(("\nEnumerate personalities with application name \"%s\" and GTA_PERSONALITY_ENUM_ALL\n", "provider_test"));
    pers_enumerate_application(test_params->h_inst, "provider_test", GTA_PERSONALITY_ENUM_ALL);

    DEBUG_PRINT(("\nEnumerate personalities with application name \"%s\" and GTA_PERSONALITY_ENUM_ACTIVE\n", "provider_test"));
    pers_enumerate_application(test_params->h_inst, "provider_test", GTA_PERSONALITY_ENUM_ACTIVE);

    DEBUG_PRINT(("\nEnumerate personalities with application name \"%s\" and GTA_PERSONALITY_ENUM_INACTIVE\n", "provider_test"));
    pers_enumerate_application(test_params->h_inst, "provider_test", GTA_PERSONALITY_ENUM_INACTIVE);
}

static void personality_attributes_enumerate(void ** state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    struct test_params_t * test_params = (struct test_params_t *)(*state);

    for (int profile_index = 0; profile_index < NUM_PROFILES; ++profile_index) {
        if (profile_creation_supported[profile_index]) {
            pers_attr_enumerate(test_params->h_inst, get_personality_name(profile_index));
        }
    }
}

/*
 * todo: this needs to be refactored. Currently only some basic aspects are
 * tested (e.g., serialization of access policies).
 */
static void access_control(void ** state)
{
    struct test_params_t * test_params = (struct test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;

    myio_ifilestream_t istream_personality_content = { 0 };
    gta_access_policy_handle_t h_auth_use = GTA_HANDLE_INVALID;
    gta_access_policy_handle_t h_auth_admin = GTA_HANDLE_INVALID;
    struct gta_protection_properties_t protection_properties = { 0 };
    gta_context_handle_t h_ctx = GTA_HANDLE_INVALID;

    gta_personality_fingerprint_t fingerprint_1 = {
       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf
    };

    gta_personality_fingerprint_t fingerprint_2 = {
       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    gta_personality_fingerprint_t fingerprint_3 = {
       0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
       0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
       0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
       0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };

    h_auth_use = gta_access_policy_create(test_params->h_inst, &errinfo);
    gta_access_policy_add_pers_derived_access_token_descriptor(h_auth_use, fingerprint_1, "test.profile.1", &errinfo);
    gta_access_policy_add_pers_derived_access_token_descriptor(h_auth_use, fingerprint_2, "test.profile.1", &errinfo);
    gta_access_policy_add_basic_access_token_descriptor(h_auth_use, &errinfo);
    assert_int_not_equal(h_auth_use, GTA_HANDLE_INVALID);

    h_auth_admin = gta_access_policy_create(test_params->h_inst, &errinfo);
    gta_access_policy_add_pers_derived_access_token_descriptor(h_auth_admin, fingerprint_3, "test.profile.1", &errinfo);
    gta_access_policy_add_pers_derived_access_token_descriptor(h_auth_admin, fingerprint_2, "test.profile.1", &errinfo);
    gta_access_policy_add_pers_derived_access_token_descriptor(h_auth_admin, fingerprint_1, "test.profile.2", &errinfo);
    assert_int_not_equal(h_auth_admin, GTA_HANDLE_INVALID);

    assert_true(myio_open_ifilestream(&istream_personality_content, TESTFILE_TXT , &errinfo));

    assert_true(gta_personality_deploy(test_params->h_inst,
        IDENTIFIER1_VALUE,
        "pers_passcode_with_access_token",
        "provider_test",
        "ch.iec.30168.basic.passcode",
        (gtaio_istream_t*)&istream_personality_content,
        h_auth_use,
        h_auth_admin,
        protection_properties,
        &errinfo));

    assert_true(gta_access_policy_destroy(h_auth_admin, &errinfo));
    assert_true(gta_access_policy_destroy(h_auth_use, &errinfo));

    gta_access_token_t access_token;

    /* Open a context to get access personality_derived_access token (todo) */
    assert_non_null(h_ctx = gta_context_open(test_params->h_inst,
                            "pers_passcode_with_access_token",
                            "ch.iec.30168.basic.passcode",
                            &errinfo
                        ));

    assert_false(gta_access_token_get_pers_derived(
                    h_ctx,
                    "pers_passcode_with_access_token",
                    GTA_ACCESS_TOKEN_USAGE_USE,
                    &access_token,
                    &errinfo
                ));

    assert_true(gta_context_auth_set_access_token(
                    h_ctx,
                    (char*) &access_token,
                    &errinfo
                ));

    assert_true(myio_close_ifilestream(&istream_personality_content, &errinfo));
    assert_true(gta_context_close(h_ctx, &errinfo));
}

static void access_policies_and_access_tokens(void ** state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    struct test_params_t * test_params = (struct test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_context_handle_t h_ctx = GTA_HANDLE_INVALID;
    gta_access_policy_handle_t h_auth_use = GTA_HANDLE_INVALID;
    gta_access_policy_handle_t h_auth_admin = GTA_HANDLE_INVALID;
    struct gta_protection_properties_t protection_properties = { 0 };
    gta_personality_fingerprint_t fingerprint = { 0 };

    h_auth_use = gta_access_policy_create(test_params->h_inst, &errinfo);
    gta_access_policy_add_basic_access_token_descriptor(h_auth_use, &errinfo);
    gta_access_policy_add_pers_derived_access_token_descriptor(h_auth_use, fingerprint, "todo", &errinfo);
    assert_int_not_equal(h_auth_use, GTA_HANDLE_INVALID);
    assert_int_equal(0, errinfo);

    h_auth_admin = gta_access_policy_simple(test_params->h_inst, GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN, &errinfo);
    assert_int_not_equal(h_auth_use, GTA_HANDLE_INVALID);
    assert_int_equal(0, errinfo);

    /* Physical presence policy not allowed for personalities (auth_use, auth_admin) */
    assert_false(gta_personality_create(test_params->h_inst,
                                        IDENTIFIER2_VALUE,
                                        "local_data_prot_access_control",
                                        "local_data_protection",
                                        "ch.iec.30168.basic.local_data_protection",
                                        h_auth_use,
                                        h_auth_admin,
                                        protection_properties,
                                        &errinfo));
    assert_int_equal(GTA_ERROR_ACCESS_POLICY, errinfo);
    errinfo = 0;
    h_auth_admin = h_auth_use;

    assert_true(gta_personality_create(test_params->h_inst,
                                       IDENTIFIER2_VALUE,
                                       "local_data_prot_access_control",
                                       "local_data_protection",
                                       "ch.iec.30168.basic.local_data_protection",
                                       h_auth_use,
                                       h_auth_admin,
                                       protection_properties,
                                       &errinfo));
    assert_int_equal(0, errinfo);

    assert_true(gta_access_policy_destroy(h_auth_use, &errinfo));

    h_ctx = gta_context_open(test_params->h_inst,
                             "local_data_prot_access_control",
                             "ch.iec.30168.basic.local_data_protection",
                             &errinfo);

    assert_non_null(h_ctx);
    assert_int_equal(0, errinfo);

    const char * test_input = "test";
    istream_from_buf_t istream = { 0 };

    gtaio_ostream_t ostream_null = { 0 };
    ostream_null.write = (gtaio_stream_write_t)ostream_null_write;
    ostream_null.finish = (gtaio_stream_finish_t)ostream_finish;

    istream_from_buf_init(&istream, test_input, strlen(test_input));
    assert_false(gta_seal_data(h_ctx, (gtaio_istream_t*)&istream, &ostream_null, &errinfo));
    assert_int_equal(GTA_ERROR_ACCESS, errinfo);
    errinfo = 0;

    gta_access_token_t invalid_granting_token = { 0 };
    gta_access_token_t access_token = { 0 };
    gta_access_token_t invalid_access_token = { 0 };

    assert_false(gta_access_token_get_basic(test_params->h_inst, invalid_granting_token, "local_data_prot_access_control", GTA_ACCESS_TOKEN_USAGE_USE, access_token, &errinfo));
    assert_int_equal(GTA_ERROR_ACCESS, errinfo);
    errinfo = 0;

    assert_false(gta_access_token_get_basic(test_params->h_inst, test_params->granting_token, "invalid personality", GTA_ACCESS_TOKEN_USAGE_USE, access_token, &errinfo));
    assert_int_equal(GTA_ERROR_ITEM_NOT_FOUND, errinfo);
    errinfo = 0;

    assert_true(gta_access_token_get_basic(test_params->h_inst, test_params->granting_token, "local_data_prot_access_control", GTA_ACCESS_TOKEN_USAGE_USE, access_token, &errinfo));
    assert_int_equal(0, errinfo);

    /* Add valid, but unnecessary access token to context (increase coverage) */
    assert_true(gta_context_auth_set_access_token(h_ctx, test_params->physical_presence_token, &errinfo));
    assert_int_equal(0, errinfo);

    /* Add invalid access token to context (increase coverage) */
    assert_true(gta_context_auth_set_access_token(h_ctx, invalid_access_token, &errinfo));
    assert_int_equal(0, errinfo);

    istream_from_buf_init(&istream, test_input, strlen(test_input));
    assert_false(gta_seal_data(h_ctx, (gtaio_istream_t*)&istream, &ostream_null, &errinfo));
    assert_int_equal(GTA_ERROR_ACCESS, errinfo);
    errinfo = 0;

    assert_true(gta_context_auth_set_access_token(h_ctx, access_token, &errinfo));
    assert_int_equal(0, errinfo);

    istream_from_buf_init(&istream, test_input, strlen(test_input));
    assert_true(gta_seal_data(h_ctx, (gtaio_istream_t*)&istream, &ostream_null, &errinfo));
    assert_int_equal(0, errinfo);

    assert_false(gta_access_token_revoke(test_params->h_inst, invalid_granting_token, &errinfo));
    assert_int_equal(GTA_ERROR_ACCESS, errinfo);
    errinfo = 0;

    assert_true(gta_access_token_revoke(test_params->h_inst, access_token, &errinfo));
    assert_int_equal(0, errinfo);

    istream_from_buf_init(&istream, test_input, strlen(test_input));
    assert_false(gta_seal_data(h_ctx, (gtaio_istream_t*)&istream, &ostream_null, &errinfo));
    assert_int_equal(GTA_ERROR_ACCESS, errinfo);
    errinfo = 0;

    assert_true(gta_context_close(h_ctx, &errinfo));
    assert_int_equal(0, errinfo);

    /* Create another personality */
    h_auth_use = gta_access_policy_create(test_params->h_inst, &errinfo);
    gta_access_policy_add_pers_derived_access_token_descriptor(h_auth_use, fingerprint, "todo", &errinfo);
    assert_int_not_equal(h_auth_use, GTA_HANDLE_INVALID);
    assert_int_equal(0, errinfo);

    h_auth_admin = gta_access_policy_simple(test_params->h_inst, GTA_ACCESS_DESCRIPTOR_TYPE_BASIC_TOKEN, &errinfo);
    assert_int_not_equal(h_auth_use, GTA_HANDLE_INVALID);
    assert_int_equal(0, errinfo);

    assert_true(gta_personality_create(test_params->h_inst,
                                       IDENTIFIER2_VALUE,
                                       "ec_access_control",
                                       "access control",
                                       "com.github.generic-trust-anchor-api.basic.ec",
                                       h_auth_use,
                                       h_auth_admin,
                                       protection_properties,
                                       &errinfo));
    assert_int_equal(0, errinfo);
    assert_true(gta_access_policy_destroy(h_auth_use, &errinfo));

    h_ctx = gta_context_open(test_params->h_inst,
        "ec_access_control",
        "com.github.generic-trust-anchor-api.basic.tls",
        &errinfo);

    assert_non_null(h_ctx);
    assert_int_equal(0, errinfo);

    assert_true(gta_access_token_get_basic(test_params->h_inst, test_params->granting_token, "local_data_prot_access_control", GTA_ACCESS_TOKEN_USAGE_USE, access_token, &errinfo));
    assert_int_equal(0, errinfo);

    assert_true(gta_context_auth_set_access_token(h_ctx, access_token, &errinfo));
    assert_int_equal(0, errinfo);

    assert_true(gta_access_token_get_basic(test_params->h_inst, test_params->granting_token, "ec_access_control", GTA_ACCESS_TOKEN_USAGE_USE, access_token, &errinfo));
    assert_int_equal(0, errinfo);

    assert_true(gta_context_auth_set_access_token(h_ctx, access_token, &errinfo));
    assert_int_equal(0, errinfo);

    istream_from_buf_init(&istream, test_input, strlen(test_input));
    assert_false(gta_authenticate_data_detached(h_ctx, (gtaio_istream_t*)&istream, &ostream_null, &errinfo));
    assert_int_equal(GTA_ERROR_ACCESS, errinfo);
    errinfo = 0;

    assert_false(gta_personality_add_trusted_attribute(h_ctx, "ch.iec.30168.trustlist.certificate.trusted.x509v3", "Dummy EE Cert trusted", (gtaio_istream_t *)&istream, &errinfo));
    assert_int_equal(GTA_ERROR_ACCESS, errinfo);
    errinfo = 0;

    assert_true(gta_access_token_get_basic(test_params->h_inst, test_params->granting_token, "ec_access_control", GTA_ACCESS_TOKEN_USAGE_ADMIN, access_token, &errinfo));
    assert_int_equal(0, errinfo);

    assert_true(gta_context_auth_set_access_token(h_ctx, access_token, &errinfo));
    assert_int_equal(0, errinfo);

    assert_true(gta_personality_add_trusted_attribute(h_ctx, "ch.iec.30168.trustlist.certificate.trusted.x509v3", "Dummy EE Cert trusted", (gtaio_istream_t *)&istream, &errinfo));
    assert_int_equal(0, errinfo);

    assert_true(gta_context_close(h_ctx, &errinfo));
    assert_int_equal(0, errinfo);

    /* Revoke some access tokens */
    assert_true(gta_access_token_revoke(test_params->h_inst, test_params->physical_presence_token, &errinfo));
    assert_int_equal(0, errinfo);

    assert_false(gta_access_token_revoke(test_params->h_inst, test_params->physical_presence_token, &errinfo));
    assert_int_equal(GTA_ERROR_ACCESS, errinfo);
    errinfo = 0;

    assert_true(gta_access_token_revoke(test_params->h_inst, test_params->granting_token, &errinfo));
    assert_int_equal(0, errinfo);

    assert_false(gta_access_token_revoke(test_params->h_inst, test_params->granting_token, &errinfo));
    assert_int_equal(GTA_ERROR_ACCESS, errinfo);
    errinfo = 0;

    assert_false(gta_access_token_get_basic(test_params->h_inst, test_params->granting_token, "local_data_prot_access_control", GTA_ACCESS_TOKEN_USAGE_USE, access_token, &errinfo));
    assert_int_equal(GTA_ERROR_ACCESS, errinfo);
    errinfo = 0;
}

/*
 * This tests creates a new instance to test the deserialization of the previous
 * state.
 */
static void provider_deserialize(void ** state)
{
    DEBUG_PRINT(("gta_sw_provider tests: %s\n", __func__));
    gta_errinfo_t errinfo = 0;
    gta_instance_handle_t h_inst = GTA_HANDLE_INVALID;

    struct gta_instance_params_t inst_params = {
        NULL,
        {
            .calloc = &calloc,
            .free = &free,
            .mutex_create  = NULL,
            .mutex_destroy = NULL,
            .mutex_lock    = NULL,
            .mutex_unlock  = NULL,
        },
        NULL
    };
    istream_from_buf_t init_config = { 0 };
    istream_from_buf_init(&init_config, DIRECTORY_CLEAN_STATE, sizeof(DIRECTORY_CLEAN_STATE) - 1);

    h_inst = gta_instance_init(&inst_params, &errinfo);
    assert_non_null(h_inst);

    /* register a profile to trigger deserialization */
    assert_true(gta_sw_provider_gta_register_provider(h_inst, (gtaio_istream_t*)&init_config, supported_profiles[1], &errinfo));
    assert_int_equal(0, errinfo);

    assert_true(gta_instance_final(h_inst, &errinfo));
}

/*-----------------------------------------------------------------------------
 * group tests
 */
int ts_gta_sw_provider(void)
{
    const struct CMUnitTest gta_sw_provider_tests[] = {
        /* Tests for physical presence and issuing token */
        cmocka_unit_test(get_physical_presence_and_issuing_token),
        /* Tests for gta_identifier assign */
        cmocka_unit_test(identifier_assign),
        /* Tests profile spec vs impl support */
        cmocka_unit_test(profile_spec_create),

        /* Tests for the mandatory profiles */
        cmocka_unit_test(profile_local_data_protection),
        /* Tests for creation / deployment profiles only */
        cmocka_unit_test(profile_passcode),

        /* Tests for creation / deployment / enrollment / usage profiles */
        /* Tests for usage profiles only */
        cmocka_unit_test(profile_jwt),
        cmocka_unit_test(profile_tls),
        /* Additional tests for mandatory provider functions */
        cmocka_unit_test(identifier_enumerate),
        cmocka_unit_test(personality_enumerate),
        cmocka_unit_test(personality_enumerate_application),
        cmocka_unit_test(personality_attributes_enumerate),
        /* Tests for access control (may be temporary) */
        // cmocka_unit_test(access_control),
        cmocka_unit_test(access_policies_and_access_tokens),
        /* Tests for persistent storage */
        cmocka_unit_test(provider_deserialize),
    };

    return cmocka_run_group_tests_name(
                                  "gta-api-sw-provider_tests",
                                  gta_sw_provider_tests,
                                  init_suite_gta_sw_provider_clean_state,
                                  clean_suite_gta_sw_provider);
}

int main(void)
{
    int result = 0;
    result |= ts_gta_sw_provider();
    return result;
}

