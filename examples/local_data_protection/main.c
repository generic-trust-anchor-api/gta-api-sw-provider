/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#include "myio_filestream.h"
#include <dirent.h>
#include <gta_api/gta_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Default directory for SW provider state */
static char * STATE_DIR_DEFAULT = "./sw_provider_state";

/*
 * Provider initialization function exported by the provider to implement
 * gta_provider_init_t
 */
extern const struct gta_function_list_t * gta_sw_provider_init(
    gta_context_handle_t,
    gtaio_istream_t *,
    gtaio_ostream_t *,
    void **,
    void (**)(void *),
    gta_errinfo_t *);

/* gtaio_istream implementation to read from a temporary buffer */
typedef struct istream_from_buf {
    /* public interface as defined for gtaio_istream */
    gtaio_stream_read_t read;
    gtaio_stream_eof_t eof;
    void * p_reserved2;
    void * p_reserved3;

    /* private implementation details */
    char * buf;      /* data buffer */
    size_t buf_size; /* data buffer size */
    size_t buf_pos;  /* current position in data buffer */
} istream_from_buf_t;

/* Forward declaration of helper functions */
static bool create_gta_instance(gta_instance_handle_t * h_inst, char * p_state_dir);
static void print_usage(char * name);
static void istream_from_buf_init(istream_from_buf_t * istream, char * buf, size_t buf_size);
static size_t istream_from_buf_read(istream_from_buf_t * istream, char * data, size_t len, gta_errinfo_t * p_errinfo);
static bool istream_from_buf_eof(istream_from_buf_t * istream, gta_errinfo_t * p_errinfo);

int main(int argc, char * argv[])
{
    /*
     * Read the environment variable SW_PROVIDER_STATE_DIR if existing,
     * otherwise set a default directory to store the state.
     */
    char * p_state_dir_env = getenv("SW_PROVIDER_STATE_DIR");
    char * p_state_dir = NULL;
    DIR * dir = NULL;
    bool b_ret = false;
    gta_instance_handle_t h_inst = GTA_HANDLE_INVALID;
    gta_context_handle_t h_ctx = GTA_HANDLE_INVALID;
    gta_access_policy_handle_t h_auth = GTA_HANDLE_INVALID;
    struct gta_protection_properties_t protection_properties = {0};
    gta_errinfo_t errinfo = 0;

    /* Setup streams for input (stdin) and output (stdout) */
    myio_ifilestream_t istream = {0};
    istream.read = (gtaio_stream_read_t)myio_ifilestream_read;
    istream.eof = (gtaio_stream_eof_t)myio_ifilestream_eof;
    istream.file = stdin;

    myio_ofilestream_t ostream = {0};
    ostream.write = (gtaio_stream_write_t)myio_ofilestream_write;
    ostream.finish = (gtaio_stream_finish_t)myio_ofilestream_finish;
    ostream.file = stdout;

    if (NULL != p_state_dir_env) {
        p_state_dir = p_state_dir_env;
    } else {
        p_state_dir = STATE_DIR_DEFAULT;
    }

    /* Check command line arguments */
    if (argc != 2) {
        print_usage(argv[0]);
        goto cleanup;
    }

    if (0 == strcmp(argv[1], "init")) {
        /*
         * Check whether the state directory already exists. If yes, empty it,
         * otherwise create the directory.
         */
        dir = opendir(p_state_dir);
        if (NULL != dir) {
            printf("Delete existing GTA API state\n");
            struct dirent * entry;
            while (NULL != (entry = readdir(dir))) {
                if (DT_REG == entry->d_type) {
                    char file_path[1024];
                    snprintf(file_path, sizeof(file_path), "%s/%s", p_state_dir, entry->d_name);
                    if (0 != remove(file_path)) {
                        fprintf(stderr, "Error: Removing existing state failed!\n");
                        closedir(dir);
                        goto cleanup;
                    }
                }
            }
            closedir(dir);
        } else {
            printf("Create GTA API state directory\n");
            if (0 != mkdir(p_state_dir, 0755)) {
                fprintf(stderr, "Error: Creating state directory failed!\n");
                goto cleanup;
            }
        }

        /* Initialize GTA API (only needed once per application) */
        if (!create_gta_instance(&h_inst, p_state_dir)) {
            fprintf(stderr, "Error: Creating a GTA API instance failed!\n");
            goto cleanup;
        }

        /*
         * Create a device local personality
         */
        printf("Create a device local personality\n");
        if (!gta_identifier_assign(h_inst, "ch.iec.30168.identifier.generic", "local", &errinfo)) {
            fprintf(stderr, "Error: gta_identifier_assign failed!\n");
            goto cleanup;
        }

        h_auth = gta_access_policy_simple(h_inst, GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL, &errinfo);
        if (GTA_HANDLE_INVALID == h_auth) {
            fprintf(stderr, "Error: gta_access_policy_simple failed!\n");
            goto cleanup;
        }

        if (!gta_personality_create(
                h_inst,
                "local",
                "local-pers",
                "local-application",
                "ch.iec.30168.basic.local_data_protection",
                h_auth,
                h_auth,
                protection_properties,
                &errinfo)) {

            fprintf(stderr, "Error: gta_personality_create failed!\n");
            goto cleanup;
        }
        printf("Done!\n");
        b_ret = true;
    } else if (0 == strcmp(argv[1], "seal")) {
        /* Initialize GTA API (only needed once per application) */
        if (!create_gta_instance(&h_inst, p_state_dir)) {
            fprintf(stderr, "Error: Creating a GTA API instance failed!\n");
            goto cleanup;
        }

        /* Open context for "ch.iec.30168.basic.local_data_protection" profile */
        h_ctx = gta_context_open(h_inst, "local-pers", "ch.iec.30168.basic.local_data_protection", &errinfo);
        if (NULL == h_ctx) {
            fprintf(stderr, "Error: gta_context_open failed!\n");
            goto cleanup;
        }

        /* Seal data with "ch.iec.30168.basic.local_data_protection" */
        if (!gta_seal_data(h_ctx, (gtaio_istream_t *)&istream, (gtaio_ostream_t *)&ostream, &errinfo)) {
            fprintf(stderr, "Error: gta_seal_data failed!\n");
            goto cleanup;
        }
        /* Note: `gta_context_close()` is called next (see cleanup) */
        b_ret = true;
    } else if (0 == strcmp(argv[1], "unseal")) {
        /* Initialize GTA API (only needed once per application) */
        if (!create_gta_instance(&h_inst, p_state_dir)) {
            fprintf(stderr, "Error: Creating a GTA API instance failed!\n");
            goto cleanup;
        }

        /* Open context for "ch.iec.30168.basic.local_data_protection" profile */
        h_ctx = gta_context_open(h_inst, "local-pers", "ch.iec.30168.basic.local_data_protection", &errinfo);
        if (NULL == h_ctx) {
            fprintf(stderr, "Error: gta_context_open failed!\n");
            goto cleanup;
        }

        /* Unseal data with "ch.iec.30168.basic.local_data_protection" */
        if (!gta_unseal_data(h_ctx, (gtaio_istream_t *)&istream, (gtaio_ostream_t *)&ostream, &errinfo)) {
            fprintf(stderr, "Error: gta_unseal_data failed!\n");
            goto cleanup;
        }

        /* Note: `gta_context_close()` is called next (see cleanup) */
        b_ret = true;
    } else {
        fprintf(stderr, "Error: Command line argument unsupported!\n");
        print_usage(argv[0]);
        goto cleanup;
    }

cleanup:

    if (GTA_HANDLE_INVALID != h_ctx) {
        gta_context_close(h_ctx, &errinfo);
    }
    if (GTA_HANDLE_INVALID != h_inst) {
        gta_instance_final(h_inst, &errinfo);
    }
    return b_ret;
}

/* Helper function for GTA API initialization */
bool create_gta_instance(gta_instance_handle_t * h_inst, char * p_state_dir)
{
    gta_errinfo_t errinfo = 0;
    bool b_ret = false;

    /* Initialization parameters for GTA API */
    struct gta_instance_params_t inst_params = {
        NULL, /* global_mutex */
        {
            /* os functions */
            .calloc = &calloc,
            .free = &free,
            /* no multithreading */
            .mutex_create = NULL,
            .mutex_destroy = NULL,
            .mutex_lock = NULL,
            .mutex_unlock = NULL,
        },
        NULL /* logging */
    };

    istream_from_buf_t init_config = {0};
    struct gta_provider_info_t provider_info = {
        .version = 0,
        .type = GTA_PROVIDER_INFO_CALLBACK,
        .provider_init = gta_sw_provider_init,
        .provider_init_config = (gtaio_istream_t *)&init_config,
        .profile_info = {
            .profile_name = "ch.iec.30168.basic.local_data_protection", .protection_properties = {0}, .priority = 0}};

    /* Create GTA API instance to be used by this application */
    *h_inst = gta_instance_init(&inst_params, &errinfo);
    if (GTA_HANDLE_INVALID == *h_inst) {
        goto cleanup;
    }

    istream_from_buf_init(&init_config, p_state_dir, strlen(p_state_dir));

    /* Register profile for "ch.iec.30168.basic.local_data_protection" */
    b_ret = gta_register_provider(*h_inst, &provider_info, &errinfo);

cleanup:
    return b_ret;
}

void print_usage(char * name)
{
    printf("--- Usage ---\n");
    printf("Initialization of gta-api-sw-provider state:\n");
    printf("%s init\n", name);
    printf("\nSeal data using ch.iec.30168.basic.local_data_protection:\n");
    printf("%s seal\n", name);
    printf("\nUnseal data using ch.iec.30168.basic.local_data_protection:\n");
    printf("%s unseal\n", name);
}

/*
 * Stream functions to read the input from a temporary buffer.
 */
static size_t istream_from_buf_read(istream_from_buf_t * istream, char * data, size_t len, gta_errinfo_t * p_errinfo)
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

static bool istream_from_buf_eof(istream_from_buf_t * istream, gta_errinfo_t * p_errinfo)
{
    /* Return true if we are at the end of the buffer */
    return (istream->buf_pos == istream->buf_size);
}

static void istream_from_buf_init(istream_from_buf_t * istream, char * buf, size_t buf_size)
{
    istream->read = (gtaio_stream_read_t)istream_from_buf_read;
    istream->eof = (gtaio_stream_eof_t)istream_from_buf_eof;
    istream->buf = buf;
    istream->buf_size = buf_size;
    istream->buf_pos = 0;
}