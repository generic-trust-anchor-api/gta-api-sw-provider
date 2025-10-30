/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PROF_HELPER_FUNCTIONS_H
#define PROF_HELPER_FUNCTIONS_H

#include <gta_api/gta_api.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#define CHUNK_LEN 512
#define CURVENAME_LENGTH_MAX 64

/*
 * Helper function, returning the number of bits of a private key.
 * It is intended to be used in order to check if the properties
 * of a personality matches the expectations of a profile.
 */
int pkey_bits(const EVP_PKEY * evp_private_key);

/*
 * Helper function, returning the OpenSSL curve NID of an EC private key.
 * It is intended to be used in order to check if the properties
 * of a personality matches the expectations of a profile.
 * Returns 0 in case of error.
 */
int pkey_ec_nid(const EVP_PKEY * evp_private_key);

/* Helper function, returning an OpenSSL EVP_PKEY from DER encoded buffer. */
EVP_PKEY * get_pkey_from_der(unsigned char * p_der_content, const size_t der_size, gta_errinfo_t * p_errinfo);

/* Helper function to read the whole input from gtaio_istream_t into a buffer */
bool read_input_buffer(
    gtaio_istream_t * data,
    unsigned char ** pp_data,
    size_t * p_data_size,
    gta_errinfo_t * p_errinfo);

#endif // PROF_HELPER_FUNCTIONS_H
