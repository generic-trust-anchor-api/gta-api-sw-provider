/*
 * SPDX-FileCopyrightText: Copyright 2024-2026 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef KEY_MANAGEMENT_H
#define KEY_MANAGEMENT_H

#include <gta_api/gta_api.h>
#include <stdbool.h>
#include <stdint.h>

#define HUK_SIZE_32 32

struct hw_unique_key_32 {
    uint8_t data[HUK_SIZE_32];
};

bool get_hw_unique_key_32(struct hw_unique_key_32 * key);

bool init_monotonic_counter(gta_context_handle_t h_ctx, unsigned char ** metadata, size_t * metadata_len);
bool read_monotonic_counter(unsigned char * metadata, size_t metadata_len, uint64_t * counter_value);
bool increment_monotonic_counter(unsigned char * metadata, size_t metadata_len);

#endif /* KEY_MANAGEMENT_H */
