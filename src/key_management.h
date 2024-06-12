/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#ifndef KEY_MANAGEMENT_H
#define KEY_MANAGEMENT_H

#include <stdbool.h>
#include <stdint.h>

#define HUK_SIZE_32 32

struct hw_unique_key_32 {
    uint8_t data[HUK_SIZE_32];
};

bool get_hw_unique_key_32(struct hw_unique_key_32 *key);

#endif /* KEY_MANAGEMENT_H */
