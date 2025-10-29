/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#include "key_management.h"

#include <string.h>

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
