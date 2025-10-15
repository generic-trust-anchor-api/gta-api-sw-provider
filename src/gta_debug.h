/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#ifndef GTA_DEBUG_H
#define GTA_DEBUG_H

#include <stdio.h>

#ifdef NDEBUG
#define DEBUG_PRINT(msg)
#else
#define DEBUG_PRINT(msg)                                                                                               \
    do {                                                                                                               \
        printf msg;                                                                                                    \
    } while (0)
#endif

#endif /* GTA_DEBUG_H */
