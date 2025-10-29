/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#ifndef PROVIDER_MOCKUP_GTA_PROVIDER_PERSISTENT_STORAGE_NEW_H_
#define PROVIDER_MOCKUP_GTA_PROVIDER_PERSISTENT_STORAGE_NEW_H_

#include "gta_sw_provider.h"
#include <gta_api/gta_api.h>
#include <stdbool.h>

bool serialized_file_exists(const char * se_dir);

bool provider_serialize(const char * se_dir, struct devicestate_stack_item_t * p_devicestate_stack);

bool provider_deserialize(
    const char * se_dir,
    struct devicestate_stack_item_t ** pp_devicestate_stack,
    gta_context_handle_t h_ctx);

#endif /* PROVIDER_MOCKUP_GTA_PROVIDER_PERSISTENT_STORAGE_NEW_H_ */
