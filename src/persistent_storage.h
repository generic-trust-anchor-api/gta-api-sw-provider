/*
 * SPDX-FileCopyrightText: Copyright 2024-2026 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PROVIDER_MOCKUP_GTA_PROVIDER_PERSISTENT_STORAGE_NEW_H_
#define PROVIDER_MOCKUP_GTA_PROVIDER_PERSISTENT_STORAGE_NEW_H_

#include "gta_sw_provider.h"
#include <gta_api/gta_api.h>
#include <stdbool.h>

bool serialized_file_exists(const char * se_dir);

bool provider_serialize(const char * se_dir, struct gta_sw_provider_params_t * provider_params);

bool provider_serialize_init(const char * se_dir, struct gta_sw_provider_params_t * provider_params);

bool provider_deserialize(const char * se_dir, struct gta_sw_provider_params_t * provider_params);

#endif /* PROVIDER_MOCKUP_GTA_PROVIDER_PERSISTENT_STORAGE_NEW_H_ */
