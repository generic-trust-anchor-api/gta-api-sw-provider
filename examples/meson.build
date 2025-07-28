#;**********************************************************************;
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2024, Siemens AG
#
#;**********************************************************************;

example_local_data_protection_files = files(
  './local_data_protection/main.c',
  './local_data_protection/myio_filestream.c',
)

build_dep = [ dep_gta_core,
            ]

if build_examples
    example_local_data_protection = executable(
        'local_data_protection',
        example_local_data_protection_files,
        dependencies : build_dep,
        link_with : [ gta_sw_provider_static,
                    ],
    )
endif
