#;**********************************************************************;
# SPDX-License-Identifier: MPL-2.0
#
# Copyright (c) 2024, Siemens AG
#
#;**********************************************************************;

gta_sw_provider_files = files (
  'gta_sw_provider.c',
  'persistent_storage.c',
  'provider_data_model.c',
  'key_management.c'
  )

build_dep = [ dep_libcrypto,
              dep_qcbor,
              dep_t_cose,
            ]

if enable_pqc
    build_dep += [ dep_liboqs,
                 ]
endif

gta_sw_provider_static = static_library('gta_sw_provider',
    gta_sw_provider_files,
    dependencies : build_dep,
          c_args : ['-DNDEBUG',
                   ],
    install: true
)

