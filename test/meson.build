#;**********************************************************************;
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2024, Siemens AG
#
#;**********************************************************************;

gta_test_files = files(
  'main.c',
  'myio_filestream.c',
)

build_dep = [ dep_cmocka,
              dep_libcrypto,
              dep_gta_core,
            ]

if enable_pqc
    build_dep += [ dep_liboqs,
                 ]
endif

gta_provider_test = executable(
    'gta_provider_test',
    gta_test_files,
    dependencies : build_dep,
    link_with : [ gta_sw_provider_static,
                ],
)

test_output_dir = 'CMOCKA_XML_FILE=' + meson.current_build_dir() + '/%g.xml'

test(
    'gta_provider_test',
    gta_provider_test,
    env: [ test_output_dir,
           'CMOCKA_MESSAGE_OUTPUT=XML',
     ],
)

