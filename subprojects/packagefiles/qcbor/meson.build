#;**********************************************************************;
# SPDX-License-Identifier: MPL-2.0
#
# Copyright (c) 2024, Siemens AG
#
#;**********************************************************************;

project('QCBOR',
    ['c'],
    default_options : [     # TODO can be overwritten by override_options in specific build targets
        'c_std=gnu99',      # TODO building openssl requires gnu extensions, setting it in "subproject" does not work
        'warning_level=3',  # highest warning level
        'buildtype=plain',
    ],
    meson_version: '>=0.56.0',
    version: '1.2',
)

qcbor_files = files (
  './src/qcbor_decode.c',
  './src/qcbor_encode.c',
  './src/qcbor_err_to_str.c',
  './src/UsefulBuf.c',
  )

qcbor_include = include_directories( './inc', )

libqcbor = static_library('qcbor_static',
              qcbor_files,
              include_directories: [qcbor_include,],
              c_args : ['-DNDEBUG',
                        '-DQCBOR_DISABLE_FLOAT_HW_USE',
                        '-DUSEFULBUF_DISABLE_ALL_FLOAT',
                       ],
)

qcbor_dep = declare_dependency(
  link_with : libqcbor,
  include_directories : qcbor_include,
  version : meson.project_version(),
)

