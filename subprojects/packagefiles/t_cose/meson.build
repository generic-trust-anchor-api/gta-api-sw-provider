# SPDX-FileCopyrightText: Copyright 2024 Siemens
#
# SPDX-License-Identifier: Apache-2.0

project('t_cose',
    ['c'],
    default_options : [     # TODO can be overwritten by override_options in specific build targets
        'c_std=gnu99',      # TODO building openssl requires gnu extensions, setting it in "subproject" does not work
        'warning_level=3',  # highest warning level
        'buildtype=plain',
    ],
    meson_version: '>=0.56.0',
    version: '1.2',
)

t_cose_files = files (
  './src/t_cose_encrypt_dec.c',
  './src/t_cose_encrypt_enc.c',
  './src/t_cose_key.c',
  './src/t_cose_mac_compute.c',
  './src/t_cose_mac_validate.c',
  './src/t_cose_parameters.c',
  './src/t_cose_qcbor_gap.c',
  './src/t_cose_recipient_dec_esdh.c',
  './src/t_cose_recipient_dec_keywrap.c',
  './src/t_cose_recipient_enc_esdh.c',
  './src/t_cose_recipient_enc_keywrap.c',
  './src/t_cose_sign_sign.c',
  './src/t_cose_sign_verify.c',
  './src/t_cose_sign1_sign.c',
  './src/t_cose_sign1_verify.c',
  './src/t_cose_signature_sign_eddsa.c',
  './src/t_cose_signature_sign_main.c',
  './src/t_cose_signature_sign_restart.c',
  './src/t_cose_signature_verify_eddsa.c',
  './src/t_cose_signature_verify_main.c',
  './src/t_cose_util.c',
  './crypto_adapters/t_cose_openssl_crypto.c',
)

t_cose_include = include_directories(
                                      './inc', 
                                      './src',
                                    )

if get_option('build-dependencies')
   # Build libcrypto and qcbor locally
   openssl_proj   = subproject('openssl', default_options : ['c_std=gnu99', 'default_library=static',] )
   dep_libcrypto  = openssl_proj.get_variable('libcrypto_dep')
   qcbor_proj     = subproject('qcbor')
   dep_qcbor      = qcbor_proj.get_variable('qcbor_dep')
else
   # Use OpenSSL from the OS
   dep_libcrypto = dependency('libcrypto', static: true)
   # TODO: currently qcbor is still handled by the build system because there
   # are no official distribution packages available. When it becomes easier
   # to install qcbor on the OS, this should also be handled by globally
   # installed libraries
   qcbor_proj     = subproject('qcbor')
   dep_qcbor      = qcbor_proj.get_variable('qcbor_dep')
endif


libtcose = static_library('t_cose_static',
              t_cose_files,
              include_directories: [t_cose_include,],
              dependencies : [ dep_libcrypto,
                               dep_qcbor,
                             ],
                    c_args : ['-DNDEBUG',
                              '-DT_COSE_USE_OPENSSL_CRYPTO',
                             ],

)

t_cose_dep = declare_dependency(
  link_with : libtcose,
  include_directories : t_cose_include,
  version : meson.project_version(),
)

