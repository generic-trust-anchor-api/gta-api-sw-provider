# SPDX-FileCopyrightText: Copyright 2024-2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

gta_sw_provider_files = files (
  'gta_sw_provider.c',
  'persistent_storage.c',
  'provider_data_model.c',
  'key_management.c',
  'profiles/prof_ch_iec_30168_basic_passcode.c',
  'profiles/prof_ch_iec_30168_basic_local_data_integrity_only.c',
  'profiles/prof_ch_iec_30168_basic_local_data_protection.c',
  'profiles/prof_com_github_generic_trust_anchor_api_basic_rsa.c',
  'profiles/prof_com_github_generic_trust_anchor_api_basic_ec.c',
  'profiles/prof_com_github_generic_trust_anchor_api_basic_dilithium.c',
  'profiles/prof_com_github_generic_trust_anchor_api_basic_jwt.c',
  'profiles/prof_com_github_generic_trust_anchor_api_basic_signature.c',
  'profiles/prof_com_github_generic_trust_anchor_api_basic_enroll.c',
  'profiles/prof_helper_functions.c',
  'profiles/prof_org_opcfoundation_ecc_nistp256.c'  
  )

build_dep = [ dep_libcrypto,
              dep_qcbor,
              dep_t_cose,
              dep_gta_core,
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

pkg = import('pkgconfig')
pkg.generate(libraries : [gta_sw_provider_static],
             version : meson.project_version(),
             name : 'libgta_sw_provider',
             description : 'Generic Trust Anchor API SW Provider')