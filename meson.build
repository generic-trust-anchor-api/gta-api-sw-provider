#;**********************************************************************;
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2024, Siemens AG
#
#;**********************************************************************;

# Global project definition for GTA API implementation
project('Generic Trust Anchor API SW Provider',
    ['c'],
    default_options : [     # TODO can be overwritten by override_options in specific build targets
        'c_std=gnu99',      # TODO building openssl requires gnu extensions, setting it in "subproject" does not work
        'warning_level=3',  # highest warning level
        'buildtype=plain',
    ],
    license: 'Apache-2.0',
    meson_version: '>=0.56.0',
    version: '0.2'
)

# Specify global compiler options
c_compiler = meson.get_compiler('c')
add_project_arguments(
  c_compiler.get_supported_arguments(
     '-Wextra',
     '-Wpedantic',
     '-Wno-unused-function',  # TODO check if supressing this warning is a good idea
     '-Wno-unused-parameter', # TODO check if supressing this warning is a good idea
  ),
  language: 'c'
)

# Get custom build options from meson_options.txt
build_type = get_option('build')
build_dep = get_option('build-dependencies')
disable_deprecated = get_option('disable-deprecated-warnings')
enable_pqc = get_option('enable-post-quantum-crypto')
enable_test_log = get_option('enable-test-log')
build_examples = get_option('build-examples')

# TODO consider to use more generic override_options for build targets
if build_type == 'release'
add_project_arguments(
   c_compiler.get_supported_arguments(
      '-O2',
   ),
   language: 'c'
)
elif build_type == 'debug'
add_project_arguments(
   c_compiler.get_supported_arguments(
      '-O0',
      '-g',
   ),
   language: 'c'
)
endif

# Get target OS
target_os = host_machine.system()
if target_os == 'linux'
   add_project_arguments(
   c_compiler.get_supported_arguments(
      '-DLINUX',
   ),
   language: 'c'
)
elif target_os == 'windows'
   add_project_arguments(
   c_compiler.get_supported_arguments(
      '-DWINDOWS',
   ),
   language: 'c'
)
endif

if enable_pqc
   add_project_arguments(
   c_compiler.get_supported_arguments(
      '-DENABLE_PQC',
   ),
   language: 'c'
)
endif

if enable_test_log
   add_project_arguments(
   c_compiler.get_supported_arguments(
      '-DLOG_TEST_OUTPUT',
   ),
   language: 'c'
)
endif

# Disable warnings for deprecated functions
if disable_deprecated
add_global_arguments(
   c_compiler.get_supported_arguments(
      '-Wno-deprecated-declarations',
   ),
   language: 'c'
)
endif

# External dependencies
dep_gta_core = dependency('libgta', static: true)

if build_dep
   openssl_proj   = subproject('openssl', default_options : ['c_std=gnu99', 'default_library=static',] )
   dep_libcrypto  = openssl_proj.get_variable('libcrypto_dep')
   cmocka_proj    = subproject('cmocka')
   dep_cmocka     = cmocka_proj.get_variable('cmocka_dep')
   qcbor_proj     = subproject('qcbor')
   dep_qcbor      = qcbor_proj.get_variable('qcbor_dep')
   t_cose_proj    = subproject('t_cose')
   dep_t_cose     = t_cose_proj.get_variable('t_cose_dep')
else
   dep_libcrypto = dependency('libcrypto', static: true)
   dep_cmocka    = dependency('cmocka')
   # TODO: currently qcbor/t_cose are still handled by the build system because there
   # are no official distribution packages available. When it becomes easier
   # to install qcbor/t_cose on the OS, this should also be handled by globally
   # installed libraries
   qcbor_proj     = subproject('qcbor')
   dep_qcbor      = qcbor_proj.get_variable('qcbor_dep')
   t_cose_proj    = subproject('t_cose')
   dep_t_cose     = t_cose_proj.get_variable('t_cose_dep')
endif

if enable_pqc
   # TODO Building liboqs as meson CMake target does not work!
   # Therefore, we are building liboqs natively and install it on /usr/local
   # It seems that the CMake integration into meson is not fully functional
   # and we have to write a meson file for liboqs in order to allow to
   # integrate it into the build system as subproject.
   dep_liboqs = dependency('liboqs', static: true)
endif

subdir('src') # Compile provider code as static library

# Build and call tests
subdir('test')

# Include examples directory
subdir('examples')

# Looking for Valgrind
prog_valgrind = find_program('valgrind', required: false)
if prog_valgrind.found()
   # Run valgrind memory leakage test
   run_target('gta_provider_memcheck',
      command: [prog_valgrind, '--trace-children=yes', '--leak-check=full', '--show-leak-kinds=all', '--error-exitcode=99', '--errors-for-leak-kinds=all', gta_provider_test.full_path()],
      depends: [gta_provider_test],
   )
endif
