# Generic Trust Anchor API SW Provider

## Introduction
This project contains an example implementation for a secure element provider
for GTA API. The implementation is software-only, i.e., there is no protection
by a hardware secure element. The motivation for the GTA API software provider
is to provide a starting point to get familiar with GTA API but it is not
intended for productive use.

Nevertheless, the software provider is prepared to achieve a minimal security
level by protecting its persisted state (i.e., device state, personalities,
further metadata) with a hardware unique key. The 32 Byte platform specific
hardware unique key needs to be provided to the function `get_hw_unique_key_32`
in the file [key_management.c](src/key_management.c).

The GTA API software provider allows to develop an application which is based on
the GTA API interfaces without having a secure element. The GTA API software
provider can then be enhanced (e.g., by providing a hardware unique key) or
replaced by another provider supporting some hardware secure element at a later
stage.

The cryptographic functions are computed using the
[OpenSSL](https://openssl-library.org/) library as 3rd party cryptographic
service provider.

Please note, that the development is currently work in progress and no releases
have been created up to the time being.

## Structure of the Repository
| File        | Description |
| :---        |      :---   |
| ./meson_options.txt | Project specific configuration options used by Meson build system |
| ./cross-files | Configurations for cross compile targets in Meson |
| ./subprojects | External build dependencies that are used by Meson |
| ./src | Implementation of the GTA API SW provider |
| ./test      | Test suite for the GTA API SW provider |
| ./examples | Examples to get started with GTA API |

## Supported Profiles
The following table lists the profiles currently supported by the GTA API SW
provider. Please note that the provider is still under development and support
for more profiles will be added.

| Supported | Profile name | Reference | Short description |
| :-------- | :----------- | :-------- | :---------------- |
| :white_check_mark: | ch.iec.30168.basic.passcode | [ISO/IEC TS 30168](https://www.iso.org/standard/53288.html) Annex B.1 | Simple authentication method for personality derived access tokens |
| :x: (WIP) | ch.iec.30168.basic.local_data_integrity_only | [ISO/IEC TS 30168](https://www.iso.org/standard/53288.html) Annex B.2 | Integrity protection of local data on the device |
| :white_check_mark: | ch.iec.30168.basic.local_data_protection | [ISO/IEC TS 30168](https://www.iso.org/standard/53288.html) Annex B.3 | Integrity and confidentiality protection of local data on the device |
| :white_check_mark: | com.github.generic-trust-anchor-api.basic.dilithium | [Link](https://github.com/generic-trust-anchor-api/gta-api-profiles/blob/main/doc/profile_com.github.generic-trust-anchor-api.basic.dilithium.md) | Creation of a Dilithium based personality |
| :white_check_mark:| com.github.generic-trust-anchor-api.basic.ec | [Link](https://github.com/generic-trust-anchor-api/gta-api-profiles/blob/main/doc/profile_com.github.generic-trust-anchor-api.basic.ec.md) | Creation of an Elliptic Curve based personality |
| :white_check_mark: | com.github.generic-trust-anchor-api.basic.enroll | [Link](https://github.com/generic-trust-anchor-api/gta-api-profiles/blob/main/doc/profile_com.github.generic-trust-anchor-api.basic.enroll.md) | Creation of a Certificate Signing Request (CSR) |
| :white_check_mark:| com.github.generic-trust-anchor-api.basic.jwt | [Link](https://github.com/generic-trust-anchor-api/gta-api-profiles/blob/main/doc/profile_com.github.generic-trust-anchor-api.basic.jwt.md) | Creation of signed JWT |
| :white_check_mark:| com.github.generic-trust-anchor-api.basic.rsa | [Link](https://github.com/generic-trust-anchor-api/gta-api-profiles/blob/main/doc/profile_com.github.generic-trust-anchor-api.basic.rsa.md) | Creation of a RSA based personality |
| :white_check_mark:| com.github.generic-trust-anchor-api.basic.signature | [Link](https://github.com/generic-trust-anchor-api/gta-api-profiles/blob/main/doc/profile_com.github.generic-trust-anchor-api.basic.signature.md) | Creation of a digital signature |
| :white_check_mark:| com.github.generic-trust-anchor-api.basic.tls | [Link](https://github.com/generic-trust-anchor-api/gta-api-profiles/blob/main/doc/profile_com.github.generic-trust-anchor-api.basic.tls.md) | Alias for com.github.generic-trust-anchor-api.basic.signature |

## Dependencies
The build and test of the GTA API SW provider depend on the GTA API Core and
it's dependencies. To build the provider with Post-Quantum crypto algorithms,
[liboqs](https://github.com/open-quantum-safe/liboqs) needs to be installed on
the system.

## Local build
* In the project root, initialize build system and build directory (like ./configure for automake):
```
$ meson setup <build_dir>
```

* Compile the code, the build directory is specified with the `-C` option:
```
$ ninja -C <build_dir>
```

* The tests are executed by calling ninja with the test target selected:
```
$ ninja -C <build_dir> test
```

* To install the library and header files, the following target can be used:
```
$ sudo ninja -C <build_dir> install
```

* The Valgrind tool can be used to perform some dynamic code analysis by calling
  the following target:
```
$ ninja -C <build_dir> gta_provider_memcheck
```

All build artifacts are kept in the specified build directory. It is also
possible to use several build directories in parallel with different
configurations.

## Getting started with examples
### Using GTA API with ch.iec.30168.basic.local_data_protection
Build the SW provider with the option `build-examples=true`:
```
$ meson setup <build_dir> -Dbuild-examples=true
$ ninja -C <build_dir>
```

Switch to the build directory and initialize GTA API for this example. This will
create a GTA API state with an identifier and a personality. The default
location of the state is `./sw_provider_state`. This can be changed using the
environment variable `SW_PROVIDER_STATE_DIR`.
```
$ cd <build_dir>/examples
$ ./local_data_protection init
```

Now, local data can be sealed and unsealed using the profile
ch.iec.30168.basic.local_data_protection. The example reads data from stdin and
writes the result to stdout. The return code indicates whether the operation
was successful (1) or not (0).
```
$ echo "Hello world" | ./local_data_protection seal > protected_data.bin
$ echo $?
1
```
```
$ cat protected_data.bin | ./local_data_protection unseal
Hello world
```
In case the protected data is modified, the unsealing fails. In the following
example, four bytes of protected_data.bin are overwritten by random bytes.
```
$ dd if=/dev/random of=./protected_data.bin seek=40 bs=1 count=4 conv=notrunc
$ cat protected_data.bin | ./local_data_protection unseal
Error: gta_unseal_data failed!
```

## Cross Builds / Cross Compilation
Meson is well suited for cross compilation. For this, a cross configuration file
is required. This file has to be passed to meson when the build directory is
configured.

```
$ meson setup <build_dir> --cross-file cross-files/aarch64-linux-gnu.txt
```

The file aarch64-linux-gnu.txt allows building for the ARM64 architecture on a
x86 Debian Linux machine with the prerequisite that the required compiler was
installed before with the following command:

```
sudo apt install gcc-aarch64-linux-gnu
```

## Meson Options File
Meson allows to customize the build with an option file which includes user
specified, project specific options that modify the characteristics of the
build. The defined options are accessed by the `meson.build` files and are
specified in the file `meson_options.txt`. This allows a separation of the build
scripts and the build options.

Currently the following options are available:

| Option Name | Possible values | Description |
| :---------- | :-------------- | :---------- |
| build       | combo: { 'debug', 'release' } | Select the build type with associated tool configuration (e.g., compiler flags for debugging). |
| build-dependencies | boolean : { true, false } | Select whether to build dependencies locally rather than use system installed libraries. |
| disable-deprecated-warnings | boolean : { true, false } | Select whether or not warnings for deprecated functions are displayed. |
| enable-post-quantum-crypto | boolean : { true, false } | This switch enables post quantum crypto algorithms. |
| enable-test-log | boolean : { true, false } | This switch enables log messages for the provider tests. |
| build-examples | boolean : { true, false } | This switch enables the build of examples. |


## Coverage Report
For coverage reporting the code has to be instrumented. Meson can be
instructed to perform the instrumentation by specifying the respective compiler
options. Furthermore, additional build targets are generated to create different
coverage reports.

* Configure build environment for coverage reporting:
```
$ meson setup <build_dir> -Db_coverage=true
```

* Create all available coverage reports:
```
$ ninja -C <build_dir> test
$ ninja -C <build_dir> coverage
```
Notes:
* It seems that there is a bug in meson. It is required to execute the test
  suite before generating the coverage reports.
* The coverage-target creates all available reports. Alternatively, only
  required reports can be generated by using the following targets:
   * coverage-xml
   * coverage-text
   * coverage-sonarqube
   * coverage-html
* Especially, the html-target creates a nice report that can be viewed in a
  web-browser. It can be found in the build directory under
 `meson-logs/coveragereport/index.html`

## Test Results
Meson does only report tests results on per test executable basis in the
terminal. More detailed test results are exported to junit XML-files. These files
can be found in the build directory in the test subdirectory.

