# UNIT TESTS using GoogleTest (to be run on the host NOT on the embedded device)

# EXTERNAL DEPENDENCIES

# GoogleTest - Google Testing and Mocking Framework for C++
# Note: It also works great for testing C code (which is what our codebase is written in).
# https://google.github.io/googletest/quickstart-cmake.html#set-up-a-project
include(FetchContent)
FetchContent_Declare(
		googletest
		URL https://github.com/google/googletest/archive/2b6b042a77446ff322cd7522ca068d9f2a21c1d1.zip # 2025-01-16T20:51:11.000Z
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# {fmt} - Implementation of C++20 std::format and C++23 std::print
# Note: We use it inside the implementation of the custom SameBytes (EXPECT_SAME_BYTES) GoogleTest assertion.
# https://fmt.dev/11.1/get-started/#cmake
FetchContent_Declare(
		fmt
		GIT_REPOSITORY https://github.com/fmtlib/fmt
		GIT_TAG 8303d140a1a11f19b982a9f664bbe59a1ccda3f4 # 11.1.2
)
FetchContent_MakeAvailable(fmt)

# LIBRARIES

# see https://cmake.org/cmake/help/latest/manual/cmake-buildsystem.7.html#target-commands
# see https://cmake.org/cmake/help/latest/manual/cmake-buildsystem.7.html#target-usage-requirements

# TinyCBOR
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(WITH_FREESTANDING OFF)
set(WITH_CBOR2JSON OFF)
set(WITH_FLOATING_POINT OFF)
add_subdirectory(../lib/tinycbor ${CMAKE_BINARY_DIR}/lib/tinycbor)
target_compile_definitions(tinycbor PUBLIC
		CBOR_PARSER_MAX_RECURSIONS=4
)

add_library(tinyaes STATIC)
target_sources(tinyaes
		PRIVATE
		../crypto/tiny-AES-c/aes.c
)
target_compile_definitions(tinyaes
		# we need only AES-256-CBC
		PUBLIC TINYAES_ENABLE_AES256=1 TINYAES_ENABLE_CBC=1 TINYAES_ENABLE_ECB=0 TINYAES_ENABLE_CTR=0
)
target_include_directories(tinyaes
		INTERFACE
		../crypto/tiny-AES-c
)

add_library(micro_ecc STATIC)
target_sources(micro_ecc
		PRIVATE
		../crypto/micro-ecc/uECC.c
		INTERFACE
		../crypto/micro-ecc/uECC.h
)
target_compile_definitions(micro_ecc
		PUBLIC
		# uECC_PLATFORM=5 # if not provided directly, it will be auto-guessed from compiler macros
		uECC_OPTIMIZATION_LEVEL=4
		uECC_SQUARE_FUNC=1
		uECC_SUPPORT_COMPRESSED_POINT=0
)
target_include_directories(micro_ecc
		INTERFACE
		../crypto/micro-ecc
)

# https://github.com/B-Con/crypto-algorithms/blob/master/sha256.h
add_library(sha256 STATIC)
target_sources(sha256
		PRIVATE
		../crypto/sha256/sha256.c
		../crypto/sha256/hmac.c
		../crypto/sha256/hkdf.c
		INTERFACE
		../crypto/sha256/sha256.h
		../crypto/sha256/hmac.h
		../crypto/sha256/hkdf.h
)
target_include_directories(sha256
		INTERFACE
		../crypto/sha256
)

add_library(core STATIC)
target_sources(core PUBLIC
		../core/ctap.c
		../core/ctap_credentials.c
		../core/ctap_get_info.c
		../core/ctap_parse.c
		../core/ctap_pin.c
		../core/ctap_reset.c
		../core/ctap_selection.c
		../core/ctaphid.c
		../core/utils.c
		lionkey/consistent_prng.cpp
		lionkey/time.c
		lionkey/wait_for_user_presence.c
		lionkey/keepalive.c
		lionkey/ctap_test.c
)
target_include_directories(core PUBLIC ../core lionkey)
target_link_libraries(core PUBLIC
		tinycbor sha256 tinyaes micro_ecc
)
target_compile_definitions(core PUBLIC
		LIONKEY_DEBUG_LEVEL=3
)

add_library(tinyusb_fifo_test INTERFACE)
target_sources(tinyusb_fifo_test PUBLIC
		# common
		../lib/tinyusb/src/tusb.c
		../lib/tinyusb/src/common/tusb_fifo.c
		# device
		../lib/tinyusb/src/device/usbd.c
		../lib/tinyusb/src/device/usbd_control.c
		../lib/tinyusb/src/class/audio/audio_device.c
		../lib/tinyusb/src/class/cdc/cdc_device.c
		../lib/tinyusb/src/class/dfu/dfu_device.c
		../lib/tinyusb/src/class/dfu/dfu_rt_device.c
		../lib/tinyusb/src/class/hid/hid_device.c
		../lib/tinyusb/src/class/midi/midi_device.c
		../lib/tinyusb/src/class/msc/msc_device.c
		../lib/tinyusb/src/class/net/ecm_rndis_device.c
		../lib/tinyusb/src/class/net/ncm_device.c
		../lib/tinyusb/src/class/usbtmc/usbtmc_device.c
		../lib/tinyusb/src/class/vendor/vendor_device.c
		../lib/tinyusb/src/class/video/video_device.c
		# host
		../lib/tinyusb/src/host/usbh.c
		../lib/tinyusb/src/host/hub.c
		../lib/tinyusb/src/class/cdc/cdc_host.c
		../lib/tinyusb/src/class/hid/hid_host.c
		../lib/tinyusb/src/class/midi/midi_host.c
		../lib/tinyusb/src/class/msc/msc_host.c
		../lib/tinyusb/src/class/vendor/vendor_host.c
		# typec
		../lib/tinyusb/src/typec/usbc.c
)
target_compile_definitions(tinyusb_fifo_test INTERFACE
		CFG_TUSB_MCU=OPT_MCU_NONE
)
target_include_directories(tinyusb_fifo_test INTERFACE ../lib/tinyusb/src)
target_include_directories(tinyusb_fifo_test INTERFACE tinyusb)

# TESTS

# Include the GoogleTest module, which defines the gtest_discover_tests() function
# that enables CTest (CMake's test runner) to discover the tests (individual test cases within test executables).
# Docs:
#   https://cmake.org/cmake/help/latest/module/GoogleTest.html
#   https://cmake.org/cmake/help/latest/module/GoogleTest.html#command:gtest_discover_tests
# Note that once can also manually add CTest's tests using add_test:
#   https://cmake.org/cmake/help/latest/command/add_test.html
include(GoogleTest)

# Define a custom function to simplify defining test executables
# Example:
#    std_test(demo src/demo_part1.cpp src/demo_part2.cpp ...)
#    The statement above results in a new target (executable) with a name "test_${name}".
#    You can use standard CMake functions to further customize the target (e.g., link additional libraries).
# CMake docs:
#   https://cmake.org/cmake/help/latest/command/macro.html
#   https://cmake.org/cmake/help/latest/command/function.html
#   https://cmake.org/cmake/help/latest/command/cmake_parse_arguments.html
function(std_test name)
	set(sources "${ARGN}")
	message("adding std test ${name}, sources = ${sources}")
	add_executable(
			test_${name}
			src/gtest_sanitizers_integration.cpp
			"${sources}"
	)
	target_link_libraries(
			test_${name}
			GTest::gtest_main
	)
	gtest_discover_tests(test_${name}
			# Currently, all of our value-parameterized tests use a custom name_generator
			# (passed as the last arg to the INSTANTIATE_TEST_SUITE_P macro)
			# that adequately describes the values.
			# Therefore we want to supress the default GoogleTest CTest behavior:
			#   By default, the value index of value-parameterized tests is replaced
			#   by the actual value in the CTest test name.
			NO_PRETTY_VALUES
	)
endfunction()

function(core_test name)
	set(sources "${ARGN}")
	std_test("${name}" "src/${name}_test.cpp" "${sources}")
	target_link_libraries("test_${name}" core hex_utils gtest_custom_assertions)
endfunction()

# the custom SameBytes (EXPECT_SAME_BYTES) GoogleTest assertion
add_library(gtest_custom_assertions STATIC gtest_custom_assertions/gtest_custom_assertions.cpp)
target_include_directories(gtest_custom_assertions INTERFACE gtest_custom_assertions)
target_link_libraries(gtest_custom_assertions
		PRIVATE fmt::fmt
		PUBLIC GTest::gtest_main
)

# hex utils
add_library(hex_utils INTERFACE)
target_sources(hex_utils INTERFACE hex_utils/hex.hpp)
target_include_directories(hex_utils INTERFACE hex_utils)
# https://cmake.org/cmake/help/latest/manual/cmake-compile-features.7.html#requiring-language-standards
# https://cmake.org/cmake/help/latest/prop_gbl/CMAKE_CXX_KNOWN_FEATURES.html#high-level-meta-features-indicating-c-standard-support
target_compile_features(hex_utils INTERFACE cxx_std_20)

std_test(hex_utils src/hex_utils_test.cpp)
target_link_libraries(test_hex_utils hex_utils)

std_test(hello src/hello_test.cpp)

# a special test that is expected to fail
add_executable(
		test_ubsan
		src/gtest_sanitizers_integration.cpp
		src/ubsan_test.cpp
)
target_link_libraries(
		test_ubsan
		GTest::gtest_main
)
# We expect the UbsanTest's test cases to fail.
# This way, we check that our gtest_sanitizers_integration.cpp works correctly.
# https://cmake.org/cmake/help/latest/command/set_tests_properties.html
# https://cmake.org/cmake/help/latest/manual/cmake-properties.7.html#test-properties
# https://cmake.org/cmake/help/latest/prop_test/WILL_FAIL.html
gtest_discover_tests(test_ubsan PROPERTIES WILL_FAIL true)

std_test(cbor src/cbor_test.cpp)
target_link_libraries(test_cbor tinycbor hex_utils gtest_custom_assertions)

std_test(tiny_aes src/tiny_aes_test.cpp)
target_link_libraries(test_tiny_aes tinyaes hex_utils gtest_custom_assertions)

std_test(micro_ecc src/micro_ecc_test.cpp)
target_link_libraries(test_micro_ecc micro_ecc hex_utils gtest_custom_assertions)

std_test(sha256 src/sha256_test.cpp)
target_link_libraries(test_sha256 sha256 hex_utils gtest_custom_assertions)

std_test(hmac_sha256 src/hmac_sha256_test.cpp)
target_link_libraries(test_hmac_sha256 sha256 hex_utils gtest_custom_assertions)

std_test(hkdf_sha256 src/hkdf_sha256_test.cpp)
target_link_libraries(test_hkdf_sha256 sha256 hex_utils gtest_custom_assertions)

core_test(ctap_parse_client_pin)
core_test(ctap_parse_make_credential)
core_test(ctap_parse_get_assertion)
core_test(ctap_parse_credential_management)
core_test(ctap_client_pin)
core_test(ctap_make_credential)
core_test(ctap_get_assertion)
core_test(ctap_get_info)
core_test(ctap_asn1)
core_test(ctap_string_truncation)
core_test(ctaphid)

std_test(tusb_fifo src/tusb_fifo_test.cpp)
target_link_libraries(test_tusb_fifo tinyusb_fifo_test)
