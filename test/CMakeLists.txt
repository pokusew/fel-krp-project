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

add_library(
		tinycbor
		STATIC
		../tinycbor/src/cborerrorstrings.c
		../tinycbor/src/cborencoder.c
		../tinycbor/src/cborparser.c
)
# CTAP2 spec, Section 8. Message Encoding:
# Because some authenticators are memory constrained,
# the depth of nested CBOR structures used by all message encodings
# is limited to at most four (4) levels of any combination of CBOR maps
# and/or CBOR arrays. Authenticators MUST support at least 4 levels of CBOR nesting.
# Clients, platforms, and servers MUST NOT use more than 4 levels of CBOR nesting.
target_compile_definitions(
		tinycbor
		PUBLIC
		CBOR_PARSER_MAX_RECURSIONS=4
)
target_include_directories(
		tinycbor
		INTERFACE
		../tinycbor/src
)

add_library(
		core_ctap_parse
		STATIC
		../core/ctap_parse.c
)
target_include_directories(
		core_ctap_parse
		INTERFACE
		../core
)
target_include_directories(
		core_ctap_parse
		PRIVATE
		../fido2
)
target_link_libraries(
		core_ctap_parse
		tinycbor
)
target_compile_definitions(
		core_ctap_parse
		PRIVATE
		LIONKEY_LOG=1
)


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
	gtest_discover_tests(test_${name})
endfunction()

# the custom SameBytes (EXPECT_SAME_BYTES) GoogleTest assertion
add_library(gtest_custom_assertions STATIC gtest_custom_assertions/gtest_custom_assertions.cpp)
target_include_directories(gtest_custom_assertions INTERFACE gtest_custom_assertions)
target_link_libraries(gtest_custom_assertions
		PRIVATE fmt::fmt
		PUBLIC GTest::gtest_main
)

std_test(hello src/hello_test.cpp)

std_test(ubsan src/ubsan_test.cpp)
# We expect the UbsanTest's test cases to fail.
# This way, we check that our gtest_sanitizers_integration.cpp works correctly.
# https://cmake.org/cmake/help/latest/command/set_tests_properties.html
# https://cmake.org/cmake/help/latest/manual/cmake-properties.7.html#test-properties
# https://cmake.org/cmake/help/latest/prop_test/WILL_FAIL.html
gtest_discover_tests(test_ubsan PROPERTIES WILL_FAIL true)

std_test(cbor src/cbor_test.cpp)
target_link_libraries(test_cbor tinycbor)

std_test(ctap_parse_client_pin src/ctap_parse_client_pin_test.cpp)
target_link_libraries(test_ctap_parse_client_pin core_ctap_parse gtest_custom_assertions)
