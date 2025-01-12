# unit tests using GoogleTest (to be run on the host not on the embedded device)

# https://google.github.io/googletest/quickstart-cmake.html#set-up-a-project
include(FetchContent)
FetchContent_Declare(
		googletest
		URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# TESTS

add_executable(
		hello_test
		src/hello_test.cpp
)
target_link_libraries(
		hello_test
		GTest::gtest_main
)

add_library(
		tinycbor
		STATIC
		../tinycbor/src/cborerrorstrings.c
		../tinycbor/src/cborencoder.c
		../tinycbor/src/cborencoder_close_container_checked.c
		../tinycbor/src/cborparser.c
		../tinycbor/src/cborpretty.c
		../tinycbor/src/cbor.h
)
# Because some authenticators are memory constrained,
# the depth of nested CBOR structures used by all message encodings
# is limited to at most four (4) levels of any combination of CBOR maps
# and/or CBOR arrays. Authenticators MUST support at least 4 levels of CBOR nesting.
# Clients, platforms, and servers MUST NOT use more than 4 levels of CBOR nesting.
target_compile_definitions(
		tinycbor
		INTERFACE
		CBOR_PARSER_MAX_RECURSIONS=4
)
target_include_directories(
		tinycbor
		INTERFACE
		../tinycbor/src
)

# add_library(
# 		ctap
# 		STATIC
# 		../fido2/ctap.c
# )
# target_link_libraries(
# 		ctap
# 		tinycbor
# )

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

add_executable(
		ctap_get_info
		src/ctap_get_info.cpp
)
#target_compile_definitions(
#		ctap_get_info
#		PRIVATE
#		-DAPP_CONFIG="inc/app.h"
#)
#target_include_directories(
#		ctap_get_info
#		PRIVATE
#		../Inc
#		../fido2
#		../tinycbor/src
#)
target_link_libraries(
		ctap_get_info
		GTest::gtest_main
		tinycbor
		# ctap
)


add_executable(
		ctap_parse
		src/ctap_parse.cpp
)
target_link_libraries(
		ctap_parse
		GTest::gtest_main
		core_ctap_parse
)

add_executable(
		test_ctap_parse_client_pin
		src/ctap_parse_client_pin_test.cpp
)
target_link_libraries(
		test_ctap_parse_client_pin
		GTest::gtest_main
		core_ctap_parse
)

# enable CTest (CMake's test runner) to discover the tests
include(GoogleTest)
gtest_discover_tests(hello_test)
