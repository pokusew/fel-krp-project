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

# enable CTest (CMake's test runner) to discover the tests
include(GoogleTest)
gtest_discover_tests(hello_test)
