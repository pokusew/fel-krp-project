cmake_minimum_required(VERSION 3.30)

set(BUILD_TARGET "host" CACHE STRING "Build the embedded targets")
set_property(CACHE BUILD_TARGET PROPERTY STRINGS "host" "stm32f407")

option(SANITIZERS "Enable sanitizers (only takes effect when BUILD_TARGET=host)" OFF)

if ((BUILD_TARGET STREQUAL "host") AND SANITIZERS)
	message("Enabling sanitizers ...")
	# # https://clang.llvm.org/docs/AddressSanitizer.html
	## https://clang.llvm.org/docs/MemorySanitizer.html
	## https://clang.llvm.org/docs/LeakSanitizer.html
	## https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
	## -fsanitize=address -fsanitize=undefined
	## ASAN_OPTIONS=detect_leaks=1
	#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic -Wall -std=c99 -O0 -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -g")
	## set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic -Wall -std=c99 -O3")
	#set(CMAKE_CXX_STANDARD 11)
	## set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -O2 -pipe -DONLINE_JUDGE")
	#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic -Wall -O0 -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -g")
	## set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -O3 -pthread") # -march=native

	# See how others do it:
	# https://github.com/ada-url/ada/blob/main/cmake/add-cpp-test.cmake
	# https://github.com/ada-url/ada/blob/main/cmake/codecoverage.cmake

	# -fsanitize=unsigned-integer-overflow:
	#     Unsigned integer overflow, where the result of an unsigned integer computation
	#     cannot be represented in its type. Unlike signed integer overflow,
	#     this is NOT undefined behavior, but it is often unintentional.
	set(SANITIZERS_FLAGS "-fsanitize=address,undefined")

	message("current CMAKE_C_FLAGS = ${CMAKE_C_FLAGS}")
	message("current CMAKE_CXX_FLAGS = ${CMAKE_CXX_FLAGS}")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SANITIZERS_FLAGS} -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SANITIZERS_FLAGS} -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${SANITIZERS_FLAGS}")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${SANITIZERS_FLAGS}")
	# set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} ${SANITIZERS_FLAGS}")
	set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${SANITIZERS_FLAGS}")


	# if buildtype == 'debug' and get_option('debug_with_sanitizers')
	#  # Sanitizers with Meson:
	#  #   Sanitizers can be enabled using the Meson `b_sanitize` option
	#  #   (https://mesonbuild.com/Builtin-options.html#base-options),
	#  #   BUT it cannot be done conditionally based on the `buildtype` option values
	#  #   (https://stackoverflow.com/questions/59422411/meson-conditional-address-sanitization).
	#  #   So we have to do it manually (and we have to ignore
	#  #   the "Consider using the built-in option for ..." warning).
	#  # Sanitizers:
	#  #   Sanitizers are typically mutually exclusive, see https://stackoverflow.com/a/50367940:
	#  #     ...you can combine only Asan+UBsan+Lsan, via -fsanitize=address,undefined,leak
	#  #   -fsanitize: https://clang.llvm.org/docs/UsersManual.html#cmdoption-f-no-sanitize
	#  #     note: when using the -fsanitize directly,
	#  #           it must also be provided when linking (i.e., both with c_args and c_link_args)
	#  #   https://clang.llvm.org/docs/AddressSanitizer.html
	#  #   https://clang.llvm.org/docs/MemorySanitizer.html
	#  #   https://clang.llvm.org/docs/LeakSanitizer.html
	#  #   https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
	#  additional_debug_link_args = [
	#    '-fsanitize=address,undefined', # leak not supported on macOS (TODO: add conditionally)
	#  ]
	#  additional_debug_args = additional_debug_link_args + [
	#    # to get nicer stack traces in error messages add -fno-omit-frame-pointer
	#    # (these flags are needed only during compilation, not linking)
	#    '-fno-omit-frame-pointer',
	#    '-mno-omit-leaf-frame-pointer',
	#  ]
	#  add_project_arguments(additional_debug_args, language : ['cpp', 'c'])
	#  add_project_link_arguments(additional_debug_link_args, language : ['cpp', 'c'])
	#endif

	# https://stackoverflow.com/questions/44320465/whats-the-proper-way-to-enable-addresssanitizer-in-cmake-that-works-in-xcode
	# CMAKE_EXE_LINKER_FLAGS
	# CMAKE_EXE_LINKER_FLAGS_DEBUG
	# CMAKE_SHARED_LINKER_FLAGS
	# CMAKE_SHARED_LINKER_FLAGS_DEBUG
	# https://github.com/alandefreitas/moderncpp/blob/master/cmake/functions/sanitizers.cmake
	# https://alandefreitas.github.io/moderncpp/cmake-functions/sanitizers/
endif ()

if (BUILD_TARGET STREQUAL "host")
	message("Configuring for the host build (BUILD_TARGET=${BUILD_TARGET}) ...")
	project(lionkey C CXX ASM)
	set(CMAKE_CXX_STANDARD 17)
	set(CMAKE_C_STANDARD 11)
	# enable ctest
	enable_testing()
	# add unit tests which are designed to run on the host
	add_subdirectory(test)
else ()
	message("Configuring for the embedded build (BUILD_TARGET=${BUILD_TARGET}) ...")
	add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/targets/${BUILD_TARGET})
endif ()
