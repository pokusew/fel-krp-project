cmake_minimum_required(VERSION 3.26)

option(EMBEDDED_BUILD "Build the embedded targets" ON)
option(SANITIZERS "Enable sanitizers" OFF)

if (EMBEDDED_BUILD)
	# Note: A more standard way of specifying the variables for cross-compilation
	# would be to use cmake CLI option --toolchain path/to/file or -DCMAKE_TOOLCHAIN_FILE=path/to/file
	# or CMake presets (CMakePresets.json).
	set(CMAKE_SYSTEM_NAME Generic)
	set(CMAKE_SYSTEM_VERSION 1)
	set(CMAKE_C_COMPILER arm-none-eabi-gcc)
	set(CMAKE_CXX_COMPILER arm-none-eabi-g++)
	set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)
	set(CMAKE_AR arm-none-eabi-ar)
	set(CMAKE_OBJCOPY arm-none-eabi-objcopy)
	set(CMAKE_OBJDUMP arm-none-eabi-objdump)
	set(SIZE arm-none-eabi-size)
	set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
endif ()

if ((NOT EMBEDDED_BUILD) AND SANITIZERS)
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


# project settings
project(fel-krp-project C CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

# enable ctest
enable_testing()

if (EMBEDDED_BUILD)
	message("Configuring for the embedded build (EMBEDDED_BUILD=ON) ...")

	# Uncomment for hardware floating point
	# salty: required by salty (crypto/salty)
	add_compile_definitions(ARM_MATH_CM4;ARM_MATH_MATRIX_CHECK;ARM_MATH_ROUNDING)
	add_compile_options(-mfloat-abi=hard -mfpu=fpv4-sp-d16)
	add_link_options(-mfloat-abi=hard -mfpu=fpv4-sp-d16)

	# Uncomment for software floating point
	# add_compile_options(-mfloat-abi=soft)

	add_compile_options(-mcpu=cortex-m4 -mthumb -mthumb-interwork)
	add_compile_options(-ffunction-sections -fdata-sections -fno-common -fmessage-length=0)

	# uncomment to mitigate c++17 absolute addresses warnings
	# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-register")

	# Enable assembler files preprocessing
	add_compile_options($<$<COMPILE_LANGUAGE:ASM>:-x$<SEMICOLON>assembler-with-cpp>)

	if ("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
		message(STATUS "Maximum optimization for speed")
		add_compile_options(-Ofast)
	elseif ("${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
		message(STATUS "Maximum optimization for speed, debug info included")
		add_compile_options(-Ofast -g)
	elseif ("${CMAKE_BUILD_TYPE}" STREQUAL "MinSizeRel")
		message(STATUS "Maximum optimization for size")
		add_compile_options(-Os)
	else ()
		message(STATUS "Minimal optimization, debug info included")
		add_compile_options(-Og -g)
	endif ()


	include_directories(
			Inc
			Drivers/STM32F4xx_HAL_Driver/Inc
			Drivers/STM32F4xx_HAL_Driver/Inc/Legacy
			Drivers/CMSIS/Device/ST/STM32F4xx/Include
			Drivers/CMSIS/Include
			Middlewares/ST/STM32_USB_Device_Library/Core/Inc
			Middlewares/ST/STM32_USB_Device_Library/Class/CustomHID/Inc

			fido2

			tinycbor/src

			crypto/tiny-AES-c
			crypto/cifra/src
			crypto/cifra/src/ext
			crypto/salty/c-api
			crypto/sha256
			crypto/micro-ecc
	)

	link_directories(
			# TODO: build tinycbor as a library independently and then just link it
			# tinycbor/lib
			crypto/salty/c-api
	)

	add_definitions(-DDEBUG -DUSE_HAL_DRIVER -DSTM32F407xx -DAES256=1 -DCHIP=STM32L432xx -DAPP_CONFIG="app.h" -DDEBUG_LEVEL=1)

	# for crypto/micro-ecc/uECC.c
	add_definitions(-DuECC_PLATFORM=5 -DuECC_OPTIMIZATION_LEVEL=4 -DuECC_SQUARE_FUNC=1 -DuECC_SUPPORT_COMPRESSED_POINT=0)

	file(GLOB_RECURSE SOURCES "Startup/*.*" "Src/*.*" "Middlewares/*.*" "Drivers/*.*"

			fido2/util.c
			fido2/log.c
			fido2/time.c
			fido2/ctaphid.c
			fido2/linked_list.c
			fido2/ctap.c
			fido2/ctap_parse.c
			fido2/crypto.c
			fido2/version.c
			fido2/device.c

			crypto/sha256/sha256.c
			crypto/micro-ecc/uECC.c
			crypto/tiny-AES-c/aes.c
			crypto/cifra/src/sha512.c
			crypto/cifra/src/blockwise.c

			tinycbor/src/cbortojson.c
			# tinycbor/src/open_memstream.c
			tinycbor/src/cborvalidation.c
			tinycbor/src/cborparser_dup_string.c
			tinycbor/src/cborpretty_stdio.c
			tinycbor/src/cborencoder_close_container_checked.c
			tinycbor/src/cborpretty.c
			tinycbor/src/cborerrorstrings.c
			tinycbor/src/cborparser.c
			tinycbor/src/cborencoder.c
	)

	# TINYCBOR_HEADERS = src/cbor.h src/cborjson.h src/tinycbor-version.h
	#TINYCBOR_FREESTANDING_SOURCES = \
	#	src/cborerrorstrings.c \
	#	src/cborencoder.c \
	#	src/cborencoder_close_container_checked.c \
	#	src/cborparser.c \
	#	src/cborpretty.c \

	set(LINKER_SCRIPT ${CMAKE_SOURCE_DIR}/STM32F407IGHX_FLASH.ld)

	add_link_options(-Wl,-gc-sections,--print-memory-usage,-Map=${PROJECT_BINARY_DIR}/${PROJECT_NAME}.map)
	add_link_options(-mcpu=cortex-m4 -mthumb -mthumb-interwork)
	add_link_options(-T ${LINKER_SCRIPT})

	# salty: required in order to successfully link salty
	# taken from https://github.com/solokeys/solo1/blob/master/targets/stm32l432/build/application.mk#L55-L56
	add_link_options(-specs=nano.specs -specs=nosys.specs -lnosys -Wl,-Bstatic -lsalty)

	add_executable(${PROJECT_NAME}.elf ${SOURCES} ${LINKER_SCRIPT})

	# salty
	target_link_libraries(${PROJECT_NAME}.elf salty)

	set(HEX_FILE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}.hex)
	set(BIN_FILE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}.bin)

	add_custom_command(TARGET ${PROJECT_NAME}.elf POST_BUILD
			COMMAND ${CMAKE_OBJCOPY} -Oihex $<TARGET_FILE:${PROJECT_NAME}.elf> ${HEX_FILE}
			COMMAND ${CMAKE_OBJCOPY} -Obinary $<TARGET_FILE:${PROJECT_NAME}.elf> ${BIN_FILE}
			COMMENT "Building ${HEX_FILE}
	Building ${BIN_FILE}")

else ()
	message("Configuring for the host build (EMBEDDED_BUILD=OFF) ...")
	# add unit tests which are designed to run on the host
	add_subdirectory(test)
endif ()
