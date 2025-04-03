cmake_minimum_required(VERSION 3.30)
message("Configuring for the embedded build STM3240G-EVAL board with the STM32F407IGH6 MCU (EMBEDDED_BUILD=stm32f407) ...")

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

project(lionkey_stm32f407 C CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

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

		../../fido2

		../../lib/tinycbor/src

		../../crypto/tiny-AES-c
		../../crypto/cifra/src
		../../crypto/cifra/src/ext
		../../crypto/salty/c-api
		../../crypto/sha256
		../../crypto/micro-ecc
)

link_directories(
		# TODO: build tinycbor as a library independently and then just link it
		# tinycbor/lib
		../../crypto/salty/c-api
)

add_definitions(-DDEBUG -DUSE_HAL_DRIVER -DSTM32F407xx -DTINYAES_ENABLE_AES256=1 -DCHIP=STM32L432xx -DAPP_CONFIG="app.h" -DDEBUG_LEVEL=1)

# for crypto/micro-ecc/uECC.c
add_definitions(-DuECC_PLATFORM=5 -DuECC_OPTIMIZATION_LEVEL=4 -DuECC_SQUARE_FUNC=1 -DuECC_SUPPORT_COMPRESSED_POINT=0)

file(GLOB_RECURSE SOURCES "Startup/*.*" "Src/*.*" "Middlewares/*.*" "Drivers/*.*"

		../../fido2/util.c
		../../fido2/log.c
		../../fido2/time.c
		../../fido2/ctaphid.c
		../../fido2/linked_list.c
		../../fido2/ctap.c
		../../fido2/ctap_parse.c
		../../fido2/crypto.c
		../../fido2/version.c
		../../fido2/device.c

		../../crypto/sha256/sha256.c
		../../crypto/micro-ecc/uECC.c
		../../crypto/tiny-AES-c/aes.c
		../../crypto/cifra/src/sha512.c
		../../crypto/cifra/src/blockwise.c

		../../lib/tinycbor/src/cbortojson.c
		# ../../lib/tinycbor/src/open_memstream.c
		../../lib/tinycbor/src/cborvalidation.c
		../../lib/tinycbor/src/cborparser_dup_string.c
		../../lib/tinycbor/src/cborpretty_stdio.c
		../../lib/tinycbor/src/cborencoder_close_container_checked.c
		../../lib/tinycbor/src/cborpretty.c
		../../lib/tinycbor/src/cborerrorstrings.c
		../../lib/tinycbor/src/cborparser.c
		../../lib/tinycbor/src/cborencoder.c
)

# TINYCBOR_HEADERS = src/cbor.h src/cborjson.h src/tinycbor-version.h
#TINYCBOR_FREESTANDING_SOURCES = \
#	src/cborerrorstrings.c \
#	src/cborencoder.c \
#	src/cborencoder_close_container_checked.c \
#	src/cborparser.c \
#	src/cborpretty.c \

set(LINKER_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/STM32F407IGHX_FLASH.ld)

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
