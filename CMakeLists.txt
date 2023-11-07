#THIS FILE IS AUTO GENERATED FROM THE TEMPLATE! DO NOT CHANGE!
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_VERSION 1)
cmake_minimum_required(VERSION 3.26)

# specify cross-compilers and tools
set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER arm-none-eabi-g++)
set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)
set(CMAKE_AR arm-none-eabi-ar)
set(CMAKE_OBJCOPY arm-none-eabi-objcopy)
set(CMAKE_OBJDUMP arm-none-eabi-objdump)
set(SIZE arm-none-eabi-size)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# project settings
project(fel-krp-project C CXX ASM)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

#Uncomment for hardware floating point
#add_compile_definitions(ARM_MATH_CM4;ARM_MATH_MATRIX_CHECK;ARM_MATH_ROUNDING)
#add_compile_options(-mfloat-abi=hard -mfpu=fpv4-sp-d16)
#add_link_options(-mfloat-abi=hard -mfpu=fpv4-sp-d16)

#Uncomment for software floating point
#add_compile_options(-mfloat-abi=soft)

add_compile_options(-mcpu=cortex-m4 -mthumb -mthumb-interwork)
add_compile_options(-ffunction-sections -fdata-sections -fno-common -fmessage-length=0)

# uncomment to mitigate c++17 absolute addresses warnings
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-register")

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


set(TINYCBOR_LIBRARY ${CMAKE_CURRENT_SOURCE_DIR}/solo1/tinycbor/lib/libtinycbor.a)
add_custom_target(build_tinycbor ALL
		COMMAND ./build.sh
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/solo1/tinycbor
		COMMENT "Original TinyCBOR makefile target")

# now create an imported static target
add_library(tinycbor STATIC IMPORTED)
# Import target "tinycbor" for configuration ""
set_property(TARGET tinycbor APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(tinycbor PROPERTIES
		IMPORTED_LOCATION_NOCONFIG "${TINYCBOR_LIBRARY}")

# now you can use scintilla as if it were a regular cmake built target in your project
add_dependencies(tinycbor build_tinycbor)

# SEARCH=-L../../tinycbor/lib -L../../crypto/salty/c-api

include_directories(
		Inc
		Drivers/STM32F4xx_HAL_Driver/Inc
		Drivers/STM32F4xx_HAL_Driver/Inc/Legacy
		Drivers/CMSIS/Device/ST/STM32F4xx/Include
		Drivers/CMSIS/Include
		Middlewares/ST/STM32_USB_Device_Library/Core/Inc
		Middlewares/ST/STM32_USB_Device_Library/Class/CustomHID/Inc

		solo1/fido2
		solo1/fido2/extensions
		solo1/tinycbor/src
		solo1/crypto/tiny-AES-c
		solo1/crypto/cifra/src
		solo1/crypto/cifra/src/ext
		solo1/crypto/salty/c-api
		solo1/crypto/sha256

		solo1/crypto/micro-ecc

)

add_definitions(-DDEBUG -DUSE_HAL_DRIVER -DSTM32F407xx -DAES256=1 -DCHIP=STM32L432xx -DAPP_CONFIG="app.h" -DDEBUG_LEVEL=1)

file(GLOB_RECURSE SOURCES "Startup/*.*" "Src/*.*" "Middlewares/*.*" "Drivers/*.*"

		solo1/fido2/apdu.c solo1/fido2/util.c solo1/fido2/u2f.c solo1/fido2/test_power.c
		solo1/fido2/stubs.c solo1/fido2/log.c solo1/fido2/ctaphid.c solo1/fido2/ctap.c
		solo1/fido2/ctap_parse.c solo1/fido2/crypto.c
		solo1/fido2/version.c
		solo1/fido2/data_migration.c
		solo1/fido2/extensions/extensions.c solo1/fido2/extensions/solo.c
		solo1/fido2/extensions/wallet.c

		solo1/fido2/device.c

		solo1/crypto/sha256/sha256.c solo1/crypto/micro-ecc/uECC.c solo1/crypto/tiny-AES-c/aes.c
		solo1/crypto/cifra/src/sha512.c solo1/crypto/cifra/src/blockwise.c

		solo1/crypto/micro-ecc/uECC.c
)

set(LINKER_SCRIPT ${CMAKE_SOURCE_DIR}/STM32F407IGHX_FLASH.ld)

link_directories(
		solo1/tinycbor/lib
		solo1/crypto/salty/c-api
)

add_link_options(-Wl,-gc-sections,--print-memory-usage,-Map=${PROJECT_BINARY_DIR}/${PROJECT_NAME}.map)
add_link_options(-mcpu=cortex-m4 -mthumb -mthumb-interwork)
add_link_options(-T ${LINKER_SCRIPT})
#add_link_options(-ltinycbor)

add_executable(${PROJECT_NAME}.elf ${SOURCES} ${LINKER_SCRIPT})
target_link_libraries(${PROJECT_NAME}.elf tinycbor)

set(HEX_FILE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}.hex)
set(BIN_FILE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}.bin)

add_custom_command(TARGET ${PROJECT_NAME}.elf POST_BUILD
		COMMAND ${CMAKE_OBJCOPY} -Oihex $<TARGET_FILE:${PROJECT_NAME}.elf> ${HEX_FILE}
		COMMAND ${CMAKE_OBJCOPY} -Obinary $<TARGET_FILE:${PROJECT_NAME}.elf> ${BIN_FILE}
		COMMENT "Building ${HEX_FILE}
Building ${BIN_FILE}")
