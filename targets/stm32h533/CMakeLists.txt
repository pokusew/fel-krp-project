cmake_minimum_required(VERSION 3.22)

# Setup compiler settings
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

project(lionkey_stm32h533 C ASM)

message("Build type: " ${CMAKE_BUILD_TYPE})

# Create an executable object type
add_executable(${PROJECT_NAME})

# Add STM32CubeMX generated sources
add_subdirectory(cmake/stm32cubemx)


add_library(
		tinycbor
		STATIC
		../../lib/tinycbor/src/cborerrorstrings.c
		../../lib/tinycbor/src/cborencoder.c
		../../lib/tinycbor/src/cborparser.c
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
		../../lib/tinycbor/src
)

add_library(tinyaes STATIC)
target_sources(tinyaes
		PRIVATE
		../../crypto/tiny-AES-c/aes.c
)
target_compile_definitions(tinyaes
		# we need only AES-256-CBC
		PUBLIC TINYAES_ENABLE_AES_256=1 TINYAES_ENABLE_CTR=0 TINYAES_ENABLE_CTR=0
)
target_include_directories(tinyaes
		INTERFACE
		../../crypto/tiny-AES-c
)

add_library(micro_ecc STATIC)
target_sources(micro_ecc
		PRIVATE
		../../crypto/micro-ecc/uECC.c
		INTERFACE
		../../crypto/micro-ecc/uECC.h
)
target_compile_definitions(micro_ecc
		PUBLIC
		uECC_PLATFORM=0 # if not provided directly, it will be auto-guessed from compiler macros
		uECC_OPTIMIZATION_LEVEL=4
		uECC_SQUARE_FUNC=1
		uECC_SUPPORT_COMPRESSED_POINT=0
)
target_include_directories(micro_ecc
		INTERFACE
		../../crypto/micro-ecc
)

# https://github.com/B-Con/crypto-algorithms/blob/master/sha256.h
add_library(sha256 STATIC)
target_sources(sha256
		PRIVATE
		../../crypto/sha256/sha256.c
		../../crypto/sha256/hmac.c
		INTERFACE
		../../crypto/sha256/sha256.h
		../../crypto/sha256/hmac.h
)
target_include_directories(sha256
		INTERFACE
		../../crypto/sha256
)

add_library(core STATIC)
target_sources(core PUBLIC
		../../core/ctap.c
		../../core/ctap_parse.c
		../../core/ctap_pin.c
		../../core/ctaphid.c
		../../core/utils.c
)
target_include_directories(core PUBLIC ../../core Inc)
target_link_libraries(core PUBLIC
		tinycbor sha256 tinyaes micro_ecc
)
target_compile_definitions(core PUBLIC
		LIONKEY_LOG=1
		LIONKEY_DEBUG_LEVEL=3
)

set(TINYUSB_SRC ../../lib/tinyusb/src)
add_library(tinyusb INTERFACE)
target_sources(tinyusb PUBLIC
		# common
		../../lib/tinyusb/src/tusb.c
		../../lib/tinyusb/src/common/tusb_fifo.c
		# device
		../../lib/tinyusb/src/device/usbd.c
		../../lib/tinyusb/src/device/usbd_control.c
		../../lib/tinyusb/src/class/audio/audio_device.c
		../../lib/tinyusb/src/class/cdc/cdc_device.c
		../../lib/tinyusb/src/class/dfu/dfu_device.c
		../../lib/tinyusb/src/class/dfu/dfu_rt_device.c
		../../lib/tinyusb/src/class/hid/hid_device.c
		../../lib/tinyusb/src/class/midi/midi_device.c
		../../lib/tinyusb/src/class/msc/msc_device.c
		../../lib/tinyusb/src/class/net/ecm_rndis_device.c
		../../lib/tinyusb/src/class/net/ncm_device.c
		../../lib/tinyusb/src/class/usbtmc/usbtmc_device.c
		../../lib/tinyusb/src/class/vendor/vendor_device.c
		../../lib/tinyusb/src/class/video/video_device.c
		# host
		../../lib/tinyusb/src/host/usbh.c
		../../lib/tinyusb/src/host/hub.c
		../../lib/tinyusb/src/class/cdc/cdc_host.c
		../../lib/tinyusb/src/class/hid/hid_host.c
		../../lib/tinyusb/src/class/midi/midi_host.c
		../../lib/tinyusb/src/class/msc/msc_host.c
		../../lib/tinyusb/src/class/vendor/vendor_host.c
		# typec
		../../lib/tinyusb/src/typec/usbc.c
)
target_sources(tinyusb PUBLIC
		../../lib/tinyusb/src/portable/st/stm32_fsdev/dcd_stm32_fsdev.c
		../../lib/tinyusb/src/portable/st/typec/typec_stm32.c
)
target_compile_definitions(tinyusb INTERFACE
		CFG_TUSB_MCU=OPT_MCU_STM32H5
)
target_include_directories(tinyusb INTERFACE ${TINYUSB_SRC})

target_link_directories(${PROJECT_NAME} PRIVATE
)


target_sources(${PROJECT_NAME} PRIVATE
		Src/usb_descriptors.c
		Src/usb.c
		Src/app.c
)

target_include_directories(${PROJECT_NAME} PRIVATE
)

target_compile_definitions(${PROJECT_NAME} PRIVATE
)

# Add linked libraries
target_link_libraries(${PROJECT_NAME}
		stm32cubemx
		tinyusb
		core
)
