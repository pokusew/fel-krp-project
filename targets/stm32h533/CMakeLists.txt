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
)

target_include_directories(${PROJECT_NAME} PRIVATE
		../../core
)

target_compile_definitions(${PROJECT_NAME} PRIVATE
)

# Add linked libraries
target_link_libraries(${PROJECT_NAME}
		stm32cubemx
		tinyusb
)
