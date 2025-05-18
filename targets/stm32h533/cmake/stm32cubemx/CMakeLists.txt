cmake_minimum_required(VERSION 3.22)
# Enable CMake support for ASM and C languages
enable_language(C ASM)
# STM32CubeMX generated symbols (macros)
set(MX_Defines_Syms
	USE_NUCLEO_64
	USE_HAL_DRIVER
	STM32H533xx
    $<$<CONFIG:Debug>:DEBUG>
)

set(MX_Root_Dir ../..)

# STM32CubeMX generated include paths
set(MX_Include_Dirs
    ${MX_Root_Dir}/Inc
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Inc
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Inc/Legacy
    ${MX_Root_Dir}/Drivers/BSP/STM32H5xx_Nucleo
    ${MX_Root_Dir}/Drivers/CMSIS/Device/ST/STM32H5xx/Include
    ${MX_Root_Dir}/Drivers/CMSIS/Include
)

# STM32CubeMX generated application sources
set(MX_Application_Src
    ${MX_Root_Dir}/Src/main.c
    ${MX_Root_Dir}/Src/stm32h5xx_it.c
    ${MX_Root_Dir}/Src/stm32h5xx_hal_msp.c
    ${MX_Root_Dir}/Src/sysmem.c
    ${MX_Root_Dir}/Src/syscalls.c
    ${MX_Root_Dir}/startup_stm32h533xx.s
)

# STM32 HAL/LL Drivers
set(STM32_Drivers_Src
    ${MX_Root_Dir}/Src/system_stm32h5xx.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_cortex.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_icache.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_hash.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_cryp.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_cryp_ex.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_pka.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_rcc.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_rcc_ex.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_flash.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_flash_ex.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_gpio.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_dma.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_dma_ex.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_pwr.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_pwr_ex.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_exti.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_rng.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_rng_ex.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_ll_rng.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_usart.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_usart_ex.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_uart_ex.c
    ${MX_Root_Dir}/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_uart.c
    ${MX_Root_Dir}/Drivers/BSP/STM32H5xx_Nucleo/stm32h5xx_nucleo.c
)

# Drivers Midllewares



# Link directories setup
set(MX_LINK_DIRS

)
# Project static libraries
set(MX_LINK_LIBS
    STM32_Drivers

)
# Interface library for includes and symbols
add_library(stm32cubemx INTERFACE)
target_include_directories(stm32cubemx INTERFACE ${MX_Include_Dirs})
target_compile_definitions(stm32cubemx INTERFACE ${MX_Defines_Syms})

# Create STM32_Drivers static library
add_library(STM32_Drivers OBJECT)
target_sources(STM32_Drivers PRIVATE ${STM32_Drivers_Src})
target_link_libraries(STM32_Drivers PUBLIC stm32cubemx)


# Add STM32CubeMX generated application sources to the project
target_sources(${PROJECT_NAME} PRIVATE ${MX_Application_Src})

# Link directories setup
target_link_directories(${PROJECT_NAME} PRIVATE ${MX_LINK_DIRS})

# Add libraries to the project
target_link_libraries(${PROJECT_NAME} ${MX_LINK_LIBS})

# Add the map file to the list of files to be removed with 'clean' target
set_target_properties(${PROJECT_NAME} PROPERTIES ADDITIONAL_CLEAN_FILES ${PROJECT_NAME}.map)

# Validate that STM32CubeMX code is compatible with C standard
if((CMAKE_C_STANDARD EQUAL 90) OR (CMAKE_C_STANDARD EQUAL 99))
    message(ERROR "Generated code requires C11 or higher")
endif()
