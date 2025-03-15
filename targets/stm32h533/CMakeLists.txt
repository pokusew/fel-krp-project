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

# Link directories setup
target_link_directories(${PROJECT_NAME} PRIVATE
    # Add user defined library search paths
)

# Add sources to executable
target_sources(${PROJECT_NAME} PRIVATE
    # Add user sources here
)

# Add include paths
target_include_directories(${PROJECT_NAME} PRIVATE
    # Add user defined include paths
)

# Add project symbols (macros)
target_compile_definitions(${PROJECT_NAME} PRIVATE
    # Add user defined symbols
)

# Add linked libraries
target_link_libraries(${PROJECT_NAME}
    stm32cubemx

    # Add user defined libraries
)
