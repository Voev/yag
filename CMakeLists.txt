cmake_minimum_required(VERSION 3.18)

project(gostone LANGUAGES C CXX)

# Set path to CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Configure result directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Enable custom CMake modules
include(CompilerSettings)
include(CreateOptions)
include(ConfigureOptions)

# Set OpenSSL settings
find_package(OpenSSL 3.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Use project include directory
include_directories(${PROJECT_SOURCE_DIR}/include)

# Entry point for provider sources
add_subdirectory(provider)

# Entry point for provider tests
if (ENABLE_TESTS)
  find_package(GTest REQUIRED)
  enable_testing()
  add_subdirectory(tests)
endif (ENABLE_TESTS)
