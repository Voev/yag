cmake_minimum_required(VERSION 3.10)
project(gostone LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include_directories(${PROJECT_SOURCE_DIR}/include)
include(CompilerSettings)
include(OpenSSLSettings)
include(GTestSettings)
include(CoverageSettings)

add_subdirectory(provider)
add_subdirectory(tests)


