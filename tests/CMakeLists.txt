cmake_minimum_required(VERSION 3.10)

option(ENABLE_TEST "Build tests" OFF)

if(ENABLE_TEST)
    enable_testing()
    find_package(GTest REQUIRED)
    message("-- GTest include directory: ${GTEST_INCLUDE_DIR}")
    message("-- GTest libraries: ${GTEST_LIBRARIES}")

    add_subdirectory(kat)
    add_subdirectory(unit)
endif()


