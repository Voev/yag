cmake_minimum_required(VERSION 3.10)

option(ENABLE_TEST "Build tests" OFF)

if(ENABLE_TEST)
    enable_testing()
    find_package(GTest REQUIRED)
    message("-- GTest include directory: ${GTEST_INCLUDE_DIR}")
    message("-- GTest libraries: ${GTEST_LIBRARIES}")

    set(APP_NAME gostone_tests)
    file(GLOB SOURCES *.cpp)
    
    add_executable(${APP_NAME} ${SOURCES})
    target_link_libraries(${APP_NAME} ${OPENSSL_LIBRARIES})
    target_link_libraries(${APP_NAME} GTest::GTest)
endif()


