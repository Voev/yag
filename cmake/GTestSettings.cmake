option(ENABLE_TEST "Build tests" OFF)

if(ENABLE_TEST)
    set(TEST_APP_NAME "${PROJECT_NAME}_tests")
    set(KATEST_APP_NAME "${PROJECT_NAME}_katests")

    enable_testing()
    find_package(GTest REQUIRED)
    
    message("-- GTest include directory: ${GTEST_INCLUDE_DIR}")
    message("-- GTest libraries: ${GTEST_LIBRARIES}")
endif()

