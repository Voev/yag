# Application name
set(TEST_NAME gostone_ka_tests)

# Sources
file(GLOB_RECURSE SOURCES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" *.cpp)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SOURCES)

# Set executable target
add_executable(${TEST_NAME} ${SOURCES})

# Set dependencies
target_link_libraries(${TEST_NAME}
    OpenSSL::Crypto
    GTest::GTest)

# Discover tests
gtest_discover_tests(
    ${TEST_NAME}
    XML_OUTPUT_DIR ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TEST_NAME}.reports
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
)