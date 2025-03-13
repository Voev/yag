# Application name
set(TEST_NAME yag_ka_tests)

# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Set executable target
add_executable(${TEST_NAME} ${SOURCES})

# Set dependencies
target_link_libraries(${TEST_NAME}
    OpenSSL::Crypto
    GTest::GTest)

# Set custom target for KAT
add_custom_target(run_kat
    COMMAND ${TEST_NAME} --provider-path ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} --provider default --provider yag --config ${CMAKE_CURRENT_SOURCE_DIR}/data/kat.txt
    DEPENDS ${TEST_NAME}
    COMMENT "Running known-answer tests..."
)
