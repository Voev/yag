set(APP_NAME gostone_ka_tests)

aux_source_directory(${PROJECT_SOURCE_DIR}/tests/kat SOURCE_FILES)

add_executable(${APP_NAME} ${SOURCE_FILES})

target_link_libraries(${APP_NAME}
    OpenSSL::Crypto
    GTest::GTest)
