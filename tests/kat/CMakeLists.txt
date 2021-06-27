cmake_minimum_required(VERSION 3.10)

if(ENABLE_TEST)
    set(APP_NAME gostone_kat)
    aux_source_directory(${PROJECT_SOURCE_DIR}/tests/kat SOURCE_FILES) 
    add_executable(${APP_NAME} ${SOURCE_FILES})
    target_link_libraries(${APP_NAME} ${OPENSSL_LIBRARIES})
    target_link_libraries(${APP_NAME} GTest::GTest)
endif()


