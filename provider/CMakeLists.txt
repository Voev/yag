cmake_minimum_required(VERSION 3.10)

set(LIB_NAME gostone)

aux_source_directory(${PROJECT_SOURCE_DIR}/provider/ SOURCES)
aux_source_directory(${PROJECT_SOURCE_DIR}/provider/ciphers SOURCES)
aux_source_directory(${PROJECT_SOURCE_DIR}/provider/digests SOURCES)
aux_source_directory(${PROJECT_SOURCE_DIR}/provider/encode SOURCES)
aux_source_directory(${PROJECT_SOURCE_DIR}/provider/kdfs SOURCES)
aux_source_directory(${PROJECT_SOURCE_DIR}/provider/keymgmt SOURCES)
aux_source_directory(${PROJECT_SOURCE_DIR}/provider/signature SOURCES)

add_library(${LIB_NAME} SHARED ${SOURCES})
set_target_properties(${LIB_NAME} PROPERTIES PREFIX "")

