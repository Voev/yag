cmake_minimum_required(VERSION 3.10)

set(LIB_NAME gostone)
aux_source_directory(./ SOURCES)
aux_source_directory(asn1 SOURCES)
aux_source_directory(digests SOURCES)
aux_source_directory(keymgmt SOURCES)
aux_source_directory(encode SOURCES)
aux_source_directory(decode SOURCES)
aux_source_directory(signature SOURCES)

add_library(${LIB_NAME} SHARED ${SOURCES})
set_target_properties(${LIB_NAME} PROPERTIES PREFIX "")
