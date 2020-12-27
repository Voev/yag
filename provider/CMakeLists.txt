cmake_minimum_required(VERSION 3.10)

set(LIB_NAME gostone)
file(GLOB SOURCES
     *.c
     digests/*.c
     keymgmt/*.c
     encode/*.c
     signature/*.c)

add_library(${LIB_NAME} SHARED ${SOURCES})
set_target_properties(${LIB_NAME} PROPERTIES PREFIX "")
