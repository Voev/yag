cmake_minimum_required(VERSION 3.10)

project(gostone
    LANGUAGES C CXX)

find_package(OpenSSL 3.0.0 REQUIRED)
message("-- OpenSSL include directory: ${OPENSSL_INCLUDE_DIR}")
message("-- OpenSSL libraries: ${OPENSSL_LIBRARIES}")
include_directories(${OPENSSL_INCLUDE_DIR})
list(APPEND LIB_LIST ${OPENSSL_LIBRARIES})

if(MSVC)
  if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
    string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
  endif()
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
  set(COMPILER_OPTIONS "-Werror -Wall -Wextra -Wpedantic")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMPILER_OPTIONS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMPILER_OPTIONS}")
endif()

include_directories(${PROJECT_SOURCE_DIR}/include)
add_subdirectory(provider)
add_subdirectory(tests)
