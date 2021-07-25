find_package(OpenSSL 3.0.0 REQUIRED)

message("-- OpenSSL include directory: ${OPENSSL_INCLUDE_DIR}")
message("-- OpenSSL libraries: ${OPENSSL_LIBRARIES}")

include_directories(${OPENSSL_INCLUDE_DIR})
list(APPEND LIB_LIST ${OPENSSL_LIBRARIES})
