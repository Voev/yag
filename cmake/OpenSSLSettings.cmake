find_package(OpenSSL 3.0 REQUIRED)

message("-- OpenSSL root directory: ${OPENSSL_ROOT_DIR}")
message("-- OpenSSL include directory: ${OPENSSL_INCLUDE_DIR}")
message("-- OpenSSL libraries: ${OPENSSL_LIBRARIES}")

include_directories(${OPENSSL_INCLUDE_DIR})
list(APPEND LIB_LIST OpenSSL::Crypto)

