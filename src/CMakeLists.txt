# Target name
set(LIB_NAME ${PROJECT_NAME})

# Sources
file(GLOB_RECURSE SOURCES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" *.c)

# Shared library target
add_library(${LIB_NAME} SHARED ${SOURCES})

# Dependencies
target_link_libraries(${LIB_NAME} PUBLIC OpenSSL::Crypto)

# Remove prefix to correctly load the library as a provider
set_target_properties(${LIB_NAME} PROPERTIES PREFIX "")

# Install options
install(
    TARGETS ${LIB_NAME}
    DESTINATION lib/ossl-modules)