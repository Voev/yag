find_package(OpenSSL 3.0 REQUIRED)

if (ENABLE_KAT STREQUAL "ON" OR ENABLE_UNIT STREQUAL "ON")
  find_package(GTest REQUIRED)
  include(GoogleTest)
  enable_testing()
endif ()
