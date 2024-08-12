find_package(OpenSSL 3.0 REQUIRED)

if (ENABLE_TESTS)
  find_package(GTest REQUIRED)
  include(GoogleTest)
endif (ENABLE_TESTS)
