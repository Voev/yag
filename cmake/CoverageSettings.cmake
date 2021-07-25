option(ENABLE_COVERAGE "Build with coverage" OFF)

if(ENABLE_COVERAGE)
   include(CodeCoverage)
   append_coverage_compiler_flags()

   setup_target_for_coverage_lcov(
       NAME coverage
       EXECUTABLE "${TEST_APP_NAME}"
       BASE_DIRECTORY "${PROJECT_SOURCE_DIR}/provider/"
       EXCLUDE "/usr/*" "${PROJECT_SOURCE_DIR}/tests/*")
endif()

