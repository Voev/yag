# Unit tests
if (ENABLE_UNIT)
  add_subdirectory(unit)
endif ()

# Known answer tests
if (ENABLE_KAT)
  add_subdirectory(kat)
endif ()