file(REMOVE_RECURSE
  "../release"
  "intermediate"
  "target"
  "cmake_tomls"
  "CMakeFiles/sgxapp-unit_test"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/sgxapp-unit_test.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()