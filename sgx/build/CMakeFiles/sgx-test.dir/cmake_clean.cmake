file(REMOVE_RECURSE
  "../release"
  "intermediate"
  "target"
  "cmake_tomls"
  "CMakeFiles/sgx-test"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/sgx-test.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
