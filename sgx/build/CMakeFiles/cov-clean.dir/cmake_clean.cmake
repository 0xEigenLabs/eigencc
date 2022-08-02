file(REMOVE_RECURSE
  "../release"
  "intermediate"
  "target"
  "cmake_tomls"
  "CMakeFiles/cov-clean"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/cov-clean.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
