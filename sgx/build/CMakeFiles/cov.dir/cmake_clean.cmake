file(REMOVE_RECURSE
  "../release"
  "intermediate"
  "target"
  "cmake_tomls"
  "CMakeFiles/cov"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/cov.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
