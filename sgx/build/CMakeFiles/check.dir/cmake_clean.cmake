file(REMOVE_RECURSE
  "../release"
  "intermediate"
  "target"
  "cmake_tomls"
  "CMakeFiles/check"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/check.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
