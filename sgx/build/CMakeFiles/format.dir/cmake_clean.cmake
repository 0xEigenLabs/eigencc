file(REMOVE_RECURSE
  "../release"
  "intermediate"
  "target"
  "cmake_tomls"
  "CMakeFiles/format"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/format.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
