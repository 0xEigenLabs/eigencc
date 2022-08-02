file(REMOVE_RECURSE
  "../release"
  "intermediate"
  "target"
  "cmake_tomls"
  "CMakeFiles/unixlib-sdk_c"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/unixlib-sdk_c.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
