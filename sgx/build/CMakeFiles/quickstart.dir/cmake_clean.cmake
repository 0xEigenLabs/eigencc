file(REMOVE_RECURSE
  "../release"
  "intermediate"
  "target"
  "cmake_tomls"
  "CMakeFiles/quickstart"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/quickstart.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
