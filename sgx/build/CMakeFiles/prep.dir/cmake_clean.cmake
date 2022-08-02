file(REMOVE_RECURSE
  "../release"
  "intermediate"
  "target"
  "cmake_tomls"
  "CMakeFiles/prep"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/prep.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
