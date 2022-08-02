file(REMOVE_RECURSE
  "../release"
  "intermediate"
  "target"
  "cmake_tomls"
  "CMakeFiles/doc"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/doc.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
