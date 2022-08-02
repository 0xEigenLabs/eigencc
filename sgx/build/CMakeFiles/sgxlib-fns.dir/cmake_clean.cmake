file(REMOVE_RECURSE
  "../release"
  "intermediate"
  "target"
  "cmake_tomls"
  "CMakeFiles/sgxlib-fns"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/sgxlib-fns.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
