file(REMOVE_RECURSE
  "../release"
  "intermediate"
  "target"
  "cmake_tomls"
  "CMakeFiles/update_sig"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/update_sig.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
