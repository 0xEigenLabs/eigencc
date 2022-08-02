file(REMOVE_RECURSE
  "../release"
  "intermediate"
  "target"
  "cmake_tomls"
  "CMakeFiles/unixapp-cli"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/unixapp-cli.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
