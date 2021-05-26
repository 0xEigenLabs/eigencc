#!/bin/bash
set -e
REQUIRED_ENVS=("MESATEE_PROJECT_ROOT" "MESATEE_BUILD_ROOT" "CMAKE_C_COMPILER")
for var in "${REQUIRED_ENVS[@]}"; do
    [ -z "${!var}" ] && echo "Please set ${var}" && exit -1
done

# Tell gcc/clang to remap absolute src paths to make enclaves' signature more reproducible
exec "${CMAKE_C_COMPILER}" "$@" -fdebug-prefix-map=${MESATEE_PROJECT_ROOT}=/tmp/mesatee_symlinks/mesatee_src -fdebug-prefix-map=${MESATEE_BUILD_ROOT}=/tmp/mesatee_symlinks/mesatee_build
