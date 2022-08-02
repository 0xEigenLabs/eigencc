cmake_minimum_required (VERSION 3.10)
project (MesaTEE C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(MesaTEEUtils)
include(ExternalProject)
check_exe_dependencies(git openssl python rustup lsof)
init_submodules()

# ====== VARIABLES FOR CMAKE -D{VAR}=VAL CONFIGURATION BEGIN ======
SET_STRVAR_FROM_ENV_OR(SGX_SDK "/opt/sgxsdk" "Path of SGX SDK")
SET_STRVAR_FROM_ENV_OR(RUSTFLAGS "" "Rust flags")
SET_STRVAR_FROM_ENV_OR(MESATEE_CMAKE_DBG "" "set to turn on debug message for cmake")
#set(MESAPY_VERSION 2b7ea38773d337d106c613a239661a60a4fa7528)
option(COV "Turn on/off coverage" OFF)
option(OFFLINE "Turn on/off cargo offline" ON)
option(TEST_MODE "Turn on/off test mode" OFF)
option(SGX_SIM_MODE "Turn on/off sgx simulation mode" OFF)

if(TEST_MODE)
    set(RUSTFLAGS "${RUSTFLAGS} --cfg test_mode")
endif()
if(SGX_SIM_MODE)
    set(RUSTFLAGS "${RUSTFLAGS} --cfg sgx_sim")
    set(SGX_MODE "SW")
else()
    set(SGX_MODE "HW")
endif()
# ======= VARIABLES FOR CMAKE -D{VAR}=VAL CONFIGURATION END =======

# =============== VARIABLES FOR MANUAL CHANGE BEGIN ===============
set(UNIX_LIBS sdk protected_fs_rs)
# ================ VARIABLES FOR MANUAL CHANGE END ================

# UNIX_APPS, SGX_APPS and SGX_LIBS are parsed from corresponding toml files
parse_cargo_packages(UNIX_APPS
    CARGO_TOML_PATH ${PROJECT_SOURCE_DIR}/cmake/tomls/Cargo.unix_app.toml
    CATEGORIES UNIX_APP_CATEGORIES
)
message(WARNING, ${CARGO_TOML_PATH}${PROJECT_SOURCE_DIR}/cmake/tomls/Cargo.unix_app.toml)

parse_cargo_packages(SGX_APPS
    CARGO_TOML_PATH ${PROJECT_SOURCE_DIR}/cmake/tomls/Cargo.sgx_untrusted_app.toml
    CATEGORIES SGX_APP_CATEGORIES
)

parse_cargo_packages(SGX_LIBS
    CARGO_TOML_PATH ${PROJECT_SOURCE_DIR}/cmake/tomls/Cargo.sgx_trusted_lib.toml
    CATEGORIES SGX_LIB_CATEGORIES
    PKG_PATHS SGX_LIB_PATHS
)

include(MesaTEEGenVars)

# ========== CONFIG-TIME CHECKS AND INITIALIZATIONS BEGIN =========
check_sgx_sdk()
generate_env_file()
# =========== CONFIG-TIME CHECKS AND INITIALIZATIONS END ==========

# UTIL TARGETS: prep, sgx-test, cov, cov-clean, format, check, doc, etc.
include(UtilTargets)

# unix_app
list(LENGTH UNIX_APPS UNIX_APP_LEN)
math(EXPR UNIX_APP_LAST_INDEX "${UNIX_APP_LEN} - 1")
foreach(_i RANGE ${UNIX_APP_LAST_INDEX})
    list(GET UNIX_APPS ${_i} _pkg_name)
    list(GET UNIX_APP_CATEGORIES ${_i} _category)
    add_cargo_build_target(${_pkg_name}
        TARGET_NAME "${UNIXAPP_PREFIX}-${_pkg_name}"
        TOML_DIR ${MT_UNIX_TOML_DIR}
        TARGET_DIR ${UNIX_TARGET_DIR}
        INSTALL_DIR ${MESATEE_INSTALL_DIR}/${_category}
        EXTRA_CARGO_FLAGS ${EXTRA_CARGO_FLAGS}
        DEPENDS prep
    )
endforeach()

# sgx_untrusted_app
list(LENGTH SGX_APPS SGX_APP_LEN)
math(EXPR SGX_APP_LAST_INDEX "${SGX_APP_LEN} - 1")
foreach(_i RANGE ${SGX_APP_LAST_INDEX})
    list(GET SGX_APPS ${_i} _pkg_name)
    list(GET SGX_APP_CATEGORIES ${_i} _category)
    add_cargo_build_target(${_pkg_name}
        TARGET_NAME "${SGXAPP_PREFIX}-${_pkg_name}"
        TOML_DIR ${MT_SGXAPP_TOML_DIR}
        TARGET_DIR ${UNTRUSTED_TARGET_DIR}
        INSTALL_DIR ${MESATEE_INSTALL_DIR}/${_category}
        EXTRA_CARGO_FLAGS ${EXTRA_CARGO_FLAGS}
        DEPENDS prep
    )
endforeach()


# sgx_trusted_lib
list(LENGTH SGX_LIBS SGX_LIB_LEN)
math(EXPR SGX_LIB_LAST_INDEX "${SGX_LIB_LEN} - 1")
foreach(_i RANGE ${SGX_LIB_LAST_INDEX})
    list(GET SGX_LIBS ${_i} _pkg_name)
    list(GET SGX_LIB_PATHS ${_i} _pkg_path)
    list(GET SGX_LIB_CATEGORIES ${_i} _category)
    add_sgx_build_target(${_pkg_path} ${_pkg_name}
        DEPENDS prep 
        INSTALL_DIR ${MESATEE_INSTALL_DIR}/${_category}
    )
endforeach()

# MesaTEE C SDK
add_cargo_build_dylib_target(sdk_c
    TARGET_NAME "${UNIXLIB_PREFIX}-sdk_c"
    TOML_DIR ${MT_UNIX_TOML_DIR}
    TARGET_DIR ${UNIX_TARGET_DIR}
    DEPENDS prep
)

add_enclave_sig_target_n_hooks()
