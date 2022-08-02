use std::env;

fn choose_sgx_dylib(is_sim: bool) {
    if is_sim {
        println!("cargo:rustc-link-lib=dylib=sgx_urts_sim");
        println!("cargo:rustc-link-lib=dylib=sgx_uae_service_sim");
    } else {
        println!("cargo:rustc-link-lib=dylib=sgx_urts");
        println!("cargo:rustc-link-lib=dylib=sgx_uae_service");
    }
}

fn main() {
    let sdk_dir = env::var("SGX_SDK").unwrap_or("/opt/intel/sgxsdk".into());
    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
    println!("cargo:rustc-link-lib=static=sgx_uprotected_fs");

    let is_sim = match env::var("SGX_MODE") {
        Ok(ref v) if v == "SW" => true,
        Ok(ref v) if v == "HW" => false,
        Err(env::VarError::NotPresent) => false,
        _ => {
            panic!("Stop build process, wrong SGX_MODE env provided.");
        }
    };

    choose_sgx_dylib(is_sim);
}
