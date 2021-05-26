// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#![feature(specialization)] // for mayfail

// Use sgx_tstd to replace Rust's default std
#![cfg_attr(feature = "mesalock_sgx", no_std)]
#[cfg(feature = "mesalock_sgx")]
#[macro_use]
extern crate sgx_tstd as std;

#[macro_use]
extern crate log;

#[cfg(feature = "mesalock_sgx")]
extern crate ring;

pub mod db;
pub mod rpc; // Syntax sugar for monadic error handling, defined in mayfail.rs

// MesaTEE Error is defined in error.rs
mod error;
pub use error::EnclaveStatus;
pub use error::Error;
pub use error::ErrorKind;
pub use error::Result;
pub use error::UntrustedStatus;

#[cfg(feature = "ipc")]
pub mod ipc;

// re-export
#[cfg(feature = "ipc")]
pub use ipc_attribute;

pub use serde::de::DeserializeOwned;
pub use serde::Serialize;

pub mod config;
pub mod prelude;

#[cfg(feature = "mesalock_sgx")]
pub fn init_service(name: &str) -> Result<()> {
    use std::backtrace;
    env_logger::init();

    debug!("Enclave [{}]: Initializing...", name);

    if backtrace::enable_backtrace(format!("{}.signed.so", name), backtrace::PrintFormat::Full)
        .is_err()
    {
        error!("Cannot enable backtrace");
        return Err(Error::from(ErrorKind::ECallError));
    }
    if !config::is_runtime_config_initialized() {
        error!("Runtime config is not initialized");
        return Err(Error::from(ErrorKind::ECallError));
    }
    crate::rpc::sgx::prelude()?;

    Ok(())
}

#[cfg(all(feature = "eigen_unit_test"))]
pub mod tests {
    use super::*;

    pub fn test_error() {
        error::tests::test_debug_error();
        error::tests::test_downcasting();
    }
}
