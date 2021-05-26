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

#![cfg_attr(feature = "mesalock_sgx", no_std)]
#[cfg(feature = "mesalock_sgx")]
#[macro_use]
extern crate sgx_tstd as std;

//#[macro_use]
extern crate log;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("OCall failed")]
    OCallError,
    #[error("Ias error")]
    IasError,
    #[error("Get quote error")]
    QuoteError,
}

#[macro_use]
mod cert;
pub mod quote;
pub mod verifier;

use cfg_if::cfg_if;
cfg_if! {
    if #[cfg(feature = "mesalock_sgx")]  {
        pub mod key;
        mod report;
        mod ias;
        pub use report::IasReport;
    } else {
    }
}

#[cfg(all(feature = "eigen_unit_test", feature = "mesalock_sgx"))]
pub mod tests {
    use super::*;
    use std::env;

    pub fn test_report() {
        let ias_key = env::var("IAS_KEY").unwrap();
        let ias_spid = env::var("IAS_SPID").unwrap();

        report::tests::test_init_quote();
        report::tests::test_create_report();
        report::tests::test_get_quote(&ias_key, &ias_spid);
    }
}
