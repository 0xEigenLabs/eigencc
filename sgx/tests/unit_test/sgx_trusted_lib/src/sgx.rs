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

#[cfg(feature = "mesalock_sgx")]
use std::prelude::v1::*;

use eigen_core::ipc::protos::ecall::{RunUnitTestInput, RunUnitTestOutput};
use eigen_core::prelude::*;
use eigen_core::Result;

use sgx_tunittest::*;

register_ecall_handler!(
    type ECallCommand,
    (ECallCommand::RunUnitTest, RunUnitTestInput, RunUnitTestOutput),
    (ECallCommand::InitEnclave, InitEnclaveInput, InitEnclaveOutput),
    (ECallCommand::FinalizeEnclave, FinalizeEnclaveInput, FinalizeEnclaveOutput),
);

#[handle_ecall]
fn handle_run_unit_test(_args: &RunUnitTestInput) -> Result<RunUnitTestOutput> {
    let mut nfailed = 0;
    if !cfg!(sgx_sim) {
        nfailed = rsgx_unit_tests!(attestation::tests::test_report,);
    };

    Ok(RunUnitTestOutput::new(nfailed))
}

#[handle_ecall]
fn handle_init_enclave(_args: &InitEnclaveInput) -> Result<InitEnclaveOutput> {
    eigen_core::init_service(env!("CARGO_PKG_NAME"))?;
    Ok(InitEnclaveOutput::default())
}

#[handle_ecall]
fn handle_finalize_enclave(_args: &FinalizeEnclaveInput) -> Result<FinalizeEnclaveOutput> {
    #[cfg(feature = "cov")]
    sgx_cov::cov_writeout();

    info!("Enclave [Unit Test]: Finalized.");
    Ok(FinalizeEnclaveOutput::default())
}
