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

#[macro_use]
extern crate log;

use eigen_core::ipc::protos::ecall::{RunUnitTestInput, RunUnitTestOutput};
use eigen_core::prelude::*;
use eigen_core::Result;

#[macro_use]
mod unittest;
use unittest::*;

use binder::TeeBinder;
use std::sync::Arc;

fn run_test_in_tee(tee: &TeeBinder) -> Result<()> {
    trace!("Running as Unit Test Client ...");
    let args_info = RunUnitTestInput::default();
    let ret_info = tee.invoke::<RunUnitTestInput, RunUnitTestOutput>(
        ECallCommand::RunUnitTest.into(),
        args_info,
    )?;
    assert_eq!(ret_info.failed_count, 0);
    Ok(())
}

fn test_from_unstrusted() {
    unit_tests!(
        eigen_core::tests::test_error,
        config::tests::test_runtime_config,
        config::tests::test_build_config,
    );
}

fn test_in_tee() -> Result<()> {
    let tee = TeeBinder::new(env!("CARGO_PKG_NAME"), 1)?;
    let tee = Arc::new(tee);
    {
        let ref_tee = tee.clone();
        ctrlc::set_handler(move || {
            info!("\nCTRL+C pressed. Destroying server enclave");
            ref_tee.finalize();
            std::process::exit(0);
        })
        .expect("Error setting Ctrl-C handler");
    }
    run_test_in_tee(&tee)?;
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();

    test_from_unstrusted();
    test_in_tee()?;

    Ok(())
}
