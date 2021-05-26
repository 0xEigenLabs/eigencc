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

// Insert std prelude in the top for the sgx feature
#[cfg(feature = "mesalock_sgx")]
use std::prelude::v1::*;

use crate::worker::{Worker, WorkerContext};
use eigen_core::{Error, ErrorKind, Result};

pub struct EchoWorker {
    worker_id: u32,
    func_name: String,
    input: Option<EchoWorkerInput>,
}
impl EchoWorker {
    pub fn new() -> Self {
        EchoWorker {
            worker_id: 0,
            func_name: "echo".to_string(),
            input: None,
        }
    }
}
struct EchoWorkerInput {
    msg: String,
}
impl Worker for EchoWorker {
    fn function_name(&self) -> &str {
        self.func_name.as_str()
    }
    fn set_id(&mut self, worker_id: u32) {
        self.worker_id = worker_id;
    }
    fn id(&self) -> u32 {
        self.worker_id
    }
    fn prepare_input(&mut self, dynamic_input: Option<String>) -> Result<()> {
        let msg = dynamic_input.ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;
        self.input = Some(EchoWorkerInput { msg });
        Ok(())
    }
    fn execute(&mut self, _context: WorkerContext) -> Result<String> {
        let input = self
            .input
            .take()
            .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;
        Ok(input.msg + "duanbing ")
    }
}
