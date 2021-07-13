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

use std::str;
use std::vec;
use crate::worker::{Worker, WorkerContext};
use eigen_core::{Error, ErrorKind, Result};
use sgx_tcrypto::{
    rsgx_sha256_slice,
    SgxEccHandle
};

pub struct RegisterWorker {
    worker_id: u32,
    func_name: String,
    input: Option<RegisterWorkerInput>,
}
impl RegisterWorker {
    pub fn new() -> Self {
        RegisterWorker {
            worker_id: 0,
            func_name: "EigenTEERegister".to_string(),
            input: None,
        }
    }
}

struct RegisterWorkerInput {
}

impl Worker for RegisterWorker {
    fn function_name(&self) -> &str {
        self.func_name.as_str()
    }

    fn set_id(&mut self, worker_id: u32) {
        self.worker_id = worker_id;
    }

    fn id(&self) -> u32 {
        self.worker_id
    }

    fn prepare_input(&mut self, _dynamic_input: Option<String>) -> Result<()> {
        Ok(())
    }

    fn execute(&mut self, _context: WorkerContext) -> Result<String> {
        let input = self
            .input
            .take()
            .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;
        // generate pk and sk
        let ec_handle = SgxEccHandle::new();
        ec_handle.open()?;
        let (_sk, pk) = ec_handle.create_key_pair()?;

        // encode, section 4.3.6 of ANSI X9.62
        let mut pub_key_bytes: Vec<u8> = vec![4]; // uncompressed point
        let mut pk_gx = pk.gx.clone();
        pk_gx.reverse(); // big-endian byte slice
        let mut pk_gy = pk.gy.clone();
        pk_gy.reverse();
        pub_key_bytes.extend_from_slice(&pk_gx);
        pub_key_bytes.extend_from_slice(&pk_gy);

        // calculate sha256 of public key
        let ret = rsgx_sha256_slice::<u8>(&pub_key_bytes.clone());
        match ret {
            Ok(key) => {
                let mut res_bytes: Vec<u8> = key.to_vec();
                res_bytes.extend_from_slice(&pub_key_bytes);
                Ok(str::from_utf8(&res_bytes)?.to_string())
            },
            Err(e) => {
                warn!("Hash failed {:?}", e);
                Err(Error::from(ErrorKind::InvalidInputError))
            }
        }
    }
}
