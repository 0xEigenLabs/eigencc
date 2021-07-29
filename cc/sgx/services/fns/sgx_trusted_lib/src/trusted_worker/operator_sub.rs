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
use crate::trusted_worker::register_func;
use eigen_core::{Error, ErrorKind, Result};


pub struct SubWorker {
    worker_id: u32,
    func_name: String,
    input: Option<SubWorkerInput>,
}

impl SubWorker {
    pub fn new() -> Self {
        SubWorker {
            worker_id: 0,
            func_name: "add".to_string(),
            input: None,
        }
    }
}

struct SubWorkerInput {
    op1: u64,
    op2: u64,
}

impl Worker for SubWorker {
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

        trace!("Before Decode: {}", msg);
        let decoded = base64::decode(&msg).expect("Decode base64 fail");
        trace!("Before Decrypt: {:?}", &decoded[..]);
        let key_pair = register_func::get_key_pair();
        let s1 = vec![];
        let s2 = vec![];
        let plain = eigen_crypto::ec::suite_b::ecies::decrypt(key_pair, &decoded, &s1, &s2).unwrap();
        let decrypted = std::str::from_utf8(&plain[..])?.to_string();
        let trimed = decrypted.trim_matches(char::from(0)).trim();
        trace!("Decrypt and trimed [{}]: {}", trimed.len(), trimed);

        let ops: Vec<u64> = trimed.split(",").map(|s| s.parse::<u64>().unwrap()).collect();

        if ops.len() != 2 {
            return Err(Error::from(ErrorKind::InvalidInputError));
        }

        let (op1, op2) = (ops[0], ops[1]);

        self.input = Some(AddWorkerInput { op1, op2 });
        Ok(())
    }

    fn execute(&mut self, _context: WorkerContext) -> Result<String> {
        let input = self
            .input
            .take()
            .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;
        let result = (input.op1 - input.op2).to_string();
        let s1 = vec![];
        let s2 = vec![];
        let key_pair = register_func::get_key_pair();

        let alg = &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
        let public_key = eigen_crypto::sign::ecdsa::UnparsedPublicKey::new(alg, key_pair.public_key());

        let cipher = eigen_crypto::ec::suite_b::ecies::encrypt(&public_key, &s1, &s2, result.as_bytes());
        let cipher = cipher.unwrap();
        Ok(base64::encode(&cipher))
    }
}
