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

use std::vec;

use eigen_crypto::sign::ecdsa::KeyPair;
use rand::Rng;

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
        let mut r = vec![0u8; 32];
        rand::thread_rng().fill(&mut r[..]);
        let private_key = eigen_crypto::sign::ecdsa::EcdsaKeyPair::from_seed_unchecked(
            &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1_SIGNING,
            untrusted::Input::from(&r),
            );

        assert_eq!(private_key.is_ok(), true);
        let private_key = private_key.unwrap();
        let msg = "hello, come on, go get it 你好!";
        let s1 = vec![];
        let s2 = vec![];

        let alg = &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
        let public_key = eigen_crypto::sign::ecdsa::UnparsedPublicKey::new(alg, private_key.public_key());

        let cipher = eigen_crypto::ec::suite_b::ecies::encrypt(&public_key, &s1, &s2, msg.as_bytes());
        assert_eq!(cipher.is_ok(), true);
        let cipher = cipher.unwrap();
        let plain = eigen_crypto::ec::suite_b::ecies::decrypt(&private_key, &cipher, &s1, &s2);

        assert_eq!(plain.is_ok(), true);
        assert_eq!(msg.as_bytes().to_vec(), (plain.unwrap()));
        std::println!("check success");
        Ok(input.msg + ", Eigen")
    }
}
