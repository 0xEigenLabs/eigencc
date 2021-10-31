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
use eigen_core::Result;

use eigen_crypto::sign::ecdsa::{KeyPair, EcdsaKeyPair};
use rand::Rng;
use lazy_static::lazy_static;

// TODO: For a naive implementation, now the key pair is never changed
//       when `fns` is launched, however, in the future, the key pair
//       may be updated by some mechanism
lazy_static! {
    static ref CACHED_KEY_PAIR: EcdsaKeyPair = {
        let mut r = vec![0u8; 32];
        rand::thread_rng().fill(&mut r[..]);
        let private_key = eigen_crypto::sign::ecdsa::EcdsaKeyPair::from_seed_unchecked(
            &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1_SIGNING,
            untrusted::Input::from(&r),
            );
        private_key.unwrap()
    };

    static ref CACHED_AES_KEY: Vec<u8> = {
        let mut r = vec![0u8; 32];
        rand::thread_rng().fill(&mut r[..]);
        r
    };
}

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
        // generate pk and sk
        let alg = &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
        let public_key = eigen_crypto::sign::ecdsa::UnparsedPublicKey::new(alg, CACHED_KEY_PAIR.public_key());
        let public_key_hex = hex::encode(public_key.as_ref());

        Ok(public_key_hex)
    }
}

pub fn get_key_pair() -> &'static EcdsaKeyPair {
    &CACHED_KEY_PAIR
}

pub fn get_aes_key() -> &'static Vec<u8> {
    &CACHED_AES_KEY
}
