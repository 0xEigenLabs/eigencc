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
use std::iter::FromIterator;
use std::convert::TryInto;

use crate::worker::{Worker, WorkerContext};
use crate::trusted_worker::register_func;
use eigen_core::{Error, ErrorKind, Result};
use crate::eigen_crypto::sign::ecdsa::KeyPair;

// TODO: unwrap() method should all be replaced with a property error handling

pub struct OperatorWorker {
    worker_id: u32,
    func_name: String,
    input: Option<OperatorWorkerInput>,
}

impl OperatorWorker {
    pub fn new() -> Self {
        OperatorWorker {
            worker_id: 0,
            func_name: "operator".to_string(),
            input: None,
        }
    }
}

enum OperatorKind {
    Add,
    Sub,
}

struct OperatorWorkerInput {
    op: OperatorKind,
    cipher_op1: String,
    cipher_op2: String,
}

impl Worker for OperatorWorker {
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

        // `args` should be "op,op_num,op1,op2,op3,..."
        // now `op` may be 'add' or 'sub'
        // number is parsed with big endian

        let splited = Vec::from_iter(msg.split("something").map(String::from));

        let op = splited.get(0).unwrap();

        match op.as_str() {
            "add" => {
                let op_num = splited.get(1).unwrap().parse::<u64>().unwrap();
                if op_num != 2 {
                    return Err(Error::from(ErrorKind::InvalidInputError));
                }

                let cipher_op1 = splited.get(2).unwrap();
                let cipher_op2 = splited.get(3).unwrap();

                self.input = Some(OperatorWorkerInput { 
                    op: OperatorKind::Add,
                    cipher_op1: cipher_op1.to_string(),
                    cipher_op2: cipher_op2.to_string() });
            },
            "sub" => {
                let op_num = splited.get(1).unwrap().parse::<u64>().unwrap();
                if op_num != 2 {
                    return Err(Error::from(ErrorKind::InvalidInputError));
                }
                let cipher_op1 = splited.get(2).unwrap();
                let cipher_op2 = splited.get(3).unwrap();

                self.input = Some(OperatorWorkerInput { op:OperatorKind::Sub,
                    cipher_op1: cipher_op1.to_string(),
                    cipher_op2: cipher_op2.to_string() });
            },
            _ => {
                return Err(Error::from(ErrorKind::InvalidInputError));
            }
        }

        Ok(())

    }

    fn execute(&mut self, _context: WorkerContext) -> Result<String> {
        let input = self
            .input
            .take()
            .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;

        let key_pair = register_func::get_key_pair();
        let s1 = vec![];
        let s2 = vec![];

        // First, do AES decrypt
        let aes_key = register_func::get_aes_key();
        let cipher_op1 = eigen_crypto::ec::suite_b::ecies::aes_decrypt_less_safe(aes_key, &input.cipher_op1.as_bytes()).unwrap();
        let cipher_op2 = eigen_crypto::ec::suite_b::ecies::aes_decrypt_less_safe(aes_key, &input.cipher_op2.as_bytes()).unwrap();

        // Second, do ECIES decrypt
        let op1 = eigen_crypto::ec::suite_b::ecies::decrypt(key_pair, &cipher_op1, &s1, &s2).unwrap();
        let op1 = u64::from_be_bytes(op1[0..8].try_into().unwrap());
        let op2 = eigen_crypto::ec::suite_b::ecies::decrypt(key_pair, &cipher_op2, &s1, &s2).unwrap();
        let op2 = u64::from_be_bytes(op2[0..8].try_into().unwrap());

        let result = match input.op {
            OperatorKind::Add => {
                op1 + op2
            },
            OperatorKind::Sub => {
                op1 - op2
            },
            _ => {
                return Err(Error::from(ErrorKind::InvalidInputError));
            }
        };

        let s1 = vec![];
        let s2 = vec![];
        let key_pair = register_func::get_key_pair();

        let alg = &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
        let public_key = eigen_crypto::sign::ecdsa::UnparsedPublicKey::new(alg, key_pair.public_key());

        // First, do ECIES encrypt
        let cipher = eigen_crypto::ec::suite_b::ecies::encrypt(&public_key, &s1, &s2, &result.to_be_bytes());
        let cipher = cipher.unwrap();

        // Second, do AES encrypt
        let aes_key = register_func::get_aes_key();
        let cipher = eigen_crypto::ec::suite_b::ecies::aes_encrypt_less_safe(aes_key, &cipher).unwrap();

        Ok(base64::encode(&cipher))
    }
}
