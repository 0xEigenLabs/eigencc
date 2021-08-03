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

use num_bigint::{BigInt, ToBigInt};
use num_bigint::{BigUint, ToBigUint};

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
    Add1,
    Sub,
    Sub1,
    Enc,
    Dec,
}

struct OperatorWorkerInput {
    // TODO: Use a more property field name to describe what we want to save here.
    //       e.g., when operator is `Enc`, `cipher_op1` is not a cipher one
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

        let splited = Vec::from_iter(msg.split(",").map(String::from));

        let op = splited.get(0).unwrap();

        match op.as_str() {
            "add" => {
                let op_num = splited.get(1).unwrap().parse::<u8>().unwrap();
                if op_num != 2 {
                    return Err(Error::from(ErrorKind::InvalidInputError));
                }

                let cipher_op1 = splited.get(2).unwrap();
                let cipher_op2 = splited.get(3).unwrap();

                self.input = Some(OperatorWorkerInput { 
                    op: OperatorKind::Add,
                    cipher_op1: cipher_op1.to_string(),
                    cipher_op2: cipher_op2.to_string()
                });
            },
            "add1" => {
                let op_num = splited.get(1).unwrap().parse::<u8>().unwrap();
                if op_num != 2 {
                    return Err(Error::from(ErrorKind::InvalidInputError));
                }

                let cipher_op1 = splited.get(2).unwrap();
                let cipher_op2 = splited.get(3).unwrap();

                self.input = Some(OperatorWorkerInput { 
                    op: OperatorKind::Add1,
                    cipher_op1: cipher_op1.to_string(),
                    cipher_op2: cipher_op2.to_string()
                });
            },
            "sub" => {
                let op_num = splited.get(1).unwrap().parse::<u8>().unwrap();
                if op_num != 2 {
                    return Err(Error::from(ErrorKind::InvalidInputError));
                }
                let cipher_op1 = splited.get(2).unwrap();
                let cipher_op2 = splited.get(3).unwrap();

                self.input = Some(OperatorWorkerInput {
                    op: OperatorKind::Sub,
                    cipher_op1: cipher_op1.to_string(),
                    cipher_op2: cipher_op2.to_string()
                });
            },
            "sub1" => {
                let op_num = splited.get(1).unwrap().parse::<u8>().unwrap();
                if op_num != 2 {
                    return Err(Error::from(ErrorKind::InvalidInputError));
                }
                let cipher_op1 = splited.get(2).unwrap();
                let cipher_op2 = splited.get(3).unwrap();

                self.input = Some(OperatorWorkerInput {
                    op: OperatorKind::Sub1,
                    cipher_op1: cipher_op1.to_string(),
                    cipher_op2: cipher_op2.to_string()
                });
            },
            "enc" => {
                let op_num = splited.get(1).unwrap().parse::<u8>().unwrap();
                if op_num != 1 {
                    return Err(Error::from(ErrorKind::InvalidInputError));
                }

                let to_enc = splited.get(2).unwrap();

                self.input = Some(OperatorWorkerInput {
                    op: OperatorKind::Enc,
                    cipher_op1: to_enc.to_string(),
                    cipher_op2: "".to_string()
                });
            }
            "dec" => {
                let op_num = splited.get(1).unwrap().parse::<u8>().unwrap();
                if op_num != 1 {
                    return Err(Error::from(ErrorKind::InvalidInputError));
                }

                let to_dec = splited.get(2).unwrap();

                self.input = Some(OperatorWorkerInput {
                    op: OperatorKind::Dec,
                    cipher_op1: to_dec.to_string(),
                    cipher_op2: "".to_string()
                });
            }
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

        match input.op {
            OperatorKind::Add | OperatorKind::Sub => {
                // First, do AES decrypt
                let aes_key = register_func::get_aes_key();
                let b1 = BigUint::parse_bytes(input.cipher_op1.as_bytes(), 10).unwrap();
                let cipher_op1 = b1.to_bytes_be();
                let b2 = BigUint::parse_bytes(input.cipher_op2.as_bytes(), 10).unwrap();
                let cipher_op2 = b2.to_bytes_be();

                let cipher_op1 = eigen_crypto::ec::suite_b::ecies::aes_decrypt_less_safe(aes_key, &cipher_op1).unwrap();
                let cipher_op2 = eigen_crypto::ec::suite_b::ecies::aes_decrypt_less_safe(aes_key, &cipher_op2).unwrap();

                // Second, do ECIES decrypt
                ///////////////////////////////////////////////////////////////////////////////////////////////
                // let key_pair = register_func::get_key_pair();
                // let s1 = vec![];
                // let s2 = vec![];
                // let op1 = eigen_crypto::ec::suite_b::ecies::decrypt(key_pair, &cipher_op1, &s1, &s2).unwrap();
                // let op1 = u64::from_be_bytes(op1[0..8].try_into().unwrap());
                // let op2 = eigen_crypto::ec::suite_b::ecies::decrypt(key_pair, &cipher_op2, &s1, &s2).unwrap();
                // let op2 = u64::from_be_bytes(op2[0..8].try_into().unwrap());

                let op1 = cipher_op1;
                let op1 = BigUint::from_bytes_be(&op1[..]);
                let op2 = cipher_op2;
                let op2 = BigUint::from_bytes_be(&op2[..]);
                ///////////////////////////////////////////////////////////////////////////////////////////////
                let result = match input.op {
                    OperatorKind::Add => op1 + op2,
                    OperatorKind::Sub => op1 - op2,
                    _ => return Err(Error::from(ErrorKind::InvalidInputError)),
                };

                // First, do ECIES encrypt
                //////////////////////////////////////////////////////////////////////////////////////////////
                // let s1 = vec![];
                // let s2 = vec![];
                // let key_pair = register_func::get_key_pair();
                // let alg = &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
                // let public_key = eigen_crypto::sign::ecdsa::UnparsedPublicKey::new(alg, key_pair.public_key());
                // let cipher = eigen_crypto::ec::suite_b::ecies::encrypt(&public_key, &s1, &s2, &result.to_be_bytes());
                // let cipher = cipher.unwrap();
                let cipher = result.to_bytes_be();
                //////////////////////////////////////////////////////////////////////////////////////////////

                // Second, do AES encrypt
                let aes_key = register_func::get_aes_key();
                let cipher = eigen_crypto::ec::suite_b::ecies::aes_encrypt_less_safe(aes_key, &cipher).unwrap();

                let b = BigUint::from_bytes_be(&cipher[..]);
                let result = b.to_str_radix(10);
                Ok(result)
            },
            OperatorKind::Add1 | OperatorKind::Sub1 => {
                // First, do AES decrypt
                let aes_key = register_func::get_aes_key();
                let b1 = BigUint::parse_bytes(input.cipher_op1.as_bytes(), 10).unwrap();
                let cipher_op1 = b1.to_bytes_be();
                let op2 = BigUint::parse_bytes(input.cipher_op2.as_bytes(), 10).unwrap();

                let cipher_op1 = eigen_crypto::ec::suite_b::ecies::aes_decrypt_less_safe(aes_key, &cipher_op1).unwrap();

                // Second, do ECIES decrypt
                ///////////////////////////////////////////////////////////////////////////////////////////////
                // let key_pair = register_func::get_key_pair();
                // let s1 = vec![];
                // let s2 = vec![];
                // let op1 = eigen_crypto::ec::suite_b::ecies::decrypt(key_pair, &cipher_op1, &s1, &s2).unwrap();
                // let op1 = u64::from_be_bytes(op1[0..8].try_into().unwrap());

                let op1 = cipher_op1;
                let op1 = BigUint::from_bytes_be(&op1[..]);
                ///////////////////////////////////////////////////////////////////////////////////////////////
                let result = match input.op {
                    OperatorKind::Add1 => op1 + op2,
                    OperatorKind::Sub1 => op1 - op2,
                    _ => return Err(Error::from(ErrorKind::InvalidInputError)),
                };

                // First, do ECIES encrypt
                //////////////////////////////////////////////////////////////////////////////////////////////
                // let s1 = vec![];
                // let s2 = vec![];
                // let key_pair = register_func::get_key_pair();
                // let alg = &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
                // let public_key = eigen_crypto::sign::ecdsa::UnparsedPublicKey::new(alg, key_pair.public_key());
                // let cipher = eigen_crypto::ec::suite_b::ecies::encrypt(&public_key, &s1, &s2, &result.to_be_bytes());
                // let cipher = cipher.unwrap();
                let cipher = result.to_bytes_be();
                //////////////////////////////////////////////////////////////////////////////////////////////

                // Second, do AES encrypt
                let aes_key = register_func::get_aes_key();
                let cipher = eigen_crypto::ec::suite_b::ecies::aes_encrypt_less_safe(aes_key, &cipher).unwrap();

                let b = BigUint::from_bytes_be(&cipher[..]);
                let result = b.to_str_radix(10);
                Ok(result)
            },
            OperatorKind::Enc => {
                // First, do ECIES encrypt
                // NOTE: `input.cipher_op1` is acually plain text
                let op1 = BigUint::parse_bytes(input.cipher_op1.as_bytes(), 10).unwrap();
                let op_bytes = op1.to_bytes_be();
                
                ///////////////////////////////////////////////////////////////////////////////////////////////
                // let s1 = vec![];
                // let s2 = vec![];
                // let key_pair = register_func::get_key_pair();

                // let alg = &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
                // let public_key = eigen_crypto::sign::ecdsa::UnparsedPublicKey::new(alg, key_pair.public_key());
                // let cipher = eigen_crypto::ec::suite_b::ecies::encrypt(&public_key, &s1, &s2, &op_bytes);
                // let cipher = cipher.unwrap();

                // XXX:
                let cipher = op_bytes;
                ///////////////////////////////////////////////////////////////////////////////////////////////

                // Second, do AES encrypt
                let aes_key = register_func::get_aes_key();
                let cipher = eigen_crypto::ec::suite_b::ecies::aes_encrypt_less_safe(aes_key, &cipher).unwrap();
                
                let b = BigUint::from_bytes_be(&cipher[..]);
                let result = b.to_str_radix(10);
                Ok(result)
            }
            OperatorKind::Dec => {
                let b = BigUint::parse_bytes(input.cipher_op1.as_bytes(), 10).unwrap();
                let cipher = b.to_bytes_be();
                // let cipher_num = input.cipher_op1.parse::<u64>().unwrap();
                // let cipher = u64::to_be_bytes(cipher_num);

                // First, do AES decrypt
                let aes_key = register_func::get_aes_key();
                let cipher_op1 = eigen_crypto::ec::suite_b::ecies::aes_decrypt_less_safe(aes_key, &cipher).unwrap();

                // Second, do ECIES decrypt
                ///////////////////////////////////////////////////////////////////////////////////////////////
                // let key_pair = register_func::get_key_pair();
                // let s1 = vec![];
                // let s2 = vec![];
                // let plain = eigen_crypto::ec::suite_b::ecies::decrypt(key_pair, &cipher_op1, &s1, &s2).unwrap();
                // let plain = u64::from_be_bytes(plain[0..8].try_into().unwrap());
                let plain = cipher_op1;
                let b = BigUint::from_bytes_be(&plain[..]);
                ///////////////////////////////////////////////////////////////////////////////////////////////

                Ok(b.to_str_radix(10))

            }
            _ => {
                return Err(Error::from(ErrorKind::InvalidInputError));
            }
        }
    }
}
