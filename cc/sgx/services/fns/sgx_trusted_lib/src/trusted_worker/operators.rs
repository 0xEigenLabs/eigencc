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
use std::convert::TryInto;
use std::iter::FromIterator;
#[cfg(feature = "mesalock_sgx")]
use std::prelude::v1::*;
use std::vec;

use crate::eigen_crypto::sign::ecdsa::KeyPair;
use crate::trusted_worker::register_func;
use crate::worker::{Worker, WorkerContext};
use eigen_core::{Error, ErrorKind, Result};

use num_bigint::{BigInt, ToBigInt};
use num_bigint::{BigUint, ToBigUint};

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
    AddCipherCipher,
    AddCipherPlain,
    SubCipherCipher,
    SubCipherPlain,
    Encrypt,
    Decrypt,
}

struct OperatorWorkerInput {
    // TODO: Use a more property field name to describe what we want to save here.
    //       e.g., when operator is `Encrypt`, `operand_1` is not a cipher one
    op: OperatorKind,
    operand_1: String,
    operand_2: String,
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
        // number is parsed with big endian

        let splited = msg.split(",").collect::<Vec<_>>();

        if splited.len() <= 2 {
            return Err(Error::from(ErrorKind::InvalidInputError));
        }

        let op = splited[0];

        match op {
            "add_cipher_cipher" | "add_cipher_plain" | "sub_cipher_cipher" | "sub_cipher_plain" => {
                let op_num = splited[1]
                    .parse::<u8>()
                    .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;

                if op_num != 2 && splited.len() != 4 {
                    return Err(Error::from(ErrorKind::InvalidInputError));
                }

                let operand_1 = splited[2];
                let operand_2 = splited[3];

                let op_kind = match op {
                    "add_cipher_cipher" => OperatorKind::AddCipherCipher,
                    "add_cipher_plain" => OperatorKind::AddCipherPlain,
                    "sub_cipher_cipher" => OperatorKind::SubCipherCipher,
                    "sub_cipher_plain" => OperatorKind::SubCipherPlain,
                    _ => unreachable!(),
                };

                self.input = Some(OperatorWorkerInput {
                    op: op_kind,
                    operand_1: operand_1.to_string(),
                    operand_2: operand_2.to_string(),
                });
            }
            "encrypt" | "decrypt" => {
                let op_num = splited[1]
                    .parse::<u8>()
                    .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;

                if op_num != 1 && splited.len() != 3 {
                    return Err(Error::from(ErrorKind::InvalidInputError));
                }

                let to_enc = splited[2];

                let op_kind = match op {
                    "encrypt" => OperatorKind::Encrypt,
                    "decrypt" => OperatorKind::Decrypt,
                    _ => unreachable!(),
                };

                self.input = Some(OperatorWorkerInput {
                    op: OperatorKind::Encrypt,
                    operand_1: to_enc.to_string(),
                    operand_2: "".to_string(),
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
            OperatorKind::AddCipherCipher | OperatorKind::SubCipherCipher => {
                // First, do AES decrypt
                let aes_key = register_func::get_aes_key();
                let b1 = BigUint::parse_bytes(input.operand_1.as_bytes(), 10)
                    .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;
                let operand_1 = b1.to_bytes_be();
                let b2 = BigUint::parse_bytes(input.operand_2.as_bytes(), 10)
                    .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;
                let operand_2 = b2.to_bytes_be();

                let operand_1 =
                    eigen_crypto::ec::suite_b::ecies::aes_decrypt_less_safe(aes_key, &operand_1)
                        .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;
                let operand_2 =
                    eigen_crypto::ec::suite_b::ecies::aes_decrypt_less_safe(aes_key, &operand_2)
                        .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;

                // TODO: Second, do ECIES decrypt

                let op1 = operand_1;
                let op1 = BigUint::from_bytes_be(&op1[..]);
                let op2 = operand_2;
                let op2 = BigUint::from_bytes_be(&op2[..]);

                let result = match input.op {
                    OperatorKind::AddCipherCipher => op1 + op2,
                    OperatorKind::SubCipherCipher => op1 - op2,
                    _ => return Err(Error::from(ErrorKind::InvalidInputError)),
                };

                // TODO: First, do ECIES encrypt

                let cipher = result.to_bytes_be();

                // Second, do AES encrypt
                let aes_key = register_func::get_aes_key();
                let cipher =
                    eigen_crypto::ec::suite_b::ecies::aes_encrypt_less_safe(aes_key, &cipher)
                        .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;

                let b = BigUint::from_bytes_be(&cipher[..]);
                let result = b.to_str_radix(10);
                Ok(result)
            }
            OperatorKind::AddCipherPlain | OperatorKind::SubCipherPlain => {
                // First, do AES decrypt
                let aes_key = register_func::get_aes_key();
                let b1 = BigUint::parse_bytes(input.operand_1.as_bytes(), 10)
                    .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;
                let operand_1 = b1.to_bytes_be();
                let op2 = BigUint::parse_bytes(input.operand_2.as_bytes(), 10)
                    .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;

                let operand_1 =
                    eigen_crypto::ec::suite_b::ecies::aes_decrypt_less_safe(aes_key, &operand_1)
                        .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;

                // TODO: Second, do ECIES decrypt

                let op1 = operand_1;
                let op1 = BigUint::from_bytes_be(&op1[..]);

                let result = match input.op {
                    OperatorKind::AddCipherPlain => op1 + op2,
                    OperatorKind::SubCipherPlain => op1 - op2,
                    _ => return Err(Error::from(ErrorKind::InvalidInputError)),
                };

                // TODO: First, do ECIES encrypt

                let cipher = result.to_bytes_be();

                // Second, do AES encrypt
                let aes_key = register_func::get_aes_key();
                let cipher =
                    eigen_crypto::ec::suite_b::ecies::aes_encrypt_less_safe(aes_key, &cipher)
                        .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;

                let b = BigUint::from_bytes_be(&cipher[..]);
                let result = b.to_str_radix(10);
                Ok(result)
            }
            OperatorKind::Encrypt => {
                // NOTE: `input.operand_1` is acually plain text
                let op1 = BigUint::parse_bytes(input.operand_1.as_bytes(), 10)
                    .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;
                let op_bytes = op1.to_bytes_be();
                // TODO: First, do ECIES encrypt

                let cipher = op_bytes;

                // Second, do AES encrypt
                let aes_key = register_func::get_aes_key();
                let cipher =
                    eigen_crypto::ec::suite_b::ecies::aes_encrypt_less_safe(aes_key, &cipher)
                        .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;
                let b = BigUint::from_bytes_be(&cipher[..]);
                let result = b.to_str_radix(10);
                Ok(result)
            }
            OperatorKind::Decrypt => {
                let b = BigUint::parse_bytes(input.operand_1.as_bytes(), 10)
                    .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;
                let cipher = b.to_bytes_be();

                // First, do AES decrypt
                let aes_key = register_func::get_aes_key();
                let operand_1 =
                    eigen_crypto::ec::suite_b::ecies::aes_decrypt_less_safe(aes_key, &cipher)
                        .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;

                // TODO: Second, do ECIES decrypt
                let plain = operand_1;
                let b = BigUint::from_bytes_be(&plain[..]);

                Ok(b.to_str_radix(10))
            }
            _ => {
                return Err(Error::from(ErrorKind::InvalidInputError));
            }
        }
    }
}
