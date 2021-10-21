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

use crate::eigen_crypto::sign::ecdsa::KeyPair;
use crate::trusted_worker::register_func;
use crate::worker::{Worker, WorkerContext};
use eigen_core::{Error, ErrorKind, Result};

use num_bigint::{BigUint};

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
    ReEncrypt,
    Encrypt,
    Decrypt,
    CompareCipherCipher,
    CompareCipherPlain,
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

        // `args` should be "op|arity,,op1,op2,op3,..."
        // now `op` may be 'add' or 'sub'

        let splited = msg.split(",").collect::<Vec<_>>();

        if splited.len() < 2 {
            return Err(Error::from(ErrorKind::InvalidInputError));
        }

        let arity = splited[0].chars().last().unwrap() as u32 - '0' as u32;
        let op = &splited[0][0..splited[0].len() - 1];

        match op {
            "add_cipher_cipher"
            | "add_cipher_plain"
            | "sub_cipher_cipher"
            | "sub_cipher_plain"
            | "compare_cipher_cipher"
            | "compare_cipher_plain" => {
                if arity != 2 || splited.len() != 3 {
                    return Err(Error::from(ErrorKind::InvalidInputError));
                }

                let operand_1 = splited[1];
                let operand_2 = splited[2];

                let op_kind = match op {
                    "add_cipher_cipher" => OperatorKind::AddCipherCipher,
                    "add_cipher_plain" => OperatorKind::AddCipherPlain,
                    "sub_cipher_cipher" => OperatorKind::SubCipherCipher,
                    "sub_cipher_plain" => OperatorKind::SubCipherPlain,
                    "compare_cipher_cipher" => OperatorKind::CompareCipherCipher,
                    "compare_cipher_plain" => OperatorKind::CompareCipherPlain,
                    "re_encrypt" => OperatorKind::ReEncrypt,
                    _ => unreachable!(),
                };

                self.input = Some(OperatorWorkerInput {
                    op: op_kind,
                    operand_1: operand_1.to_string(),
                    operand_2: operand_2.to_string(),
                });
            }
            "encrypt" | "decrypt" => {
                if arity != 1 || splited.len() != 2 {
                    return Err(Error::from(ErrorKind::InvalidInputError));
                }

                let operand = splited[1];

                let op_kind = match op {
                    "encrypt" => OperatorKind::Encrypt,
                    "decrypt" => OperatorKind::Decrypt
                };

                self.input = Some(OperatorWorkerInput {
                    op: op_kind,
                    operand_1: operand.to_string(),
                    operand_2: "".to_string(),
                });
            }
            _ => {
                return Err(Error::from(ErrorKind::ParseError));
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
                // 1. Cipher is encoded as base64, should be decoded
                let cipher_operand_1 = base64::decode(&input.operand_1)
                    .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;
                let cipher_operand_2 = base64::decode(&input.operand_2)
                    .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;

                // 2. Do ECIES decrypt
                let key_pair = register_func::get_key_pair();
                let s1 = vec![];
                let s2 = vec![];
                let op1 = eigen_crypto::ec::suite_b::ecies::decrypt(
                    key_pair,
                    &cipher_operand_1,
                    &s1,
                    &s2,
                )
                .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;
                let op2 = eigen_crypto::ec::suite_b::ecies::decrypt(
                    key_pair,
                    &cipher_operand_2,
                    &s1,
                    &s2,
                )
                .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;
                let op1 = BigUint::from_bytes_be(&op1[..]);
                let op2 = BigUint::from_bytes_be(&op2[..]);

                // 3. Do calculate
                let result = match input.op {
                    OperatorKind::AddCipherCipher => (op1 + op2).to_bytes_be(),
                    OperatorKind::SubCipherCipher if op1 >= op2 => (op1 - op2).to_bytes_be(),
                    _ => return Err(Error::from(ErrorKind::InvalidInputError)),
                };

                // 4. Do ECIES encrypt
                let s1 = vec![];
                let s2 = vec![];
                let key_pair = register_func::get_key_pair();
                let alg = &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
                let public_key =
                    eigen_crypto::sign::ecdsa::UnparsedPublicKey::new(alg, key_pair.public_key());
                let cipher = eigen_crypto::ec::suite_b::ecies::encrypt(
                    &public_key,
                    &s1,
                    &s2,
                    &result,
                )
                .map_err(|_| Error::from(ErrorKind::CryptoError))?;

                // 5. Result is cipher, encode it as base64
                let result = base64::encode(&cipher);
                Ok(result)
            }
            OperatorKind::AddCipherPlain | OperatorKind::SubCipherPlain => {
                // 1. Cipher is encoded as base64, should be decoded
                let cipher_operand_1 = base64::decode(&input.operand_1)
                    .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;

                // 2. Do ECIES decrypt
                let key_pair = register_func::get_key_pair();
                let s1 = vec![];
                let s2 = vec![];
                let op1 = eigen_crypto::ec::suite_b::ecies::decrypt(
                    key_pair,
                    &cipher_operand_1,
                    &s1,
                    &s2,
                )
                .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;
                let op1 = BigUint::from_bytes_be(&op1[..]);

                // 3. Do calculate
                let op2 = BigUint::parse_bytes(input.operand_2.as_bytes(), 10)
                    .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;

                let result = match input.op {
                    OperatorKind::AddCipherPlain => op1 + op2,
                    OperatorKind::SubCipherPlain if op1 >= op2 => op1 - op2,
                    _ => return Err(Error::from(ErrorKind::InvalidInputError)),
                };

                // 4. Do ECIES encrypt
                let s1 = vec![];
                let s2 = vec![];
                let key_pair = register_func::get_key_pair();
                let alg = &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
                let public_key =
                    eigen_crypto::sign::ecdsa::UnparsedPublicKey::new(alg, key_pair.public_key());
                let cipher = eigen_crypto::ec::suite_b::ecies::encrypt(
                    &public_key,
                    &s1,
                    &s2,
                    &result.to_bytes_be(),
                )
                .map_err(|_| Error::from(ErrorKind::CryptoError))?;

                // 5. Result is cipher, encode it as base64
                let result = base64::encode(&cipher);
                Ok(result)
            }
            OperatorKind::Encrypt => {
                // NOTE: `input.operand_1` is acually plain text
                let op1 = BigUint::parse_bytes(input.operand_1.as_bytes(), 10)
                    .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;
                let op_bytes = op1.to_bytes_be();

                // 1. Do ECIES encrypt
                let s1 = vec![];
                let s2 = vec![];
                let key_pair = register_func::get_key_pair();
                let alg = &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
                let public_key =
                    eigen_crypto::sign::ecdsa::UnparsedPublicKey::new(alg, key_pair.public_key());
                let cipher =
                    eigen_crypto::ec::suite_b::ecies::encrypt(&public_key, &s1, &s2, &op_bytes)
                        .map_err(|_| Error::from(ErrorKind::CryptoError))?;

                // 2. Result is cipher, encode it as base64
                let result = base64::encode(&cipher);
                Ok(result)
            }
            OperatorKind::Decrypt => {
                // 1. Cipher is encoded as base64, should be decoded
                let cipher_operand = base64::decode(&input.operand_1)
                    .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;

                // 2. Do ECIES decrypt
                let key_pair = register_func::get_key_pair();
                let s1 = vec![];
                let s2 = vec![];
                let plain =
                    eigen_crypto::ec::suite_b::ecies::decrypt(key_pair, &cipher_operand, &s1, &s2)
                        .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;

                // 3. Parsed as BigInt from big endian
                let b = BigUint::from_bytes_be(&plain[..]);

                Ok(b.to_str_radix(10))
            }
            OperatorKind::ReEncrypt => {
                let cipher_operand = base64::decode(&input.operand_1)
                    .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;
                let cipher_operand2 = base64::decode(&input.operand_2)
                    .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;
                let key_pair = register_func::get_key_pair();
                let s1 = vec![];
                let s2 = vec![];
                let key =
                    eigen_crypto::ec::suite_b::ecies::decrypt(key_pair, &cipher_operand, &s1, &s2)
                        .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;
                let msg =
                    eigen_crypto::ec::suite_b::ecies::decrypt(key_pair, &cipher_operand2, &s1, &s2)
                        .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;

                let result = eigen_crypto::ec::suite_b::ecies::aes_encrypt_less_safe(&key, &msg)
                        .map_err(|_| Error::from(ErrorKind::CryptoError))?;
                Ok(String::from_utf8(result).map_err(|_| Error::from(ErrorKind::InvalidInputError))?)
            }
            OperatorKind::CompareCipherCipher | OperatorKind::CompareCipherPlain => {
                let key_pair = register_func::get_key_pair();
                let s1 = vec![];
                let s2 = vec![];

                let op1 = {
                    let cipher_operand_1 = base64::decode(&input.operand_1)
                        .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;
                    let op1 = eigen_crypto::ec::suite_b::ecies::decrypt(
                        key_pair,
                        &cipher_operand_1,
                        &s1,
                        &s2,
                    )
                    .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;
                    BigUint::from_bytes_be(&op1[..])
                };

                let op2 = match input.op {
                    OperatorKind::CompareCipherCipher => {
                        let cipher_operand_2 = base64::decode(&input.operand_2)
                            .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;
                        let op2 = eigen_crypto::ec::suite_b::ecies::decrypt(
                            key_pair,
                            &cipher_operand_2,
                            &s1,
                            &s2,
                        )
                        .map_err(|_| Error::from(ErrorKind::InvalidInputError))?;
                        BigUint::from_bytes_be(&op2[..])
                    }
                    OperatorKind::CompareCipherPlain => {
                        BigUint::parse_bytes(input.operand_2.as_bytes(), 10)
                            .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?
                    }
                    _ => unreachable!(),
                };

                // Do compare
                match op1.cmp(&op2) {
                    std::cmp::Ordering::Equal => Ok("0".to_string()),
                    std::cmp::Ordering::Less => Ok("-1".to_string()),
                    std::cmp::Ordering::Greater => Ok("1".to_string()),
                }
            }
            _ => {
                return Err(Error::from(ErrorKind::InvalidInputError));
            }
        }
    }
}
