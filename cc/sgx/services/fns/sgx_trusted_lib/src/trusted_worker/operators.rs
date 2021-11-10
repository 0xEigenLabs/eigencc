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
    #[allow(dead_code)]
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

    fn safe_encrypt(&mut self, result: Vec<u8>) -> Result<Vec<u8>> {
        // 4. Do ECIES encrypt
        let s1 = vec![];
        let s2 = vec![];
        let key_pair = register_func::get_key_pair();
        let alg = &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
        let public_key =
            eigen_crypto::sign::ecdsa::UnparsedPublicKey::new(alg, key_pair.public_key());
        eigen_crypto::ec::suite_b::ecies::encrypt(
            &public_key,
            &s1,
            &s2,
            &result,
        ).map_err(|e| {
            error!("safe_encrypt error, {:?}", e);
            Error::from(ErrorKind::CryptoError)
        })
    }

    fn safe_decrypt(&mut self, operand: &str) -> Result<Vec<u8>> {
        let cipher_operand = hex::decode(&operand)
            .map_err(|e| {
                error!("decode error, {:?}, error is {:?}", operand, e);
                Error::from(ErrorKind::DecodeError)
            })?;
        if cipher_operand.len() <= 0 {
            info!("safe decrypt: zero found");
            return Ok(vec![]);
        }
        let key_pair = register_func::get_key_pair();
        let s1 = vec![];
        let s2 = vec![];
        eigen_crypto::ec::suite_b::ecies::decrypt(
            key_pair,
            &cipher_operand,
            &s1,
            &s2,
        ).map_err(|e| {
            error!("safe_decrypt failed, {:?}", e);
            Error::from(ErrorKind::CryptoError)
        })
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
    #[allow(dead_code)]
    operand_3: String,
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

        let op_kind = match op {
            "add_cipher_cipher" => OperatorKind::AddCipherCipher,
            "add_cipher_plain" => OperatorKind::AddCipherPlain,
            "sub_cipher_cipher" => OperatorKind::SubCipherCipher,
            "sub_cipher_plain" => OperatorKind::SubCipherPlain,
            "compare_cipher_cipher" => OperatorKind::CompareCipherCipher,
            "compare_cipher_plain" => OperatorKind::CompareCipherPlain,
            "re_encrypt" => OperatorKind::ReEncrypt,
            "encrypt" => OperatorKind::Encrypt,
            "decrypt" => OperatorKind::Decrypt,
            _ => panic!("unknown op kind")
        };

        let operand_1 = splited[1].to_string();
        let mut operand_2 = "".to_string();
        let mut operand_3 = "".to_string();
        if arity == 2 {
            operand_2 = splited[2].to_string();
        } else if arity == 3 {
            operand_2 = splited[2].to_string();
            operand_3 = splited[3].to_string();
        }

        self.input = Some(OperatorWorkerInput {
            op: op_kind,
            operand_1: operand_1,
            operand_2: operand_2,
            operand_3: operand_3,
        });
        Ok(())
    }


    fn execute(&mut self, _context: WorkerContext) -> Result<String> {
        let input = self
            .input
            .take()
            .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;

        match input.op {
            OperatorKind::AddCipherCipher | OperatorKind::SubCipherCipher => {
                // 1. Cipher is encoded as hex, should be decoded
                let op1 = self.safe_decrypt(&input.operand_1)?;
                let op2 = self.safe_decrypt(&input.operand_2)?;
                // 2. convert to big number
                let op1 = BigUint::from_bytes_be(&op1[..]);
                let op2 = BigUint::from_bytes_be(&op2[..]);

                // 3. Do calculate
                let result = match input.op {
                    OperatorKind::AddCipherCipher => op1 + op2,
                    OperatorKind::SubCipherCipher if op1 >= op2 => (op1 - op2),
                    _ => {
                        error!("Invalid CipherCipher {} - {}", op1, op2);
                        return Err(Error::from(ErrorKind::Unknown))
                    }
                };
                // 4. Do ECIES encrypt
                let cipher = self.safe_encrypt(result.to_bytes_be())?;
                // 5. Result is cipher, encode it as hex
                let result = hex::encode(&cipher);
                Ok(result)
            }

            OperatorKind::AddCipherPlain | OperatorKind::SubCipherPlain => {
                let op1 = self.safe_decrypt(&input.operand_1)?;
                let op1 = BigUint::from_bytes_be(&op1[..]);

                let op2 = BigUint::parse_bytes(input.operand_2.as_bytes(), 10)
                    .ok_or_else(|| Error::from(ErrorKind::DecodeError))?;

                let result = match input.op {
                    OperatorKind::AddCipherPlain => op1 + op2,
                    OperatorKind::SubCipherPlain if op1 >= op2 => op1 - op2,
                    _ => {
                        error!("Invalid CipherPlain {} - {}", op1, op2);
                        return Err(Error::from(ErrorKind::Unknown))
                    }
                };

                let cipher = self.safe_encrypt(result.to_bytes_be())?;
                let result = hex::encode(&cipher);
                Ok(result)
            }
            OperatorKind::Encrypt => {
                // NOTE: `input.operand_1` is acually plain text
                let op1 = BigUint::parse_bytes(input.operand_1.as_bytes(), 10)
                    .ok_or_else(|| Error::from(ErrorKind::DecodeError))?;
                let op_bytes = op1.to_bytes_be();

                let cipher = self.safe_encrypt(op_bytes)?;
                let result = hex::encode(&cipher);
                Ok(result)
            }
            OperatorKind::Decrypt => {
                let plain = self.safe_decrypt(&input.operand_1)?;
                let b = BigUint::from_bytes_be(&plain[..]);

                Ok(b.to_str_radix(10))
            }
            OperatorKind::ReEncrypt => {
                let key = self.safe_decrypt(&input.operand_1)?;
                let msg = self.safe_decrypt(&input.operand_2)?;

                // bytes -> bigint
                // bigint -> string
                let int_msg = BigUint::from_bytes_be(&msg[..]);
                let str_msg = int_msg.to_str_radix(10);
                info!("key = {:?}, {}, msg = {:?}", key, key.len(), str_msg);
                let result = eigen_crypto::ec::suite_b::ecies::aes_encrypt_less_safe(&key, &str_msg.as_bytes())
                    .map_err(|e| {
                        error!("aes_encrypt_less_safe, {:?}", e);
                        Error::from(ErrorKind::CryptoError)
                    })?;
                let result = hex::encode(&result);
                Ok(result)
            }
            OperatorKind::CompareCipherCipher | OperatorKind::CompareCipherPlain => {
                let op1 = self.safe_decrypt(&input.operand_1)?;
                let op1 = BigUint::from_bytes_be(&op1[..]);

                let op2 = match input.op {
                    OperatorKind::CompareCipherCipher => {
                        let op2 = self.safe_decrypt(&input.operand_2)?;
                        BigUint::from_bytes_be(&op2[..])
                    }
                    OperatorKind::CompareCipherPlain => {
                        BigUint::parse_bytes(input.operand_2.as_bytes(), 10)
                            .ok_or_else(|| Error::from(ErrorKind::DecodeError))?
                    }
                    _ => panic!("Unknown op kind"),
                };

                // Do compare
                // TODO: return integer, instead of string
                match op1.cmp(&op2) {
                    std::cmp::Ordering::Equal => Ok("0".to_string()),
                    std::cmp::Ordering::Less => Ok("-1".to_string()),
                    std::cmp::Ordering::Greater => Ok("1".to_string()),
                }
            }
        }
    }
}
