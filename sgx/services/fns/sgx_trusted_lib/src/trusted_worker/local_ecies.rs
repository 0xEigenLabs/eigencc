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
use crate::trusted_worker::pk_reg;
use eigen_core::{Error, ErrorKind, Result};

pub fn safe_encrypt(result: Vec<u8>) -> Result<Vec<u8>> {
    // 4. Do ECIES encrypt
    let s1 = vec![];
    let s2 = vec![];
    let key_pair = pk_reg::get_key_pair();
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

pub fn safe_decrypt(operand: &str) -> Result<Vec<u8>> {
    let cipher_operand = hex::decode(&operand)
        .map_err(|e| {
            error!("decode error, {:?}, error is {:?}", operand, e);
            Error::from(ErrorKind::DecodeError)
        })?;
    if cipher_operand.len() <= 0 {
        info!("safe decrypt: zero found");
        return Ok(vec![]);
    }
    let key_pair = pk_reg::get_key_pair();
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
