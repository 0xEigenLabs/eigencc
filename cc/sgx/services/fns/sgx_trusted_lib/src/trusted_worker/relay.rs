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

use crate::trusted_worker::pk_reg;
use crate::worker::{Worker, WorkerContext};
use eigen_core::{Error, ErrorKind};

use super::local_ecies::safe_decrypt;

use super::kms;

pub struct RelayWorker {
  worker_id: u32,
  func_name: String,
  input: Option<RelayWorkerInput>,
}

impl RelayWorker {
  pub fn new() -> Self {
    RelayWorker {
      worker_id: 0,
      func_name: "kms".to_string(),
      input: None,
    }
  }
}

enum RelayOperation {
  Encrypt,
  Decrypt,
}

struct RelayWorkerInput {
  op: RelayOperation,
  data: String,
  user_attr: String,
  temp_key: String,
}

impl Worker for RelayWorker {
  fn function_name(&self) -> &str {
    self.func_name.as_str()
  }

  fn set_id(&mut self, worker_id: u32) {
    self.worker_id = worker_id;
  }

  fn id(&self) -> u32 {
    self.worker_id
  }

  fn prepare_input(&mut self, dynamic_input: Option<String>) -> eigen_core::Result<()> {
    let msg = dynamic_input.ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;

    // `args` should be "op|data"
    // now `op` may be 'encrypt' or 'decrypt'

    let splited = msg.split("|").collect::<Vec<_>>();

    if splited.len() != 4 {
      return Err(Error::from(ErrorKind::InvalidInputError));
    }

    let op = &splited[0][0..splited[0].len() - 1];

    let operation = match op {
      "encrypt" => RelayOperation::Encrypt,
      "decrypt" => RelayOperation::Decrypt,
      _ => panic!("unknown op kind"),
    };

    self.input = Some(RelayWorkerInput {
      op: operation,
      data: splited[1].to_string(),
      user_attr: splited[2].to_string(),
      temp_key: splited[3].to_string(),
    });
    Ok(())
  }

  fn execute(&mut self, _context: WorkerContext) -> eigen_core::Result<String> {
    let input = self
      .input
      .take()
      .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;

    let region = pk_reg::get_kms_client_region();
    let cid = pk_reg::get_kms_client_id();
    let csk = pk_reg::get_kms_client_sk();
    let client = kms::Client::new(
        "kms.tencentcloudapi.com",
        &&region,
        "kms",
        "2019-01-18",
        &cid,
        &csk
    );

    client.list_cmk();


    match input.op {
      RelayOperation::Encrypt => {
        let bc1 = safe_decrypt(&input.data)?;
        let bcc1 = safe_decrypt(&input.data)?;
        let c1 = String::from_utf8_lossy(&bc1);
        let cc1 = String::from_utf8_lossy(&bcc1);

        //base64 cipher
        let cipher_key = client.encrypt(&pk_reg::get_kms_key_id(), c1.to_string(), cc1.to_string());

        Ok(cipher_key.ciphertext_blob)
      }
      RelayOperation::Decrypt => {
        let c2 =  safe_decrypt(&input.data).unwrap();
        let cc1 = safe_decrypt(&input.user_attr).unwrap();
        let ccr = safe_decrypt(&input.temp_key).unwrap();
        let c2 =  String::from_utf8_lossy(&c2);
        let cc1 = String::from_utf8_lossy(&cc1);
        let ccr = String::from_utf8_lossy(&ccr);

        let plain_key = client.decrypt(c2.to_string(), cc1.to_string());
        let result = eigen_crypto::ec::suite_b::ecies::aes_encrypt_less_safe(&ccr.as_bytes(), &plain_key.plaintext.as_bytes())
            .map_err(|e| {
                error!("aes_encrypt_less_safe, {:?}", e);
                Error::from(ErrorKind::CryptoError)
            })?;
        Ok(base64::encode(&result))
      }
    }
  }
}
