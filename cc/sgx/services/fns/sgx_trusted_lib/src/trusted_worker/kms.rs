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
use chrono::{DateTime, Local, Utc};
use eigen_core::{Error, ErrorKind};
use ring::digest;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use reqwest::header::{HeaderMap, HeaderValue};

use num_bigint::BigUint;

pub struct KmsWorker {
  worker_id: u32,
  func_name: String,
  #[allow(dead_code)]
  input: Option<KmsWorkerInput>,
}

impl KmsWorker {
  pub fn new() -> Self {
    KmsWorker {
      worker_id: 0,
      func_name: "kms".to_string(),
      input: None,
    }
  }
}

enum KmsOperation {
  Encrypt,
  Decrypt,
}

struct KmsWorkerInput {
  op: KmsOperation,
  data: String,
}

impl Worker for KmsWorker {
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

    if splited.len() != 2 {
      return Err(Error::from(ErrorKind::InvalidInputError));
    }

    let op = &splited[0][0..splited[0].len() - 1];

    let operation = match op {
      "encrypt" => KmsOperation::Encrypt,
      "decrypt" => KmsOperation::Decrypt,
      _ => panic!("unknown op kind"),
    };

    let data = splited[1].to_string();
    self.input = Some(OperatorWorkerInput {
      op: operation,
      data: data,
    });
    Ok(())
  }

  fn execute(&mut self, _context: WorkerContext) -> eigen_core::Result<String> {
    let input = self
      .input
      .take()
      .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;

    match input.op {
      KmsOperation::Encrypt => {
        let plain = self.safe_decrypt(input.data.as_bytes())?;

        // TODO: Call KMS Encrypt here

        let result = hex::encode(&plain);
        Ok(result)
      }
      KmsOperation::Decrypt => {
        let plain = self.safe_decrypt(&input.operand_1)?;
        let b = BigUint::from_bytes_be(&plain[..]);

        Ok(b.to_str_radix(10))
      }
    }
  }

  // Just reuse from operatros
  fn safe_encrypt(&mut self, result: Vec<u8>) -> eigen_core::Result<Vec<u8>> {
    let s1 = vec![];
    let s2 = vec![];
    let key_pair = register_func::get_key_pair();
    let alg = &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
    let public_key = eigen_crypto::sign::ecdsa::UnparsedPublicKey::new(alg, key_pair.public_key());
    eigen_crypto::ec::suite_b::ecies::encrypt(&public_key, &s1, &s2, &result).map_err(|e| {
      error!("safe_encrypt error, {:?}", e);
      Error::from(ErrorKind::CryptoError)
    })
  }

  // Just reuse from operatros
  fn safe_decrypt(&mut self, operand: &str) -> eigen_core::Result<Vec<u8>> {
    let cipher_operand = hex::decode(&operand).map_err(|e| {
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
    eigen_crypto::ec::suite_b::ecies::decrypt(key_pair, &cipher_operand, &s1, &s2).map_err(|e| {
      error!("safe_decrypt failed, {:?}", e);
      Error::from(ErrorKind::CryptoError)
    })
  }
}

//region: https://intl.cloud.tencent.com/document/product/1030/32174
struct HostedRegionMap {
  regions: HashMap<String, String>,
}

pub fn get_date() -> String {
  let local_time = Local::now();
  let dt = DateTime::<Utc>::from_utc(local_time.naive_utc(), Utc);
  dt.format("%Y-%m-%d").to_string()
}

pub fn sha256_hex(data: &[u8]) -> String {
  let res = digest::digest(&digest::SHA256, data);
  hex::encode(res.as_ref().to_vec())
}

pub fn hmac_sha256(key: &[u8], payload: &[u8]) -> Vec<u8> {
  let s_key = hmac::Key::new(hmac::HMAC_SHA256, key);
  hmac::sign(&s_key, payload).as_ref().to_vec()
}

impl HostedRegionMap {
  fn new(regions_: HashMap<String, String>) -> HostedRegionMap {
    HostedRegionMap { regions: regions_ }
  }
}

#[derive(Serialize, Deserialize, Debug)]
struct Pager {
  pub Limit: i32,
  pub Offset: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct Key {
  #[serde(rename = "KeyId")]
  pub key_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ListKeysResp {
  #[serde(rename = "RequestId")]
  pub request_id: String,
  #[serde(rename = "Keys")]
  pub keys: Vec<Key>,
  #[serde(rename = "TotalCount")]
  pub total_count: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct CreateKeyReq<'a> {
  #[serde(rename = "Alias")]
  pub alias: &'a str,
  #[serde(rename = "Description")]
  pub description: Option<&'a str>,
  #[serde(rename = "KeyUsage")]
  pub key_usage: Option<&'a str>,
  #[serde(rename = "Type")]
  pub type_: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct CreateKeyResp {
  #[serde(rename = "KeyId")]
  pub key_id: String,
  #[serde(rename = "Alias")]
  pub alias: String,
  #[serde(rename = "CreateTime")]
  pub create_time: i32,
  #[serde(rename = "Description")]
  pub description: String,
  #[serde(rename = "KeyState")]
  pub key_state: String,
  #[serde(rename = "KeyUsage")]
  pub key_usage: String,
  #[serde(rename = "TagCode")]
  pub tag_code: i32,
  #[serde(rename = "TagMsg")]
  pub tag_msg: String,
  #[serde(rename = "RequestId")]
  pub request_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct EncryptReq {
  #[serde(rename = "KeyId")]
  pub key_id: String,
  #[serde(rename = "Plaintext")]
  pub plaintext: String,
  #[serde(rename = "EncryptionContext")]
  pub encryption_context: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct EncryptResp {
  #[serde(rename = "CiphertextBlob")]
  pub ciphertext_blob: String,
  #[serde(rename = "KeyId")]
  pub key_id: String,
  #[serde(rename = "RequestId")]
  pub request_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct DecryptReq {
  #[serde(rename = "CiphertextBlob")]
  pub ciphertext_blob: String,
  #[serde(rename = "EncryptionContext")]
  pub encryption_context: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct DecryptResp {
  #[serde(rename = "KeyId")]
  pub key_id: String,
  #[serde(rename = "Plaintext")]
  pub plaintext: String,
  #[serde(rename = "RequestId")]
  pub request_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct WrappedResponse<T> {
  #[serde(rename = "Response")]
  pub response: T,
}

struct Client<'a> {
  host: &'a str,
  region: &'a str,
  secretKey: &'a str,
  secretId: &'a str,
  service: &'a str,
  version: &'a str,
}

impl<'a> Client<'a> {
  fn new(
    host: &'a str,
    region: &'a str,
    service: &'a str,
    version: &'a str,
    secretId: &'a str,
    secretKey: &'a str,
  ) -> Self {
    Self {
      host: host,
      region: region,
      service: service,
      version: version,
      secretKey: secretKey,
      secretId: secretId,
    }
  }

  fn sign(
    &self,
    RequestPayload: &[u8],
    CanonicalQueryString: &str,
    Date: String,
    RequestTimestamp: String,
  ) -> String {
    let HTTPRequestMethod: String = "POST".to_owned();
    let CanonicalURI: &str = "/";
    let CanonicalHeaders = format!(
      "content-type:application/json; charset=utf-8\nhost:{}\n",
      self.host
    );
    let SignedHeaders: &str = "content-type;host";
    let newline: &str = "\n";

    let HashedRequestPayload = sha256_hex(RequestPayload);
    let CanonicalRequest = HTTPRequestMethod
      + newline
      + CanonicalURI
      + newline
      + CanonicalQueryString
      + newline
      + CanonicalHeaders.as_ref()
      + newline
      + SignedHeaders
      + newline
      + HashedRequestPayload.as_ref();

    let HashedCanonicalRequest = sha256_hex(CanonicalRequest.as_bytes());
    let Algorithm: String = "TC3-HMAC-SHA256".to_owned();

    let tc3_request: &str = "tc3_request";
    let CredentialScope = format!("{}/{}/{}", Date, self.service, tc3_request);
    let StringToSign = Algorithm
      + newline
      + RequestTimestamp.as_str()
      + newline
      + CredentialScope.as_ref()
      + newline
      + &HashedCanonicalRequest;
    let key = "TC3".to_owned() + self.secretKey;
    let SecretDate = hmac_sha256(key.as_bytes(), Date.as_bytes());
    let SecretService = hmac_sha256(&SecretDate, self.service.as_bytes());
    let SecretSigning = hmac_sha256(&SecretService, tc3_request.as_ref());
    let Signature = hex::encode(hmac_sha256(&SecretSigning, StringToSign.as_ref()));
    Signature
  }

  fn add_common_header(
    &self,
    action: &str,
    payload: &str,
  ) -> Result<HeaderMap, reqwest::header::InvalidHeaderValue> {
    let dt = Utc::now();
    let now: i64 = dt.timestamp();
    let date = get_date();
    let SignedHeaders = "content-type;host";
    let CanonicalQueryString = "";
    let authz = format!(
      "TC3-HMAC-SHA256 Credential={}/{}/{}/tc3_request, SignedHeaders={}, Signature={}",
      self.secretId,
      date,
      self.service,
      SignedHeaders,
      self.sign(
        payload.as_ref(),
        CanonicalQueryString,
        date.to_string(),
        now.to_string()
      )
    );

    let mut headers = HeaderMap::new();
    //headers.insert("Connection", "Close");
    headers.insert("Host", HeaderValue::from_str(self.host)?);
    headers.insert("Authorization", HeaderValue::from_str(authz.as_str())?);
    headers.insert(
      "Content-Type",
      HeaderValue::from_static("application/json; charset=utf-8"),
    );
    headers.insert("X-TC-Action", HeaderValue::from_str(action)?);
    headers.insert("X-TC-Region", HeaderValue::from_str(self.region)?);
    headers.insert("X-TC-Timestamp", HeaderValue::from_str(&now.to_string())?);
    headers.insert("X-TC-Version", HeaderValue::from_str(self.version)?);
    Ok(headers)
  }

  fn send(&self, action: &str, payload: &str) -> Vec<u8> {
    let endpoint = "https://".to_owned() + self.host;
    let mut buf = Vec::new();
    let headers = self.add_common_header(action, payload);
    let client = reqwest::blocking::Client::new();
    let mut resp = client
      .post(&endpoint)
      .headers(headers.unwrap())
      .body(payload.as_bytes().to_vec())
      .send()
      .unwrap();
    resp.copy_to(&mut buf).unwrap();
    println!("Response {:?}", String::from_utf8(buf.clone()));
    buf
  }

  pub fn createCMK(&self) {
    let req = CreateKeyReq {
      alias: "eigen_test_key_1",
      key_usage: Some("ENCRYPT_DECRYPT"),
      description: Some("test"),
      type_: 1,
    };
    let payload = serde_json::to_string(&req).unwrap();
    let resp_json = "{\"Response\":{\"KeyId\":\"5aa5a643-60d7-11ec-9699-da765df4a8a3\",\"Alias\":\"eigen_test_key_1\",\"CreateTime\":1639923859,\"Description\":\"test\",\"KeyState\":\"Enabled\",\"KeyUsage\":\"ENCRYPT_DECRYPT\",\"RequestId\":\"75fda37b-7d8d-40df-8bc4-5c9b0c518391\",\"TagCode\":0,\"TagMsg\":\"\"}}";
    let resp: WrappedResponse<CreateKeyResp> = serde_json::from_str(&resp_json).unwrap();
    println!("{:?}", resp);
  }

  pub fn listCMK(&self) -> ListKeysResp {
    let pager = Pager {
      Offset: 0,
      Limit: 1,
    };
    let payload = serde_json::to_string(&pager).unwrap();
    let resp = self.send("ListKeys", &payload);
    let resp_json = String::from_utf8(resp).unwrap();
    let resp: WrappedResponse<ListKeysResp> = serde_json::from_str(&resp_json).unwrap();
    resp.response
  }

  pub fn encrypt(&self, key_id: &str, plaintext: String) -> EncryptResp {
    let req = EncryptReq {
      key_id: key_id.to_string(),
      plaintext: plaintext,
      encryption_context: Some(String::from("{\"test\": \"abc\"}")),
    };
    let payload = serde_json::to_string(&req).unwrap();
    let resp = self.send("Encrypt", &payload);
    let resp_json = String::from_utf8(resp).unwrap();
    let resp: WrappedResponse<EncryptResp> = serde_json::from_str(&resp_json).unwrap();
    println!("{:?}", resp);
    resp.response
  }

  pub fn decrypt(&self, cipher_text_base64: String) -> DecryptResp {
    let req = DecryptReq {
      ciphertext_blob: cipher_text_base64,
      encryption_context: Some(String::from("{\"test\": \"abc\"}")),
    };
    let payload = serde_json::to_string(&req).unwrap();
    let resp = self.send("Decrypt", &payload);
    let resp_json = String::from_utf8(resp).unwrap();
    let resp: WrappedResponse<DecryptResp> = serde_json::from_str(&resp_json).unwrap();
    println!("{:?}", resp);
    resp.response
  }
}
