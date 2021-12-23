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
use std::format;

use crate::worker::{Worker, WorkerContext};

use chrono::{DateTime, offset::Utc};

use ring::digest;
use ring::hmac;
use serde::{Deserialize, Serialize};

use http_req::{request, tls, uri::Uri, response::Headers, request::Method};

use std::time::SystemTime;

//region: https://intl.cloud.tencent.com/document/product/1030/32174
pub fn get_date() -> String {
  let system_time = SystemTime::now();
  let dt: DateTime<Utc> = system_time.into();
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

#[derive(Serialize, Deserialize, Debug)]
struct Pager {
  #[serde(rename = "Limit")]
  pub limit: i32,
  #[serde(rename = "Offset")]
  pub offset: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Key {
  #[serde(rename = "KeyId")]
  pub key_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct UserAttr {
  #[serde(rename = "UserAttr")]
  pub user_attr: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ListKeysResp {
  #[serde(rename = "RequestId")]
  pub request_id: String,
  #[serde(rename = "Keys")]
  pub keys: Vec<Key>,
  #[serde(rename = "TotalCount")]
  pub total_count: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateKeyReq<'a> {
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
pub struct CreateKeyResp {
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
pub struct EncryptReq {
  #[serde(rename = "KeyId")]
  pub key_id: String,
  #[serde(rename = "Plaintext")]
  pub plaintext: String,
  #[serde(rename = "EncryptionContext")]
  pub encryption_context: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptResp {
  #[serde(rename = "CiphertextBlob")]
  pub ciphertext_blob: String,
  #[serde(rename = "KeyId")]
  pub key_id: String,
  #[serde(rename = "RequestId")]
  pub request_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptReq {
  #[serde(rename = "CiphertextBlob")]
  pub ciphertext_blob: String,
  #[serde(rename = "EncryptionContext")]
  pub encryption_context: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptResp {
  #[serde(rename = "KeyId")]
  pub key_id: String,
  #[serde(rename = "Plaintext")]
  pub plaintext: String,
  #[serde(rename = "RequestId")]
  pub request_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WrappedResponse<T> {
  #[serde(rename = "Response")]
  pub response: T,
}

pub struct Client<'a> {
  host: &'a str,
  region: &'a str,
  secretKey: &'a str,
  secretId: &'a str,
  service: &'a str,
  version: &'a str,
}

impl<'a> Client<'a> {
  pub fn new(
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
  ) -> Headers {
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
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

    let mut headers = Headers::new();
    //headers.insert("Connection", "Close");
    headers.insert("Host", self.host);
    headers.insert("Authorization", authz.as_str());
    headers.insert("Content-Type", "application/json; charset=utf-8");
    headers.insert("X-TC-Action", action);
    headers.insert("X-TC-Region", self.region);
    headers.insert("X-TC-Timestamp", &now.to_string());
    headers.insert("X-TC-Version", self.version);
    headers.insert("Content-Length", payload.len().to_string().as_str());
    info!("{:?} {}", headers, payload.len());
    headers
  }

  fn send(&self, action:& str, payload: &str) -> Vec<u8> {
      let endpoint = "https://".to_owned() + self.host;
      let mut buf= Vec::new();
      let headers = self.add_common_header(action, payload);
      let uri: Uri = endpoint.parse().unwrap();
      let mut client = request::Request::new(&uri);
      let res = client
          .method(Method::POST)
          .headers(headers)
          .body(payload.as_ref())
          .send(&mut buf)
          .unwrap();
      info!("Response {:?}", String::from_utf8(buf.clone()));
      buf
  }

  pub fn create_cmk(&self) {
    let req = CreateKeyReq {
      alias: "eigen_test_key_1",
      key_usage: Some("ENCRYPT_DECRYPT"),
      description: Some("test"),
      type_: 1,
    };
    let payload = serde_json::to_string(&req).unwrap();
    let resp_json = "{\"Response\":{\"KeyId\":\"5aa5a643-60d7-11ec-9699-da765df4a8a3\",\"Alias\":\"eigen_test_key_1\",\"CreateTime\":1639923859,\"Description\":\"test\",\"KeyState\":\"Enabled\",\"KeyUsage\":\"ENCRYPT_DECRYPT\",\"RequestId\":\"75fda37b-7d8d-40df-8bc4-5c9b0c518391\",\"TagCode\":0,\"TagMsg\":\"\"}}";
    let resp: WrappedResponse<CreateKeyResp> = serde_json::from_str(&resp_json).unwrap();
    info!("{:?}", resp);
  }

  pub fn list_cmk(&self) -> ListKeysResp {
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

  pub fn encrypt(&self, key_id: &str, plaintext: String, ua: String) -> EncryptResp {
    let userAttr = UserAttr {
        user_attr: ua
    };
    let res_json = serde_json::to_string(&userAttr).unwrap();
    let req = EncryptReq {
      key_id: key_id.to_string(),
      plaintext: plaintext,
      //encryption_context: Some(String::from("{\"test\": \"abc\"}")),
      encryption_context: Some(res_json),
    };
    let payload = serde_json::to_string(&req).unwrap();
    let resp = self.send("Encrypt", &payload);
    let resp_json = String::from_utf8(resp).unwrap();
    let resp: WrappedResponse<EncryptResp> = serde_json::from_str(&resp_json).unwrap();
    info!("{:?}", resp);
    resp.response
  }

  pub fn decrypt(&self, cipher_text_base64: String, ua: String) -> DecryptResp {
    let userAttr = UserAttr {
        user_attr: ua
    };
    let res_json = serde_json::to_string(&userAttr).unwrap();
    let req = DecryptReq {
      ciphertext_blob: cipher_text_base64,
      encryption_context: Some(res_json),
    };
    let payload = serde_json::to_string(&req).unwrap();
    let resp = self.send("Decrypt", &payload);
    let resp_json = String::from_utf8(resp).unwrap();
    let resp: WrappedResponse<DecryptResp> = serde_json::from_str(&resp_json).unwrap();
    info!("{:?}", resp);
    resp.response
  }
}
