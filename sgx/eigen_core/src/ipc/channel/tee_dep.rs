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

use serde_json;

use crate::DeserializeOwned;
use crate::Serialize;

use crate::ipc::IpcReceiver;
use crate::ipc::IpcService;
use crate::{Error, ErrorKind, Result};

// Implementation of Receiver
// The receiver is TEE, the sender is App
pub struct ECallReceiver {}

impl IpcReceiver for ECallReceiver {
    fn dispatch<U, V, X>(input_payload: &[u8], x: X) -> Result<Vec<u8>>
    where
        U: DeserializeOwned,
        V: Serialize,
        X: IpcService<U, V>,
    {
        let input: U = serde_json::from_slice(&input_payload)
            .map_err(|e| Error::new(ErrorKind::IPCError, e))?;

        let response = x.handle_invoke(input)?;

        let response_payload =
            serde_json::to_vec(&response).map_err(|e| Error::new(ErrorKind::IPCError, e))?;

        Ok(response_payload)
    }
}
