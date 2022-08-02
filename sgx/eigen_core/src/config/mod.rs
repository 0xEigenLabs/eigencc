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

// ip/port is dynamically dispatched for fns client.
// we cannot use the &'static str in this struct.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::prelude::v1::*;
use attestation;
use attestation::verifier::EnclaveAttr;
use config::build_config::BUILD_CONFIG;
use config::runtime_config::RuntimeConfig;
use utils::EnclaveMeasurement;

use lazy_static::lazy_static;

#[derive(Clone)]
pub struct TargetDesc {
    pub addr: SocketAddr,
    pub desc: OutboundDesc,
}

impl TargetDesc {
    pub fn new(addr: SocketAddr, desc: OutboundDesc) -> TargetDesc {
        TargetDesc { addr, desc }
    }
}

#[derive(Clone)]
pub enum InboundDesc {
    Sgx(EnclaveAttr),
    External,
}

#[derive(Clone)]
pub enum OutboundDesc {
    Sgx(EnclaveAttr),
}

impl OutboundDesc {
    pub fn default() -> OutboundDesc {
        OutboundDesc::Sgx(get_trusted_enclave_attr(vec!["fns"]))
    }

    pub fn new(measures: EnclaveMeasurement) -> OutboundDesc {
        OutboundDesc::Sgx(EnclaveAttr {
            measures: vec![measures],
        })
    }
}

fn load_presigned_enclave_info() -> HashMap<String, EnclaveMeasurement> {
    if runtime_config().audit.auditor_signatures.len() < BUILD_CONFIG.auditor_public_keys.len() {
        panic!("Number of auditor signatures is not enough for verification.")
    }

    if !utils::verify_enclave_info(
        &runtime_config().audit.enclave_info.as_bytes(),
        BUILD_CONFIG.auditor_public_keys,
        &runtime_config().audit.auditor_signatures,
    ) {
        panic!("Failed to verify the signatures of enclave info.");
    }

    utils::load_enclave_info(&runtime_config().audit.enclave_info)
}

lazy_static! {
    static ref RUNTIME_CONFIG: Option<RuntimeConfig> =
        RuntimeConfig::from_toml("runtime.config.toml");
    static ref ENCLAVE_IDENTITIES: HashMap<String, EnclaveMeasurement> =
        load_presigned_enclave_info();
}

pub fn is_runtime_config_initialized() -> bool {
    RUNTIME_CONFIG.is_some()
}

pub fn runtime_config() -> &'static RuntimeConfig {
    RUNTIME_CONFIG
        .as_ref()
        .expect("Invalid runtime config, should gracefully exit during enclave_init!")
}

pub fn get_trusted_enclave_attr(service_names: Vec<&str>) -> EnclaveAttr {
    let measures = service_names
        .iter()
        .map(|name| *ENCLAVE_IDENTITIES.get(&(*name).to_string()).unwrap())
        .collect();
    EnclaveAttr { measures }
}
