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

use eigen_crypto::sign::ecdsa::KeyPair;
use rand::Rng;

use crate::worker::{Worker, WorkerContext};
use eigen_core::{Error, ErrorKind, Result};

use gbdt::config::Config;
use gbdt::decision_tree::{DataVec, PredVec};
use gbdt::gradient_boost::GBDT;
use gbdt::input::{InputFormat, load};

pub struct EchoWorker {
    worker_id: u32,
    func_name: String,
    input: Option<EchoWorkerInput>,
}
impl EchoWorker {
    pub fn new() -> Self {
        EchoWorker {
            worker_id: 0,
            func_name: "echo".to_string(),
            input: None,
        }
    }
}
struct EchoWorkerInput {
    msg: String,
    test_dataset: String,
    training_dataset: String,
}

impl Worker for EchoWorker {
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
        let value: Vec<&str> = msg.as_str().split(",").collect();
        std::println!("input {} {} {}", value[0], value[1], value[2]);
        self.input = Some(EchoWorkerInput {
            msg: value[0].to_string(),
            test_dataset: value[1].to_string(),
            training_dataset: value[2].to_string()
            });
        Ok(())
    }
    fn execute(&mut self, _context: WorkerContext) -> Result<String> {
        let input = self
            .input
            .take()
            .ok_or_else(|| Error::from(ErrorKind::InvalidInputError))?;
        let mut r = vec![0u8; 32];
        rand::thread_rng().fill(&mut r[..]);
        let private_key = eigen_crypto::sign::ecdsa::EcdsaKeyPair::from_seed_unchecked(
            &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1_SIGNING,
            untrusted::Input::from(&r),
            );

        assert_eq!(private_key.is_ok(), true);
        let private_key = private_key.unwrap();
        let msg = "hello, come on, go get it 你好!";
        let s1 = vec![];
        let s2 = vec![];

        let alg = &eigen_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
        let public_key = eigen_crypto::sign::ecdsa::UnparsedPublicKey::new(alg, private_key.public_key());

        let cipher = eigen_crypto::ec::suite_b::ecies::encrypt(&public_key, &s1, &s2, msg.as_bytes());
        assert_eq!(cipher.is_ok(), true);
        let cipher = cipher.unwrap();
        let plain = eigen_crypto::ec::suite_b::ecies::decrypt(&private_key, &cipher, &s1, &s2);

        assert_eq!(plain.is_ok(), true);
        assert_eq!(msg.as_bytes().to_vec(), (plain.unwrap()));
        std::println!("check success");

	    if input.test_dataset.len() > 0 {
	        let mut cfg = Config::new();
	        cfg.set_feature_size(22);
	        cfg.set_max_depth(3);
	        cfg.set_iterations(50);
	        cfg.set_shrinkage(0.1);
	        cfg.set_loss("LogLikelyhood");
	        cfg.set_debug(true);
	        cfg.set_data_sample_ratio(1.0);
	        cfg.set_feature_sample_ratio(1.0);
	        cfg.set_training_optimization_level(2);

	        // load data
	        let train_file = input.training_dataset.as_str();
	        let test_file = input.test_dataset.as_str();

	        let mut input_format = InputFormat::csv_format();
	        input_format.set_feature_size(22);
	        input_format.set_label_index(22);
	        let mut train_dv: DataVec = load(train_file, input_format).expect("failed to load training data");
	        let test_dv: DataVec = load(test_file, input_format).expect("failed to load test data");

	        // train and save model
	        let mut gbdt = GBDT::new(&cfg);
	        gbdt.fit(&mut train_dv);
	        gbdt.save_model("gbdt.model").expect("failed to save the model");

	        // load model and do inference
	        let model = GBDT::load_model("gbdt.model").expect("failed to load the model");
	        let predicted: PredVec = model.predict(&test_dv);
	    }
	    Ok(input.msg + ", Eigen")
    }
}
