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

use crate::worker::{Worker, WorkerContext, WorkerInfoQueue};
use eigen_core::rpc::EnclaveService;
use eigen_core::Result;
use fns_proto::{InvokeTaskRequest, InvokeTaskResponse};
use std::marker::PhantomData;

pub trait HandleRequest {
    fn handle_request(&self) -> Result<InvokeTaskResponse>;
}

fn invoke_worker(
    worker: &mut dyn Worker,
    request: &InvokeTaskRequest,
) -> Result<InvokeTaskResponse> {
    // Generate RunningTask
    // New worker context
    let worker_context = WorkerContext {
        context_id: request.task_id.to_owned(),
    };
    let payload = request.payload.clone();
    if let Err(err) = worker.prepare_input(payload) {
        return Err(err);
    }
    let result = worker.execute(worker_context);
    match result {
        Ok(output) => {
            let response = InvokeTaskResponse::new(&output);
            Ok(response)
        }
        Err(err) => Err(err),
    }
}
impl HandleRequest for InvokeTaskRequest {
    fn handle_request(&self) -> Result<InvokeTaskResponse> {
        let mut worker = WorkerInfoQueue::aquire_worker(&self.function_name)?;
        let response = invoke_worker(worker.as_mut(), &self);
        let _ = WorkerInfoQueue::release_worker(worker);
        response
    }
}

pub struct FNSEnclave<S, T> {
    state: i32,
    x: PhantomData<S>,
    y: PhantomData<T>,
}

impl<S, T> Default for FNSEnclave<S, T> {
    fn default() -> Self {
        FNSEnclave {
            state: 0,
            x: PhantomData::<S>,
            y: PhantomData::<T>,
        }
    }
}

impl EnclaveService<InvokeTaskRequest, InvokeTaskResponse>
    for FNSEnclave<InvokeTaskRequest, InvokeTaskResponse>
{
    fn handle_invoke(&mut self, input: InvokeTaskRequest) -> Result<InvokeTaskResponse> {
        trace!("handle_invoke invoked!");
        trace!("incoming payload = {:?}", input);
        self.state += 1;
        let response = input.handle_request()?;
        trace!("{}th round complete!", self.state);
        Ok(response)
    }
}
