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

use lazy_static::lazy_static;
use sdk::{Mesatee, MesateeEnclaveInfo};
use std::net::SocketAddr;
use std::path::PathBuf;
use structopt::StructOpt;

lazy_static! {
    static ref TMS_ADDR: SocketAddr = "127.0.0.1:8082".parse().unwrap();
}

#[derive(Debug, StructOpt)]
struct EchoOpt {
    #[structopt(short = "e", required = true)]
    enclave_info: PathBuf,

    #[structopt(short = "m", required = true)]
    message: String,
}

#[derive(Debug, StructOpt)]
enum Command {
    /// Echo
    #[structopt(name = "echo")]
    Echo(EchoOpt),
}

#[derive(Debug, StructOpt)]
/// Quickstart example.
struct Cli {
    #[structopt(subcommand)]
    command: Command,
}

fn echo(args: EchoOpt) {
    println!("[+] Invoke echo function");
    let auditors = vec![]; // legacy

    let enclave_info =
        MesateeEnclaveInfo::load(auditors, args.enclave_info.to_str().unwrap()).expect("load");

    let tee = Mesatee::new(&enclave_info, "uid1", "token1", *TMS_ADDR).expect("new");
    let task = tee.create_task("echo").expect("create");
    let response = task.invoke_with_payload(&args.message).expect("invoke");
    println!("{}", response);
}

fn main() {
    let args = Cli::from_args();
    match args.command {
        Command::Echo(echo_args) => echo(echo_args),
    }
}
