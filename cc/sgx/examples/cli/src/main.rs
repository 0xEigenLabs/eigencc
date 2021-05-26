use lazy_static::lazy_static;
use sdk::{Mesatee, MesateeEnclaveInfo};
use serde_derive::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use structopt::StructOpt;

lazy_static! {
    static ref FNS_ADDR: SocketAddr = "127.0.0.1:8082".parse().unwrap();
}

#[derive(Serialize, Deserialize)]
struct XChainTFWorkerInput {
    method: String,
    args: String,
    svn: u32,
    address: String,
}

#[derive(Serialize, Deserialize)]
struct XChainKMSWorkerInput {
    method: String, // init
    kds: String,
    svn: u32,
}

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    #[structopt(name = "fns")]
    FNS(FNSOpt),
}

#[derive(Debug, StructOpt)]
struct FNSOpt {
    #[structopt(short = "e", required = true)]
    enclave_info: PathBuf,
    #[structopt(short = "m", required = true)]
    method: String,
    #[structopt(short = "v", required = true)]
    svn: u32,
    #[structopt(short = "a")]
    args: String,
    #[structopt(short = "d")]
    address: String,
}

impl FNSOpt {
    fn encode(&self) -> String {
        match &self.method[..] {
            "init" | "mint" | "inc" => {
                let create_request = XChainKMSWorkerInput {
                    method: self.method.to_owned(), // init
                    kds: self.args.to_owned(),
                    svn: self.svn,
                };
                serde_json::to_string(&create_request).unwrap()
            }
            "store" | "add" | "sub" | "mul" | "debug" => {
                let create_request = XChainTFWorkerInput {
                    method: self.method.to_owned(),
                    svn: self.svn,
                    args: self.args.to_owned(),
                    address: self.address.to_owned(),
                };
                serde_json::to_string(&create_request).unwrap()
            }
            _ => std::panic!("invalid method"),
        }
    }
}

fn run(args: FNSOpt) {
    println!("[+] Invoke echo function");
    let auditors = vec![];
    let enclave_info =
        MesateeEnclaveInfo::load(auditors, args.enclave_info.to_str().unwrap()).expect("load");
    let tee = Mesatee::new(&enclave_info, "uid1", "token1", *FNS_ADDR).expect("new");
    let function_name = match &args.method[..] {
        "init" | "mint" | "inc" => "xchainkms",
        "store" | "add" | "sub" | "mul" | "debug" => "xchaintf",
        _ => {
            std::panic!("invalid method");
        }
    };

    let request = args.encode();
    let task = tee.create_task(function_name).expect("create");
    let response = task.invoke_with_payload(&request).expect("invoke");
    println!("{:?}", response);
}

fn main() {
    let args = Cli::from_args();
    match args.command {
        Command::FNS(a) => run(a),
    }
    println!("done");
}
