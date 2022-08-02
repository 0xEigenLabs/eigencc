extern crate clap_port_flag;
#[macro_use]
extern crate structopt;

use clap_port_flag::Port;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Cli {
  #[structopt(flatten)]
  port: Port,
}

fn main() -> Result<(), std::io::Error> {
  let args = Cli::from_args();
  let tcp_listener = args.port.bind_or(8080)?;
  println!("{:?}", tcp_listener);
  Ok(())
}
