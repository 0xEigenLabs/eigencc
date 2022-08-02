extern crate clap_permission_flag;
#[macro_use]
extern crate structopt;

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Cli {
  #[structopt(flatten)]
  permission: clap_permission_flag::Permission,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let args = Cli::from_args();
  args.permission.drop()?;
  Ok(())
}
