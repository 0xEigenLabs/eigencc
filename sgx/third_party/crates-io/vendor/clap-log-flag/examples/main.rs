extern crate clap_log_flag;
#[macro_use]
extern crate log;
extern crate clap_verbosity_flag;
#[macro_use]
extern crate structopt;

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Cli {
  #[structopt(flatten)]
  verbose: clap_verbosity_flag::Verbosity,
  #[structopt(flatten)]
  log: clap_log_flag::Log,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let args = Cli::from_args();
  args.log.log_all(args.verbose.log_level())?;
  info!("hello");
  error!("oh no!");
  Ok(())
}
