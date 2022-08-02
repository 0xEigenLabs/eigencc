#![cfg_attr(feature = "nightly", deny(missing_docs))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![cfg_attr(test, deny(warnings))]

extern crate env_logger;
extern crate failure;
extern crate log;
extern crate pretty_env_logger;
#[macro_use]
extern crate structopt;

use env_logger::Builder as LoggerBuilder;
use failure::Error;
use log::Level;
use pretty_env_logger::formatted_builder;

/// Add log functionality to Structopt.
#[derive(StructOpt, Debug)]
pub struct Log {
  /// Enable pretty printing.
  #[structopt(short = "P", long = "pretty")]
  pretty: bool,
}

impl Log {
  /// Initialize `env_logger` and set the log level for the given package.
  ///
  /// All other modules default to printing warnings.
  pub fn log(&self, level: Level, own_pkg_name: &str) -> Result<(), Error> {
    let level_filter = level.to_level_filter();
    init_builder(self.pretty)?
      .filter(Some(&own_pkg_name.replace("-", "_")), level_filter)
      .filter(None, Level::Warn.to_level_filter())
      .try_init()?;
    Ok(())
  }

  /// Initialize `env_logger` and set the log level for all packages. No
  /// additional filtering is applied.
  pub fn log_all(&self, level: Level) -> Result<(), Error> {
    let level_filter = level.to_level_filter();

    init_builder(self.pretty)?
      .filter(None, level_filter)
      .try_init()?;
    Ok(())
  }
}

fn init_builder(pretty: bool) -> Result<LoggerBuilder, Error> {
  if pretty {
    Ok(formatted_builder()?)
  } else {
    Ok(LoggerBuilder::new())
  }
}
