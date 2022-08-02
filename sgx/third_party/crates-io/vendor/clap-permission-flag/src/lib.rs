#![cfg_attr(feature = "nightly", deny(missing_docs))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![cfg_attr(test, deny(warnings))]

extern crate failure;
extern crate privdrop;
#[macro_use]
extern crate structopt;

use failure::Error;

/// Drop permissions of a CLI using structopt.
#[derive(StructOpt, Debug)]
pub struct Permission {
  /// Change the process user
  #[structopt(short = "u", long = "user")]
  user: Option<String>,
  /// Change the process group
  #[structopt(short = "g", long = "group")]
  group: Option<String>,
}

impl Permission {
  /// Drop privileges.
  pub fn drop(self) -> Result<(), Error> {
    let mut drop = privdrop::PrivDrop::default();

    if let Some(user) = self.user {
      drop = drop.user(&user)?;
    }

    if let Some(group) = self.group {
      drop = drop.group(&group)?;
    }

    drop.apply()?;
    Ok(())
  }

  /// Get the user.
  pub fn user(&self) -> &Option<String> {
    &self.user
  }

  /// Get the group.
  pub fn group(&self) -> &Option<String> {
    &self.group
  }
}
