# clap-log-flag
[![crates.io version][1]][2] [![build status][3]][4]
[![downloads][5]][6] [![docs.rs docs][7]][8]

Add a logger to CLIs using structopt.

- [Documentation][8]
- [Crates.io][2]

## Usage
```rust
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
```

## Installation
```sh
$ cargo add clap-log-flag
```

## License
[MIT](./LICENSE-MIT) OR [Apache-2.0](./LICENSE-APACHE)

[1]: https://img.shields.io/crates/v/clap-log-flag.svg?style=flat-square
[2]: https://crates.io/crates/clap-log-flag
[3]: https://img.shields.io/travis/rust-clique/clap-log-flag.svg?style=flat-square
[4]: https://travis-ci.org/rust-clique/clap-log-flag
[5]: https://img.shields.io/crates/d/clap-log-flag.svg?style=flat-square
[6]: https://crates.io/crates/clap-log-flag
[7]: https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square
[8]: https://docs.rs/clap-log-flag
