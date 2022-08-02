# clap_flags
[![crates.io version][1]][2] [![build status][3]][4]
[![downloads][5]][6] [![docs.rs docs][7]][8]

Collection of reusable flags for Clap.

- [Documentation][8]
- [Crates.io][2]

## Usage
```rust
use futures::prelude::*;
use hyper::service::service_fn_ok;
use hyper::{Body, Response, Server};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Cli {
  #[structopt(flatten)]
  verbosity: clap_flags::Verbosity,
  #[structopt(flatten)]
  logger: clap_flags::Log,
  #[structopt(flatten)]
  port: clap_flags::Port,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let args = Cli::from_args();
  let listener = args.port.bind()?;

  args.logger.log_all(args.verbosity.log_level())?;

  let handle = tokio::reactor::Handle::current();
  let listener = tokio::net::TcpListener::from_std(listener, &handle)?;
  let addr = listener.local_addr()?;

  let server = Server::builder(listener.incoming())
    .serve(|| service_fn_ok(|_| Response::new(Body::from("Hello World"))))
    .map_err(|e| eprintln!("server error: {}", e));

  info!("Server listening on {}", addr);
  tokio::run(server);

  Ok(())
}
```

### Output
```txt
clap_flags 0.1.0
Yoshua Wuyts <yoshuawuyts@gmail.com>
Collection of reusable flags for Clap

USAGE:
    main [FLAGS] [OPTIONS]

FLAGS:
    -h, --help         Prints help information
    -P, --pretty       Enable pretty printing.
    -V, --version      Prints version information
    -v, --verbosity    Pass many times for more log output

OPTIONS:
    -a, --address <address>    The network address to listen to. [default: 127.0.0.1]
        --listen-fd <fd>       A previously opened network socket. [env: LISTEN_FD=]
    -p, --port <port>          The network port to listen to. [env: PORT=]
```

## Installation
```sh
$ cargo add clap_flags
```

## License
[MIT](./LICENSE-MIT) OR [Apache-2.0](./LICENSE-APACHE)

[1]: https://img.shields.io/crates/v/clap_flags.svg?style=flat-square
[2]: https://crates.io/crates/clap_flags
[3]: https://img.shields.io/travis/yoshuawuyts/clap_flags.svg?style=flat-square
[4]: https://travis-ci.org/yoshuawuyts/clap_flags
[5]: https://img.shields.io/crates/d/clap_flags.svg?style=flat-square
[6]: https://crates.io/crates/clap_flags
[7]: https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square
[8]: https://docs.rs/clap_flags
