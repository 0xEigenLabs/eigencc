# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2018-12-06

This release is only compatible with Rust 1.31.0 and later.

### Added

- The `CliResult` type alias was added as an easy to write type to be used as an
  return type in `main` functions. It uses the `exitfailure` crate internally.

### Removed

- The `Result` type alias has been removed from the prelude.

  To migrate from 0.3, please replace `Result<$X>` with `Result<$X, Error>`.
- Structopt is no longer re-exported.

  To migrate from 0.3, please add `structopt = "0.2"` to your `Cargo.toml`,
  and add `use structopt::StructOpt;` to your source files.
- The `main!` macro has been removed. It was the cause of much confusion and
  was originally introduced to work around the lack of support for using the `?`
  operator in the `main` function.
  
  To migrate from 0.3, you should use a regular `main` function like
  `fn main() -> CliResult { Ok(()) }`. You'll need to return `Ok(())` at the
  end to indicate the program was successful.
  
  To get access to your CLI arguments, use `let args = Cli::from_args();`
  (adjust the `Cli` name with the name of your struct that derives `StructOpt`.)
  
  To enable logging, it is easiest to add the line
  `args.verbosity.setup_env_logger(&env!("CARGO_PKG_NAME"))?;` right after the
  previous one loading the CLI arguments. You can also initialize a custom
  logger with the right log level directly by accessing
  `args.verbosity.log_level()`.

## [0.3.1] - 2018-10-03

### Changed

- Updated failure to 0.1.2 and use `iter_cause()` to silence deprecation warnings

## [0.3.0] - 2018-06-10

### Added

- The full code of the example projects from the guides is now also available in
  the repository's [`examples/`] directory.
- A `full-throttle` feature was added and is enabled by default. Most
  dependencies are now optional and only available when this feature (or the
  dependency itself) is enabled. In practice, this means you can easily opt-out
  of default quicli features and only enable what you need.

[`examples/`]: https://github.com/killercup/quicli/tree/master/examples

### Fixed

- Verbosity flag works for hyphenated package names

### Changed

- `prelude::LoggerBuiler` has been renamed to `prelude::LoggerBuilder`
- Now prints all causes after printing error in `main!`
- Update rayon to 1.0
- We now use the new [clap-verbosity-flag] crate for adding that `-v` flag:
    
    ```rust
    #[derive(Debug, StructOpt)]
    struct Cli {
        #[structopt(flatten)]
        verbosity: Verbosity,
    }
    ```

[clap-verbosity-flag]: https://crates.io/crates/clap-verbosity-flag

## [0.2.0] - 2018-02-11

### Fixed

- The verbosity flag of the `main!` macro now actually works! ([#45])

[#45]: https://github.com/killercup/quicli/pull/45

### Changed

- Upgrade structopt to 0.2:
  - No need to add structopt to you dependencies anymore (just delete the line in the `Cargo.toml`)
  - Their handling of "occurrences of" parameters changed, so, for verbosity you now need to write:
    
    ```rust
    #[structopt(long = "verbosity", short = "v", parse(from_occurrences))]
    verbosity: u8,
    ```

## [0.1.4] - 2018-02-09

### Changed

- Reverts "`main!` now uses the more permissive `std::result::Result` enum and `std::error::Error` trait." from 0.1.3 which broke existing code

## [0.1.3] - 2018-02-01 - Yanked!

### Changed

- `main!` now uses the more permissive `std::result::Result` enum and `std::error::Error` trait.
- Fixed a bunch of typos in the docs (thanks everyone!)
- Extended the Getting Started guide

## [0.1.2] - 2018-01-28

### Added

- [A website with guides!](https://killercup.github.io/quicli/)
- `glob`
- `create_dir`
- Re-export Rayon traits
- Export `Result` type alias using failure's Error

### Removed

- All the examples are now guides

### Changed

- `main!` now sets up logging in all cases
- Use buffered reading/writing in fs functions

## [0.1.1] - 2018-01-28

### Added

- Re-export log macros
- Automatically set up env_logger in main!
- `main!` parameter for Cli struct and its logging level field
- Readme fixes
- Expose fs module

## [0.1.0] - 2018-01-28

### Added

- `main!` macro
- Re-exports of failure, serde, structopt
- Commit Message generator example
- read/write file functions

[Unreleased]: https://github.com/killercup/quicli/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/killercup/quicli/compare/v0.4.1...v0.4.0
[0.3.1]: https://github.com/killercup/quicli/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/killercup/quicli/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/killercup/quicli/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/killercup/quicli/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/killercup/quicli/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/killercup/quicli/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/killercup/quicli/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/killercup/quicli/compare/cb747195866d2a240ab8154d00facfead3e55a9e...v0.1.0
