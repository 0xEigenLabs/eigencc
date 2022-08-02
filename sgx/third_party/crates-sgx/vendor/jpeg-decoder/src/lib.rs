//! This crate contains a JPEG decoder.
//!
//! # Examples
//!
//! ```
//! use jpeg_decoder::Decoder;
//! use std::fs::File;
//! use std::io::BufReader;
//!
//! let file = File::open("tests/reftest/images/extraneous-data.jpg").expect("failed to open file");
//! let mut decoder = Decoder::new(BufReader::new(file));
//! let pixels = decoder.decode().expect("failed to decode image");
//! let metadata = decoder.info().unwrap();
//! ```
//!
//! Get metadata from a file without decoding it:
//!
//! ```
//! use jpeg_decoder::Decoder;
//! use std::fs::File;
//! use std::io::BufReader;
//!
//! let file = File::open("tests/reftest/images/extraneous-data.jpg").expect("failed to open file");
//! let mut decoder = Decoder::new(BufReader::new(file));
//! decoder.read_info().expect("failed to read metadata");
//! let metadata = decoder.info().unwrap();
//! ```

#![deny(missing_docs)]
#![forbid(unsafe_code)]

#![cfg_attr(all(feature = "mesalock_sgx",
                not(target_env = "sgx")), no_std)]
#![cfg_attr(all(target_env = "sgx", target_vendor = "mesalock"), feature(rustc_private))]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

extern crate byteorder;
#[cfg(feature="rayon")]
extern crate rayon;

pub use decoder::{Decoder, ImageInfo, PixelFormat};
pub use error::{Error, UnsupportedFeature};

mod decoder;
mod error;
mod huffman;
mod idct;
mod marker;
mod parser;
mod upsampler;
mod worker;
