//! # GIF en- and decoding library [![Build Status](https://travis-ci.org/image-rs/image-gif.svg?branch=master)](https://travis-ci.org/image-rs/image-gif)
//! 
//! GIF en- and decoder written in Rust ([API Documentation](https://docs.rs/gif)).
//! 
//! # GIF encoding and decoding library
//! 
//! This library provides all functions necessary to de- and encode GIF files.
//! 
//! ## High level interface
//! 
//! The high level interface consists of the two types
//! [`Encoder`](struct.Encoder.html) and [`Decoder`](struct.Decoder.html).
//! They as builders for the actual en- and decoders and can be used to set various
//! options beforehand.
//! 
//! ### Decoding GIF files
//! 
//! ```rust
//! // Open the file
//! use std::fs::File;
//! use gif::SetParameter;
//! let mut decoder = gif::Decoder::new(File::open("tests/samples/sample_1.gif").unwrap());
//! // Configure the decoder such that it will expand the image to RGBA.
//! decoder.set(gif::ColorOutput::RGBA);
//! // Read the file header
//! let mut decoder = decoder.read_info().unwrap();
//! while let Some(frame) = decoder.read_next_frame().unwrap() {
//!     // Process every frame
//! }
//! ```
//! 
//! 
//! 
//! ### Encoding GIF files
//!
//! The encoder can be used so save simple computer generated images:
//! 
//! ```rust
//! use gif::{Frame, Encoder, Repeat, SetParameter};
//! use std::fs::File;
//! use std::borrow::Cow;
//! 
//! let color_map = &[0xFF, 0xFF, 0xFF, 0, 0, 0];
//! let (width, height) = (6, 6);
//! let mut beacon_states = [[
//!     0, 0, 0, 0, 0, 0,
//!     0, 1, 1, 0, 0, 0,
//!     0, 1, 1, 0, 0, 0,
//!     0, 0, 0, 1, 1, 0,
//!     0, 0, 0, 1, 1, 0,
//!     0, 0, 0, 0, 0, 0,
//! ], [
//!     0, 0, 0, 0, 0, 0,
//!     0, 1, 1, 0, 0, 0,
//!     0, 1, 0, 0, 0, 0,
//!     0, 0, 0, 0, 1, 0,
//!     0, 0, 0, 1, 1, 0,
//!     0, 0, 0, 0, 0, 0,
//! ]];
//! let mut image = File::create("tests/samples/beacon.gif").unwrap();;
//! let mut encoder = Encoder::new(&mut image, width, height, color_map).unwrap();
//! encoder.set(Repeat::Infinite).unwrap();
//! for state in &beacon_states {
//!     let mut frame = Frame::default();
//!     frame.width = width;
//!     frame.height = height;
//!     frame.buffer = Cow::Borrowed(&*state);
//!     encoder.write_frame(&frame).unwrap();
//! }
//! ```
//!
//! [`Frame::from_*`](struct.Frame.html) can be used to convert a true color image to a paletted
//! image with a maximum of 256 colors:
//!
//! ```rust
//! use std::fs::File;
//! 
//! // Get pixel data from some source
//! let mut pixels: Vec<u8> = vec![0; 30_000];
//! // Create frame from data
//! let frame = gif::Frame::from_rgb(100, 100, &mut *pixels);
//! // Create encoder
//! let mut image = File::create("target/indexed_color.gif").unwrap();
//! let mut encoder = gif::Encoder::new(&mut image, frame.width, frame.height, &[]).unwrap();
//! // Write frame to file
//! encoder.write_frame(&frame).unwrap();
//! ```


//! 
//! ## C API
//!
//! The C API is unstable and widely untested. It can be activated using the feature flag `c_api`.

// TODO: make this compile
// ```rust
// use gif::{Frame, Encoder};
// use std::fs::File;
// let color_map = &[0, 0, 0, 0xFF, 0xFF, 0xFF];
// let mut frame = Frame::default();
// // Generate checkerboard lattice
// for (i, j) in (0..10).zip(0..10) {
//     frame.buffer.push(if (i * j) % 2 == 0 {
//         1
//     } else {
//         0
//     })
// }
// # (|| {
// {
// let mut file = File::create("test.gif")?;
// let mut encoder = Encoder::new(&mut file, 100, 100);
// encoder.write_global_palette(color_map)?.write_frame(&frame)
// }
// # })().unwrap();
// ```
#![deny(missing_docs)]

#![cfg_attr(all(feature = "mesalock_sgx",
                not(target_env = "sgx")), no_std)]
#![cfg_attr(all(target_env = "sgx", target_vendor = "mesalock"), feature(rustc_private))]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "c_api")]
extern crate libc;
extern crate lzw;

mod traits;
mod common;
mod reader;
mod encoder;

#[cfg(feature = "c_api")]
mod c_api_utils;
#[cfg(feature = "c_api")]
pub mod c_api;

pub use traits::{SetParameter, Parameter};
pub use common::{Block, Extension, DisposalMethod, Frame};

pub use reader::{StreamingDecoder, Decoded, DecodingError};
/// StreamingDecoder configuration parameters
pub use reader::{ColorOutput, MemoryLimit, Extensions};
pub use reader::{Reader, Decoder};

pub use encoder::{Encoder, ExtensionData, Repeat};

#[cfg(test)]
#[test]
fn round_trip() {
    use std::io::prelude::*;
    use std::fs::File;
    let mut data = vec![];
    File::open("tests/samples/sample_1.gif").unwrap().read_to_end(&mut data).unwrap();
    let mut decoder = Decoder::new(&*data).read_info().unwrap();
    let palette: Vec<u8> = decoder.palette().unwrap().into();
    let frame = decoder.read_next_frame().unwrap().unwrap();
    let mut data2 = vec![];
    {
        let mut encoder = Encoder::new(&mut data2, frame.width, frame.height, &palette).unwrap();
        encoder.write_frame(frame).unwrap();
    }
    assert_eq!(&data[..], &data2[..])
}
