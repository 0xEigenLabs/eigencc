//! # LZW decoder and encoder
//!
//! This crates provides a `LzwEncoder` and `LzwDecoder`. The code words are written from
//! and to bit streams where it is possible to write either the most or least significant 
//! bit first. The maximum possible code size is 16 bits. Both types rely on RAII to
//! produced correct results.
//!
//! The de- and encoder expect the LZW stream to start with a clear code and end with an
//! end code which are defined as follows:
//!
//!  * `CLEAR_CODE == 1 << min_code_size`
//!  * `END_CODE   == CLEAR_CODE + 1`
//!
//! Examplary use of the encoder:
//!
//!     use lzw::{LsbWriter, Encoder};
//!     let size = 8;
//!     let data = b"TOBEORNOTTOBEORTOBEORNOT";
//!     let mut compressed = vec![];
//!     {
//!         let mut enc = Encoder::new(LsbWriter::new(&mut compressed), size).unwrap();
//!         enc.encode_bytes(data).unwrap();
//!     }

#![cfg_attr(all(feature = "mesalock_sgx",
                not(target_env = "sgx")), no_std)]
#![cfg_attr(all(target_env = "sgx", target_vendor = "mesalock"), feature(rustc_private))]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

mod lzw;
mod bitstream;

pub use lzw::{
    Decoder,
    DecoderEarlyChange,
    Encoder,
    encode
};

pub use bitstream::{
    BitReader,
    BitWriter,
    LsbReader,
    LsbWriter,
    MsbReader,
    MsbWriter,
    Bits
};
