//! Decoding and Encoding of TIFF Images
//!
//! TIFF (Tagged Image File Format) is a versatile image format that supports
//! lossless and lossy compression.
//!
//! # Related Links
//! * <http://partners.adobe.com/public/developer/tiff/index.html> - The TIFF specification

#![cfg_attr(all(feature = "mesalock_sgx",
                not(target_env = "sgx")), no_std)]
#![cfg_attr(all(target_env = "sgx", target_vendor = "mesalock"), feature(rustc_private))]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

extern crate byteorder;
extern crate lzw;
extern crate miniz_oxide;

pub mod decoder;
pub mod encoder;
mod error;

pub use self::error::{InflateError, TiffError, TiffFormatError, TiffResult, TiffUnsupportedError};

/// An enumeration over supported color types and their bit depths
#[derive(Copy, PartialEq, Eq, Debug, Clone, Hash)]
pub enum ColorType {
    /// Pixel is grayscale
    Gray(u8),

    /// Pixel contains R, G and B channels
    RGB(u8),

    /// Pixel is an index into a color palette
    Palette(u8),

    /// Pixel is grayscale with an alpha channel
    GrayA(u8),

    /// Pixel is RGB with an alpha channel
    RGBA(u8),

    /// Pixel is CMYK
    CMYK(u8),
}
