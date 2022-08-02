//! WebAssembly format library
//#![warn(missing_docs)]
#![cfg_attr(not(feature = "mesalock_sgx"), warn(missing_docs))]

#![cfg_attr(any(not(feature = "std"),
                all(feature = "mesalock_sgx", not(target_env = "sgx"))), no_std)]
#![cfg_attr(all(target_env = "sgx", target_vendor = "mesalock"), feature(rustc_private))]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

#[macro_use]
extern crate alloc;

pub mod elements;
pub mod builder;
#[cfg(not(feature = "mesalock_sgx"))]
mod io;
#[cfg(feature = "mesalock_sgx")]
pub mod io;

pub use elements::{
	Error as SerializationError,
	deserialize_buffer,
	serialize,
	peek_size,
};

#[cfg(feature = "std")]
pub use elements::{
	deserialize_file,
	serialize_to_file,
};
