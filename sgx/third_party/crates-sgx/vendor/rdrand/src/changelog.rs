//! Project changelog

/// Fix unsound mutable reference aliasing in the implementation of `try_fill_bytes`.
///
/// The affected code has been replaced with safer one where the scope of `unsafe` is reduced to
/// the loop which obtains a random word via a native instruction.
///
/// ## Breaking changes
///
/// rustc version 1.32 is now required to build the library (up from 1.30).
pub mod r0_6_0 {}

/// Replaced likely unsound use of `core::mem::uninitialized()`.
pub mod r0_5_1 {}

/// ## Breaking changes
///
/// Updated rand_core dependency from `0.3` to `0.4`.
pub mod r0_5_0 {}

/// ## Breaking changes
///
/// Crate gained an enabled-by-default `std` feature. If you relied on rdrand being `core`-able
/// change your dependency to appear as such:
///
/// ```toml
/// rdrand = { version = "0.4", default-features = false }
/// ```
///
/// This is done so that an advantage of the common feature detection functionality could be
/// employed by users that are not constrained by `core`. This functionality is faster, caches the
/// results and is shared between all users of the functionality.
///
/// For `core` usage the feature detection has also been improved and will not be done if e.g.
/// crate is built with `rdrand` instructions enabled globally.
pub mod r0_4_0 {}

/// Crate now works on stable!
///
/// ## Breaking changes
///
/// * Updated to `rand_core = ^0.3`.
pub mod r0_3_0 {}
