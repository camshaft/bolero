//! bolero-ravel plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.

#[doc(hidden)]
#[cfg(any(test, all(feature = "lib", fuzzing_ravel)))]
pub mod engine;

#[doc(hidden)]
#[cfg(all(feature = "lib", fuzzing_ravel))]
pub use engine::*;

#[doc(hidden)]
#[cfg(any(test, feature = "bin"))]
pub mod cli;
