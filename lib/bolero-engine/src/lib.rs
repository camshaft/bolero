pub type Seed = u128;

#[cfg(feature = "any")]
pub mod any;
pub mod failure;
pub mod input;
#[cfg(not(kani))]
pub mod panic;
#[cfg(kani)]
#[path = "./noop/panic.rs"]
pub mod panic;
mod result;
#[cfg(feature = "rng")]
pub mod rng;
pub mod shrink;
#[doc(hidden)]
pub mod target_location;
mod test;

pub use crate::failure::Failure;
pub use anyhow::Error;
#[cfg(kani)]
pub use bolero_generator::kani;
pub use bolero_generator::{
    driver::{self, Driver},
    TypeGenerator, ValueGenerator,
};
pub use input::Input;
pub use result::IntoResult;
#[doc(hidden)]
pub use target_location::TargetLocation;
pub use test::*;

/// Trait for defining an engine that executes a test
pub trait Engine<T: Test>: Sized {
    type Output;

    fn run(self, test: T, options: driver::Options) -> Self::Output;
}

pub trait ScopedEngine {
    type Output;

    fn run<F, R>(self, test: F, options: driver::Options) -> Self::Output
    where
        F: FnMut() -> R + core::panic::RefUnwindSafe,
        R: IntoResult;
}

// TODO change this to `!` when stabilized
#[doc(hidden)]
pub type Never = ();
