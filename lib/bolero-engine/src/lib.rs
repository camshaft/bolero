pub use anyhow::Error;
pub use bolero_generator::{
    driver::{self, Driver},
    TypeGenerator, ValueGenerator,
};

#[cfg(kani)]
pub use bolero_generator::kani;

pub type Seed = u128;

#[cfg(not(kani))]
pub mod panic;
#[cfg(kani)]
#[path = "./noop/panic.rs"]
pub mod panic;

#[cfg(feature = "rng")]
pub mod rng;
pub mod shrink;
mod test;
pub use test::*;

pub mod failure;
pub use crate::failure::Failure;

pub mod input;
pub use input::Input;

#[doc(hidden)]
pub mod target_location;
#[doc(hidden)]
pub use target_location::TargetLocation;

mod result;
pub use result::IntoResult;

/// Trait for defining an engine that executes a test
pub trait Engine<T: Test>: Sized {
    type Output;

    fn run(self, test: T, options: driver::Options) -> Self::Output;
}

// TODO change this to `!` when stabilized
#[doc(hidden)]
pub type Never = ();
