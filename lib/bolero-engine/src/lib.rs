pub use anyhow::Error;
pub use bolero_generator::{
    driver::{self, Driver, DriverMode},
    TypeGenerator, ValueGenerator,
};

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

pub mod test_failure;
pub use crate::test_failure::TestFailure;

mod test_input;
pub use test_input::*;

#[doc(hidden)]
pub mod target_location;
#[doc(hidden)]
pub use target_location::TargetLocation;

mod test_result;
pub use test_result::*;

/// Trait for defining an engine that executes a test
pub trait Engine<T: Test>: Sized {
    type Output;

    fn run(self, test: T, options: driver::Options) -> Self::Output;
}

// TODO change this to `!` when stabilized
#[doc(hidden)]
pub type Never = ();
