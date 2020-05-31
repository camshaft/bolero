cfg_if::cfg_if! {
    if #[cfg(fuzzing_libfuzzer)] {
        /// The default engine used when defining a test target
        pub use bolero_libfuzzer::LibFuzzerEngine as DefaultEngine;
    } else if #[cfg(fuzzing_afl)] {
        /// The default engine used when defining a test target
        pub use bolero_afl::AflEngine as DefaultEngine;
    } else if #[cfg(fuzzing_honggfuzz)] {
        /// The default engine used when defining a test target
        pub use bolero_honggfuzz::HonggfuzzEngine as DefaultEngine;
    } else {
        mod test;

        /// The default engine used when defining a test target
        pub use crate::test::TestEngine as DefaultEngine;
    }
}

/// Re-export of [`bolero_generator`]
pub mod generator {
    pub use bolero_generator::{self, prelude::*};
}

#[doc(hidden)]
pub use bolero_engine::{TargetLocation, __item_path__};

pub use bolero_engine::{rng::RngEngine, Driver, DriverMode, Engine, Test};

use bolero_generator::{
    combinator::{AndThenGenerator, FilterGenerator, FilterMapGenerator, MapGenerator},
    TypeValueGenerator,
};
use core::{fmt::Debug, marker::PhantomData};

/// Execute fuzz tests for a given target
///
/// This should be executed in a separate test target, for example
/// `tests/my_fuzz_target/main.rs`.
///
/// # Examples
///
/// By default, `input` is a `&[u8]`.
///
/// This mode is generally used when testing an implementation that
/// handles raw bytes, e.g. a parser.
///
/// ```rust,no_run
/// use bolero::fuzz;
///
/// fn main() {
///     fuzz!().for_each(|input| {
///         // implement checks here
///     });
/// }
/// ```
///
/// Calling `with_type::<Type>()` will generate random values of `Type`
/// to be tested. `Type` is required to implement [`generator::TypeGenerator`]
/// in order to use this method.
///
/// This mode is used for testing an implementation that requires
/// structured input.
///
/// ```rust,no_run
/// use bolero::fuzz;
///
/// fn main() {
///     fuzz!()
///         .with_type::<(u8, u16)>()
///         .for_each(|(a, b)| {
///             // implement checks here
///         });
/// }
/// ```
///
/// The function `with_generator::<Generator>(generator)` will use the provided `Generator`,
/// which implements [`generator::ValueGenerator`], to generate input
/// values of type `Generator::Output`.
///
/// This mode is used for testing an implementation that requires
/// structured input with specific constraints applied to the type.
/// In the following example, we are only interested in generating
/// two values, one being between 0 and 100, the other: 10 and 50.
///
/// ```rust,no_run
/// use bolero::fuzz;
///
/// fn main() {
///     fuzz!()
///         .with_generator((0..100, 10..50))
///         .for_each(|(a, b)| {
///             // implement checks here
///         });
/// }
/// ```
///
/// For compatibility purposes, `bolero` also supports the same interface as
/// [rust-fuzz/afl.rs](https://github.com/rust-fuzz/afl.rs). This usage
/// has a few downsides:
///
/// * The test cannot be configured
/// * The test code will be contained inside a macro which can trip up
///   some editors and IDEs.
///
/// ```rust,no_run
/// use bolero::fuzz;
///
/// fn main() {
///     fuzz!(|input| {
///         // implement checks here
///     });
/// }
/// ```

#[macro_export]
macro_rules! fuzz {
    () => {{
        let item_path = $crate::__item_path__!();
        $crate::fuzz!(name = item_path)
    }};
    ($fun:path) => {
        $crate::fuzz!(|input| { $fun(input) })
    };
    (| $input:ident $(: &[u8])? | $impl:expr) => {
        $crate::fuzz!().for_each(|$input: &[u8]| $impl)
    };
    (| $input:ident : $ty:ty | $impl:expr) => {
        $crate::fuzz!().with_type().for_each(|$input: $ty| $impl)
    };
    (name = $target_name:expr) => {{
        let location = $crate::TargetLocation {
            package_name: env!("CARGO_PKG_NAME"),
            manifest_dir: env!("CARGO_MANIFEST_DIR"),
            module_path: module_path!(),
            file: file!(),
            line: line!(),
            item_path: format!("{}", $target_name),
        };

        if !location.should_run() {
            return;
        }

        $crate::fuzz(location)
    }};
}

/// Configuration for a test target
pub struct TestTarget<Generator, Engine, InputOwnership> {
    generator: Generator,
    driver_mode: Option<DriverMode>,
    engine: Engine,
    input_ownership: PhantomData<InputOwnership>,
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BorrowedInput;

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ClonedInput;

#[doc(hidden)]
pub fn fuzz(
    location: TargetLocation,
) -> TestTarget<ByteSliceGenerator, DefaultEngine, BorrowedInput> {
    TestTarget::new(DefaultEngine::new(location))
}

/// Default generator for byte slices
#[derive(Copy, Clone, Default, PartialEq)]
pub struct ByteSliceGenerator;

impl<Engine> TestTarget<ByteSliceGenerator, Engine, BorrowedInput> {
    /// Create a `TestTarget` with the given `Engine`
    pub fn new(engine: Engine) -> TestTarget<ByteSliceGenerator, Engine, BorrowedInput> {
        Self {
            driver_mode: None,
            generator: ByteSliceGenerator,
            engine,
            input_ownership: PhantomData,
        }
    }
}

impl<G, Engine, InputOwnership> TestTarget<G, Engine, InputOwnership> {
    /// Set the value generator for the `TestTarget`
    ///
    /// The function `with_generator::<Generator>(generator)` will use the provided `Generator`,
    /// which implements [`generator::ValueGenerator`], to generate input
    /// values of type `Generator::Output`.
    ///
    /// This mode is used for testing an implementation that requires
    /// structured input with specific constraints applied to the type.
    pub fn with_generator<Generator: generator::ValueGenerator>(
        self,
        generator: Generator,
    ) -> TestTarget<Generator, Engine, InputOwnership>
    where
        Generator::Output: Debug,
    {
        TestTarget {
            driver_mode: self.driver_mode,
            generator,
            engine: self.engine,
            input_ownership: self.input_ownership,
        }
    }

    /// Set the type generator for the `TestTarget`
    ///
    /// Calling `with_type::<Type>()` will generate random values of `Type`
    /// to be tested. `Type` is required to implement [`generator::TypeGenerator`]
    /// in order to use this method.
    ///
    /// This mode is used for testing an implementation that requires
    /// structured input.
    pub fn with_type<T: Debug + generator::TypeGenerator>(
        self,
    ) -> TestTarget<TypeValueGenerator<T>, Engine, InputOwnership> {
        TestTarget {
            driver_mode: self.driver_mode,
            generator: generator::gen(),
            engine: self.engine,
            input_ownership: self.input_ownership,
        }
    }
}

impl<G: generator::ValueGenerator, Engine, InputOwnership> TestTarget<G, Engine, InputOwnership> {
    /// Map the value of the generator
    pub fn map<F: Fn(G::Output) -> T, T: Debug>(
        self,
        map: F,
    ) -> TestTarget<MapGenerator<G, F>, Engine, InputOwnership> {
        TestTarget {
            driver_mode: self.driver_mode,
            generator: self.generator.map(map),
            engine: self.engine,
            input_ownership: self.input_ownership,
        }
    }

    /// Map the value of the generator with a new generator
    pub fn and_then<F: Fn(G::Output) -> T, T: generator::ValueGenerator>(
        self,
        map: F,
    ) -> TestTarget<AndThenGenerator<G, F>, Engine, InputOwnership>
    where
        T::Output: Debug,
    {
        TestTarget {
            driver_mode: self.driver_mode,
            generator: self.generator.and_then(map),
            engine: self.engine,
            input_ownership: self.input_ownership,
        }
    }

    /// Filter the value of the generator
    pub fn filter<F: Fn(&G::Output) -> bool>(
        self,
        filter: F,
    ) -> TestTarget<FilterGenerator<G, F>, Engine, InputOwnership> {
        TestTarget {
            driver_mode: self.driver_mode,
            generator: self.generator.filter(filter),
            engine: self.engine,
            input_ownership: self.input_ownership,
        }
    }

    /// Filter the value of the generator and map it to something else
    pub fn filter_map<F: Fn(G::Output) -> Option<T>, T>(
        self,
        filter_map: F,
    ) -> TestTarget<FilterMapGenerator<G, F>, Engine, InputOwnership> {
        TestTarget {
            driver_mode: self.driver_mode,
            generator: self.generator.filter_map(filter_map),
            engine: self.engine,
            input_ownership: self.input_ownership,
        }
    }

    /// Set the driver mode for the fuzz target
    pub fn with_driver_mode(self, mode: DriverMode) -> Self {
        TestTarget {
            driver_mode: Some(mode),
            generator: self.generator,
            engine: self.engine,
            input_ownership: self.input_ownership,
        }
    }
}

impl<G, InputOwnership> TestTarget<G, RngEngine, InputOwnership> {
    /// Set the number of iterations executed
    pub fn with_iterations(mut self, iterations: usize) -> Self {
        self.engine.iterations = iterations;
        TestTarget {
            driver_mode: self.driver_mode,
            generator: self.generator,
            engine: self.engine,
            input_ownership: self.input_ownership,
        }
    }

    /// Set the maximum length of the generated bytes
    pub fn with_max_len(mut self, max_len: usize) -> Self {
        self.engine.max_len = max_len;
        TestTarget {
            driver_mode: self.driver_mode,
            generator: self.generator,
            engine: self.engine,
            input_ownership: self.input_ownership,
        }
    }
}

impl<G, Engine> TestTarget<G, Engine, BorrowedInput> {
    /// Use a cloned value for the test input
    ///
    /// Cloning the test inputs will force a call to [`Clone::clone`]
    /// on each input value, and therefore, will be less
    /// efficient than using a reference.
    pub fn cloned(self) -> TestTarget<G, Engine, ClonedInput> {
        TestTarget {
            driver_mode: self.driver_mode,
            generator: self.generator,
            engine: self.engine,
            input_ownership: PhantomData,
        }
    }
}

impl<G, E> TestTarget<G, E, BorrowedInput>
where
    G: generator::ValueGenerator,
{
    /// Iterate over all of the inputs and check the `TestTarget`
    pub fn for_each<F>(mut self, test: F) -> E::Output
    where
        E: Engine<bolero_engine::BorrowedGeneratorTest<F, G, G::Output>>,
        bolero_engine::BorrowedGeneratorTest<F, G, G::Output>: Test,
    {
        let test = bolero_engine::BorrowedGeneratorTest::new(test, self.generator);
        if let Some(mode) = self.driver_mode {
            self.engine.set_driver_mode(mode);
        }
        self.engine.run(test)
    }
}

impl<G, E> TestTarget<G, E, ClonedInput>
where
    G: generator::ValueGenerator,
{
    /// Iterate over all of the inputs and check the `TestTarget`
    pub fn for_each<F>(mut self, test: F) -> E::Output
    where
        E: Engine<bolero_engine::ClonedGeneratorTest<F, G, G::Output>>,
        bolero_engine::ClonedGeneratorTest<F, G, G::Output>: Test,
    {
        let test = bolero_engine::ClonedGeneratorTest::new(test, self.generator);
        if let Some(mode) = self.driver_mode {
            self.engine.set_driver_mode(mode);
        }
        self.engine.run(test)
    }
}

impl<E> TestTarget<ByteSliceGenerator, E, BorrowedInput> {
    /// Iterate over all of the inputs and check the `TestTarget`
    pub fn for_each<T>(mut self, test: T) -> E::Output
    where
        E: Engine<bolero_engine::BorrowedSliceTest<T>>,
        bolero_engine::BorrowedSliceTest<T>: Test,
    {
        let test = bolero_engine::BorrowedSliceTest::new(test);
        if let Some(mode) = self.driver_mode {
            self.engine.set_driver_mode(mode);
        }
        self.engine.run(test)
    }
}

impl<E> TestTarget<ByteSliceGenerator, E, ClonedInput> {
    /// Iterate over all of the inputs and check the `TestTarget`
    pub fn for_each<T>(mut self, test: T) -> E::Output
    where
        E: Engine<bolero_engine::ClonedSliceTest<T>>,
        bolero_engine::ClonedSliceTest<T>: Test,
    {
        let test = bolero_engine::ClonedSliceTest::new(test);
        if let Some(mode) = self.driver_mode {
            self.engine.set_driver_mode(mode);
        }
        self.engine.run(test)
    }
}

#[test]
#[should_panic]
fn slice_generator_test() {
    fuzz!().for_each(|input| {
        assert!(input.len() > 1000);
    });
}

#[test]
#[should_panic]
fn type_generator_test() {
    fuzz!().with_type().for_each(|input: &u8| {
        assert!(input < &128);
    });
}

#[test]
#[should_panic]
fn type_generator_cloned_test() {
    fuzz!().with_type().cloned().for_each(|input: u8| {
        assert!(input < 128);
    });
}

#[test]
fn range_generator_test() {
    fuzz!().with_generator(0..=5).for_each(|_input: &u8| {
        // println!("{:?}", input);
    });
}

#[test]
fn range_generator_cloned_test() {
    fuzz!()
        .with_generator(0..=5)
        .cloned()
        .for_each(|_input: u8| {
            // println!("{:?}", input);
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_test() {
        fuzz!().with_generator(0..=5).for_each(|_input: &u8| {
            // println!("{:?}", input);
        });
    }
}
