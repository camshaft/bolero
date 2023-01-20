use bolero_generator::{
    combinator::{AndThenGenerator, FilterGenerator, FilterMapGenerator, MapGenerator},
    TypeValueGenerator,
};
use core::{fmt::Debug, marker::PhantomData, time::Duration};

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
    } else if #[cfg(kani)] {
        pub use bolero_kani::KaniEngine as DefaultEngine;
    } else {
        mod test;

        /// The default engine used when defining a test target
        pub use crate::test::TestEngine as DefaultEngine;
    }
}

/// Re-export of [`bolero_generator`]
pub mod generator {
    // TODO: remove the use of prelude::* for the next major release
    pub use bolero_generator::{self, prelude::*};
}

// For users' sake, re-expose the prelude functions straight under bolero::
pub use bolero_generator::prelude::*;

#[doc(hidden)]
pub use bolero_engine::{self, TargetLocation, __item_path__};

pub use bolero_engine::{Driver, DriverMode, Engine, Test};

/// Execute tests for a given target
///
/// This should be executed in a separate test target, for example
/// `tests/my_test_target/main.rs`.
///
/// # Examples
///
/// By default, `input` is a `&[u8]`.
///
/// This mode is generally used when testing an implementation that
/// handles raw bytes, e.g. a parser.
///
/// ```rust
/// use bolero::check;
///
/// check!().for_each(|input| {
///     // implement checks here
/// });
/// ```
///
/// Calling `with_type::<Type>()` will generate random values of `Type`
/// to be tested. `Type` is required to implement [`generator::TypeGenerator`]
/// in order to use this method.
///
/// This mode is used for testing an implementation that requires
/// structured input.
///
/// ```rust
/// use bolero::check;
///
/// check!()
///     .with_type::<(u8, u16)>()
///     .for_each(|(a, b)| {
///         // implement checks here
///     });
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
/// ```rust
/// use bolero::check;
///
/// check!()
///     .with_generator((0..100, 10..50))
///     .for_each(|(a, b)| {
///         // implement checks here
///     });
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
/// ```rust
/// use bolero::check;
///
/// check!(|input| {
///     // implement checks here
/// });
/// ```

#[macro_export]
macro_rules! check {
    () => {{
        let location = $crate::TargetLocation {
            package_name: env!("CARGO_PKG_NAME"),
            manifest_dir: env!("CARGO_MANIFEST_DIR"),
            module_path: module_path!(),
            file: file!(),
            line: line!(),
            item_path: $crate::__item_path__!(),
            test_name: None,
        };

        if !location.should_run() {
            return;
        }

        $crate::test(location)
    }};
    ($fun:path) => {
        $crate::check!(|input| { $fun(input) })
    };
    (| $input:ident $(: &[u8])? | $impl:expr) => {
        $crate::check!().for_each(|$input: &[u8]| $impl)
    };
    (| $input:ident : $ty:ty | $impl:expr) => {
        $crate::check!().with_type().for_each(|$input: $ty| $impl)
    };
    (name = $target_name:expr) => {{
        let location = $crate::TargetLocation {
            package_name: env!("CARGO_PKG_NAME"),
            manifest_dir: env!("CARGO_MANIFEST_DIR"),
            module_path: module_path!(),
            file: file!(),
            line: line!(),
            item_path: $crate::__item_path__!(),
            test_name: Some(format!("{}", $target_name)),
        };

        if !location.should_run() {
            return;
        }

        $crate::test(location)
    }};
}

#[macro_export]
#[deprecated = "`fuzz!` has been deprecated in favor of `check!`."]
macro_rules! fuzz {
    ($($arg:tt)*) => {
        $crate::check!($($arg)*)
    }
}

/// Configuration for a test target
pub struct TestTarget<Generator, Engine, InputOwnership> {
    generator: Generator,
    driver_mode: Option<DriverMode>,
    shrink_time: Option<Duration>,
    engine: Engine,
    input_ownership: PhantomData<InputOwnership>,
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BorrowedInput;

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClonedInput;

#[doc(hidden)]
pub fn test(
    location: TargetLocation,
) -> TestTarget<ByteSliceGenerator, DefaultEngine, BorrowedInput> {
    TestTarget::new(DefaultEngine::new(location))
}

/// Default generator for byte slices
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct ByteSliceGenerator;

impl<Engine> TestTarget<ByteSliceGenerator, Engine, BorrowedInput> {
    /// Create a `TestTarget` with the given `Engine`
    pub fn new(engine: Engine) -> TestTarget<ByteSliceGenerator, Engine, BorrowedInput> {
        Self {
            driver_mode: None,
            shrink_time: None,
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
            shrink_time: self.shrink_time,
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
            shrink_time: self.shrink_time,
            generator: generator::gen(),
            engine: self.engine,
            input_ownership: self.input_ownership,
        }
    }

    /// Set the amount of time that will be spent shrinking an input on failure
    ///
    /// Engines can optionally shrink inputs on failures to make it easier to debug
    /// and identify the failure. Increasing this time can potentially lead to smaller
    /// values.
    pub fn with_shrink_time(self, shrink_time: Duration) -> Self {
        Self {
            shrink_time: Some(shrink_time),
            ..self
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
            shrink_time: self.shrink_time,
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
            shrink_time: self.shrink_time,
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
            shrink_time: self.shrink_time,
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
            shrink_time: self.shrink_time,
            generator: self.generator.filter_map(filter_map),
            engine: self.engine,
            input_ownership: self.input_ownership,
        }
    }

    /// Set the driver mode for the test target
    pub fn with_driver_mode(self, mode: DriverMode) -> Self {
        TestTarget {
            driver_mode: Some(mode),
            shrink_time: self.shrink_time,
            generator: self.generator,
            engine: self.engine,
            input_ownership: self.input_ownership,
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(any(fuzzing, kani))] {
        impl<G, Engine, InputOwnership> TestTarget<G, Engine, InputOwnership> {
            /// Set the number of iterations executed
            pub fn with_iterations(self, iterations: usize) -> Self {
                let _ = iterations;
                self
            }

            /// Set the maximum length of the generated bytes
            pub fn with_max_len(self, max_len: usize) -> Self {
                let _ = max_len;
                self
            }
        }
    } else {
        impl<G, InputOwnership> TestTarget<G, bolero_engine::rng::RngEngine, InputOwnership> {
            /// Set the number of iterations executed
            pub fn with_iterations(mut self, iterations: usize) -> Self {
                self.engine.iterations = iterations;
                self
            }

            /// Set the maximum length of the generated bytes
            pub fn with_max_len(mut self, max_len: usize) -> Self {
                self.engine.max_len = max_len;
                self
            }
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
            shrink_time: self.shrink_time,
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
        if let Some(shrink_time) = self.shrink_time {
            self.engine.set_shrink_time(shrink_time);
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
        if let Some(shrink_time) = self.shrink_time {
            self.engine.set_shrink_time(shrink_time);
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
        if let Some(shrink_time) = self.shrink_time {
            self.engine.set_shrink_time(shrink_time);
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
        if let Some(shrink_time) = self.shrink_time {
            self.engine.set_shrink_time(shrink_time);
        }
        self.engine.run(test)
    }
}

#[test]
#[should_panic]
fn slice_generator_test() {
    check!().for_each(|input| {
        assert!(input.len() > 1000);
    });
}

#[test]
#[should_panic]
fn type_generator_test() {
    check!().with_type().for_each(|input: &u8| {
        assert!(input < &128);
    });
}

#[test]
#[should_panic]
fn type_generator_cloned_test() {
    check!().with_type().cloned().for_each(|input: u8| {
        assert!(input < 128);
    });
}

#[test]
fn range_generator_test() {
    check!().with_generator(0..=5).for_each(|_input: &u8| {
        // println!("{:?}", input);
    });
}

#[test]
fn range_generator_cloned_test() {
    check!()
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
        check!().with_generator(0..=5).for_each(|_input: &u8| {
            // println!("{:?}", input);
        });
    }
}
