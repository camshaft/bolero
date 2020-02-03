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
    } else if #[cfg(test)] {
        mod test;

        // when testing bolero always use the RngEngine
        pub use bolero_engine::rng::RngEngine as DefaultEngine;
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
pub use bolero_engine::TargetLocation;

pub use bolero_engine::{rng::RngEngine, Driver, DriverMode, Engine, Test};

use bolero_generator::{
    combinator::{AndThenGenerator, FilterGenerator, FilterMapGenerator, MapGenerator},
    TypeValueGenerator,
};
use core::fmt::Debug;

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
/// ```rust
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
/// ```rust
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
/// ```rust
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
/// ```rust
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
    ($($tt:tt)*) => {
        $crate::__bolero_parse_input!(fuzz; $($tt)*)
    };
}

/// Execute property checks for a given target
///
/// # Examples
///
/// By default, `input` is a `&[u8]`.
///
/// This mode is generally used when testing an implementation that
/// handles raw bytes, e.g. a parser.
///
/// ```rust
/// #[test]
/// fn bytes_test() {
///     bolero::check!().for_each(|input| {
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
/// ```rust
/// #[test]
/// fn type_generator_test() {
///     bolero::check!()
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
/// ```rust
/// #[test]
/// fn value_generator_test() {
///     bolero::check!()
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
/// ```rust
/// #[test]
/// fn compatibility_test() {
///     bolero::check!(|input| {
///         // implement checks here
///     });
/// }
/// ```

#[macro_export]
macro_rules! check {
    ($($tt:tt)*) => {
        $crate::__bolero_parse_input!(check; $($tt)*)
    };
}

/// Configuration for a test target
pub struct TestTarget<Generator, Engine> {
    generator: Generator,
    driver_mode: Option<DriverMode>,
    engine: Engine,
}

#[doc(hidden)]
pub fn fuzz(location: TargetLocation) -> TestTarget<ByteSliceGenerator, DefaultEngine> {
    // cargo-bolero needs to resolve the path of the binary
    if std::env::var("CARGO_BOLERO_PATH").is_ok() {
        print!("{}", std::env::args().next().unwrap());
        std::process::exit(0);
    }

    TestTarget::new(DefaultEngine::new(location))
}

#[doc(hidden)]
pub fn check(location: TargetLocation) -> TestTarget<ByteSliceGenerator, RngEngine> {
    TestTarget::new(RngEngine::new(location))
}

/// Default generator for byte slices
#[derive(Copy, Clone, Default, PartialEq)]
pub struct ByteSliceGenerator;

impl<Engine> TestTarget<ByteSliceGenerator, Engine> {
    /// Create a `TestTarget` with the given `Engine`
    pub fn new(engine: Engine) -> TestTarget<ByteSliceGenerator, Engine> {
        Self {
            driver_mode: None,
            generator: ByteSliceGenerator,
            engine,
        }
    }
}

impl<G, Engine> TestTarget<G, Engine> {
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
    ) -> TestTarget<Generator, Engine>
    where
        Generator::Output: Debug,
    {
        TestTarget {
            driver_mode: self.driver_mode,
            generator,
            engine: self.engine,
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
    ) -> TestTarget<TypeValueGenerator<T>, Engine> {
        TestTarget {
            driver_mode: self.driver_mode,
            generator: generator::gen(),
            engine: self.engine,
        }
    }
}

impl<G: generator::ValueGenerator, Engine> TestTarget<G, Engine> {
    /// Map the value of the generator
    pub fn map<F: Fn(G::Output) -> T, T: Debug>(
        self,
        map: F,
    ) -> TestTarget<MapGenerator<G, F>, Engine> {
        TestTarget {
            driver_mode: self.driver_mode,
            generator: self.generator.map(map),
            engine: self.engine,
        }
    }

    /// Map the value of the generator with a new generator
    pub fn and_then<F: Fn(G::Output) -> T, T: generator::ValueGenerator>(
        self,
        map: F,
    ) -> TestTarget<AndThenGenerator<G, F>, Engine>
    where
        T::Output: Debug,
    {
        TestTarget {
            driver_mode: self.driver_mode,
            generator: self.generator.and_then(map),
            engine: self.engine,
        }
    }

    /// Filter the value of the generator
    pub fn filter<F: Fn(&G::Output) -> bool>(
        self,
        filter: F,
    ) -> TestTarget<FilterGenerator<G, F>, Engine> {
        TestTarget {
            driver_mode: self.driver_mode,
            generator: self.generator.filter(filter),
            engine: self.engine,
        }
    }

    /// Filter the value of the generator and map it to something else
    pub fn filter_map<F: Fn(G::Output) -> Option<T>, T>(
        self,
        filter_map: F,
    ) -> TestTarget<FilterMapGenerator<G, F>, Engine> {
        TestTarget {
            driver_mode: self.driver_mode,
            generator: self.generator.filter_map(filter_map),
            engine: self.engine,
        }
    }

    /// Set the driver mode for the fuzz target
    pub fn with_driver_mode(self, mode: DriverMode) -> Self {
        TestTarget {
            driver_mode: Some(mode),
            generator: self.generator,
            engine: self.engine,
        }
    }
}

impl<G> TestTarget<G, RngEngine> {
    /// Set the number of iterations executed
    pub fn with_iterations(mut self, iterations: usize) -> Self {
        self.engine.iterations = iterations;
        TestTarget {
            driver_mode: self.driver_mode,
            generator: self.generator,
            engine: self.engine,
        }
    }

    /// Set the maximum length of the generated bytes
    pub fn with_max_len(mut self, max_len: usize) -> Self {
        self.engine.max_len = max_len;
        TestTarget {
            driver_mode: self.driver_mode,
            generator: self.generator,
            engine: self.engine,
        }
    }
}

impl<G, E> TestTarget<G, E>
where
    G: generator::ValueGenerator,
{
    /// Iterate over all of the inputs and check the `TestTarget`
    pub fn for_each<F>(mut self, test: F) -> E::Output
    where
        E: Engine<bolero_engine::GeneratorTest<F, G>>,
        bolero_engine::GeneratorTest<F, G>: Test,
    {
        let test = bolero_engine::GeneratorTest::new(test, self.generator);
        if let Some(mode) = self.driver_mode {
            self.engine.set_driver_mode(mode);
        }
        self.engine.run(test)
    }
}

impl<E> TestTarget<ByteSliceGenerator, E> {
    /// Iterate over all of the inputs and check the `TestTarget`
    pub fn for_each<T, Ret>(mut self, test: T) -> E::Output
    where
        E: Engine<T>,
        T: Test + FnMut(&[u8]) -> Ret,
    {
        if let Some(mode) = self.driver_mode {
            self.engine.set_driver_mode(mode);
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
    check!().with_type().for_each(|input: u8| {
        assert!(input < 128);
    });
}

#[test]
fn range_generator_test() {
    check!().with_generator(0..=5).for_each(|_input: u8| {
        // println!("{:?}", input);
    });
}

#[doc(hidden)]
#[macro_export]
macro_rules! __bolero_parse_input {
    ($target:ident;) => {
        $crate::$target($crate::TargetLocation {
            manifest_dir: env!("CARGO_MANIFEST_DIR"),
            module_path: module_path!(),
            file: file!(),
            line: line!(),
        })
    };
    ($target:ident; for $value:pat in gen() { $($tt:tt)* }) => {
        $crate::$target!(for $value in ($crate::generator::gen()) { $($tt)* })
    };
    ($target:ident; for $value:pat in all() { $($tt:tt)* }) => {
        $crate::$target!(for $value in ($crate::generator::gen()) { $($tt)* })
    };
    ($target:ident; for $value:pat in all($gen:expr) { $($tt:tt)* }) => {
        $crate::$target!(for $value in ($gen) { $($tt)* })
    };
    ($target:ident; for $value:pat in each($gen:expr) { $($tt:tt)* }) => {
        $crate::$target!(for $value in ($gen) { $($tt)* })
    };
    ($target:ident; for $value:pat in $gen:path { $($tt:tt)* }) => {
        $crate::$target!(for $value in ($gen) { $($tt)* })
    };
    ($target:ident; for $value:pat in ($gen:expr) { $($tt:tt)* }) => {
        $crate::$target!()
            .with_generator({
                use $crate::generator::*;
                $gen
            })
            .for_each(|$value| {
                $($tt)*
            })
    };
    ($target:ident; $fun:path) => {
        $crate::$target!(|input| { $fun(input); })
    };
    ($target:ident; |$input:ident $(: &[u8])?| $impl:expr) => {
        $crate::$target!().for_each(|$input: &[u8]| {
            $impl;
        })
    };
    ($target:ident; |$input:ident: $ty:ty| $impl:expr) => {
        $crate::$target!().with_type().for_each(|$input: $ty| {
            $impl;
        })
    };
}
