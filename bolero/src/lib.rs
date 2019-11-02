pub use bolero_generator as generator;

mod fuzz;
mod test;

#[doc(hidden)]
#[cfg(fuzzing)]
pub use fuzz::exec;

#[doc(hidden)]
#[cfg(not(fuzzing))]
pub use test::exec;

/// Execute fuzz tests
///
/// # Examples
///
/// ```rust
/// use bolero::fuzz;
///
/// fn main() {
///     fuzz!(|input| {
///         if input.len() < 3 {
///             return;
///         }
///
///         if input[0] == 0 && input[1] == 1 && input[2] == 2 {
///             panic!("you found me!");
///         }
///     });
/// }
/// ```
///
/// ```rust
/// use bolero::fuzz;
///
/// fn main() {
///     fuzz!().for_each(|input| {
///         if input.len() < 3 {
///             return;
///         }
///
///         if input[0] == 0 && input[1] == 1 && input[2] == 2 {
///             panic!("you found me!");
///         }
///     });
/// }
/// ```
///
/// ```rust
/// use bolero::fuzz;
///
/// fn main() {
///     fuzz!(for (a, b) in all((gen::<u8>(), gen::<u8>())) {
///         if a == 42 && b == 24 {
///             panic!("you found me!");
///         }
///     });
/// }
/// ```
///
/// ```rust
/// use bolero::fuzz;
///
/// fn main() {
///     fuzz!()
///         .with_generator((0..100, 10..50))
///         .for_each(|(a, b)| {
///             if a == 42 && b == 24 {
///                 panic!("you found me!");
///             }
///         });
/// }
/// ```
#[macro_export]
macro_rules! fuzz {
    () => {
        $crate::fuzz(file!())
    };
    (for $value:pat in gen() { $($tt:tt)* }) => {
        $crate::fuzz!(for $value in ($crate::generator::gen()) { $($tt)* });
    };
    (for $value:pat in all() { $($tt:tt)* }) => {
        $crate::fuzz!(for $value in ($crate::generator::gen()) { $($tt)* });
    };
    (for $value:pat in all($gen:expr) { $($tt:tt)* }) => {
        $crate::fuzz!(for $value in ($gen) { $($tt)* });
    };
    (for $value:pat in each($gen:expr) { $($tt:tt)* }) => {
        $crate::fuzz!(for $value in ($gen) { $($tt)* });
    };
    (for $value:pat in $gen:path { $($tt:tt)* }) => {
        $crate::fuzz!(for $value in ($gen) { $($tt)* });
    };
    (for $value:pat in ($gen:expr) { $($tt:tt)* }) => {
        $crate::fuzz!()
            .with_generator({
                use $crate::generator::*;
                $gen
            })
            .for_each(|$value| {
                $($tt)*
            });
    };
    ($fun:path) => {
        $crate::fuzz!(|input| { $fun(input); });
    };
    (|$input:ident $(: &[u8])?| $impl:expr) => {
        $crate::fuzz!().for_each(|$input: &[u8]| {
            $impl;
        });
    };
    (|$input:ident: $ty:ty| $impl:expr) => {
        $crate::fuzz!().with_type().for_each(|$input: $ty| {
            $impl;
        });
    };
}

/// Configuration for a fuzz target
pub struct FuzzTarget<G> {
    file: &'static str,
    generator: G,
}

/// Create a fuzz target for a given file
pub fn fuzz(file: &'static str) -> FuzzTarget<SliceGenerator> {
    FuzzTarget::new(file)
}

/// Default generator for byte slices
pub struct SliceGenerator;

impl FuzzTarget<SliceGenerator> {
    /// Create a `FuzzTarget` for a given file
    pub fn new(file: &'static str) -> FuzzTarget<SliceGenerator> {
        Self {
            file,
            generator: SliceGenerator,
        }
    }
}

impl<G> FuzzTarget<G> {
    /// Set the value generator for the `FuzzTarget`
    pub fn with_generator<NewG: generator::ValueGenerator>(
        self,
        generator: NewG,
    ) -> FuzzTarget<NewG> {
        FuzzTarget {
            file: self.file,
            generator,
        }
    }

    /// Set the type generator for the `FuzzTarget`
    pub fn with_type<T: generator::TypeGenerator>(
        self,
    ) -> FuzzTarget<generator::TypeValueGenerator<T>> {
        FuzzTarget {
            file: self.file,
            generator: generator::gen(),
        }
    }
}

impl<G: generator::ValueGenerator> FuzzTarget<G> {
    /// Map the value of the generator
    pub fn map<F: Fn(G::Output) -> T, T>(
        self,
        map: F,
    ) -> FuzzTarget<generator::combinator::MapGenerator<G, F>> {
        FuzzTarget {
            file: self.file,
            generator: self.generator.map(map),
        }
    }

    /// Map the value of the generator with a new generator
    pub fn and_then<F: Fn(G::Output) -> T, T: generator::ValueGenerator>(
        self,
        map: F,
    ) -> FuzzTarget<generator::combinator::AndThenGenerator<G, F>> {
        FuzzTarget {
            file: self.file,
            generator: self.generator.and_then(map),
        }
    }
}

impl<G: std::panic::RefUnwindSafe + generator::ValueGenerator> FuzzTarget<G> {
    /// Iterate over all of the inputs and check the `FuzzTarget`
    pub fn for_each<F: std::panic::RefUnwindSafe + FnMut(G::Output)>(self, mut check: F) -> ! {
        let generator = self.generator;
        unsafe {
            exec(self.file, &mut move |input| {
                check(generator::ValueGenerator::generate(
                    &generator,
                    &mut generator::rng::FuzzRng::new(input),
                ));
            });
        }
    }
}

impl FuzzTarget<SliceGenerator> {
    /// Iterate over all of the inputs and check the `FuzzTarget`
    pub fn for_each<F: std::panic::RefUnwindSafe + FnMut(&[u8])>(self, mut check: F) -> ! {
        unsafe {
            exec(self.file, &mut check);
        }
    }
}

#[test]
fn slice_generator_test() {
    fuzz!().for_each(|input| {
        println!("{:?}", input);
    });
}

#[test]
fn type_generator_test() {
    fuzz!().with_type().for_each(|input: u8| {
        println!("{:?}", input);
    });
}

#[test]
fn range_generator_test() {
    fuzz!().with_generator(0..=5).for_each(|input: u8| {
        println!("{:?}", input);
    });
}
