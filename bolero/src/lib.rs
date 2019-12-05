mod fuzz;
mod test;

#[doc(hidden)]
#[cfg(fuzzing)]
use fuzz::exec;

#[doc(hidden)]
#[cfg(not(fuzzing))]
#[allow(unused_imports)]
use test::exec;

/// Re-export of `bolero_generator`
pub mod generator {
    pub use bolero_generator::{self, prelude::*};
}

use bolero_generator::{
    combinator::{AndThenGenerator, FilterGenerator, FilterMapGenerator, MapGenerator},
    TypeValueGenerator,
};

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
        $crate::fuzz(env!("CARGO_MANIFEST_DIR"), file!())
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
    manifest_dir: &'static str,
    file: &'static str,
    generator: G,
}

/// Create a fuzz target for a given file
pub fn fuzz(manifest_dir: &'static str, file: &'static str) -> FuzzTarget<SliceGenerator> {
    FuzzTarget::new(manifest_dir, file)
}

/// Default generator for byte slices
pub struct SliceGenerator;

impl FuzzTarget<SliceGenerator> {
    /// Create a `FuzzTarget` for a given file
    pub fn new(manifest_dir: &'static str, file: &'static str) -> FuzzTarget<SliceGenerator> {
        Self {
            manifest_dir,
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
            manifest_dir: self.manifest_dir,
            file: self.file,
            generator,
        }
    }

    /// Set the type generator for the `FuzzTarget`
    pub fn with_type<T: generator::TypeGenerator>(self) -> FuzzTarget<TypeValueGenerator<T>> {
        FuzzTarget {
            manifest_dir: self.manifest_dir,
            file: self.file,
            generator: generator::gen(),
        }
    }
}

impl<G: generator::ValueGenerator> FuzzTarget<G> {
    /// Map the value of the generator
    pub fn map<F: Fn(G::Output) -> T, T>(self, map: F) -> FuzzTarget<MapGenerator<G, F>> {
        FuzzTarget {
            manifest_dir: self.manifest_dir,
            file: self.file,
            generator: self.generator.map(map),
        }
    }

    /// Map the value of the generator with a new generator
    pub fn and_then<F: Fn(G::Output) -> T, T: generator::ValueGenerator>(
        self,
        map: F,
    ) -> FuzzTarget<AndThenGenerator<G, F>> {
        FuzzTarget {
            manifest_dir: self.manifest_dir,
            file: self.file,
            generator: self.generator.and_then(map),
        }
    }

    /// Filter the value of the generator
    pub fn filter<F: Fn(&G::Output) -> bool>(self, filter: F) -> FuzzTarget<FilterGenerator<G, F>> {
        FuzzTarget {
            manifest_dir: self.manifest_dir,
            file: self.file,
            generator: self.generator.filter(filter),
        }
    }

    /// Filter the value of the generator and map it to something else
    pub fn filter_map<F: Fn(G::Output) -> Option<T>, T>(
        self,
        filter_map: F,
    ) -> FuzzTarget<FilterMapGenerator<G, F>> {
        FuzzTarget {
            manifest_dir: self.manifest_dir,
            file: self.file,
            generator: self.generator.filter_map(filter_map),
        }
    }
}

#[cfg(not(test))]
impl<G: std::panic::RefUnwindSafe + generator::ValueGenerator> FuzzTarget<G> {
    /// Iterate over all of the inputs and check the `FuzzTarget`
    pub fn for_each<F: std::panic::RefUnwindSafe + FnMut(G::Output)>(self, mut check: F) -> ! {
        use bolero_generator::driver::FuzzDriver;

        unsafe {
            exec(self.manifest_dir, self.file, &mut move |input, mode| {
                if let Some(value) = self.generator.generate(&mut FuzzDriver::new(input, mode)) {
                    check(value);
                    true
                } else {
                    false
                }
            });
        }
    }
}

#[cfg(test)]
impl<G: std::panic::RefUnwindSafe + generator::ValueGenerator> FuzzTarget<G> {
    /// Iterate over all of the inputs and check the `FuzzTarget`
    pub fn for_each<F: std::panic::RefUnwindSafe + FnMut(G::Output)>(self, mut check: F) {
        for _ in 0u8..100 {
            if let Some(value) = self.generator.generate(&mut rand::thread_rng()) {
                check(value);
            }
        }
    }
}

#[cfg(not(test))]
impl FuzzTarget<SliceGenerator> {
    /// Iterate over all of the inputs and check the `FuzzTarget`
    pub fn for_each<F: std::panic::RefUnwindSafe + FnMut(&[u8])>(self, mut check: F) -> ! {
        unsafe {
            exec(self.manifest_dir, self.file, &mut move |input, _mode| {
                check(input);
                true
            });
        }
    }
}

#[cfg(test)]
impl FuzzTarget<SliceGenerator> {
    /// Iterate over all of the inputs and check the `FuzzTarget`
    pub fn for_each<F: std::panic::RefUnwindSafe + FnMut(&[u8])>(self, mut check: F) {
        for i in 0u8..100 {
            let input = vec![i; i as usize];
            check(&input[..]);
        }
    }
}

#[test]
fn slice_generator_test() {
    fuzz!().for_each(|_input| {
        // println!("{:?}", input);
    });
}

#[test]
fn type_generator_test() {
    fuzz!().with_type().for_each(|_input: u8| {
        // println!("{:?}", input);
    });
}

#[test]
fn range_generator_test() {
    fuzz!().with_generator(0..=5).for_each(|_input: u8| {
        // println!("{:?}", input);
    });
}

mod derive_tests {
    use bolero_generator::TypeGenerator;

    #[derive(Debug, TypeGenerator)]
    pub struct Bar {
        foo: u32,
        bar: u64,
        baz: u8,
    }

    #[derive(Debug, TypeGenerator)]
    pub enum Operation {
        Insert {
            #[generator(1..3)]
            index: usize,
            value: u32,
        },
        Remove {
            #[generator(4..6)]
            index: usize,
        },
        Bar(Bar),
        // Foo(Foo),
        Other(#[generator(42..53)] usize),
        Clear,
    }

    #[derive(TypeGenerator)]
    pub union Foo {
        foo: u32,
        bar: u64,
        baz: u8,
    }

    #[test]
    fn operation_test() {
        fuzz!().with_type().for_each(|input: Vec<Operation>| {
            println!("{:?}", input);
        });
    }
}
