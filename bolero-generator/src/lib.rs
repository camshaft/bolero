#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

use crate::combinator::{AndThenGenerator, FilterGenerator, FilterMapGenerator, MapGenerator};
use core::marker::PhantomData;

#[cfg(feature = "either")]
pub use either;

#[cfg(test)]
macro_rules! generator_test {
    ($gen:expr) => {{
        use $crate::*;
        let gen = $gen;
        let driver = &mut $crate::driver::DirectRng::new(rand::thread_rng());
        for _ in 0..1000 {
            ValueGenerator::generate(&gen, driver);
        }
        let driver = &mut rand::thread_rng();
        for _ in 0..1000 {
            ValueGenerator::generate(&gen, driver);
        }
        ValueGenerator::generate(&gen, driver)
    }};
}

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
#[path = "alloc/mod.rs"]
#[macro_use]
pub mod alloc_generators;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
#[path = "std/mod.rs"]
pub mod std_generators;

pub use bolero_generator_derive::*;

pub mod array;
pub mod atomic;
pub mod bool;
pub mod bounded;
pub mod char;
pub mod combinator;
pub mod driver;
pub mod num;
pub mod range;
pub mod result;
pub mod time;
pub mod tuple;

pub use driver::Driver;

/// Generate a value for a given type
pub trait TypeGenerator: Sized {
    fn generate<R: Driver>(driver: &mut R) -> Option<Self>;

    /// Returns a generator for a given type
    #[inline]
    fn gen() -> TypeValueGenerator<Self> {
        gen()
    }
}

/// Generate a value with a parameterized generator
pub trait ValueGenerator: Sized {
    type Output;
    fn generate<R: Driver>(&self, driver: &mut R) -> Option<Self::Output>;

    /// Map the value of a generator
    fn map<F: Fn(Self::Output) -> T, T>(self, map: F) -> MapGenerator<Self, F> {
        MapGenerator {
            generator: self,
            map,
        }
    }

    /// Map the value of a generator, exists to reduce conflicts with
    /// other `map` functions.
    fn map_gen<F: Fn(Self::Output) -> T, T>(self, map: F) -> MapGenerator<Self, F> {
        MapGenerator {
            generator: self,
            map,
        }
    }

    /// Map the value of a generator with a new generator
    fn and_then<F: Fn(Self::Output) -> T, T: ValueGenerator>(
        self,
        and_then: F,
    ) -> AndThenGenerator<Self, F> {
        AndThenGenerator {
            generator: self,
            and_then,
        }
    }

    /// Map the value of a generator with a new generator, exists to
    /// reduce conflicts with other `map` functions.
    fn and_then_gen<F: Fn(Self::Output) -> T, T: ValueGenerator>(
        self,
        and_then: F,
    ) -> AndThenGenerator<Self, F> {
        AndThenGenerator {
            generator: self,
            and_then,
        }
    }

    /// Filter the value of a generator
    fn filter<F: Fn(&Self::Output) -> bool>(self, filter: F) -> FilterGenerator<Self, F> {
        FilterGenerator {
            generator: self,
            filter,
        }
    }

    /// Filter the value of a generator, exists to
    /// reduce conflicts with other `filter` functions.
    fn filter_gen<F: Fn(&Self::Output) -> bool>(self, filter: F) -> FilterGenerator<Self, F> {
        FilterGenerator {
            generator: self,
            filter,
        }
    }

    /// Filter the value of a generator and map it to something else
    fn filter_map<F: Fn(Self::Output) -> Option<T>, T>(
        self,
        filter_map: F,
    ) -> FilterMapGenerator<Self, F> {
        FilterMapGenerator {
            generator: self,
            filter_map,
        }
    }

    /// Filter the value of a generator and map it to something else, exists to
    /// reduce conflicts with other `filter_map` functions.
    fn filter_map_gen<F: Fn(Self::Output) -> Option<T>, T>(
        self,
        filter_map: F,
    ) -> FilterMapGenerator<Self, F> {
        FilterMapGenerator {
            generator: self,
            filter_map,
        }
    }
}

/// Convert a type generator into the default value generator
pub trait TypeGeneratorWithParams {
    type Output: ValueGenerator;

    fn gen_with() -> Self::Output;
}

/// Non-parameterized ValueGenerator given a TypeGenerator
#[derive(Copy, Clone, Debug)]
pub struct TypeValueGenerator<T: TypeGenerator>(PhantomData<T>);

impl<T: TypeGenerator> Default for TypeValueGenerator<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T: TypeGenerator + TypeGeneratorWithParams> TypeValueGenerator<T> {
    pub fn with(self) -> <T as TypeGeneratorWithParams>::Output {
        T::gen_with()
    }
}

impl<T: TypeGenerator> ValueGenerator for TypeValueGenerator<T> {
    type Output = T;

    fn generate<R: Driver>(&self, driver: &mut R) -> Option<Self::Output> {
        T::generate(driver)
    }
}

/// Generate a value for a given type
#[inline]
pub fn gen<T: TypeGenerator>() -> TypeValueGenerator<T> {
    TypeValueGenerator(PhantomData)
}

/// Generate a value for a given type with additional constraints
#[inline]
pub fn gen_with<T: TypeGeneratorWithParams>() -> T::Output {
    T::gen_with()
}

impl<T> ValueGenerator for PhantomData<T> {
    type Output = Self;

    fn generate<R: Driver>(&self, _driver: &mut R) -> Option<Self::Output> {
        Some(PhantomData)
    }
}

impl<T> TypeGenerator for PhantomData<T> {
    fn generate<R: Driver>(_driver: &mut R) -> Option<Self> {
        Some(PhantomData)
    }
}

pub struct Constant<T> {
    value: T,
}

impl<T: Clone> ValueGenerator for Constant<T> {
    type Output = T;

    fn generate<R: Driver>(&self, _driver: &mut R) -> Option<Self::Output> {
        Some(self.value.clone())
    }
}

/// Always generate the same value
#[inline]
pub fn constant<T: Clone>(value: T) -> Constant<T> {
    Constant { value }
}

pub mod prelude {
    pub use crate::{
        constant, gen, gen_with, TypeGenerator, TypeGeneratorWithParams, ValueGenerator,
    };
}
