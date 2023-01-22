#![cfg_attr(not(any(test, feature = "std")), no_std)]

use crate::combinator::{AndThenGenerator, FilterGenerator, FilterMapGenerator, MapGenerator};
use core::marker::PhantomData;

#[cfg(test)]
#[macro_use]
mod testing;

mod uniform;

#[cfg(feature = "either")]
pub use either;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
#[path = "alloc/mod.rs"]
#[macro_use]
pub mod alloc_generators;

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(any(test, feature = "std"))]
#[path = "std/mod.rs"]
pub mod std_generators;

pub use bolero_generator_derive::*;
#[cfg(feature = "arbitrary")]
pub mod arbitrary;

pub mod array;
pub mod atomic;
pub mod bool;
pub mod bounded;
pub mod char;
pub mod combinator;
pub mod driver;
pub mod num;
pub mod one_of;
pub mod range;
pub mod result;
pub mod time;
pub mod tuple;

#[cfg(feature = "arbitrary")]
pub use crate::arbitrary::gen_arbitrary;

pub use crate::driver::Driver;

/// Generate a value for a given type
pub trait TypeGenerator: Sized {
    /// Generates a value with the given driver
    fn generate<D: Driver>(driver: &mut D) -> Option<Self>;

    /// Mutates an existing value with the given driver
    fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
        *self = Self::generate(driver)?;
        Some(())
    }

    /// Returns a generator for a given type
    #[inline]
    fn gen() -> TypeValueGenerator<Self> {
        gen()
    }
}

/// Generate a value with a parameterized generator
pub trait ValueGenerator: Sized {
    type Output;

    /// Generates a value with the given driver
    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output>;

    /// Mutates an existing value with the given driver
    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        *value = self.generate(driver)?;
        Some(())
    }

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

impl<'a, T: ValueGenerator> ValueGenerator for &'a T {
    type Output = T::Output;

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        (*self).generate(driver)
    }

    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        (*self).mutate(driver, value)
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

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        T::generate(driver)
    }

    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut T) -> Option<()> {
        T::mutate(value, driver)
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

pub use one_of::{one_of, one_value_of};

impl<T> ValueGenerator for PhantomData<T> {
    type Output = Self;

    fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self::Output> {
        Some(PhantomData)
    }
}

impl<T> TypeGenerator for PhantomData<T> {
    fn generate<D: Driver>(_driver: &mut D) -> Option<Self> {
        Some(PhantomData)
    }
}

pub struct Constant<T> {
    value: T,
}

impl<T: Clone> ValueGenerator for Constant<T> {
    type Output = T;

    fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self::Output> {
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
        constant, gen, gen_with,
        one_of::{one_of, one_value_of, OneOfExt, OneValueOfExt},
        TypeGenerator, TypeGeneratorWithParams, ValueGenerator,
    };

    #[cfg(feature = "arbitrary")]
    pub use crate::gen_arbitrary;
}
