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

#[cfg(any(test, feature = "std", feature = "arbitrary"))]
extern crate std;

#[cfg(any(test, feature = "std"))]
#[path = "std/mod.rs"]
pub mod std_generators;

pub use bolero_generator_derive::*;
#[cfg(feature = "arbitrary")]
pub mod arbitrary;

#[cfg(feature = "any")]
pub mod any;
pub mod array;
pub mod atomic;
pub mod bool;
pub mod bounded;
pub mod char;
pub mod combinator;
pub mod driver;
#[cfg(any(test, kani))]
pub mod kani;
pub mod num;
pub mod one_of;
pub mod prelude;
pub mod range;
pub mod result;
pub mod time;
#[cfg(feature = "std")]
pub mod trace;
pub mod tuple;

#[cfg(feature = "arbitrary")]
pub use crate::arbitrary::gen_arbitrary;

pub use crate::driver::Driver;

/// Generate a value for a given type
pub trait TypeGenerator: 'static + Sized {
    /// Generates a value with the given driver
    fn generate<D: Driver>(driver: &mut D) -> Option<Self>;

    /// Mutates an existing value with the given driver
    #[inline]
    fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
        match Self::generate(driver) {
            Some(next) => {
                let prev = core::mem::replace(self, next);
                Self::driver_cache(prev, driver);
                Some(())
            }
            None => None,
        }
    }

    #[inline(always)]
    fn driver_cache<D: Driver>(self, driver: &mut D) {
        let _ = driver;
    }

    /// Returns a generator for a given type
    #[inline]
    fn produce() -> TypeValueGenerator<Self> {
        produce()
    }

    #[deprecated = "Use `produce` instead (`gen` conflicts with edition2024)"]
    #[inline]
    fn gen() -> TypeValueGenerator<Self> {
        produce()
    }
}

/// Generate a value with a parameterized generator
pub trait ValueGenerator: Sized {
    type Output: 'static;

    /// Generates a value with the given driver
    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output>;

    /// Mutates an existing value with the given driver
    #[inline]
    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        match self.generate(driver) {
            Some(next) => {
                let prev = core::mem::replace(value, next);
                self.driver_cache(driver, prev);
                Some(())
            }
            None => None,
        }
    }

    #[inline(always)]
    fn driver_cache<D: Driver>(&self, driver: &mut D, value: Self::Output) {
        let _ = driver;
        let _ = value;
    }

    /// Map the value of a generator
    fn map_gen<F: Fn(Self::Output) -> T, T>(self, map: F) -> MapGenerator<Self, F> {
        MapGenerator {
            generator: self,
            map,
        }
    }

    /// Map the value of a generator with a new generator
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
    fn filter_gen<F: Fn(&Self::Output) -> bool>(self, filter: F) -> FilterGenerator<Self, F> {
        FilterGenerator {
            generator: self,
            filter,
        }
    }

    /// Filter the value of a generator and map it to something else
    fn filter_map_gen<F: Fn(Self::Output) -> Option<T>, T>(
        self,
        filter_map: F,
    ) -> FilterMapGenerator<Self, F> {
        FilterMapGenerator {
            generator: self,
            filter_map,
        }
    }

    /// Traces generated values to `stderr`
    #[cfg(feature = "std")]
    #[inline]
    fn trace(self) -> trace::Trace<Self> {
        trace::Trace::new(self)
    }
}

impl<T: ValueGenerator> ValueGenerator for &T {
    type Output = T::Output;

    #[inline]
    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        (*self).generate(driver)
    }

    #[inline]
    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        (*self).mutate(driver, value)
    }

    #[inline]
    fn driver_cache<D: Driver>(&self, driver: &mut D, value: Self::Output) {
        (*self).driver_cache(driver, value)
    }
}

/// Convert a type generator into the default value generator
pub trait TypeGeneratorWithParams {
    type Output: ValueGenerator;

    fn gen_with() -> Self::Output;
}

/// Non-parameterized ValueGenerator given a TypeGenerator
#[derive(Debug)]
pub struct TypeValueGenerator<T: TypeGenerator>(PhantomData<T>);

// this needs to be implemented manually so it doesn't force `T: Copy`
impl<T: TypeGenerator> Copy for TypeValueGenerator<T> {}

impl<T: TypeGenerator> Clone for TypeValueGenerator<T> {
    fn clone(&self) -> Self {
        *self
    }
}

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

    #[inline(always)]
    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        T::generate(driver)
    }

    #[inline(always)]
    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut T) -> Option<()> {
        T::mutate(value, driver)
    }

    #[inline(always)]
    fn driver_cache<D: Driver>(&self, driver: &mut D, value: T) {
        T::driver_cache(value, driver)
    }
}

/// Generate a value for a given type
#[inline]
pub fn produce<T: TypeGenerator>() -> TypeValueGenerator<T> {
    TypeValueGenerator(PhantomData)
}

/// Generate a value for a given type
#[deprecated = "Use `produce` instead (`gen` conflicts with edition2024)"]
#[inline]
pub fn gen<T: TypeGenerator>() -> TypeValueGenerator<T> {
    TypeValueGenerator(PhantomData)
}

/// Generate a value for a given type with additional constraints
#[inline]
pub fn produce_with<T: TypeGeneratorWithParams>() -> T::Output {
    T::gen_with()
}

/// Generate a value for a given type
#[deprecated = "Use `produce_with` instead (`gen_with` conflicts with edition2024)"]
#[inline]
pub fn gen_with<T: TypeGeneratorWithParams>() -> T::Output {
    produce_with::<T>()
}

pub use one_of::{one_of, one_value_of};

impl<T: 'static> ValueGenerator for PhantomData<T> {
    type Output = Self;

    fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self::Output> {
        Some(PhantomData)
    }
}

impl<T: 'static> TypeGenerator for PhantomData<T> {
    fn generate<D: Driver>(_driver: &mut D) -> Option<Self> {
        Some(PhantomData)
    }
}

pub struct Constant<T> {
    value: T,
}

impl<T: 'static + Clone> ValueGenerator for Constant<T> {
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
