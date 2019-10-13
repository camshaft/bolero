#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

use crate::combinator::{AndThenGenerator, MapGenerator};
use core::marker::PhantomData;

#[cfg(feature = "either")]
pub use either;

#[cfg(test)]
macro_rules! generator_test {
    ($gen:expr) => {{
        use $crate::*;
        ValueGenerator::generate(&($gen), &mut $crate::rng::FuzzRng::new(&[]))
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

pub mod atomic;
pub mod bool;
pub mod bounded;
pub mod char;
pub mod combinator;
pub mod num;
pub mod range;
pub mod result;
pub mod rng;
pub mod time;
pub mod tuple;

pub use rng::Rng;

pub trait TypeGenerator: Sized {
    fn generate<R: Rng>(rng: &mut R) -> Self;

    #[inline]
    fn gen() -> TypeValueGenerator<Self> {
        gen()
    }
}

pub trait ValueGenerator: Sized {
    type Output;
    fn generate<R: Rng>(&self, rng: &mut R) -> Self::Output;

    fn map<F: Fn(Self::Output) -> T, T>(self, map: F) -> MapGenerator<Self, F> {
        MapGenerator {
            generator: self,
            map,
        }
    }

    fn and_then<F: Fn(Self::Output) -> T, T: ValueGenerator>(
        self,
        and_then: F,
    ) -> AndThenGenerator<Self, F> {
        AndThenGenerator {
            generator: self,
            and_then,
        }
    }
}

pub trait TypeGeneratorWithParams {
    type Output: ValueGenerator;

    fn gen_with() -> Self::Output;
}

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

    fn generate<R: Rng>(&self, rng: &mut R) -> Self::Output {
        T::generate(rng)
    }
}

impl<T> ValueGenerator for PhantomData<T> {
    type Output = Self;

    fn generate<R: Rng>(&self, _rng: &mut R) -> Self::Output {
        PhantomData
    }
}

impl<T> TypeGenerator for PhantomData<T> {
    fn generate<R: Rng>(_rng: &mut R) -> Self {
        PhantomData
    }
}

#[inline]
pub fn gen<T: TypeGenerator>() -> TypeValueGenerator<T> {
    TypeValueGenerator(PhantomData)
}

#[inline]
pub fn gen_with<T: TypeGeneratorWithParams>() -> T::Output {
    T::gen_with()
}

impl TypeGenerator for () {
    fn generate<R: Rng>(_rng: &mut R) -> Self {}
}

impl ValueGenerator for () {
    type Output = ();

    fn generate<R: Rng>(&self, _rng: &mut R) -> Self {}
}

pub struct Constant<T> {
    value: T,
}

impl<T: Clone> ValueGenerator for Constant<T> {
    type Output = T;

    fn generate<R: Rng>(&self, _rng: &mut R) -> Self::Output {
        self.value.clone()
    }
}

#[inline]
pub fn constant<T: Clone>(value: T) -> Constant<T> {
    Constant { value }
}
