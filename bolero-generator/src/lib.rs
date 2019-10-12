#![no_std]

extern crate alloc;

use core::marker::PhantomData;

pub use either;

#[cfg(test)]
macro_rules! generator_test {
    ($gen:expr) => {{
        use $crate::*;
        let mut generator = $gen;
        ValueGenerator::generate(&mut generator, &mut FuzzRng::new(&[]))
    }};
}

pub mod bool;
pub mod bounded;
pub mod combinator;
pub mod num;
pub mod range;
pub mod result;
pub mod rng;
pub mod string;
pub mod tuple;
pub mod vec;

pub use crate::bool::*;
pub use bounded::*;
pub use combinator::*;
pub use num::*;
pub use range::*;
pub use result::*;
pub use rng::*;
pub use string::*;
pub use tuple::*;
pub use vec::*;

pub trait TypeGenerator: Sized {
    fn generate<R: Rng>(rng: &mut R) -> Self;

    #[inline]
    fn gen() -> TypedGen<Self> {
        gen()
    }
}

pub trait ValueGenerator: Sized {
    type Output;
    fn generate<R: Rng>(&mut self, rng: &mut R) -> Self::Output;

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

#[derive(Clone, Debug, Default)]
pub struct TypedGen<T: TypeGenerator>(PhantomData<T>);

impl<T: TypeGenerator> ValueGenerator for TypedGen<T> {
    type Output = T;

    fn generate<R: Rng>(&mut self, rng: &mut R) -> Self::Output {
        T::generate(rng)
    }
}

#[inline]
pub fn gen<T: TypeGenerator>() -> TypedGen<T> {
    TypedGen(PhantomData)
}

impl TypeGenerator for () {
    fn generate<R: Rng>(_rng: &mut R) -> Self {}
}

impl ValueGenerator for () {
    type Output = ();

    fn generate<R: Rng>(&mut self, _rng: &mut R) -> Self {}
}

pub struct Constant<T: Clone> {
    value: T,
}

impl<T: Clone> ValueGenerator for Constant<T> {
    type Output = T;

    fn generate<R: Rng>(&mut self, _rng: &mut R) -> Self::Output {
        self.value.clone()
    }
}

#[inline]
pub fn constant<T: Clone>(value: T) -> Constant<T> {
    Constant { value }
}
