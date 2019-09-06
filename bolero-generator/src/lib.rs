#![no_std]

use byteorder::{ByteOrder, NativeEndian};
use core::{marker::PhantomData, mem::size_of};
pub use rand_core::{Error as RngError, RngCore};

pub trait RngExt {
    fn gen<T: TypeGenerator>(&mut self) -> T;
}

impl<R: RngCore> RngExt for R {
    #[inline]
    fn gen<T: TypeGenerator>(&mut self) -> T {
        gen().generate(self)
    }
}

pub trait TypeGenerator: Sized {
    fn generate(rng: &mut dyn RngCore) -> Self;

    #[inline]
    fn gen() -> TypedGen<Self> {
        gen()
    }
}

pub trait ValueGenerator: Sized {
    type Output;
    fn generate(&mut self, rng: &mut dyn RngCore) -> Self::Output;

    fn map<F: Fn(Self::Output) -> T, T>(self, map: F) -> MapGenerator<Self, F> {
        MapGenerator {
            generator: self,
            map,
        }
    }

    fn and_then<F: Fn(Self::Output, &mut dyn RngCore) -> T, T: ValueGenerator>(
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

    fn generate(&mut self, rng: &mut dyn RngCore) -> Self::Output {
        T::generate(rng)
    }
}

#[inline]
pub fn gen<T: TypeGenerator>() -> TypedGen<T> {
    TypedGen(PhantomData)
}

#[derive(Clone, Debug)]
pub struct MapGenerator<Generator, Map> {
    generator: Generator,
    map: Map,
}

impl<G: ValueGenerator, M: Fn(G::Output) -> T, T> ValueGenerator for MapGenerator<G, M> {
    type Output = T;

    fn generate(&mut self, rng: &mut dyn RngCore) -> Self::Output {
        (self.map)(self.generator.generate(rng))
    }
}

#[derive(Clone, Debug)]
pub struct AndThenGenerator<Generator, AndThen> {
    generator: Generator,
    and_then: AndThen,
}

impl<G: ValueGenerator, M: Fn(G::Output, &mut dyn RngCore) -> T, T> ValueGenerator
    for AndThenGenerator<G, M>
{
    type Output = T;

    fn generate(&mut self, rng: &mut dyn RngCore) -> Self::Output {
        let value = self.generator.generate(rng);
        (self.and_then)(value, rng)
    }
}

macro_rules! impl_byte {
    ($name:ident, $ty:ident) => {
        pub fn $name() -> TypedGen<$ty> {
            gen::<$ty>()
        }

        impl TypeGenerator for $ty {
            fn generate(rng: &mut dyn RngCore) -> Self {
                let mut bytes = [0; size_of::<$ty>()];
                rng.fill_bytes(&mut bytes);
                bytes[0] as $ty
            }
        }
    };
}

impl_byte!(gen_u8, u8);
impl_byte!(gen_i8, i8);

macro_rules! impl_integer {
    ($name:ident, $ty:ident, $call:ident) => {
        pub fn $name() -> TypedGen<$ty> {
            gen::<$ty>()
        }

        impl TypeGenerator for $ty {
            fn generate(rng: &mut dyn RngCore) -> Self {
                let mut bytes = [0; size_of::<$ty>()];
                rng.fill_bytes(&mut bytes);
                NativeEndian::$call(&bytes)
            }
        }
    };
}

impl_integer!(gen_u16, u16, read_u16);
impl_integer!(gen_i16, i16, read_i16);
impl_integer!(gen_u32, u32, read_u32);
impl_integer!(gen_i32, i32, read_i32);
impl_integer!(gen_u64, u64, read_u64);
impl_integer!(gen_i64, i64, read_i64);
impl_integer!(gen_u128, u128, read_u128);
impl_integer!(gen_i128, i128, read_i128);
impl_integer!(gen_f32, f32, read_f32);
impl_integer!(gen_f64, f64, read_f64);

macro_rules! impl_native_integer {
    ($name:ident, $ty:ident) => {
        pub fn $name() -> TypedGen<$ty> {
            gen::<$ty>()
        }

        impl TypeGenerator for $ty {
            fn generate(rng: &mut dyn RngCore) -> Self {
                let mut bytes = [0; size_of::<$ty>()];
                rng.fill_bytes(&mut bytes);
                NativeEndian::read_uint(&bytes, bytes.len()) as $ty
            }
        }
    };
}
impl_native_integer!(gen_usize, usize);
impl_native_integer!(gen_isize, isize);

impl TypeGenerator for () {
    fn generate(_rng: &mut dyn RngCore) -> Self {}
}

macro_rules! impl_tuple {
    ([$($acc:ident($a_value:tt),)*]) => {
        // done
    };
    ($head:ident($h_value:tt), $($tail:ident($t_value:tt), )* [$($acc:ident($a_value:tt),)*]) => {
        impl<$head: TypeGenerator $(, $acc: TypeGenerator)*> TypeGenerator for ($($acc, )* $head ,) {
            fn generate(rng: &mut dyn RngCore) -> Self {
                ($(
                    $acc::generate(rng),
                )* $head::generate(rng), )
            }
        }

        impl<$head: ValueGenerator $(, $acc: ValueGenerator)*> ValueGenerator for ($($acc, )* $head ,) {
            type Output = ($head::Output, $( $acc::Output, )*);

            fn generate(&mut self, rng: &mut dyn RngCore) -> Self::Output {
                (self.$h_value.generate(rng), $(
                    self.$a_value.generate(rng),
                )*)
            }
        }

        impl_tuple!($($tail($t_value),)* [$($acc($a_value),)* $head($h_value),]);
    };
}

impl_tuple!(
    A(0),
    B(1),
    C(2),
    D(3),
    E(4),
    F(5),
    G(6),
    H(7),
    I(8),
    J(9),
    K(10),
    L(11),
    M(12),
    N(13),
    O(14),
    P(15),
    Q(16),
    R(17),
    S(18),
    T(19),
    U(20),
    V(21),
    W(22),
    X(23),
    Y(24),
    Z(25),
    []
);

pub struct Constant<T: Clone> {
    value: T,
}

impl<T: Clone> ValueGenerator for Constant<T> {
    type Output = T;

    fn generate(&mut self, _rng: &mut dyn RngCore) -> Self::Output {
        self.value.clone()
    }
}

#[inline]
pub fn constant<T: Clone>(value: T) -> Constant<T> {
    Constant { value }
}

#[derive(Debug)]
pub struct BooleanGenerator {
    weight: f32,
}

impl ValueGenerator for BooleanGenerator {
    type Output = bool;

    fn generate(&mut self, rng: &mut dyn RngCore) -> Self::Output {
        let value = rng.next_u32() as f32 / core::u32::MAX as f32;
        value > self.weight
    }
}

impl TypeGenerator for bool {
    fn generate(rng: &mut dyn RngCore) -> Self {
        gen_bool().generate(rng)
    }
}

pub fn gen_bool() -> BooleanGenerator {
    gen_bool_weighted(0.5)
}

pub fn gen_bool_weighted(weight: f32) -> BooleanGenerator {
    BooleanGenerator { weight }
}

pub struct FnGenerator<F, T> {
    generator: F,
    value: PhantomData<T>,
}

impl<F: Fn(&mut dyn RngCore) -> T, T> ValueGenerator for FnGenerator<F, T> {
    type Output = T;

    fn generate(&mut self, rng: &mut dyn RngCore) -> Self::Output {
        (self.generator)(rng)
    }
}

pub fn from_fn<F, T>(generator: F) -> FnGenerator<F, T>
where
    for<'r> F: Fn(&'r mut (dyn RngCore + 'r)) -> T,
{
    FnGenerator {
        generator,
        value: PhantomData,
    }
}

#[test]
fn map_test() {
    let gen = u16::gen().map(|v| v / 8).map(|v| v == 1);
}
