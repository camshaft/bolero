use crate::{
    uniform::{FillBytes, Uniform},
    TypeGenerator,
};
use core::ops::Bound;
use rand_core::RngCore;

#[macro_use]
mod macros;

mod bytes;
mod rng;

pub use bytes::ByteSliceDriver;
pub use rng::{DirectRng, ForcedRng};

macro_rules! gen_method {
    ($name:ident, $ty:ty) => {
        fn $name(&mut self, min: Bound<&$ty>, max: Bound<&$ty>) -> Option<$ty>;
    };
}

/// Trait for driving the generation of a value
///
/// In a test engine, this is typically backed by
/// a byte slice, but other drivers can be used instead, e.g.
/// an RNG implementation.
pub trait Driver: Sized {
    /// Generate a value with type `T`
    fn gen<T: TypeGenerator>(&mut self) -> Option<T> {
        T::generate(self)
    }

    gen_method!(gen_u8, u8);
    gen_method!(gen_i8, i8);
    gen_method!(gen_u16, u16);
    gen_method!(gen_i16, i16);
    gen_method!(gen_u32, u32);
    gen_method!(gen_i32, i32);
    gen_method!(gen_u64, u64);
    gen_method!(gen_i64, i64);
    gen_method!(gen_u128, u128);
    gen_method!(gen_i128, i128);
    gen_method!(gen_usize, usize);
    gen_method!(gen_isize, isize);
    gen_method!(gen_f32, f32);
    gen_method!(gen_f64, f64);
    gen_method!(gen_char, char);

    fn gen_bool(&mut self, probability: Option<f32>) -> Option<bool>;
}

/// Byte exhaustion strategy for the driver
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum DriverMode {
    /// When the driver bytes are exhausted, the driver will fail fill input bytes.
    /// This is useful for fuzz engines that want accurate mapping of inputs to coverage.
    Direct,

    /// When the driver bytes are exhausted, the driver will continue to fill input bytes with 0.
    /// This is useful for engines that want to maximize the amount of time spent executing tests.
    Forced,
}
