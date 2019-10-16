use crate::{
    bounded::{BoundedGenerator, BoundedValue},
    Rng, TypeGenerator, TypeGeneratorWithParams, TypeValueGenerator, ValueGenerator,
};
use byteorder::{ByteOrder, NativeEndian};
use core::{mem::size_of, ops::Bound};

macro_rules! impl_bounded_integer {
    ($ty:ident) => {
        impl BoundedValue for $ty {
            fn bounded(self, start: Bound<Self>, end: Bound<Self>) -> Self {
                use Bound::*;

                let start = match start {
                    Included(value) => value,
                    Excluded(value) => value.saturating_add(1),
                    Unbounded => core::$ty::MIN,
                };

                let end = match end {
                    Included(value) => value,
                    Excluded(value) => value.saturating_sub(1),
                    Unbounded => core::$ty::MAX,
                };

                let (lower, upper) = if start < end {
                    (start, end)
                } else {
                    (end, start)
                };

                let range = upper - lower;

                (self % range) + lower
            }
        }

        impl TypeGeneratorWithParams for $ty {
            type Output = BoundedGenerator<TypeValueGenerator<$ty>, $ty>;

            fn gen_with() -> Self::Output {
                BoundedGenerator::new(Default::default(), $ty::default()..)
            }
        }
    };
}

macro_rules! impl_byte {
    ($name:ident, $ty:ident) => {
        impl TypeGenerator for $ty {
            fn generate<R: Rng>(rng: &mut R) -> Self {
                let mut bytes = [0; size_of::<$ty>()];
                Rng::fill_bytes(rng, &mut bytes);
                bytes[0] as $ty
            }
        }

        impl ValueGenerator for $ty {
            type Output = $ty;

            fn generate<R: Rng>(&self, _rng: &mut R) -> Self {
                *self
            }
        }

        impl_bounded_integer!($ty);
    };
}

impl_byte!(gen_u8, u8);
impl_byte!(gen_i8, i8);

macro_rules! impl_integer {
    ($name:ident, $ty:ident, $call:ident) => {
        impl TypeGenerator for $ty {
            fn generate<R: Rng>(rng: &mut R) -> Self {
                let mut bytes = [0; size_of::<$ty>()];
                Rng::fill_bytes(rng, &mut bytes);
                NativeEndian::$call(&bytes)
            }
        }

        impl ValueGenerator for $ty {
            type Output = $ty;

            fn generate<R: Rng>(&self, _rng: &mut R) -> Self {
                *self
            }
        }

        impl_bounded_integer!($ty);
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

macro_rules! impl_native_integer {
    ($name:ident, $ty:ident) => {
        impl TypeGenerator for $ty {
            fn generate<R: Rng>(rng: &mut R) -> Self {
                let mut bytes = [0; size_of::<$ty>()];
                Rng::fill_bytes(rng, &mut bytes);
                NativeEndian::read_uint(&bytes, bytes.len()) as $ty
            }
        }

        impl ValueGenerator for $ty {
            type Output = $ty;

            fn generate<R: Rng>(&self, _rng: &mut R) -> Self {
                *self
            }
        }

        impl_bounded_integer!($ty);
    };
}

impl_native_integer!(gen_usize, usize);
impl_native_integer!(gen_isize, isize);

macro_rules! impl_float {
    ($name:ident, $ty:ident, $call:ident) => {
        impl TypeGenerator for $ty {
            fn generate<R: Rng>(rng: &mut R) -> Self {
                let mut bytes = [0; size_of::<$ty>()];
                Rng::fill_bytes(rng, &mut bytes);
                NativeEndian::$call(&bytes)
            }
        }

        impl ValueGenerator for $ty {
            type Output = $ty;

            fn generate<R: Rng>(&self, _rng: &mut R) -> Self {
                *self
            }
        }

        // TODO impl_bounded
    };
}

impl_float!(gen_f32, f32, read_f32);
impl_float!(gen_f64, f64, read_f64);
