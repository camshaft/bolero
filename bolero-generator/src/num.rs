use crate::{gen, BoundedGenerator, BoundedValue, Rng, TypeGenerator, TypedGen, ValueGenerator};
use byteorder::{ByteOrder, NativeEndian};
use core::{
    cmp::{max, min},
    mem::size_of,
    ops::{Bound, RangeBounds},
};

macro_rules! impl_bounded_integer {
    ($ty:ident) => {
        impl BoundedValue for $ty {
            fn bounded(self, start: Bound<Self>, end: Bound<Self>) -> Self {
                use Bound::*;

                let start = match start {
                    Included(value) => value,
                    Excluded(value) => value.saturating_add(1),
                    Unbounded => 0,
                };
                let end = match end {
                    Included(value) => value,
                    Excluded(value) => value.saturating_sub(1),
                    Unbounded => core::$ty::MAX,
                };

                let lower = min(start, end);
                let upper = max(start, end);
                let range = upper - lower;

                (self % range) + lower
            }
        }
    };
}

macro_rules! impl_byte {
    ($name:ident, $bounded:ident, $ty:ident) => {
        pub fn $name() -> TypedGen<$ty> {
            gen::<$ty>()
        }

        pub fn $bounded<Bounds: RangeBounds<$ty>>(bound: Bounds) -> BoundedGenerator<$ty> {
            BoundedGenerator::new(bound)
        }

        impl TypeGenerator for $ty {
            fn generate<R: Rng>(rng: &mut R) -> Self {
                let mut bytes = [0; size_of::<$ty>()];
                rng.fill_bytes(&mut bytes);
                bytes[0] as $ty
            }
        }

        impl ValueGenerator for $ty {
            type Output = $ty;

            fn generate<R: Rng>(&mut self, _rng: &mut R) -> Self {
                *self
            }
        }

        impl_bounded_integer!($ty);
    };
}

impl_byte!(gen_u8, gen_u8_in, u8);
impl_byte!(gen_i8, gen_i8_in, i8);

macro_rules! impl_integer {
    ($name:ident, $bounded:ident, $ty:ident, $call:ident) => {
        pub fn $name() -> TypedGen<$ty> {
            gen::<$ty>()
        }

        pub fn $bounded<Bounds: RangeBounds<$ty>>(bound: Bounds) -> BoundedGenerator<$ty> {
            BoundedGenerator::new(bound)
        }

        impl TypeGenerator for $ty {
            fn generate<R: Rng>(rng: &mut R) -> Self {
                let mut bytes = [0; size_of::<$ty>()];
                rng.fill_bytes(&mut bytes);
                NativeEndian::$call(&bytes)
            }
        }

        impl ValueGenerator for $ty {
            type Output = $ty;

            fn generate<R: Rng>(&mut self, _rng: &mut R) -> Self {
                *self
            }
        }

        impl_bounded_integer!($ty);
    };
}

impl_integer!(gen_u16, gen_u16_in, u16, read_u16);
impl_integer!(gen_i16, gen_i16_in, i16, read_i16);
impl_integer!(gen_u32, gen_u32_in, u32, read_u32);
impl_integer!(gen_i32, gen_i32_in, i32, read_i32);
impl_integer!(gen_u64, gen_u64_in, u64, read_u64);
impl_integer!(gen_i64, gen_i64_in, i64, read_i64);
impl_integer!(gen_u128, gen_u128_in, u128, read_u128);
impl_integer!(gen_i128, gen_i128_in, i128, read_i128);

macro_rules! impl_native_integer {
    ($name:ident, $bounded:ident, $ty:ident) => {
        pub fn $name() -> TypedGen<$ty> {
            gen::<$ty>()
        }

        pub fn $bounded<Bounds: RangeBounds<$ty>>(bound: Bounds) -> BoundedGenerator<$ty> {
            BoundedGenerator::new(bound)
        }

        impl TypeGenerator for $ty {
            fn generate<R: Rng>(rng: &mut R) -> Self {
                let mut bytes = [0; size_of::<$ty>()];
                rng.fill_bytes(&mut bytes);
                NativeEndian::read_uint(&bytes, bytes.len()) as $ty
            }
        }

        impl ValueGenerator for $ty {
            type Output = $ty;

            fn generate<R: Rng>(&mut self, _rng: &mut R) -> Self {
                *self
            }
        }

        impl_bounded_integer!($ty);
    };
}
impl_native_integer!(gen_usize, gen_usize_in, usize);
impl_native_integer!(gen_isize, gen_isize_in, isize);

macro_rules! impl_float {
    ($name:ident, $ty:ident, $call:ident) => {
        pub fn $name() -> TypedGen<$ty> {
            gen::<$ty>()
        }

        impl TypeGenerator for $ty {
            fn generate<R: Rng>(rng: &mut R) -> Self {
                let mut bytes = [0; size_of::<$ty>()];
                rng.fill_bytes(&mut bytes);
                NativeEndian::$call(&bytes)
            }
        }

        impl ValueGenerator for $ty {
            type Output = $ty;

            fn generate<R: Rng>(&mut self, _rng: &mut R) -> Self {
                *self
            }
        }

        // TODO impl_bounded
    };
}
impl_float!(gen_f32, f32, read_f32);
impl_float!(gen_f64, f64, read_f64);
