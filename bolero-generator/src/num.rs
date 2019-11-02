use crate::{
    bounded::{BoundedGenerator, BoundedValue},
    Rng, TypeGenerator, TypeGeneratorWithParams, TypeValueGenerator, ValueGenerator,
};
use byteorder::{ByteOrder, NativeEndian};
use core::{mem::size_of, ops::Bound};

macro_rules! impl_bounded_unsigned_integer {
    ($ty:ident) => {
        impl BoundedValue for $ty {
            fn bounded(self, start: Bound<Self>, end: Bound<Self>) -> Self {
                use Bound::*;

                match (start, end) {
                    (Included(start), Included(end)) if end > start => {
                        (self % (end - start + 1)) + start
                    }
                    (Included(end), Included(start)) if end > start => {
                        (self % (end - start + 1)) + start
                    }
                    (Included(start), Included(_)) => start,
                    (Included(start), Excluded(end)) if end > start => {
                        (self % (end - start)) + start
                    }
                    (Included(end), Excluded(start)) if end > start => {
                        (self % (end - start + 2)) + start - 1
                    }
                    (Included(start), Excluded(_)) => start,
                    (Included(0), Unbounded) => self,
                    (Included(start), Unbounded) => (self % (core::$ty::MAX - start + 1)) + start,
                    (Excluded(start), Excluded(end)) if end > start => {
                        (self % (end - start - 1)) + start + 1
                    }
                    (Excluded(end), Excluded(start)) if end > start => {
                        (self % (end - start - 1)) + start + 1
                    }
                    (Excluded(start), Excluded(_)) => start,
                    (Excluded(start), Included(end)) if end > start => {
                        (self % (end - start)) + start + 1
                    }
                    (Excluded(end), Included(start)) if end > start => {
                        (self % (end - start)) + start
                    }
                    (Excluded(_), Included(end)) => end,
                    (Excluded(start), Unbounded) => (self % (core::$ty::MAX - start)) + start + 1,
                    (Unbounded, Unbounded) => self,
                    (Unbounded, Included(end)) => {
                        if let Some(range) = end.checked_add(1) {
                            self % range
                        } else {
                            self
                        }
                    }
                    (Unbounded, Excluded(end)) => (self % end),
                }
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

macro_rules! impl_bounded_signed_integer {
    ($ty:ident, $unsigned:ident) => {
        impl BoundedValue for $ty {
            fn bounded(self, start: Bound<Self>, end: Bound<Self>) -> Self {
                use Bound::*;

                let to_unsigned = |value: $ty| {
                    if value == core::$ty::MIN {
                        return 0;
                    }

                    if value >= 0 {
                        return value as $unsigned + core::$ty::MAX as $unsigned + 1;
                    }

                    value as $unsigned - core::$ty::MAX as $unsigned - 1
                };

                let from_unsigned = |value: $unsigned| {
                    if value == 0 {
                        return core::$ty::MIN;
                    }

                    if value > core::$ty::MAX as $unsigned {
                        return (value - core::$ty::MAX as $unsigned - 1) as $ty;
                    }

                    (value + core::$ty::MAX as $unsigned) as $ty + 1
                };

                let start = match start {
                    Included(value) => Included(to_unsigned(value)),
                    Excluded(value) => Excluded(to_unsigned(value)),
                    Unbounded => Unbounded,
                };

                let end = match end {
                    Included(value) => Included(to_unsigned(value)),
                    Excluded(value) => Excluded(to_unsigned(value)),
                    Unbounded => Unbounded,
                };

                from_unsigned(BoundedValue::bounded(to_unsigned(self), start, end))
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
    };
}

impl_byte!(gen_u8, u8);
impl_bounded_unsigned_integer!(u8);
impl_byte!(gen_i8, i8);
impl_bounded_signed_integer!(i8, u8);

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
    };
}

impl_integer!(gen_u16, u16, read_u16);
impl_bounded_unsigned_integer!(u16);
impl_integer!(gen_i16, i16, read_i16);
impl_bounded_signed_integer!(i16, u16);
impl_integer!(gen_u32, u32, read_u32);
impl_bounded_unsigned_integer!(u32);
impl_integer!(gen_i32, i32, read_i32);
impl_bounded_signed_integer!(i32, u32);
impl_integer!(gen_u64, u64, read_u64);
impl_bounded_unsigned_integer!(u64);
impl_integer!(gen_i64, i64, read_i64);
impl_bounded_signed_integer!(i64, u64);
impl_integer!(gen_u128, u128, read_u128);
impl_bounded_unsigned_integer!(u128);
impl_integer!(gen_i128, i128, read_i128);
impl_bounded_signed_integer!(i128, u128);

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
    };
}

impl_native_integer!(gen_usize, usize);
impl_bounded_unsigned_integer!(usize);
impl_native_integer!(gen_isize, isize);
impl_bounded_signed_integer!(isize, usize);

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

macro_rules! impl_non_zero_integer {
    ($ty:ident) => {
        impl TypeGenerator for core::num::$ty {
            fn generate<R: Rng>(rng: &mut R) -> Self {
                let value = (1..).generate(rng);
                unsafe { Self::new_unchecked(value) }
            }
        }

        impl BoundedValue for core::num::$ty {
            fn bounded(self, start: Bound<Self>, end: Bound<Self>) -> Self {
                use Bound::*;

                let start = match start {
                    Included(value) => Included(value.get()),
                    Excluded(value) => Excluded(value.get()),
                    Unbounded => Unbounded,
                };

                let end = match end {
                    Included(value) => Included(value.get()),
                    Excluded(value) => Excluded(value.get()),
                    Unbounded => Unbounded,
                };

                let mut inner = self.get();

                // try a few times before giving up
                for _ in 0..=3 {
                    if let Some(value) = Self::new(inner.bounded(start, end)) {
                        return value;
                    } else {
                        inner = inner.wrapping_add(1);
                    }
                }

                panic!(concat!(
                    "could not satisfy bounded value for ",
                    stringify!($ty)
                ))
            }
        }

        impl TypeGeneratorWithParams for core::num::$ty {
            type Output = BoundedGenerator<TypeValueGenerator<core::num::$ty>, core::num::$ty>;

            fn gen_with() -> Self::Output {
                BoundedGenerator::new(
                    Default::default(),
                    unsafe { core::num::$ty::new_unchecked(1) }..,
                )
            }
        }
    };
}

impl_non_zero_integer!(NonZeroI8);
impl_non_zero_integer!(NonZeroU8);
impl_non_zero_integer!(NonZeroI16);
impl_non_zero_integer!(NonZeroU16);
impl_non_zero_integer!(NonZeroI32);
impl_non_zero_integer!(NonZeroU32);
impl_non_zero_integer!(NonZeroI64);
impl_non_zero_integer!(NonZeroU64);
impl_non_zero_integer!(NonZeroI128);
impl_non_zero_integer!(NonZeroU128);
impl_non_zero_integer!(NonZeroIsize);
impl_non_zero_integer!(NonZeroUsize);
