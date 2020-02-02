use crate::{
    bounded::{is_within, BoundedGenerator, BoundedValue},
    driver::DriverMode,
    Driver, TypeGenerator, TypeGeneratorWithParams, TypeValueGenerator, ValueGenerator,
};
use byteorder::{ByteOrder, LittleEndian};
use core::{
    mem::size_of,
    ops::{RangeBounds, RangeFrom},
};

trait NumBindWithin {
    fn bind_within<R: RangeBounds<Self>>(&mut self, range_bounds: &R);
}

macro_rules! impl_unsigned_bounded_integer {
    ($ty:ident) => {
        impl NumBindWithin for $ty {
            fn bind_within<R: RangeBounds<Self>>(&mut self, range_bounds: &R) {
                use core::ops::Bound::*;

                let start = match range_bounds.start_bound() {
                    Included(value) => *value,
                    Excluded(value) => value.saturating_add(1),
                    Unbounded => core::$ty::MIN,
                };

                let end = match range_bounds.end_bound() {
                    Included(value) => *value,
                    Excluded(value) => value.saturating_sub(1),
                    Unbounded => core::$ty::MAX,
                };

                let steps = (end - start).saturating_add(1);
                let values_per_step = core::$ty::MAX / steps;
                *self = core::cmp::min(start.saturating_add(*self / values_per_step), end);
            }
        }

        impl_bounded_integer!($ty);
    };
}

macro_rules! impl_bounded_integer {
    ($ty:ident) => {
        impl<R: RangeBounds<Self>> BoundedValue<R> for $ty {
            type BoundValue = $ty;

            #[inline(always)]
            fn is_within(&self, range_bounds: &R) -> bool {
                is_within(self, range_bounds)
            }

            #[inline(always)]
            fn bind_within(&mut self, range_bounds: &R) {
                NumBindWithin::bind_within(self, range_bounds)
            }
        }

        impl TypeGeneratorWithParams for $ty {
            type Output = BoundedGenerator<TypeValueGenerator<$ty>, RangeFrom<$ty>>;

            fn gen_with() -> Self::Output {
                BoundedGenerator::new(Default::default(), core::$ty::MIN..)
            }
        }
    };
}

impl TypeGenerator for u8 {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        let mut bytes = [0; size_of::<u8>()];
        Driver::fill_bytes(driver, &mut bytes)?;
        Some(bytes[0])
    }
}

impl ValueGenerator for u8 {
    type Output = u8;

    fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self> {
        Some(*self)
    }
}

impl_unsigned_bounded_integer!(u8);

macro_rules! impl_unsigned_integer {
    ($ty:ident, $call:ident) => {
        impl TypeGenerator for $ty {
            fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
                let mut bytes = [0; size_of::<$ty>()];
                Driver::fill_bytes(driver, &mut bytes)?;
                Some(LittleEndian::$call(&bytes))
            }
        }

        impl ValueGenerator for $ty {
            type Output = $ty;

            fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self> {
                Some(*self)
            }
        }

        impl_unsigned_bounded_integer!($ty);
    };
}

macro_rules! impl_signed_integer {
    ($ty:ident, $unsigned:ident) => {
        impl TypeGenerator for $ty {
            fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
                let unsigned: $unsigned = driver.gen()?;

                // When using Direct, use simple conversions instead of zigzag
                let signed = if driver.mode() == DriverMode::Direct {
                    unsigned as $ty
                } else {
                    ((unsigned >> 1) as $ty) ^ (-((unsigned & 1) as $ty))
                };

                Some(signed)
            }
        }

        impl ValueGenerator for $ty {
            type Output = $ty;

            fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self> {
                Some(*self)
            }
        }

        impl NumBindWithin for $ty {
            #[inline]
            fn bind_within<R: RangeBounds<Self>>(&mut self, range_bounds: &R) {
                use core::ops::Bound::*;

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

                let start = match range_bounds.start_bound() {
                    Included(value) => Included(to_unsigned(*value)),
                    Excluded(value) => Excluded(to_unsigned(*value)),
                    Unbounded => Unbounded,
                };

                let end = match range_bounds.end_bound() {
                    Included(value) => Included(to_unsigned(*value)),
                    Excluded(value) => Excluded(to_unsigned(*value)),
                    Unbounded => Unbounded,
                };

                let mut unsigned = to_unsigned(*self);
                NumBindWithin::bind_within(&mut unsigned, &(start, end));
                *self = from_unsigned(unsigned);
            }
        }

        impl_bounded_integer!($ty);
    };
}

impl_signed_integer!(i8, u8);

impl_unsigned_integer!(u16, read_u16);
impl_signed_integer!(i16, u16);

impl_unsigned_integer!(u32, read_u32);
impl_signed_integer!(i32, u32);

impl_unsigned_integer!(u64, read_u64);
impl_signed_integer!(i64, u64);

impl_unsigned_integer!(u128, read_u128);
impl_signed_integer!(i128, u128);

impl TypeGenerator for usize {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        let mut bytes = [0; size_of::<usize>()];
        Driver::fill_bytes(driver, &mut bytes)?;
        Some(LittleEndian::read_uint(&bytes, bytes.len()) as usize)
    }
}

impl ValueGenerator for usize {
    type Output = Self;

    fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self> {
        Some(*self)
    }
}

impl_unsigned_bounded_integer!(usize);
impl_signed_integer!(isize, usize);

macro_rules! impl_float {
    ($name:ident, $ty:ident, $call:ident) => {
        impl TypeGenerator for $ty {
            fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
                let mut bytes = [0; size_of::<$ty>()];
                Driver::fill_bytes(driver, &mut bytes)?;
                Some(unsafe { core::mem::transmute(bytes) })
            }
        }

        impl ValueGenerator for $ty {
            type Output = $ty;

            fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self> {
                Some(*self)
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
            fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
                let value = (1..).generate(driver)?;
                Some(unsafe { Self::new_unchecked(value) })
            }
        }

        impl<R: RangeBounds<Self>> BoundedValue<R> for core::num::$ty {
            type BoundValue = core::num::$ty;

            #[inline(always)]
            fn is_within(&self, range_bounds: &R) -> bool {
                is_within(self, range_bounds)
            }

            #[inline(always)]
            fn bind_within(&mut self, range_bounds: &R) {
                use core::ops::Bound::*;

                let start = match range_bounds.start_bound() {
                    Included(value) => Included(value.get()),
                    Excluded(value) => Excluded(value.get()),
                    Unbounded => Unbounded,
                };

                let end = match range_bounds.end_bound() {
                    Included(value) => Included(value.get()),
                    Excluded(value) => Excluded(value.get()),
                    Unbounded => Unbounded,
                };

                let mut inner = self.get();

                // try a few times before giving up
                for _ in 0..=3 {
                    NumBindWithin::bind_within(&mut inner, &(start, end));
                    if let Some(value) = Self::new(inner) {
                        *self = value;
                        return;
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
            type Output =
                BoundedGenerator<TypeValueGenerator<core::num::$ty>, RangeFrom<core::num::$ty>>;

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
