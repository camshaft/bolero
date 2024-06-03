use crate::{
    bounded::{BoundExt, BoundedGenerator, BoundedValue},
    Driver, TypeGenerator, TypeGeneratorWithParams, ValueGenerator,
};
use core::ops::{Bound, RangeFrom, RangeFull};

macro_rules! impl_integer {
    ($ty:ident, $call:ident, $constant:ident) => {
        impl TypeGenerator for $ty {
            fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
                driver.$call(Bound::Unbounded, Bound::Unbounded)
            }
        }

        impl ValueGenerator for $ty {
            type Output = $ty;

            fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self> {
                driver.$constant(*self)
            }
        }

        impl BoundedValue for $ty {
            fn gen_bounded<D: Driver>(
                driver: &mut D,
                min: Bound<&Self>,
                max: Bound<&Self>,
            ) -> Option<Self> {
                driver.$call(min, max)
            }
        }

        impl TypeGeneratorWithParams for $ty {
            type Output = BoundedGenerator<Self, RangeFull>;

            fn gen_with() -> Self::Output {
                BoundedGenerator::new(..)
            }
        }
    };
}

impl_integer!(u8, gen_u8, gen_u8_constant);
impl_integer!(i8, gen_i8, gen_i8_constant);
impl_integer!(u16, gen_u16, gen_u16_constant);
impl_integer!(i16, gen_i16, gen_i16_constant);
impl_integer!(u32, gen_u32, gen_u32_constant);
impl_integer!(i32, gen_i32, gen_i32_constant);
impl_integer!(u64, gen_u64, gen_u64_constant);
impl_integer!(i64, gen_i64, gen_i64_constant);
impl_integer!(u128, gen_u128, gen_u128_constant);
impl_integer!(i128, gen_i128, gen_i128_constant);
impl_integer!(usize, gen_usize, gen_usize_constant);
impl_integer!(isize, gen_isize, gen_isize_constant);

#[test]
fn integer_test() {
    let _ = generator_test!(gen::<u8>());
    let _ = generator_test!(gen::<i8>());
    let _ = generator_test!(gen::<u16>());
    let _ = generator_test!(gen::<i16>());
    let _ = generator_test!(gen::<u32>());
    let _ = generator_test!(gen::<i32>());
    let _ = generator_test!(gen::<u64>());
    let _ = generator_test!(gen::<i64>());
    let _ = generator_test!(gen::<u128>());
    let _ = generator_test!(gen::<i128>());
    let _ = generator_test!(gen::<usize>());
    let _ = generator_test!(gen::<isize>());
}

macro_rules! impl_float {
    ($ty:ident, $call:ident, $constant:ident) => {
        impl TypeGenerator for $ty {
            fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
                driver.$call(Bound::Unbounded, Bound::Unbounded)
            }
        }

        impl ValueGenerator for $ty {
            type Output = $ty;

            fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self> {
                driver.$constant(*self)
            }
        }

        impl BoundedValue for $ty {
            fn gen_bounded<D: Driver>(
                driver: &mut D,
                min: Bound<&Self>,
                max: Bound<&Self>,
            ) -> Option<Self> {
                driver.$call(min, max)
            }
        }

        impl TypeGeneratorWithParams for $ty {
            type Output = BoundedGenerator<Self, RangeFull>;

            fn gen_with() -> Self::Output {
                BoundedGenerator::new(..)
            }
        }
    };
}

impl_float!(f32, gen_f32, gen_f32_constant);
impl_float!(f64, gen_f64, gen_f64_constant);

#[test]
fn float_test() {
    // TODO filter NaN for mutation comparison
    //let _ = generator_test!(gen::<f32>());
    //let _ = generator_test!(gen::<f64>());
}

macro_rules! impl_non_zero_integer {
    ($ty:ident, $inner:ty) => {
        impl TypeGenerator for core::num::$ty {
            fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
                let value = (1..).generate(driver)?;
                Self::new(value)
            }
        }

        impl BoundedValue for core::num::$ty {
            fn gen_bounded<D: Driver>(
                driver: &mut D,
                min: Bound<&Self>,
                max: Bound<&Self>,
            ) -> Option<Self> {
                let min = BoundExt::map(min, |value| value.get());
                let max = BoundExt::map(max, |value| value.get());

                let value = BoundedValue::gen_bounded(
                    driver,
                    BoundExt::as_ref(&min),
                    BoundExt::as_ref(&max),
                )?;
                Self::new(value)
            }
        }

        impl BoundedValue<$inner> for core::num::$ty {
            fn gen_bounded<D: Driver>(
                driver: &mut D,
                min: Bound<&$inner>,
                max: Bound<&$inner>,
            ) -> Option<Self> {
                let value = BoundedValue::gen_bounded(driver, min, max)?;
                Self::new(value)
            }
        }

        impl TypeGeneratorWithParams for core::num::$ty {
            type Output = BoundedGenerator<Self, RangeFrom<Self>>;

            fn gen_with() -> Self::Output {
                BoundedGenerator::new(unsafe { core::num::$ty::new_unchecked(1) }..)
            }
        }
    };
}

impl_non_zero_integer!(NonZeroI8, i8);
impl_non_zero_integer!(NonZeroU8, u8);
impl_non_zero_integer!(NonZeroI16, i16);
impl_non_zero_integer!(NonZeroU16, u16);
impl_non_zero_integer!(NonZeroI32, i32);
impl_non_zero_integer!(NonZeroU32, u32);
impl_non_zero_integer!(NonZeroI64, i64);
impl_non_zero_integer!(NonZeroU64, u64);
impl_non_zero_integer!(NonZeroI128, i128);
impl_non_zero_integer!(NonZeroU128, u128);
impl_non_zero_integer!(NonZeroIsize, isize);
impl_non_zero_integer!(NonZeroUsize, usize);
