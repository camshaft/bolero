use crate::{
    bounded::{BoundExt, BoundedGenerator, BoundedValue},
    Driver, TypeGenerator, TypeGeneratorWithParams,
};
use core::{
    cell::{Cell, RefCell, UnsafeCell},
    ops::{Bound, RangeFull},
    sync::atomic::{
        AtomicBool, AtomicI16, AtomicI32, AtomicI64, AtomicI8, AtomicIsize, AtomicU16, AtomicU32,
        AtomicU64, AtomicU8, AtomicUsize, Ordering,
    },
};

impl TypeGenerator for AtomicBool {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(AtomicBool::new(driver.produce()?))
    }

    fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
        self.store(driver.produce()?, Ordering::SeqCst);
        Some(())
    }
}

macro_rules! impl_atomic_integer {
    ($ty:ident, $inner:ident) => {
        impl TypeGenerator for $ty {
            fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
                Some(Self::new(driver.produce()?))
            }

            fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
                self.store(driver.produce()?, Ordering::SeqCst);
                Some(())
            }
        }

        impl BoundedValue for $ty {
            fn gen_bounded<D: Driver>(
                driver: &mut D,
                min: Bound<&Self>,
                max: Bound<&Self>,
            ) -> Option<Self> {
                let min = BoundExt::map(min, |value| value.load(Ordering::SeqCst));
                let max = BoundExt::map(max, |value| value.load(Ordering::SeqCst));

                let value = BoundedValue::gen_bounded(
                    driver,
                    BoundExt::as_ref(&min),
                    BoundExt::as_ref(&max),
                )?;
                Some(Self::new(value))
            }
        }

        impl BoundedValue<$inner> for $ty {
            fn gen_bounded<D: Driver>(
                driver: &mut D,
                min: Bound<&$inner>,
                max: Bound<&$inner>,
            ) -> Option<Self> {
                let value = BoundedValue::gen_bounded(driver, min, max)?;
                Some(Self::new(value))
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

#[test]
fn atomicu8_test() {
    let _ = generator_no_clone_test!(gen::<AtomicU8>());
}

// #[test]
// fn atomicu8_with_test() {
//     let _ = generator_test!(gen::<AtomicU8>()
//         .with()
//         .bounds(AtomicU8::new(0u8)..AtomicU8::new(5)));
// }

impl_atomic_integer!(AtomicI8, i8);
impl_atomic_integer!(AtomicU8, u8);
impl_atomic_integer!(AtomicI16, i16);
impl_atomic_integer!(AtomicU16, u16);
impl_atomic_integer!(AtomicI32, i32);
impl_atomic_integer!(AtomicU32, u32);
impl_atomic_integer!(AtomicI64, i64);
impl_atomic_integer!(AtomicU64, u64);
impl_atomic_integer!(AtomicIsize, isize);
impl_atomic_integer!(AtomicUsize, usize);

impl<T: TypeGenerator> TypeGenerator for Cell<T> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(Self::new(driver.produce()?))
    }
}

impl<T: TypeGenerator> TypeGenerator for RefCell<T> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(Self::new(driver.produce()?))
    }
}

impl<T: TypeGenerator> TypeGenerator for UnsafeCell<T> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(Self::new(driver.produce()?))
    }
}
