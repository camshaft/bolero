use crate::{
    bounded::{BoundedGenerator, BoundedValue},
    Driver, TypeGenerator, TypeGeneratorWithParams, TypeValueGenerator,
};
use core::{
    cell::{Cell, RefCell, UnsafeCell},
    ops::{RangeBounds, RangeFrom},
    sync::atomic::{
        AtomicBool, AtomicI16, AtomicI32, AtomicI64, AtomicI8, AtomicIsize, AtomicU16, AtomicU32,
        AtomicU64, AtomicU8, AtomicUsize, Ordering,
    },
};

impl TypeGenerator for AtomicBool {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(AtomicBool::new(driver.gen()?))
    }

    fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
        self.store(driver.gen()?, Ordering::SeqCst);
        Some(())
    }
}

macro_rules! impl_atomic_integer {
    ($ty:ident, $inner:ident) => {
        impl TypeGenerator for $ty {
            fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
                Some($ty::new(driver.gen()?))
            }

            fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
                self.store(driver.gen()?, Ordering::SeqCst);
                Some(())
            }
        }

        impl<R: RangeBounds<$inner>> BoundedValue<R> for $ty {
            type BoundValue = $inner;

            fn is_within(&self, range_bounds: &R) -> bool {
                self.load(Ordering::SeqCst).is_within(range_bounds)
            }

            fn bind_within(&mut self, range_bounds: &R) {
                let mut value = self.load(Ordering::SeqCst);
                value.bind_within(range_bounds);
                self.store(value, Ordering::SeqCst);
            }
        }

        impl TypeGeneratorWithParams for $ty {
            type Output = BoundedGenerator<TypeValueGenerator<$ty>, RangeFrom<$inner>>;

            fn gen_with() -> Self::Output {
                BoundedGenerator::new(Default::default(), core::$inner::MIN..)
            }
        }
    };
}

#[test]
fn atomicu8_test() {
    let _ = generator_test!(gen::<AtomicU8>());
}

// #[test]
// fn atomicu8_with_test() {
//     let _ = generator_test!(gen::<AtomicU8>().with().bounds(0u8..5));
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
        Some(Self::new(driver.gen()?))
    }
}

impl<T: TypeGenerator> TypeGenerator for RefCell<T> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(Self::new(driver.gen()?))
    }
}

impl<T: TypeGenerator> TypeGenerator for UnsafeCell<T> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(Self::new(driver.gen()?))
    }
}
