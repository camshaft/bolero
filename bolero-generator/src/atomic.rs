use crate::{Rng, TypeGenerator};
use core::{
    cell::{Cell, RefCell, UnsafeCell},
    sync::atomic::{
        AtomicBool, AtomicI16, AtomicI32, AtomicI64, AtomicI8, AtomicIsize, AtomicU16, AtomicU32,
        AtomicU64, AtomicU8, AtomicUsize,
    },
};

impl TypeGenerator for AtomicBool {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        AtomicBool::new(rng.gen())
    }
}

macro_rules! impl_atomic_integer {
    ($ty:ident) => {
        impl TypeGenerator for $ty {
            fn generate<R: Rng>(rng: &mut R) -> Self {
                $ty::new(rng.gen())
            }
        }

        // TODO
        // impl_bounded_integer!($ty);
    };
}

impl_atomic_integer!(AtomicI8);
impl_atomic_integer!(AtomicU8);
impl_atomic_integer!(AtomicI16);
impl_atomic_integer!(AtomicU16);
impl_atomic_integer!(AtomicI32);
impl_atomic_integer!(AtomicU32);
impl_atomic_integer!(AtomicI64);
impl_atomic_integer!(AtomicU64);
impl_atomic_integer!(AtomicIsize);
impl_atomic_integer!(AtomicUsize);

impl<T: TypeGenerator> TypeGenerator for Cell<T> {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        Self::new(rng.gen())
    }
}

impl<T: TypeGenerator> TypeGenerator for RefCell<T> {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        Self::new(rng.gen())
    }
}

impl<T: TypeGenerator> TypeGenerator for UnsafeCell<T> {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        Self::new(rng.gen())
    }
}
