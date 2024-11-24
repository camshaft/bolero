use crate::{Driver, ValueGenerator};
use core::{
    marker::PhantomData,
    ops::{Bound, RangeBounds},
};

pub(crate) trait BoundExt<T> {
    fn as_ref(&self) -> Bound<&T>;
    fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Bound<U>;
}

impl<T> BoundExt<T> for Bound<T> {
    #[inline(always)]
    fn as_ref(&self) -> Bound<&T> {
        match self {
            Self::Excluded(v) => Bound::Excluded(v),
            Self::Included(v) => Bound::Included(v),
            Self::Unbounded => Bound::Unbounded,
        }
    }

    #[inline(always)]
    fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Bound<U> {
        match self {
            Self::Excluded(v) => Bound::Excluded(f(v)),
            Self::Included(v) => Bound::Included(f(v)),
            Self::Unbounded => Bound::Unbounded,
        }
    }
}

pub trait BoundedValue<B = Self>: 'static + Sized {
    fn gen_bounded<D: Driver>(driver: &mut D, min: Bound<&B>, max: Bound<&B>) -> Option<Self>;

    fn mutate_bounded<D: Driver>(
        &mut self,
        driver: &mut D,
        min: Bound<&B>,
        max: Bound<&B>,
    ) -> Option<()> {
        *self = Self::gen_bounded(driver, min, max)?;
        Some(())
    }
}

macro_rules! range_generator {
    ($ty:ident) => {
        impl<T: BoundedValue> ValueGenerator for core::ops::$ty<T> {
            type Output = T;

            #[inline]
            fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
                let min = self.start_bound();
                let max = self.end_bound();
                T::gen_bounded(driver, min, max)
            }

            #[inline]
            fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
                let min = self.start_bound();
                let max = self.end_bound();
                value.mutate_bounded(driver, min, max)
            }
        }
    };
}

range_generator!(Range);
range_generator!(RangeFrom);
range_generator!(RangeInclusive);
range_generator!(RangeTo);
range_generator!(RangeToInclusive);

impl<T: BoundedValue> ValueGenerator for (core::ops::Bound<T>, core::ops::Bound<T>) {
    type Output = T;

    #[inline]
    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let min = self.start_bound();
        let max = self.end_bound();
        T::gen_bounded(driver, min, max)
    }

    #[inline]
    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        let min = self.start_bound();
        let max = self.end_bound();
        value.mutate_bounded(driver, min, max)
    }
}

#[derive(Debug)]
pub struct BoundedGenerator<T, B> {
    range_bounds: B,
    output: PhantomData<T>,
}

impl<T: BoundedValue, B: RangeBounds<T>> BoundedGenerator<T, B> {
    pub fn new(range_bounds: B) -> Self {
        BoundedGenerator {
            range_bounds,
            output: PhantomData,
        }
    }

    pub fn bounds<NewB: RangeBounds<T>>(self, range_bounds: NewB) -> BoundedGenerator<T, NewB> {
        BoundedGenerator {
            range_bounds,
            output: PhantomData,
        }
    }
}

impl<T: BoundedValue, B: RangeBounds<T>> ValueGenerator for BoundedGenerator<T, B> {
    type Output = T;

    #[inline]
    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let min = self.range_bounds.start_bound();
        let max = self.range_bounds.end_bound();
        T::gen_bounded(driver, min, max)
    }

    #[inline]
    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        let min = self.range_bounds.start_bound();
        let max = self.range_bounds.end_bound();
        value.mutate_bounded(driver, min, max)
    }
}

#[test]
fn with_bounds_test() {
    let _ = generator_test!(gen::<u8>().with().bounds(0..32));
}
