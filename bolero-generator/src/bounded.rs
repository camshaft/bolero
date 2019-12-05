use crate::{driver::DriverMode, Driver, TypeGenerator, ValueGenerator};
use core::ops::RangeBounds;

pub trait BoundedValue<RangeBounds> {
    type BoundValue;

    fn is_within(&self, range: &RangeBounds) -> bool;
    fn bind_within(self, range: &RangeBounds) -> Self;
}

#[inline(always)]
pub(crate) fn is_within<T: PartialOrd, R: RangeBounds<T>>(value: &T, range_bounds: &R) -> bool {
    #![allow(clippy::neg_cmp_op_on_partial_ord)]
    use core::ops::Bound::*;

    macro_rules! ensure {
        ($value:expr) => {{
            if !($value) {
                return false;
            }
        }};
    }

    match range_bounds.start_bound() {
        Included(start) => ensure!(start <= value),
        Excluded(start) => ensure!(start < value),
        Unbounded => {}
    }

    match range_bounds.end_bound() {
        Included(end) => ensure!(value <= end),
        Excluded(end) => ensure!(value < end),
        Unbounded => {}
    }

    true
}

macro_rules! range_generator {
    ($ty:ident) => {
        impl<T: TypeGenerator + BoundedValue<Self>> ValueGenerator for core::ops::$ty<T> {
            type Output = T;

            fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
                if driver.mode() == DriverMode::Forced {
                    Some(T::generate(driver)?.bind_within(self))
                } else {
                    T::generate(driver).filter(|value| value.is_within(self))
                }
            }
        }
    };
}

range_generator!(Range);
range_generator!(RangeFrom);
range_generator!(RangeInclusive);
range_generator!(RangeTo);
range_generator!(RangeToInclusive);

#[derive(Debug)]
pub struct BoundedGenerator<G, B> {
    generator: G,
    range_bounds: B,
}

impl<T: BoundedValue<B>, G: ValueGenerator<Output = T>, B: RangeBounds<T::BoundValue>>
    BoundedGenerator<G, B>
{
    pub fn new(generator: G, range_bounds: B) -> Self {
        BoundedGenerator {
            generator,
            range_bounds,
        }
    }

    pub fn bounds<NewB: RangeBounds<T>>(self, range_bounds: NewB) -> BoundedGenerator<G, NewB> {
        BoundedGenerator {
            generator: self.generator,
            range_bounds,
        }
    }
}

impl<T: BoundedValue<B>, G: ValueGenerator<Output = T>, B: RangeBounds<T::BoundValue>>
    ValueGenerator for BoundedGenerator<G, B>
{
    type Output = T;

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<T> {
        self.generator
            .generate(driver)
            .filter(|value| value.is_within(&self.range_bounds))
    }
}

#[test]
fn with_bounds_test() {
    let _ = generator_test!(gen::<u8>().with().bounds(0..32));
}

#[test]
fn bounded_u8_test() {
    use core::ops::Bound;
    fn test_bound<Bounds: std::fmt::Debug + RangeBounds<u8>>(v: u8, bounds: Bounds) {
        assert_eq!(v.is_within(&bounds), bounds.contains(&v));
        let bound = v.bind_within(&bounds);
        assert!(bounds.contains(&bound), "{:?} not in {:?}", bound, bounds);
    }

    for v in 0u8..=255 {
        test_bound(v, 4..10);
        test_bound(v, 4..=10);
        test_bound(v, ..10);
        test_bound(v, ..);
        test_bound(v, 4..);
        test_bound(v, (Bound::Excluded(4), Bound::Unbounded));
    }
}

#[test]
fn bounded_i8_test() {
    use core::ops::Bound;
    fn test_bound<Bounds: core::fmt::Debug + RangeBounds<i8>>(v: i8, bounds: Bounds) {
        assert_eq!(v.is_within(&bounds), bounds.contains(&v));
        let bound = v.bind_within(&bounds);
        assert!(bounds.contains(&bound), "{:?} not in {:?}", bound, bounds);
    }

    for v in -128i8..=127 {
        test_bound(v, -5..=5);
        test_bound(v, -10..=-5);
        test_bound(v, 4..10);
        test_bound(v, 4..=10);
        test_bound(v, ..-10);
        test_bound(v, ..=-10);
        test_bound(v, ..);
        test_bound(v, 4..);
        test_bound(v, -127..0);
        test_bound(v, -120..120);
        test_bound(v, (Bound::Excluded(4), Bound::Unbounded));
    }
}
