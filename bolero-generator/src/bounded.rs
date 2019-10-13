use crate::{Rng, TypeGenerator, ValueGenerator};
use core::ops::{Bound, RangeBounds};

macro_rules! range_generator {
    ($ty:ident) => {
        impl<T: TypeGenerator + BoundedValue> ValueGenerator for core::ops::$ty<T> {
            type Output = T;

            fn generate<R: Rng>(&self, rng: &mut R) -> Self::Output {
                T::generate(rng).bounded(
                    clone_bound(self.start_bound()),
                    clone_bound(self.end_bound()),
                )
            }
        }
    };
}

range_generator!(Range);
range_generator!(RangeFrom);
range_generator!(RangeInclusive);
range_generator!(RangeTo);
range_generator!(RangeToInclusive);

pub trait BoundedValue: Clone + Sized {
    fn bounded(self, start: Bound<Self>, end: Bound<Self>) -> Self;
}

#[derive(Debug)]
pub struct BoundedGenerator<G, T> {
    generator: G,
    start: Bound<T>,
    end: Bound<T>,
}

impl<G: ValueGenerator<Output = T>, T: BoundedValue> BoundedGenerator<G, T> {
    pub fn new<Bounds: RangeBounds<T>>(generator: G, bounds: Bounds) -> Self {
        BoundedGenerator {
            generator,
            start: clone_bound(bounds.start_bound()),
            end: clone_bound(bounds.end_bound()),
        }
    }

    pub fn bounds<Bounds: RangeBounds<T>>(self, bounds: Bounds) -> Self {
        BoundedGenerator {
            generator: self.generator,
            start: clone_bound(bounds.start_bound()),
            end: clone_bound(bounds.end_bound()),
        }
    }
}

impl<T: BoundedValue, G: ValueGenerator<Output = T>> ValueGenerator for BoundedGenerator<G, T> {
    type Output = T;

    fn generate<R: Rng>(&self, rng: &mut R) -> T {
        self.generator
            .generate(rng)
            .bounded(self.start.clone(), self.end.clone())
    }
}

fn clone_bound<T: Clone>(bound: Bound<&T>) -> Bound<T> {
    match bound {
        Bound::Unbounded => Bound::Unbounded,
        Bound::Included(x) => Bound::Included(x.clone()),
        Bound::Excluded(x) => Bound::Excluded(x.clone()),
    }
}

#[test]
fn with_bounds_test() {
    let _ = generator_test!(gen::<u8>().with().bounds(0..32));
}

#[test]
fn bounded_u8_test() {
    fn test_bound<Bounds: RangeBounds<u8>>(v: u8, bounds: Bounds) {
        let v = v.bounded(
            clone_bound(bounds.start_bound()),
            clone_bound(bounds.end_bound()),
        );
        assert!(bounds.contains(&v));
    }

    for v in 0u8..255 {
        test_bound(v, 4..10);
        test_bound(v, 4..=10);
        test_bound(v, ..10);
        test_bound(v, ..);
        test_bound(v, 4..);
        test_bound(v, (Bound::Excluded(4), Bound::Unbounded));
    }
}
