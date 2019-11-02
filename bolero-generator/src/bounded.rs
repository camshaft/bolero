use crate::{Rng, TypeGenerator, ValueGenerator};
use core::ops::{Bound, RangeBounds};

macro_rules! range_generator {
    ($ty:ident) => {
        impl<T: TypeGenerator + BoundedValue> ValueGenerator for core::ops::$ty<T> {
            type Output = T;

            fn generate<R: Rng>(&self, rng: &mut R) -> Self::Output {
                T::generate(rng).bounded(
                    map_bound(self.start_bound(), |b| b.clone()),
                    map_bound(self.end_bound(), |b| b.clone()),
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
    pub fn new<Bounds: RangeBounds<B>, B: Clone + Into<T>>(generator: G, bounds: Bounds) -> Self {
        BoundedGenerator {
            generator,
            start: map_bound(bounds.start_bound(), |b| b.clone().into()),
            end: map_bound(bounds.end_bound(), |b| b.clone().into()),
        }
    }

    pub fn bounds<Bounds: RangeBounds<B>, B: Clone + Into<T>>(self, bounds: Bounds) -> Self {
        BoundedGenerator {
            generator: self.generator,
            start: map_bound(bounds.start_bound(), |b| b.clone().into()),
            end: map_bound(bounds.end_bound(), |b| b.clone().into()),
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

fn map_bound<T, U, F: Fn(&T) -> U>(bound: Bound<&T>, map: F) -> Bound<U> {
    match bound {
        Bound::Unbounded => Bound::Unbounded,
        Bound::Included(x) => Bound::Included(map(x)),
        Bound::Excluded(x) => Bound::Excluded(map(x)),
    }
}

#[test]
fn with_bounds_test() {
    let _ = generator_test!(gen::<u8>().with().bounds(0..32));
}

#[test]
fn bounded_u8_test() {
    fn test_bound<Bounds: std::fmt::Debug + RangeBounds<u8>>(v: u8, bounds: Bounds) {
        let out = v.bounded(
            map_bound(bounds.start_bound(), |b| *b),
            map_bound(bounds.end_bound(), |b| *b),
        );
        assert!(bounds.contains(&out), "{:?} not in {:?}", out, bounds);
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
    fn test_bound<Bounds: core::fmt::Debug + RangeBounds<i8>>(v: i8, bounds: Bounds) {
        let out = v.bounded(
            map_bound(bounds.start_bound(), |b| *b),
            map_bound(bounds.end_bound(), |b| *b),
        );
        assert!(bounds.contains(&out), "{:?} not in {:?}", out, bounds);
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
