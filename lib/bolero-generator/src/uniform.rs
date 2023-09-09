use crate::{bounded::BoundExt, driver::DriverMode};
use core::ops::{Bound, RangeBounds};

pub trait Uniform: Sized {
    fn sample<F: FillBytes>(fill: &mut F, min: Bound<&Self>, max: Bound<&Self>) -> Option<Self>;
}

pub trait FillBytes {
    fn mode(&self) -> DriverMode;

    fn peek_bytes(&mut self, offset: usize, bytes: &mut [u8]) -> Option<()>;
    fn consume_bytes(&mut self, consumed: usize);

    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Option<()> {
        self.peek_bytes(0, bytes)?;
        self.consume_bytes(bytes.len());
        Some(())
    }
}

macro_rules! uniform_int {
    ($ty:ident, $unsigned:ident $(, $smaller:ident)?) => {
        impl Uniform  for $ty {
            #[inline]
            fn sample<F: FillBytes>(fill: &mut F, min: Bound<&$ty>, max: Bound<&$ty>) -> Option<$ty> {
                match (min, max) {
                    (Bound::Unbounded, Bound::Unbounded)
                    | (Bound::Unbounded, Bound::Included(&$ty::MAX))
                    | (Bound::Included(&$ty::MIN), Bound::Unbounded)
                    | (Bound::Included(&$ty::MIN), Bound::Included(&$ty::MAX)) => {
                        let mut bytes = [0u8; core::mem::size_of::<$ty>()];
                        fill.fill_bytes(&mut bytes)?;
                        return Some(<$ty>::from_le_bytes(bytes));
                    }
                    (Bound::Included(&x), Bound::Included(&y)) if x == y => {
                        return Some(x);
                    }
                    (Bound::Included(&x), Bound::Excluded(&y)) if x + 1 == y  => {
                        return Some(x);
                    }
                    _ => {}
                }

                // if we're in direct mode, just sample a value and check if it's within the provided range
                if fill.mode() == DriverMode::Direct {
                    return Self::sample(fill, Bound::Unbounded, Bound::Unbounded)
                        .filter(|value| (min, max).contains(value));
                }

                let lower = match min {
                    Bound::Included(&v) => v,
                    Bound::Excluded(v) => v.saturating_add(1),
                    Bound::Unbounded => $ty::MIN,
                };

                let upper = match max {
                    Bound::Included(&v) => v,
                    Bound::Excluded(v) => v.saturating_sub(1),
                    Bound::Unbounded => $ty::MAX,
                };

                // swap the two if reversed
                let (lower, upper) = if upper > lower {
                    (lower, upper)
                } else {
                    (upper, lower)
                };

                let range = upper.wrapping_sub(lower) as $unsigned;

                if range == 0 {
                    return Some(lower);
                }

                $({
                    use core::convert::TryInto;

                    // if the range fits in a smaller data type use that instead
                    if let Ok(range) = range.try_into() {
                        let value: $smaller = Uniform::sample(fill, Bound::Unbounded, Bound::Included(&range))?;
                        let value = value as $ty;
                        let value = lower.wrapping_add(value);

                        // make sure we actually generated a correct value in tests
                        if cfg!(test) {
                            assert!((min, max).contains(&value), "{:?} < {} < {:?}", min, value, max);
                        }

                        return Some(value);
                    }
                })?

                let value: $unsigned = Uniform::sample(fill, Bound::Unbounded, Bound::Unbounded)?;

                // TODO make this less biased
                let value = value % range;
                let value = value as $ty;
                let value = lower.wrapping_add(value);

                // make sure we actually generated a correct value in tests
                if cfg!(test) {
                    assert!((min, max).contains(&value), "{:?} < {} < {:?}", min, value, max);
                }

                Some(value)
            }
        }
    };
}

uniform_int!(u8, u8);
uniform_int!(i8, u8);
uniform_int!(u16, u16, u8);
uniform_int!(i16, u16, u8);
uniform_int!(u32, u32, u16);
uniform_int!(i32, u32, u16);
uniform_int!(u64, u64, u32);
uniform_int!(i64, u64, u32);
uniform_int!(u128, u128, u64);
uniform_int!(i128, u128, u64);
uniform_int!(usize, usize, u64);
uniform_int!(isize, usize, u64);

impl Uniform for char {
    #[inline]
    fn sample<F: FillBytes>(fill: &mut F, min: Bound<&Self>, max: Bound<&Self>) -> Option<Self> {
        if fill.mode() == DriverMode::Direct {
            let value = u32::sample(fill, Bound::Unbounded, Bound::Unbounded)?;
            return char::from_u32(value);
        }

        const START: u32 = 0xD800;
        const LEN: u32 = 0xE000 - START;

        fn map_to_u32(c: &char) -> u32 {
            match *c as u32 {
                c if c >= START => c - LEN,
                c => c,
            }
        }

        let lower = BoundExt::map(min, map_to_u32);
        let upper = match max {
            Bound::Excluded(v) => Bound::Excluded(map_to_u32(v)),
            Bound::Included(v) => Bound::Included(map_to_u32(v)),
            Bound::Unbounded => Bound::Included(map_to_u32(&char::MAX)),
        };

        let mut value = u32::sample(fill, BoundExt::as_ref(&lower), BoundExt::as_ref(&upper))?;

        if value >= START {
            value += LEN;
        }

        char::from_u32(value)
    }
}
