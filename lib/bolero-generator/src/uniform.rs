use crate::{bounded::BoundExt, driver::DriverMode};
use core::ops::{Bound, RangeBounds};

pub trait Uniform: Sized + PartialEq + Eq + PartialOrd + Ord {
    fn sample<F: FillBytes>(fill: &mut F, min: Bound<&Self>, max: Bound<&Self>) -> Option<Self>;
    fn sample_unbound<F: FillBytes>(fill: &mut F) -> Option<Self>;
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
    ($ty:ident, $unsigned:ident $(, $smaller:ident)*) => {
        impl Uniform  for $ty {
            #[inline(always)]
            fn sample_unbound<F: FillBytes>(fill: &mut F) -> Option<$ty> {
                let mut bytes = [0u8; core::mem::size_of::<$ty>()];
                fill.fill_bytes(&mut bytes)?;
                return Some(<$ty>::from_le_bytes(bytes));
            }

            #[inline]
            fn sample<F: FillBytes>(fill: &mut F, min: Bound<&$ty>, max: Bound<&$ty>) -> Option<$ty> {
                match (min, max) {
                    // filter invalid ranges
                    (Bound::Unbounded, Bound::Excluded(&$ty::MIN)) | (Bound::Excluded(&$ty::MAX), Bound::Unbounded)  => {
                        return None;
                    }
                    (Bound::Included(&x), Bound::Included(&y)) if x > y  => {
                        return None;
                    }
                    (Bound::Included(&x), Bound::Excluded(&y)) if x >= y  => {
                        return None;
                    }
                    (Bound::Excluded(&x), Bound::Included(&y)) if x >= y  => {
                        return None;
                    }
                    (Bound::Excluded(&x), Bound::Excluded(&y)) if x.saturating_add(1) >= y  => {
                        return None;
                    }
                    // full ranges
                    (Bound::Unbounded, Bound::Unbounded)
                    | (Bound::Unbounded, Bound::Included(&$ty::MAX))
                    | (Bound::Included(&$ty::MIN), Bound::Unbounded)
                    | (Bound::Included(&$ty::MIN), Bound::Included(&$ty::MAX)) => {
                        return Self::sample_unbound(fill);
                    }
                    _ => {}
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

                let range_inclusive = upper.wrapping_sub(lower) as $unsigned;

                if range_inclusive == 0 {
                    return Some(lower);
                }

                $({
                    // if the range fits in a smaller data type use that instead
                    if let Ok(range_inclusive) = range_inclusive.try_into() {
                        let value: $smaller = Uniform::sample(fill, Bound::Unbounded, Bound::Included(&range_inclusive))?;
                        let value = value as $ty;
                        let value = lower.wrapping_add(value);

                        // make sure we actually generated a correct value in tests
                        if cfg!(test) {
                            assert!((min, max).contains(&value), "{:?} < {} < {:?}", min, value, max);
                        }

                        return Some(value);
                    }
                })*

                let value: $unsigned = Uniform::sample_unbound(fill)?;

                if cfg!(test) {
                    assert!(range_inclusive < $unsigned::MAX, "range inclusive should always be less than the max value");
                }
                let range_exclusive = range_inclusive.wrapping_add(1);
                let value = value.scale(range_exclusive);
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
uniform_int!(u32, u32, u8, u16);
uniform_int!(i32, u32, u8, u16);
uniform_int!(u64, u64, u8, u16, u32);
uniform_int!(i64, u64, u8, u16, u32);
uniform_int!(usize, usize, u8, u16, u32);
uniform_int!(isize, usize, u8, u16, u32);
uniform_int!(u128, u128, u8, u16, u32, u64);
uniform_int!(i128, u128, u8, u16, u32, u64);

trait Scaled: Sized {
    fn scale(self, range: Self) -> Self;
}

macro_rules! scaled {
    ($s:ty, $upper:ty) => {
        impl Scaled for $s {
            #[inline(always)]
            fn scale(self, range: Self) -> Self {
                // similar approach to Lemire random sampling
                // see https://lemire.me/blog/2019/06/06/nearly-divisionless-random-integer-generation-on-various-systems/
                let m = self as $upper * range as $upper;
                (m >> Self::BITS) as Self
            }
        }
    };
}

scaled!(u8, u16);
scaled!(u16, u32);
scaled!(u32, u64);
scaled!(u64, u128);
scaled!(usize, u128);

impl Scaled for u128 {
    #[inline(always)]
    fn scale(self, range: Self) -> Self {
        // adapted from mulddi3 https://github.com/llvm/llvm-project/blob/6a3982f8b7e37987659706cb3e6427c54c9bc7ce/compiler-rt/lib/builtins/multi3.c#L19
        const BITS_IN_DWORD_2: u32 = 64;
        const LOWER_MASK: u128 = u128::MAX >> BITS_IN_DWORD_2;

        let a = self;
        let b = range;

        let mut low = (a & LOWER_MASK) * (b & LOWER_MASK);
        let mut t = low >> BITS_IN_DWORD_2;
        low &= LOWER_MASK;
        t += (a >> BITS_IN_DWORD_2) * (b & LOWER_MASK);
        low += (t & LOWER_MASK) << BITS_IN_DWORD_2;
        let mut high = t >> BITS_IN_DWORD_2;
        t = low >> BITS_IN_DWORD_2;
        low &= LOWER_MASK;
        t += (b >> BITS_IN_DWORD_2) * (a & LOWER_MASK);
        low += (t & LOWER_MASK) << BITS_IN_DWORD_2;
        high += t >> BITS_IN_DWORD_2;
        high += (a >> BITS_IN_DWORD_2) * (b >> BITS_IN_DWORD_2);

        // discard the low bits
        let _ = low;

        high
    }
}

impl Uniform for char {
    #[inline(always)]
    fn sample_unbound<F: FillBytes>(fill: &mut F) -> Option<Self> {
        Self::sample(fill, Bound::Unbounded, Bound::Unbounded)
    }

    #[inline]
    fn sample<F: FillBytes>(fill: &mut F, min: Bound<&Self>, max: Bound<&Self>) -> Option<Self> {
        const START: u32 = 0xD800;
        const LEN: u32 = 0xE000 - START;

        #[inline]
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

        if cfg!(test) {
            assert!(
                char::from_u32(value).is_some(),
                "invalid value generated: {}",
                value
            );
        }

        char::from_u32(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt;

    #[test]
    fn scaled_u128_test() {
        assert_eq!(0u128.scale(3), 0);
        assert_eq!(u128::MAX.scale(3), 2);
        assert_eq!((u128::MAX - 1).scale(3), 2);
        assert_eq!((u128::MAX / 2).scale(3), 1);
    }

    #[derive(Clone, Copy, Debug)]
    struct Byte {
        value: Option<u8>,
        driver_mode: DriverMode,
    }

    impl FillBytes for Byte {
        fn mode(&self) -> DriverMode {
            self.driver_mode
        }

        fn peek_bytes(&mut self, offset: usize, bytes: &mut [u8]) -> Option<()> {
            if offset > 0 {
                return None;
            }

            match (bytes.len(), self.value) {
                (0, Some(_)) => Some(()),
                (1, Some(value)) => {
                    bytes[0] = value;
                    Some(())
                }
                _ => None,
            }
        }

        fn consume_bytes(&mut self, consumed: usize) {
            match consumed {
                0 => {}
                1 => self.value = None,
                _ => panic!(),
            }
        }
    }

    #[derive(Clone, Copy, PartialEq)]
    struct Seen<T: SeenValue>([bool; 256], core::marker::PhantomData<T>);

    impl<T: SeenValue> Default for Seen<T> {
        fn default() -> Self {
            Self([false; 256], Default::default())
        }
    }

    impl<T: SeenValue> fmt::Debug for Seen<T> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_list()
                .entries(
                    self.0
                        .iter()
                        .enumerate()
                        .filter_map(|(idx, seen)| if *seen { Some(idx) } else { None }),
                )
                .finish()
        }
    }

    impl<T: SeenValue> Seen<T> {
        fn insert(&mut self, v: T) {
            self.0[v.index()] = true;
        }
    }

    trait SeenValue: Copy + Uniform + core::fmt::Debug {
        const ENTRIES: usize;

        fn index(self) -> usize;
        fn fill_expected(min: Bound<Self>, max: Bound<Self>, seen: &mut Seen<Self>);
    }

    impl SeenValue for u8 {
        const ENTRIES: usize = 256;

        fn index(self) -> usize {
            self as _
        }

        fn fill_expected(min: Bound<Self>, max: Bound<Self>, seen: &mut Seen<Self>) {
            for value in Self::MIN..=Self::MAX {
                if (min, max).contains(&value) {
                    seen.insert(value);
                }
            }
        }
    }

    impl SeenValue for i8 {
        const ENTRIES: usize = 256;

        fn index(self) -> usize {
            (self as isize + -(i8::MIN as isize)).try_into().unwrap()
        }

        fn fill_expected(min: Bound<Self>, max: Bound<Self>, seen: &mut Seen<Self>) {
            for value in Self::MIN..=Self::MAX {
                if (min, max).contains(&value) {
                    seen.insert(value);
                }
            }
        }
    }

    fn range_test<T: SeenValue>(
        driver_mode: DriverMode,
        map: impl Fn(u8, u8) -> (Bound<T>, Bound<T>),
    ) {
        for min in 0..=255 {
            for max in 0..=255 {
                let (min_b, max_b) = map(min, max);
                let mut expected = Seen::default();
                T::fill_expected(min_b, max_b, &mut expected);

                let min_b = BoundExt::as_ref(&min_b);
                let max_b = BoundExt::as_ref(&max_b);

                let mut actual = Seen::default();
                for seed in 0..=255 {
                    let mut driver = Byte {
                        value: Some(seed),
                        driver_mode,
                    };
                    let result = T::sample(&mut driver, min_b, max_b);
                    if let Some(value) = result {
                        assert!(
                            (min_b, max_b).contains(&value),
                            "generated value ({:?}) outside of bounds ({:?}, {:?}) in {:?}",
                            value,
                            min_b,
                            max_b,
                            driver_mode,
                        );
                        actual.insert(value);
                    }
                }

                assert_eq!(&expected, &actual, "min: {:?}, max: {:?}", min_b, max_b);
            }
        }
    }

    macro_rules! range_tests {
        ($name:ident, $ty:ident, $map:expr) => {
            mod $name {
                use super::*;

                range_tests!(Direct, direct, $ty, $map);
                range_tests!(Forced, forced, $ty, $map);
            }
        };
        ($mode:ident, $name:ident, $ty:ident, $map:expr) => {
            mod $name {
                use super::*;

                // Inclusive
                #[test]
                fn inclusive_inclusive() {
                    range_test(DriverMode::$mode, |min, max| {
                        (Bound::Included(($map)(min)), Bound::Included(($map)(max)))
                    });
                }

                #[test]
                fn inclusive_exclusive() {
                    range_test(DriverMode::$mode, |min, max| {
                        (Bound::Included(($map)(min)), Bound::Excluded(($map)(max)))
                    });
                }

                #[test]
                fn inclusive_unbounded() {
                    range_test(DriverMode::$mode, |min, _max| {
                        (Bound::Included(($map)(min)), Bound::Unbounded)
                    });
                }

                // Exclusive
                #[test]
                fn exclusive_inclusive() {
                    range_test(DriverMode::$mode, |min, max| {
                        (Bound::Excluded(($map)(min)), Bound::Included(($map)(max)))
                    });
                }

                #[test]
                fn exclusive_exclusive() {
                    range_test(DriverMode::$mode, |min, max| {
                        (Bound::Excluded(($map)(min)), Bound::Excluded(($map)(max)))
                    });
                }

                #[test]
                fn exclusive_unbounded() {
                    range_test(DriverMode::$mode, |min, _max| {
                        (Bound::Excluded(($map)(min)), Bound::Unbounded)
                    });
                }

                // Unbounded
                #[test]
                fn unbounded_inclusive() {
                    range_test(DriverMode::$mode, |_min, max| {
                        (Bound::Unbounded, Bound::Included(($map)(max)))
                    });
                }

                #[test]
                fn unbounded_exclusive() {
                    range_test(DriverMode::$mode, |_min, max| {
                        (Bound::Unbounded, Bound::Excluded(($map)(max)))
                    });
                }

                #[test]
                fn unbounded_unbounded() {
                    range_test(DriverMode::$mode, |_min, _max| {
                        (<Bound<$ty>>::Unbounded, Bound::Unbounded)
                    });
                }
            }
        };
    }

    range_tests!(unsigned, u8, |value| value);
    range_tests!(signed, i8, |value| -> i8 {
        // shift the u8 into the i8 range
        (value as i16 - -(i8::MIN as i16)).try_into().unwrap()
    });
}
