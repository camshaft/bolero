use crate::bounded::BoundExt;
use core::ops::{Bound, RangeBounds, RangeInclusive};

pub trait Uniform: Sized + PartialEq + PartialOrd {
    fn bounds_to_range(min: Bound<&Self>, max: Bound<&Self>) -> Option<RangeInclusive<Self>>;
    fn sample<F: FillBytes>(fill: &mut F, min: Bound<&Self>, max: Bound<&Self>) -> Option<Self>;
    fn sample_unbound<F: FillBytes>(fill: &mut F) -> Option<Self>;
}

macro_rules! fill_bytes_sample {
    ($name:ident, $ty:ty) => {
        #[inline(always)]
        fn $name(&mut self) -> Option<$ty> {
            let mut bytes = [0u8; core::mem::size_of::<$ty>()];
            self.fill_bytes(&mut bytes)?;
            Some(<$ty>::from_le_bytes(bytes))
        }
    };
}

pub trait FillBytes {
    const SHOULD_SHRINK: bool = true;

    fn peek_bytes(&mut self, offset: usize, bytes: &mut [u8]) -> Option<()>;
    fn consume_bytes(&mut self, consumed: usize);

    fill_bytes_sample!(sample_u8, u8);
    fill_bytes_sample!(sample_i8, i8);
    fill_bytes_sample!(sample_u16, u16);
    fill_bytes_sample!(sample_i16, i16);
    fill_bytes_sample!(sample_u32, u32);
    fill_bytes_sample!(sample_i32, i32);
    fill_bytes_sample!(sample_u64, u64);
    fill_bytes_sample!(sample_i64, i64);
    fill_bytes_sample!(sample_u128, u128);
    fill_bytes_sample!(sample_i128, i128);
    fill_bytes_sample!(sample_usize, usize);
    fill_bytes_sample!(sample_isize, isize);

    #[inline(always)]
    fn sample_bool(&mut self) -> Option<bool> {
        let value = self.sample_u8()?;
        Some(value < (u8::MAX / 2))
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Option<()> {
        self.peek_bytes(0, bytes)?;
        self.consume_bytes(bytes.len());
        Some(())
    }
}

macro_rules! uniform_int {
    ($sample:ident, $ty:ident, $unsigned:ident $(, $smaller:ident)*) => {
        impl Uniform for $ty {
            #[inline(always)]
            fn bounds_to_range(min: Bound<&$ty>, max: Bound<&$ty>) -> Option<RangeInclusive<$ty>> {
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
                        return Some($ty::MIN..=$ty::MAX);
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

                Some(lower..=upper)
            }

            #[inline(always)]
            fn sample_unbound<F: FillBytes>(fill: &mut F) -> Option<$ty> {
                fill.$sample()
            }

            #[inline]
            fn sample<F: FillBytes>(fill: &mut F, min: Bound<&$ty>, max: Bound<&$ty>) -> Option<$ty> {
                let range = Self::bounds_to_range(min, max)?;
                let (lower, upper) = (*range.start(), *range.end());

                // if the bounds includes everything then just sample the whole range
                if lower == $ty::MIN && upper == $ty::MAX {
                    return Self::sample_unbound(fill);
                }

                let range_inclusive = upper.wrapping_sub(lower) as $unsigned;

                if range_inclusive == 0 {
                    return Some(lower);
                }

                // try to shrink the range if the FillBytes says we should
                if F::SHOULD_SHRINK {
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
                }

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

uniform_int!(sample_u8, u8, u8);
uniform_int!(sample_i8, i8, u8);
uniform_int!(sample_u16, u16, u16, u8);
uniform_int!(sample_i16, i16, u16, u8);
uniform_int!(sample_u32, u32, u32, u8, u16);
uniform_int!(sample_i32, i32, u32, u8, u16);
uniform_int!(sample_u64, u64, u64, u8, u16, u32);
uniform_int!(sample_i64, i64, u64, u8, u16, u32);
uniform_int!(sample_usize, usize, usize, u8, u16, u32);
uniform_int!(sample_isize, isize, usize, u8, u16, u32);
uniform_int!(sample_u128, u128, u128, u8, u16, u32, u64);
uniform_int!(sample_i128, i128, u128, u8, u16, u32, u64);

macro_rules! uniform_float {
    ($ty:ident) => {
        impl Uniform for $ty {
            #[inline]
            fn bounds_to_range(
                min: Bound<&Self>,
                max: Bound<&Self>,
            ) -> Option<RangeInclusive<Self>> {
                let min = BoundExt::map(min, |&v| v.to_bits());
                let max = BoundExt::map(max, |&v| v.to_bits());
                let range = Uniform::bounds_to_range(min.as_ref(), max.as_ref())?;
                let (lower, upper) = (*range.start(), *range.end());
                let lower = Self::from_bits(lower);
                let upper = Self::from_bits(upper);
                Some(lower..=upper)
            }

            #[inline]
            fn sample<F: FillBytes>(
                fill: &mut F,
                min: Bound<&Self>,
                max: Bound<&Self>,
            ) -> Option<Self> {
                let range = Self::bounds_to_range(min, max)?;
                let (lower, upper) = (*range.start(), *range.end());
                let bound = upper.to_bits() - lower.to_bits();
                let value = Uniform::sample(fill, Bound::Unbounded, Bound::Included(&bound))?;
                let value = Self::from_bits(lower.to_bits() + value);
                Some(value)
            }

            #[inline]
            fn sample_unbound<F: FillBytes>(fill: &mut F) -> Option<Self> {
                Some(Self::from_bits(Uniform::sample_unbound(fill)?))
            }
        }
    };
}

uniform_float!(f32);
uniform_float!(f64);

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

const CHAR_START: u32 = 0xD800;
const CHAR_LEN: u32 = 0xE000 - CHAR_START;

#[inline]
pub(crate) fn char_from_u32(mut value: u32) -> Option<char> {
    if value >= CHAR_START {
        value += CHAR_LEN;
    }

    char::from_u32(value)
}

impl Uniform for char {
    fn bounds_to_range(min: Bound<&Self>, max: Bound<&Self>) -> Option<RangeInclusive<Self>> {
        #[inline]
        fn map_to_u32(c: &char) -> u32 {
            match *c as u32 {
                c if c >= CHAR_START => c - CHAR_LEN,
                c => c,
            }
        }

        let lower = BoundExt::map(min, map_to_u32);
        let upper = match max {
            Bound::Excluded(v) => Bound::Excluded(map_to_u32(v)),
            Bound::Included(v) => Bound::Included(map_to_u32(v)),
            Bound::Unbounded => Bound::Included(map_to_u32(&char::MAX)),
        };

        let range = u32::bounds_to_range(BoundExt::as_ref(&lower), BoundExt::as_ref(&upper))?;
        let (start, end) = (*range.start(), *range.end());
        let start = char::from_u32(start)?;
        let end = char::from_u32(end)?;
        Some(start..=end)
    }

    #[inline(always)]
    fn sample_unbound<F: FillBytes>(fill: &mut F) -> Option<Self> {
        Self::sample(fill, Bound::Unbounded, Bound::Unbounded)
    }

    #[inline]
    fn sample<F: FillBytes>(fill: &mut F, min: Bound<&Self>, max: Bound<&Self>) -> Option<Self> {
        let range = Self::bounds_to_range(min, max)?;
        let lower = Bound::Included(*range.start() as u32);
        let upper = Bound::Included(*range.end() as u32);

        let bytes = u32::sample(fill, BoundExt::as_ref(&lower), BoundExt::as_ref(&upper))?;

        let value = char_from_u32(bytes);

        if cfg!(test) {
            assert!(value.is_some(), "invalid value generated: {}", bytes);
        }

        value
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::redundant_closure_call)]

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
    }

    impl FillBytes for Byte {
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

    fn range_test<T: SeenValue>(map: impl Fn(u8, u8) -> (Bound<T>, Bound<T>)) {
        for min in 0..=T::ENTRIES {
            for max in 0..=T::ENTRIES {
                let (min_b, max_b) = map(min as _, max as _);
                let mut expected = Seen::default();
                T::fill_expected(min_b, max_b, &mut expected);

                let min_b = BoundExt::as_ref(&min_b);
                let max_b = BoundExt::as_ref(&max_b);

                let mut actual = Seen::default();
                for seed in 0..=T::ENTRIES {
                    let mut driver = Byte {
                        value: Some(seed as _),
                    };
                    let result = T::sample(&mut driver, min_b, max_b);
                    if let Some(value) = result {
                        assert!(
                            (min_b, max_b).contains(&value),
                            "generated value ({:?}) outside of bounds ({:?}, {:?})",
                            value,
                            min_b,
                            max_b,
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

                // Inclusive
                #[test]
                fn inclusive_inclusive() {
                    range_test(|min, max| {
                        (Bound::Included(($map)(min)), Bound::Included(($map)(max)))
                    });
                }

                #[test]
                fn inclusive_exclusive() {
                    range_test(|min, max| {
                        (Bound::Included(($map)(min)), Bound::Excluded(($map)(max)))
                    });
                }

                #[test]
                fn inclusive_unbounded() {
                    range_test(|min, _max| (Bound::Included(($map)(min)), Bound::Unbounded));
                }

                // Exclusive
                #[test]
                fn exclusive_inclusive() {
                    range_test(|min, max| {
                        (Bound::Excluded(($map)(min)), Bound::Included(($map)(max)))
                    });
                }

                #[test]
                fn exclusive_exclusive() {
                    range_test(|min, max| {
                        (Bound::Excluded(($map)(min)), Bound::Excluded(($map)(max)))
                    });
                }

                #[test]
                fn exclusive_unbounded() {
                    range_test(|min, _max| (Bound::Excluded(($map)(min)), Bound::Unbounded));
                }

                // Unbounded
                #[test]
                fn unbounded_inclusive() {
                    range_test(|_min, max| (Bound::Unbounded, Bound::Included(($map)(max))));
                }

                #[test]
                fn unbounded_exclusive() {
                    range_test(|_min, max| (Bound::Unbounded, Bound::Excluded(($map)(max))));
                }

                #[test]
                fn unbounded_unbounded() {
                    range_test(|_min, _max| (<Bound<$ty>>::Unbounded, Bound::Unbounded));
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
