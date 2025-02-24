use super::rng::Buffer;
use crate::{
    bounded::BoundExt,
    uniform::{self, Uniform},
};
use alloc::vec::Vec;
use core::ops::{Bound, ControlFlow};

#[derive(Clone, Debug)]
pub struct Driver {
    state: State,
    depth: usize,
    max_depth: usize,
    buffer: Buffer,
}

impl Default for Driver {
    fn default() -> Self {
        Self::new(&super::Options::default())
    }
}

impl Driver {
    pub fn new(options: &super::Options) -> Self {
        Self {
            depth: 0,
            max_depth: options.max_depth_or_default(),
            state: State::default(),
            buffer: Buffer::default(),
        }
    }

    pub fn serialize(&self) -> Vec<u64> {
        self.state.serialize()
    }

    pub fn deserialize(&mut self, state: &[u64]) {
        self.state.deserialize(state);
    }

    pub fn estimate(&self) -> f64 {
        self.state.estimate()
    }

    pub fn step(&mut self) -> ControlFlow<()> {
        self.state.step()
    }

    pub fn replay(&mut self) {
        self.state.cursor = 0;
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Frame {
    value: u64,
    bound: u64,
}

#[derive(Clone, Debug, Default)]
struct State {
    started: bool,
    stack: Vec<Frame>,
    cursor: usize,
    estimate: f64,
}

impl State {
    fn serialize(&self) -> Vec<u64> {
        self.stack.iter().map(|f| f.value).collect()
    }

    fn deserialize(&mut self, state: &[u64]) {
        self.stack.clear();
        self.stack
            .extend(state.iter().map(|&v| Frame { value: v, bound: v }));
        self.cursor = 0;
        self.started = !state.is_empty();
        self.estimate = 1.0;
    }

    fn estimate(&self) -> f64 {
        self.estimate
    }

    fn step(&mut self) -> ControlFlow<()> {
        if !self.started {
            self.started = true;
            self.estimate = 1.0;
            return ControlFlow::Continue(());
        }

        // depth-first search the state space
        for i in (0..self.stack.len()).rev() {
            if self.stack[i].value < self.stack[i].bound {
                self.stack[i].value += 1;
                self.stack.truncate(i + 1);
                self.cursor = 0;
                return ControlFlow::Continue(());
            }
        }

        ControlFlow::Break(())
    }

    /// Returns a value between 0 and `bound` inclusive.
    #[inline]
    fn select(&mut self, bound: u64) -> u64 {
        // no point in tracking this since there's only one option
        if bound == 0 {
            return 0;
        }

        while self.cursor >= self.stack.len() {
            if self.cursor == self.stack.len() {
                self.estimate += bound as f64;
            }

            self.stack.push(Default::default());
        }

        let frame = &mut self.stack[self.cursor];

        self.cursor += 1;

        frame.bound = frame.bound.max(bound);
        frame.value.min(bound)
    }

    #[inline]
    fn select_u128(&mut self, bound: u128) -> u128 {
        // no point in tracking this since it doesn't vary
        if bound == 0 {
            return 0;
        }

        // check if we can generate a value with a single u64
        if bound <= u64::MAX as u128 {
            return self.select(bound as u64) as u128;
        }

        let mut value = self.select(u64::MAX) as u128;
        let bound = bound - u64::MAX as u128;

        // generate the remaining upper bits
        let upper = self.select(bound as u64);

        // shift the upper bits into place
        value |= (upper as u128) << 64;

        value
    }
}

macro_rules! impl_u {
    ($fun:ident, $ty:ident) => {
        #[inline(always)]
        fn $fun(&mut self, min: Bound<&$ty>, max: Bound<&$ty>) -> Option<$ty> {
            let min = BoundExt::map(min, |v| *v as u64);
            let mut max = BoundExt::map(max, |v| *v as u64);
            if max == Bound::Unbounded {
                max = Bound::Included($ty::MAX as _);
            }
            let value = self.gen_u64(min.as_ref(), max.as_ref())?;
            Some(value as $ty)
        }
    };
}

macro_rules! impl_i {
    ($fun:ident, $ty:ident) => {
        #[inline(always)]
        fn $fun(&mut self, min: Bound<&$ty>, max: Bound<&$ty>) -> Option<$ty> {
            let mut min = BoundExt::map(min, |v| *v as i64);
            if min == Bound::Unbounded {
                min = Bound::Included($ty::MIN as _);
            }
            let mut max = BoundExt::map(max, |v| *v as i64);
            if max == Bound::Unbounded {
                max = Bound::Included($ty::MAX as _);
            }
            let value = self.gen_i64(min.as_ref(), max.as_ref())?;
            Some(value as $ty)
        }
    };
}

macro_rules! impl_driver {
    ($ty:ty) => {
        impl super::Driver for $ty {
            #[inline(always)]
            fn depth(&self) -> usize {
                self.depth
            }

            #[inline(always)]
            fn set_depth(&mut self, depth: usize) {
                self.depth = depth;
            }

            #[inline(always)]
            fn max_depth(&self) -> usize {
                self.max_depth
            }

            #[inline(always)]
            fn gen_variant(&mut self, variants: usize, base_case: usize) -> Option<usize> {
                if self.depth == self.max_depth {
                    return Some(base_case);
                }

                self.gen_usize(Bound::Unbounded, Bound::Excluded(&variants))
            }

            impl_u!(gen_u8, u8);
            impl_i!(gen_i8, i8);
            impl_u!(gen_u16, u16);
            impl_i!(gen_i16, i16);
            impl_u!(gen_u32, u32);
            impl_i!(gen_i32, i32);
            impl_u!(gen_usize, usize);
            impl_i!(gen_isize, isize);

            #[inline(always)]
            fn gen_u64(&mut self, min: Bound<&u64>, max: Bound<&u64>) -> Option<u64> {
                let range = Uniform::bounds_to_range(min, max)?;
                let value = self.state.select(*range.end() - *range.start());
                Some(*range.start() + value)
            }

            #[inline(always)]
            fn gen_i64(&mut self, min: Bound<&i64>, max: Bound<&i64>) -> Option<i64> {
                let range = Uniform::bounds_to_range(min, max)?;
                let value = self.state.select((*range.end() - *range.start()) as u64);
                Some(*range.start() + value as i64)
            }

            #[inline(always)]
            fn gen_u128(&mut self, min: Bound<&u128>, max: Bound<&u128>) -> Option<u128> {
                let range = Uniform::bounds_to_range(min, max)?;

                let bound = *range.end() - *range.start();
                let mut value = self.state.select_u128(bound);
                value += *range.start();
                Some(value)
            }

            #[inline(always)]
            fn gen_i128(&mut self, min: Bound<&i128>, max: Bound<&i128>) -> Option<i128> {
                let range = Uniform::bounds_to_range(min, max)?;

                let bound = *range.end() - *range.start();
                let mut value = self.state.select_u128(bound as _) as i128;
                value += *range.start();
                Some(value)
            }

            #[inline(always)]
            fn gen_f32(&mut self, min: Bound<&f32>, max: Bound<&f32>) -> Option<f32> {
                let range = Uniform::bounds_to_range(min, max)?;
                let (lower, upper) = (*range.start(), *range.end());
                let bound = upper.to_bits() - lower.to_bits();
                let value = self.gen_u32(Bound::Unbounded, Bound::Included(&bound))?;
                let value = f32::from_bits(lower.to_bits() + value);
                Some(value)
            }

            #[inline(always)]
            fn gen_f64(&mut self, min: Bound<&f64>, max: Bound<&f64>) -> Option<f64> {
                let range = Uniform::bounds_to_range(min, max)?;
                let (lower, upper) = (*range.start(), *range.end());
                let bound = upper.to_bits() - lower.to_bits();
                let value = self.gen_u64(Bound::Unbounded, Bound::Included(&bound))?;
                let value = f64::from_bits(lower.to_bits() + value);
                Some(value)
            }

            #[inline(always)]
            fn gen_char(&mut self, min: Bound<&char>, max: Bound<&char>) -> Option<char> {
                let range = Uniform::bounds_to_range(min, max)?;
                let lower = Bound::Included(*range.start() as u32);
                let upper = Bound::Included(*range.end() as u32);
                let bytes = self.gen_u32(lower.as_ref(), upper.as_ref())?;
                uniform::char_from_u32(bytes)
            }

            #[inline(always)]
            fn gen_bool(&mut self, _probability: Option<f32>) -> Option<bool> {
                Some(self.state.select(1) == 1)
            }

            #[inline(always)]
            fn gen_from_bytes<Hint, Gen, T>(&mut self, hint: Hint, mut produce: Gen) -> Option<T>
            where
                Hint: FnOnce() -> (usize, Option<usize>),
                Gen: FnMut(&[u8]) -> Option<(usize, T)>,
            {
                let (min, max) = hint();

                let max = max
                    .unwrap_or(usize::MAX)
                    // make sure max is at least min
                    .max(min)
                    .min(Buffer::MAX_CAPACITY);

                let len = self.gen_usize(Bound::Included(&min), Bound::Included(&max))?;
                self.buffer.fill(len, &mut Rng(&mut self.state))?;
                let (_consumed, value) = produce(self.buffer.slice_mut(len))?;
                self.buffer.clear();
                Some(value)
            }
        }
    };
}

impl_driver!(Driver);
impl_driver!(&mut Driver);

struct Rng<'a>(&'a mut State);

impl rand_core::RngCore for Rng<'_> {
    fn next_u32(&mut self) -> u32 {
        self.0.select(u32::MAX as _) as _
    }

    fn next_u64(&mut self) -> u64 {
        self.0.select(u64::MAX)
    }

    fn fill_bytes(&mut self, mut dest: &mut [u8]) {
        while dest.len() >= 8 {
            let (chunk, rest) = dest.split_at_mut(8);
            dest = rest;
            let value = self.next_u64();
            chunk.copy_from_slice(&value.to_be_bytes());
        }

        let value = self.0.select((1 << dest.len()) * 8);
        dest.copy_from_slice(&value.to_be_bytes()[..dest.len()]);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ValueGenerator;

    #[test]
    fn exhaustive_u8_test() {
        let mut driver = Driver::default();

        let mut count = 0usize;
        while driver.step().is_continue() {
            let value = crate::produce::<u8>().generate(&mut driver).unwrap();
            assert_eq!(value as usize, count);
            count += 1;
            eprintln!("{:.2}", count as f64 / driver.estimate() * 100.0);
        }

        assert_eq!(count, 256);
        assert_eq!(driver.estimate(), 256.0);
    }

    #[test]
    fn exhaustive_i8_test() {
        let mut driver = Driver::default();

        let mut count = 0usize;
        let mut expected = -128i16;
        while driver.step().is_continue() {
            let value = crate::produce::<i8>().generate(&mut driver).unwrap();
            assert_eq!(value as i16, expected);
            count += 1;
            expected += 1;
            eprintln!("{:.2}", count as f64 / driver.estimate() * 100.0);
        }

        assert_eq!(count, 256);
        assert_eq!(driver.estimate(), 256.0);
    }

    #[test]
    fn exhaustive_range_test() {
        let mut driver = Driver::default();

        let mut count = 0;
        while driver.step().is_continue() {
            let range = 3..=5;

            for _ in 0..3 {
                let value = range.generate(&mut driver).unwrap();
                assert!(range.contains(&value));
            }

            count += 1;
            eprintln!("{:.2}", count as f64 / driver.estimate() * 100.0);
        }

        assert_eq!(count, 27);
        assert_eq!(driver.estimate(), 27.0);
    }

    #[test]
    fn exhaustive_float_test() {
        let mut driver = Driver::default();

        let range = 0.1f32..=0.101;
        let mut count = 0;
        while driver.step().is_continue() {
            let value = range.generate(&mut driver).unwrap();
            assert!(range.contains(&value));
            count += 1;
        }

        assert_eq!(count, range.end().to_bits() - range.start().to_bits() + 1);
    }
}
