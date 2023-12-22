use crate::ValueGenerator;
use alloc::{collections::VecDeque, vec::Vec};
use core::{fmt, ops::Bound};

pub trait Output {
    fn push_front(&mut self, choice: u32);
    fn finish(&mut self);
}

impl Output for Vec<u32> {
    fn push_front(&mut self, choice: u32) {
        self.push(choice);
    }

    fn finish(&mut self) {
        self.reverse();
    }
}

impl Output for VecDeque<u32> {
    fn push_front(&mut self, choice: u32) {
        (*self).push_front(choice)
    }

    fn finish(&mut self) {}
}

#[derive(Clone, Default)]
pub struct Selection {
    path: Vec<u32>,
}

impl fmt::Debug for Selection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl Selection {
    pub fn with_driver<'a, D: crate::Driver>(&'a self, driver: &'a mut D) -> Driver<'a, D> {
        Driver {
            path: &self.path,
            driver,
        }
    }

    pub fn clear(&mut self) {
        self.path.clear();
    }

    pub fn len(&self) -> usize {
        self.path.len()
    }

    pub fn is_empty(&self) -> bool {
        self.path.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.path.iter().map(|v| *v as usize).rev()
    }
}

impl Output for Selection {
    fn push_front(&mut self, choice: u32) {
        self.path.push(choice);
    }

    fn finish(&mut self) {
        // we iterate in reverse later to avoid having to reverse here
    }
}

pub struct Driver<'a, D: crate::Driver> {
    path: &'a [u32],
    driver: &'a mut D,
}

impl<'a, D: crate::Driver> crate::Driver for Driver<'a, D> {
    #[inline]
    fn depth(&self) -> usize {
        self.driver.depth()
    }

    #[inline]
    fn set_depth(&mut self, depth: usize) {
        self.driver.set_depth(depth);
    }

    #[inline]
    fn max_depth(&self) -> usize {
        self.driver.max_depth()
    }

    #[inline]
    fn gen_variant(&mut self, variants: usize, _base_case: usize) -> Option<usize> {
        let (variant, rest) = self.path.split_last()?;
        let variant = *variant as usize;
        debug_assert!(variant < variants);
        self.path = rest;
        Some(variant)
    }

    #[inline]
    fn enter_list<Output, F, L, R>(&mut self, _lens: &L, mut f: F) -> Option<R>
    where
        F: FnMut(&mut Self, usize) -> Option<R>,
        L: ValueGenerator<Output = usize>,
    {
        let len = self.gen_variant(usize::MAX, 0)?;
        self.depth_guard(|driver| f(driver, len))
    }

    #[inline]
    fn gen_u8(&mut self, min: Bound<&u8>, max: Bound<&u8>) -> Option<u8> {
        self.driver.gen_u8(min, max)
    }

    #[inline]
    fn gen_i8(&mut self, min: Bound<&i8>, max: Bound<&i8>) -> Option<i8> {
        self.driver.gen_i8(min, max)
    }

    #[inline]
    fn gen_u16(&mut self, min: Bound<&u16>, max: Bound<&u16>) -> Option<u16> {
        self.driver.gen_u16(min, max)
    }

    #[inline]
    fn gen_i16(&mut self, min: Bound<&i16>, max: Bound<&i16>) -> Option<i16> {
        self.driver.gen_i16(min, max)
    }

    #[inline]
    fn gen_u32(&mut self, min: Bound<&u32>, max: Bound<&u32>) -> Option<u32> {
        self.driver.gen_u32(min, max)
    }

    #[inline]
    fn gen_i32(&mut self, min: Bound<&i32>, max: Bound<&i32>) -> Option<i32> {
        self.driver.gen_i32(min, max)
    }

    #[inline]
    fn gen_u64(&mut self, min: Bound<&u64>, max: Bound<&u64>) -> Option<u64> {
        self.driver.gen_u64(min, max)
    }

    #[inline]
    fn gen_i64(&mut self, min: Bound<&i64>, max: Bound<&i64>) -> Option<i64> {
        self.driver.gen_i64(min, max)
    }

    #[inline]
    fn gen_u128(&mut self, min: Bound<&u128>, max: Bound<&u128>) -> Option<u128> {
        self.driver.gen_u128(min, max)
    }

    #[inline]
    fn gen_i128(&mut self, min: Bound<&i128>, max: Bound<&i128>) -> Option<i128> {
        self.driver.gen_i128(min, max)
    }

    #[inline]
    fn gen_usize(&mut self, min: Bound<&usize>, max: Bound<&usize>) -> Option<usize> {
        self.driver.gen_usize(min, max)
    }

    #[inline]
    fn gen_isize(&mut self, min: Bound<&isize>, max: Bound<&isize>) -> Option<isize> {
        self.driver.gen_isize(min, max)
    }

    #[inline]
    fn gen_f32(&mut self, min: Bound<&f32>, max: Bound<&f32>) -> Option<f32> {
        self.driver.gen_f32(min, max)
    }

    #[inline]
    fn gen_f64(&mut self, min: Bound<&f64>, max: Bound<&f64>) -> Option<f64> {
        self.driver.gen_f64(min, max)
    }

    #[inline]
    fn gen_char(&mut self, min: Bound<&char>, max: Bound<&char>) -> Option<char> {
        self.driver.gen_char(min, max)
    }

    #[inline]
    fn gen_bool(&mut self, probability: Option<f32>) -> Option<bool> {
        self.driver.gen_bool(probability)
    }

    #[inline]
    fn gen_from_bytes<Hint, Gen, T>(&mut self, hint: Hint, gen: Gen) -> Option<T>
    where
        Hint: FnOnce() -> (usize, Option<usize>),
        Gen: FnMut(&[u8]) -> Option<(usize, T)>,
    {
        // TODO override the hint with the selected choice
        todo!()
    }

    #[inline]
    fn cache_get<T: 'static>(&mut self) -> Option<T> {
        self.driver.cache_get()
    }

    #[inline]
    fn cache_put<T: 'static>(&mut self, value: T) {
        self.driver.cache_put(value)
    }
}
