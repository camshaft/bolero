use alloc::{
    boxed::Box,
    collections::{btree_map::Entry as MapEntry, BTreeMap},
    vec::Vec,
};
use core::{
    any::{Any, TypeId},
    fmt,
    ops::Bound,
};

pub struct Cache {
    max_total_entries: usize,
    total_entries: usize,
    max_entries: usize,
    entries: BTreeMap<TypeId, Box<dyn Any>>,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            max_total_entries: usize::MAX,
            total_entries: 0,
            max_entries: 1024,
            entries: Default::default(),
        }
    }
}

impl fmt::Debug for Cache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cache")
            .field("total_entries", &self.total_entries)
            .finish()
    }
}

impl core::panic::RefUnwindSafe for Cache {}

impl Cache {
    #[inline]
    pub fn put<T: 'static>(&mut self, value: T) {
        if self.total_entries >= self.max_total_entries {
            return;
        }

        let id = TypeId::of::<Vec<T>>();

        match self.entries.entry(id) {
            MapEntry::Occupied(mut queue) => {
                let queue = queue.get_mut();

                let queue = unsafe { &mut *(queue as *mut Box<dyn Any> as *mut Box<Vec<T>>) };

                if queue.len() >= self.max_entries {
                    return;
                }

                queue.push(value);
            }
            MapEntry::Vacant(queue) => {
                queue.insert(Box::new(alloc::vec![value]));
            }
        };

        self.total_entries += 1;
    }

    #[inline]
    pub fn get<T: 'static>(&mut self) -> Option<T> {
        if self.total_entries == 0 {
            return None;
        }

        let id = TypeId::of::<Vec<T>>();
        let queue = self.entries.get_mut(&id)?;
        let queue = unsafe { &mut *(queue as *mut Box<dyn Any> as *mut Box<Vec<T>>) };
        let value = queue.pop()?;
        self.total_entries -= 1;
        Some(value)
    }
}

pub struct Driver<'a, I: super::Driver> {
    cache: &'a mut Cache,
    inner: I,
}

impl<'a, I: super::Driver> Driver<'a, I> {
    #[inline]
    pub fn new(inner: I, cache: &'a mut Cache) -> Self {
        Self { cache, inner }
    }
}

impl<I: super::Driver> AsRef<I> for Driver<'_, I> {
    #[inline]
    fn as_ref(&self) -> &I {
        &self.inner
    }
}

impl<I: super::Driver> super::Driver for Driver<'_, I> {
    #[inline(always)]
    fn depth(&self) -> usize {
        self.inner.depth()
    }

    #[inline(always)]
    fn set_depth(&mut self, depth: usize) {
        self.inner.set_depth(depth)
    }

    #[inline(always)]
    fn max_depth(&self) -> usize {
        self.inner.max_depth()
    }

    #[inline(always)]
    fn gen_variant(&mut self, variants: usize, base_case: usize) -> Option<usize> {
        self.inner.gen_variant(variants, base_case)
    }

    #[inline(always)]
    fn gen_u8(&mut self, min: Bound<&u8>, max: Bound<&u8>) -> Option<u8> {
        self.inner.gen_u8(min, max)
    }

    #[inline(always)]
    fn gen_i8(&mut self, min: Bound<&i8>, max: Bound<&i8>) -> Option<i8> {
        self.inner.gen_i8(min, max)
    }

    #[inline(always)]
    fn gen_u16(&mut self, min: Bound<&u16>, max: Bound<&u16>) -> Option<u16> {
        self.inner.gen_u16(min, max)
    }

    #[inline(always)]
    fn gen_i16(&mut self, min: Bound<&i16>, max: Bound<&i16>) -> Option<i16> {
        self.inner.gen_i16(min, max)
    }

    #[inline(always)]
    fn gen_u32(&mut self, min: Bound<&u32>, max: Bound<&u32>) -> Option<u32> {
        self.inner.gen_u32(min, max)
    }

    #[inline(always)]
    fn gen_i32(&mut self, min: Bound<&i32>, max: Bound<&i32>) -> Option<i32> {
        self.inner.gen_i32(min, max)
    }

    #[inline(always)]
    fn gen_u64(&mut self, min: Bound<&u64>, max: Bound<&u64>) -> Option<u64> {
        self.inner.gen_u64(min, max)
    }

    #[inline(always)]
    fn gen_i64(&mut self, min: Bound<&i64>, max: Bound<&i64>) -> Option<i64> {
        self.inner.gen_i64(min, max)
    }

    #[inline(always)]
    fn gen_u128(&mut self, min: Bound<&u128>, max: Bound<&u128>) -> Option<u128> {
        self.inner.gen_u128(min, max)
    }

    #[inline(always)]
    fn gen_i128(&mut self, min: Bound<&i128>, max: Bound<&i128>) -> Option<i128> {
        self.inner.gen_i128(min, max)
    }

    #[inline(always)]
    fn gen_usize(&mut self, min: Bound<&usize>, max: Bound<&usize>) -> Option<usize> {
        self.inner.gen_usize(min, max)
    }

    #[inline(always)]
    fn gen_isize(&mut self, min: Bound<&isize>, max: Bound<&isize>) -> Option<isize> {
        self.inner.gen_isize(min, max)
    }

    #[inline(always)]
    fn gen_f32(&mut self, min: Bound<&f32>, max: Bound<&f32>) -> Option<f32> {
        self.inner.gen_f32(min, max)
    }

    #[inline(always)]
    fn gen_f64(&mut self, min: Bound<&f64>, max: Bound<&f64>) -> Option<f64> {
        self.inner.gen_f64(min, max)
    }

    #[inline(always)]
    fn gen_char(&mut self, min: Bound<&char>, max: Bound<&char>) -> Option<char> {
        self.inner.gen_char(min, max)
    }

    #[inline(always)]
    fn gen_bool(&mut self, probability: Option<f32>) -> Option<bool> {
        self.inner.gen_bool(probability)
    }

    #[inline(always)]
    fn gen_from_bytes<Hint, Gen, T>(&mut self, hint: Hint, gen: Gen) -> Option<T>
    where
        Hint: FnOnce() -> (usize, Option<usize>),
        Gen: FnMut(&[u8]) -> Option<(usize, T)>,
    {
        self.inner.gen_from_bytes(hint, gen)
    }

    #[inline(always)]
    fn cache_put<T: 'static>(&mut self, value: T) {
        self.cache.put(value);
    }

    #[inline(always)]
    fn cache_get<T: 'static>(&mut self) -> Option<T> {
        self.cache.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_test() {
        let mut cache = Cache::default();

        cache.put(123usize);
        assert_eq!(cache.get(), Some(123usize));
        assert_eq!(cache.get::<usize>(), None);
    }
}
