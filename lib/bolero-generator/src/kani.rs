use crate::TypeGenerator;
use core::ops::{Bound, RangeBounds};

pub struct Driver {
    pub(crate) depth: usize,
    pub(crate) max_depth: usize,
}

impl Default for Driver {
    #[inline]
    fn default() -> Self {
        Self::new(&crate::driver::Options::default())
    }
}

impl Driver {
    #[inline]
    pub fn new(options: &crate::driver::Options) -> Self {
        Self {
            depth: 0,
            max_depth: options.max_depth_or_default(),
        }
    }
}

macro_rules! produce {
    ($name:ident, $ty:ident) => {
        #[inline(always)]
        fn $name(&mut self, min: Bound<&$ty>, max: Bound<&$ty>) -> Option<$ty> {
            let value: $ty = shim::any();
            shim::assume((min, max).contains(&value));
            Some(value)
        }
    };
}

impl crate::Driver for Driver {
    produce!(gen_u8, u8);

    produce!(gen_i8, i8);

    produce!(gen_u16, u16);

    produce!(gen_i16, i16);

    produce!(gen_u32, u32);

    produce!(gen_i32, i32);

    produce!(gen_u64, u64);

    produce!(gen_i64, i64);

    produce!(gen_u128, u128);

    produce!(gen_i128, i128);

    produce!(gen_usize, usize);

    produce!(gen_isize, isize);

    produce!(gen_f32, f32);

    produce!(gen_f64, f64);

    #[inline(always)]
    fn produce<T: TypeGenerator>(&mut self) -> Option<T> {
        let value = T::generate(self);
        shim::assume(value.is_some());
        value
    }

    #[inline(always)]
    fn gen_char(&mut self, min: Bound<&char>, max: Bound<&char>) -> Option<char> {
        let value = shim::any();
        shim::assume((min, max).contains(&value));
        Some(value)
    }

    #[inline(always)]
    fn gen_bool(&mut self, _probability: Option<f32>) -> Option<bool> {
        Some(shim::any())
    }

    #[inline(always)]
    fn gen_from_bytes<Hint, Gen, T>(&mut self, _hint: Hint, mut produce: Gen) -> Option<T>
    where
        Hint: FnOnce() -> (usize, Option<usize>),
        Gen: FnMut(&[u8]) -> Option<(usize, T)>,
    {
        // TODO make this configurable
        const MAX_LEN: usize = 256;

        let bytes = shim::any::<[u8; MAX_LEN]>();
        let len = shim::any::<usize>();
        shim::assume(len <= MAX_LEN);

        let value = produce(&bytes[..len]).map(|v| v.1);
        shim::assume(value.is_some());
        value
    }

    #[inline(always)]
    fn gen_variant(&mut self, variants: usize, base_case: usize) -> Option<usize> {
        if self.depth == self.max_depth {
            return Some(base_case);
        }

        let selected: usize = shim::any();
        shim::assume(selected < variants);
        Some(selected)
    }

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
}

/// Make a shim for when kani isn't available
#[cfg(not(kani))]
#[allow(dead_code)]
mod shim {
    pub fn any<T>() -> T {
        todo!()
    }

    pub fn assume(cond: bool) {
        // no-op
        let _ = cond;
    }
}

#[cfg(kani)]
use ::kani as shim;
