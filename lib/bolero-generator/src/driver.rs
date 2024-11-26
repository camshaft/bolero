use crate::{
    uniform::{FillBytes, Uniform},
    TypeGenerator, ValueGenerator,
};
use core::ops::Bound;
use rand_core::RngCore;

#[macro_use]
mod macros;

pub mod bytes;
#[cfg(feature = "alloc")]
pub mod cache;
#[cfg(feature = "alloc")]
pub mod exhaustive;
pub mod object;
mod rng;

pub use bytes::ByteSliceDriver;
pub use rng::Rng;

macro_rules! gen_method {
    ($name:ident, $constant:ident, $ty:ty) => {
        fn $name(&mut self, min: Bound<&$ty>, max: Bound<&$ty>) -> Option<$ty>;

        #[inline(always)]
        fn $constant(&mut self, value: $ty) -> Option<$ty> {
            Some(value)
        }
    };
}

/// Trait for driving the generation of a value
///
/// In a test engine, this is typically backed by
/// a byte slice, but other drivers can be used instead, e.g.
/// an RNG implementation.
pub trait Driver: Sized {
    /// Generate a value with type `T`
    #[inline(always)]
    fn gen<T: TypeGenerator>(&mut self) -> Option<T> {
        T::generate(self)
    }

    #[inline]
    fn depth_guard<F, R>(&mut self, f: F) -> Option<R>
    where
        F: FnOnce(&mut Self) -> Option<R>,
    {
        let depth = self.depth();
        if depth == self.max_depth() {
            return None;
        }

        let new_depth = depth + 1;
        self.set_depth(new_depth);
        let value = f(self);
        self.set_depth(depth);

        value
    }

    fn depth(&self) -> usize;

    fn set_depth(&mut self, depth: usize);

    fn max_depth(&self) -> usize;

    #[inline(always)]
    fn enter_product<Output, F, Ret>(&mut self, mut f: F) -> Option<Ret>
    where
        Output: 'static,
        F: FnMut(&mut Self) -> Option<Ret>,
    {
        f(self)
    }

    #[inline(always)]
    fn enter_sum<Output, F, Ret>(
        &mut self,
        element_names: Option<&'static [&'static str]>,
        elements: usize,
        base_case: usize,
        mut f: F,
    ) -> Option<Ret>
    where
        Output: 'static,
        F: FnMut(&mut Self, usize) -> Option<Ret>,
    {
        let _ = element_names;
        let idx = self.gen_variant(elements, base_case)?;
        f(self, idx)
    }

    #[inline(always)]
    fn enter_list<Output, F, Len, Ret>(&mut self, lens: &Len, mut f: F) -> Option<Ret>
    where
        Output: 'static,
        F: FnMut(&mut Self, usize) -> Option<Ret>,
        Len: ValueGenerator<Output = usize>,
    {
        self.depth_guard(|driver| {
            let len = lens.generate(driver)?;
            f(driver, len)
        })
    }

    #[inline(always)]
    fn enter_combinator<Output, F, Ret>(&mut self, mut f: F) -> Option<Ret>
    where
        Output: 'static,
        F: FnMut(&mut Self) -> Option<Ret>,
    {
        f(self)
    }

    fn gen_variant(&mut self, variants: usize, base_case: usize) -> Option<usize>;

    gen_method!(gen_u8, gen_u8_constant, u8);
    gen_method!(gen_i8, gen_i8_constant, i8);
    gen_method!(gen_u16, gen_u16_constant, u16);
    gen_method!(gen_i16, gen_i16_constant, i16);
    gen_method!(gen_u32, gen_u32_constant, u32);
    gen_method!(gen_i32, gen_i32_constant, i32);
    gen_method!(gen_u64, gen_u64_constant, u64);
    gen_method!(gen_i64, gen_i64_constant, i64);
    gen_method!(gen_u128, gen_u128_constant, u128);
    gen_method!(gen_i128, gen_i128_constant, i128);
    gen_method!(gen_usize, gen_usize_constant, usize);
    gen_method!(gen_isize, gen_isize_constant, isize);
    gen_method!(gen_f32, gen_f32_constant, f32);
    gen_method!(gen_f64, gen_f64_constant, f64);
    gen_method!(gen_char, gen_char_constant, char);

    fn gen_bool(&mut self, probability: Option<f32>) -> Option<bool>;

    /// Generate a value from bytes off this generator
    ///
    /// `len` is the size of the slice that should be passed to `gen`. The range's minimal size
    /// is the minimal amount of bytes needed to properly generate an input. The range's maximal
    /// value should be so that every `T` can be generated by `gen` from a slice of this length.
    ///
    /// `gen` is the function that actually does the generation. It takes as input the byte slice,
    /// and returns either `None` (if not enough bytes were provided to build a `T`, this can
    /// happen even with a slice of maximum length but should happen as rarely as possible), or
    /// a `Some` value if it could generate a `T`. In this case, it also returns the number of
    /// bytes that were actually consumed from the slice.
    ///
    /// Note that `gen` may be called multiple times with increasing slice lengths, eg. if the
    /// driver is in forced mode.
    fn gen_from_bytes<Hint, Gen, T>(&mut self, hint: Hint, gen: Gen) -> Option<T>
    where
        Hint: FnOnce() -> (usize, Option<usize>),
        Gen: FnMut(&[u8]) -> Option<(usize, T)>;

    #[inline(always)]
    fn cache_put<T: 'static>(&mut self, value: T) {
        let _ = value;
    }

    #[inline(always)]
    fn cache_get<T: 'static>(&mut self) -> Option<T> {
        None
    }
}

/// Byte exhaustion strategy for the driver
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
#[deprecated = "Driver mode should no longer used by generator implementations"]
pub enum DriverMode {
    /// When the driver bytes are exhausted, the driver will fail fill input bytes.
    /// This is useful for fuzz engines that want accurate mapping of inputs to coverage.
    Direct,

    /// When the driver bytes are exhausted, the driver will continue to fill input bytes with 0.
    /// This is useful for engines that want to maximize the amount of time spent executing tests.
    Forced,
}

#[derive(Clone, Debug, Default)]
pub struct Options {
    shrink_time: Option<core::time::Duration>,
    max_depth: Option<usize>,
    max_len: Option<usize>,
    exhaustive: bool,
}

impl Options {
    pub const DEFAULT_MAX_DEPTH: usize = 5;
    pub const DEFAULT_MAX_LEN: usize = 4096;
    pub const DEFAULT_SHRINK_TIME: core::time::Duration = core::time::Duration::from_secs(1);

    pub fn with_shrink_time(mut self, shrink_time: core::time::Duration) -> Self {
        self.shrink_time = Some(shrink_time);
        self
    }

    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = Some(max_depth);
        self
    }

    pub fn with_max_len(mut self, max_len: usize) -> Self {
        self.max_len = Some(max_len);
        self
    }

    pub fn with_exhaustive(mut self, exhaustive: bool) -> Self {
        self.exhaustive = exhaustive;
        self
    }

    pub fn set_exhaustive(&mut self, exhaustive: bool) -> &mut Self {
        self.exhaustive = exhaustive;
        self
    }

    pub fn set_shrink_time(&mut self, shrink_time: core::time::Duration) -> &mut Self {
        self.shrink_time = Some(shrink_time);
        self
    }

    pub fn set_max_depth(&mut self, max_depth: usize) -> &mut Self {
        self.max_depth = Some(max_depth);
        self
    }

    pub fn set_max_len(&mut self, max_len: usize) -> &mut Self {
        self.max_len = Some(max_len);
        self
    }

    #[inline]
    pub fn exhaustive(&self) -> bool {
        self.exhaustive
    }

    #[inline]
    pub fn max_depth(&self) -> Option<usize> {
        self.max_depth
    }

    #[inline]
    pub fn max_len(&self) -> Option<usize> {
        self.max_len
    }

    #[inline]
    pub fn shrink_time(&self) -> Option<core::time::Duration> {
        self.shrink_time
    }

    #[inline]
    pub fn max_depth_or_default(&self) -> usize {
        self.max_depth.unwrap_or(Self::DEFAULT_MAX_DEPTH)
    }

    #[inline]
    pub fn max_len_or_default(&self) -> usize {
        self.max_len.unwrap_or(Self::DEFAULT_MAX_LEN)
    }

    #[inline]
    pub fn shrink_time_or_default(&self) -> core::time::Duration {
        self.shrink_time.unwrap_or(Self::DEFAULT_SHRINK_TIME)
    }

    #[inline]
    pub fn merge_from(&mut self, other: &Self) {
        macro_rules! merge {
            ($name:ident) => {
                if let Some($name) = other.$name {
                    self.$name = Some($name);
                }
            };
        }

        merge!(max_depth);
        merge!(max_len);
        merge!(shrink_time);
    }
}
