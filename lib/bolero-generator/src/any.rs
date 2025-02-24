use crate::{produce, TypeGenerator, ValueGenerator};

#[cfg(not(kani))]
mod default;

#[cfg(any(kani, test))]
#[cfg_attr(not(kani), allow(dead_code, unused_imports))]
mod kani;

#[cfg(test)]
mod tests;

pub mod scope {
    #[cfg(not(kani))]
    pub use super::default::*;
    #[cfg(kani)]
    pub use super::kani::*;
}

pub use scope::{assume, fill_bytes, Error};

pub trait Any: ValueGenerator {
    fn any(&self) -> Self::Output;
}

impl<G: 'static + ValueGenerator> Any for G {
    #[track_caller]
    fn any(&self) -> Self::Output {
        scope::any(self)
    }
}

#[inline]
pub fn any<T: TypeGenerator>() -> T {
    produce().any()
}

pub trait AnySliceExt<T> {
    fn pick(&self) -> &T;
}

impl<T> AnySliceExt<T> for [T] {
    #[inline]
    fn pick(&self) -> &T {
        let index = (0..self.len()).any();
        &self[index]
    }
}

pub trait AnySliceMutExt<T> {
    fn shuffle(&mut self);
    fn fill_any(&mut self)
    where
        T: TypeGenerator;
}

impl<T> AnySliceMutExt<T> for [T] {
    #[inline]
    fn shuffle(&mut self) {
        let max_dst = self.len().saturating_sub(1);
        for src in 0..max_dst {
            let dst = (src..=max_dst).any();
            self.swap(src, dst);
        }
    }

    #[inline]
    fn fill_any(&mut self)
    where
        T: TypeGenerator,
    {
        for value in self {
            *value = any();
        }
    }
}

#[cfg(feature = "alloc")]
impl<T> AnySliceMutExt<T> for alloc::collections::VecDeque<T> {
    #[inline]
    fn shuffle(&mut self) {
        let max_dst = self.len().saturating_sub(1);
        for src in 0..max_dst {
            let dst = (src..=max_dst).any();
            self.swap(src, dst);
        }
    }

    #[inline]
    fn fill_any(&mut self)
    where
        T: TypeGenerator,
    {
        for value in self {
            *value = any();
        }
    }
}

#[inline]
pub fn fill<T>(values: &mut [T])
where
    T: TypeGenerator,
{
    values.fill_any()
}

#[inline]
pub fn shuffle<T>(items: &mut [T]) {
    items.shuffle()
}

#[inline]
pub fn pick<T>(items: &[T]) -> &T {
    items.pick()
}
