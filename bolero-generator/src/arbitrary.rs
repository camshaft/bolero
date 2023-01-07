use core::{cmp, marker::PhantomData};

use arbitrary::{Arbitrary, Unstructured};

use crate::{gen_with, Driver, ValueGenerator};

pub struct ArbitraryGenerator<T>(PhantomData<T>);

const ABUSIVE_SIZE: usize = 1024 * 1024;
const MIN_INCREASE: usize = 32;

impl<T> ValueGenerator for ArbitraryGenerator<T>
where
    T: for<'a> Arbitrary<'a>,
{
    type Output = T;

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<T> {
        let size = T::size_hint(0);
        let mut data = match T::size_hint(0) {
            (min, Some(max)) if max < ABUSIVE_SIZE => gen_with::<Vec<u8>>()
                .len(min..=max)
                .generate(&mut *driver)?,
            (min, _) => gen_with::<Vec<u8>>().len(min).generate(&mut *driver)?,
        };
        loop {
            match Unstructured::new(&data).arbitrary() {
                Ok(res) => return Some(res),
                Err(arbitrary::Error::NotEnoughData) => (), // fall-through to another iter
                Err(_) => return None,
            }
            let mut additional_size = cmp::max(data.len(), MIN_INCREASE); // exponential growth
            if let Some(max) = size.1 {
                let max_increase = max.saturating_sub(data.len());
                if max_increase == 0 {
                    return None; // bug in the size_hint impl
                }
                if max_increase < additional_size || max_increase < ABUSIVE_SIZE {
                    additional_size = max_increase;
                }
            }
            data.extend_from_slice(
                &gen_with::<Vec<u8>>()
                    .len(additional_size)
                    .generate(&mut *driver)?,
            );
        }
    }
}

#[inline]
pub fn gen_arbitrary<T>() -> ArbitraryGenerator<T>
where
    T: for<'a> Arbitrary<'a>,
{
    ArbitraryGenerator(PhantomData)
}

#[cfg(test)]
mod tests {
    #[test]
    fn tuple() {
        let _ = generator_test!(gen_arbitrary::<(u8, u32, u64)>());
    }

    #[test]
    fn vec() {
        let _ = generator_test!(gen_arbitrary::<Vec<usize>>());
    }
}
