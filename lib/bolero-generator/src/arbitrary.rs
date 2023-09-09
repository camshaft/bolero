use crate::{Driver, ValueGenerator};
use arbitrary::Unstructured;
use core::marker::PhantomData;

pub use arbitrary::Arbitrary;

pub struct ArbitraryGenerator<T>(PhantomData<T>);

impl<T> ValueGenerator for ArbitraryGenerator<T>
where
    T: for<'a> Arbitrary<'a>,
{
    type Output = T;

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<T> {
        let len = match T::size_hint(0) {
            (min, None) => min..=usize::MAX,
            (min, Some(max)) => min..=max,
        };
        driver.gen_from_bytes(len, |b| {
            let initial_len = b.len();
            let mut b = Unstructured::new(b);
            let res = T::arbitrary(&mut b).ok()?;
            let remaining_len = b.len();
            Some((initial_len - remaining_len, res))
        })
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
