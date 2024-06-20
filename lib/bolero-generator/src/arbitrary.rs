use crate::{Driver, ValueGenerator};
use arbitrary::Unstructured;
use core::marker::PhantomData;

#[cfg(not(kani))]
mod hint_cache {
    //! Some recursive size hints are computationally expensive
    //!
    //! Here we cache the hint for each type that we use.
    //! See https://github.com/rust-fuzz/arbitrary/issues/144
    use super::*;
    use core::{any::TypeId, cell::RefCell};
    use std::collections::HashMap;

    std::thread_local! {
        static DEPTHS: RefCell<HashMap<TypeId, (usize, Option<usize>)>> = Default::default();
    }

    pub fn hint<T>() -> (usize, Option<usize>)
    where
        T: 'static,
        T: for<'a> Arbitrary<'a>,
    {
        DEPTHS.with(|depths| {
            *depths
                .borrow_mut()
                .entry(TypeId::of::<T>())
                .or_insert_with(|| T::size_hint(0))
        })
    }
}

pub use arbitrary::Arbitrary;

pub struct ArbitraryGenerator<T>(PhantomData<T>);

impl<T> ValueGenerator for ArbitraryGenerator<T>
where
    T: 'static,
    T: for<'a> Arbitrary<'a>,
{
    type Output = T;

    #[inline]
    fn generate<D: Driver>(&self, driver: &mut D) -> Option<T> {
        #[cfg(not(kani))]
        let hint = hint_cache::hint::<T>;

        #[cfg(kani)]
        let hint = || (0, None);

        driver.gen_from_bytes(hint, |bytes| {
            let initial_len = bytes.len();
            let mut input = Unstructured::new(bytes);
            let res = T::arbitrary(&mut input).ok()?;
            let remaining_len = bytes.len();
            let consumed = initial_len - remaining_len;
            Some((consumed, res))
        })
    }
}

#[inline]
pub fn gen_arbitrary<T>() -> ArbitraryGenerator<T>
where
    T: 'static,
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
        let results = generator_test!(gen_arbitrary::<Vec<usize>>());
        assert!(results.into_iter().any(|v| !v.is_empty()));
    }

    #[test]
    fn string() {
        let results = generator_test!(gen_arbitrary::<String>());
        assert!(results.into_iter().any(|v| !v.is_empty()));
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RandomlyValid(bool);

    impl<'a> arbitrary::Arbitrary<'a> for RandomlyValid {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let v: bool = u.arbitrary()?;
            if !v {
                return Err(arbitrary::Error::IncorrectFormat);
            }
            Ok(Self(v))
        }
    }

    #[test]
    fn randomly_valid() {
        let results = generator_test!(gen_arbitrary::<RandomlyValid>());
        assert!(!results.is_empty());
    }
}
