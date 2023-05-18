use crate::{Driver, ValueGenerator};
use arbitrary::Unstructured;
use core::{any::TypeId, cell::RefCell, marker::PhantomData};
use std::collections::HashMap;

#[cfg(not(kani))]
std::thread_local! {
    static DEPTHS: RefCell<HashMap<TypeId, (usize, Option<usize>)>> = Default::default();
}

pub use arbitrary::Arbitrary;

pub struct ArbitraryGenerator<T>(PhantomData<T>);

impl<T> ValueGenerator for ArbitraryGenerator<T>
where
    T: 'static,
    T: for<'a> Arbitrary<'a>,
{
    type Output = T;

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<T> {
        #[cfg(not(kani))]
        let hint = || {
            // Some recursive size hints are computationally expensive
            //
            // Here we cache the hint for each type that we use
            DEPTHS.with(|depths| {
                *depths
                    .borrow_mut()
                    .entry(TypeId::of::<T>())
                    .or_insert_with(|| T::size_hint(0))
            })
        };

        #[cfg(kani)]
        let hint = || (0, None);

        driver.gen_from_bytes(hint, |b| {
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
