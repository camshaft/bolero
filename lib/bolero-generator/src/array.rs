use crate::{Driver, TypeGenerator, TypeGeneratorWithParams, TypeValueGenerator, ValueGenerator};

impl<T: TypeGenerator, const LEN: usize> TypeGenerator for [T; LEN] {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        driver.enter_product::<Self, _, _>(|driver| {
            // TODO use core::array::try_from_fn once stable
            //      see: https://github.com/rust-lang/rust/issues/89379
            //      see: https://github.com/camshaft/bolero/issues/133
            let mut maybe_init: [Option<T>; LEN] = [(); LEN].map(|_| None);

            for value in &mut maybe_init {
                *value = Some(T::generate(driver)?);
            }

            Some(maybe_init.map(|t| t.unwrap()))
        })
    }

    fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
        driver.enter_product::<Self, _, _>(|driver| {
            for item in self.iter_mut() {
                item.mutate(driver)?;
            }
            Some(())
        })
    }
}

impl<G: ValueGenerator, const LEN: usize> ValueGenerator for [G; LEN] {
    type Output = [G::Output; LEN];

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        driver.enter_product::<Self::Output, _, _>(|driver| {
            // TODO use core::array::try_from_fn once stable
            //      see: https://github.com/rust-lang/rust/issues/89379
            //      see: https://github.com/camshaft/bolero/issues/133
            let mut maybe_init: [Option<G::Output>; LEN] = [(); LEN].map(|_| None);

            for (generator, value) in self.iter().zip(&mut maybe_init) {
                *value = Some(generator.generate(driver)?);
            }

            Some(maybe_init.map(|t| t.unwrap()))
        })
    }

    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        driver.enter_product::<Self::Output, _, _>(|driver| {
            for (generator, value) in self.iter().zip(value.iter_mut()) {
                generator.mutate(driver, value)?;
            }
            Some(())
        })
    }
}

impl<T: TypeGenerator, const LEN: usize> TypeGeneratorWithParams for [T; LEN] {
    type Output = [TypeValueGenerator<T>; LEN];

    fn gen_with() -> Self::Output {
        [T::produce(); LEN]
    }
}

#[test]
fn array_type_test() {
    let _ = generator_test!(produce::<[u8; 10]>());
}

#[test]
fn array_gen_test() {
    let _ = generator_test!([produce::<u8>(), produce::<u8>()]);
}
