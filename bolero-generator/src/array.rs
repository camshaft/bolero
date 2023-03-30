use crate::{Driver, TypeGenerator, TypeGeneratorWithParams, TypeValueGenerator, ValueGenerator};

impl<T: TypeGenerator, const LEN: usize> TypeGenerator for [T; LEN] {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        // TODO use core::array::try_from_fn once stable https://github.com/rust-lang/rust/issues/89379
        let mut maybe_init: [Option<T>; LEN] = [(); LEN].map(|_| None);

        for value in &mut maybe_init {
            *value = Some(T::generate(driver)?);
        }

        Some(maybe_init.map(|t| t.unwrap()))
    }

    fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
        for item in self {
            item.mutate(driver)?;
        }
        Some(())
    }
}

impl<G: ValueGenerator, const LEN: usize> ValueGenerator for [G; LEN] {
    type Output = [G::Output; LEN];

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        // TODO use core::array::try_from_fn once stable https://github.com/rust-lang/rust/issues/89379
        let mut maybe_init: [Option<G::Output>; LEN] = [(); LEN].map(|_| None);

        for (generator, value) in self.iter().zip(&mut maybe_init) {
            *value = Some(generator.generate(driver)?);
        }

        Some(maybe_init.map(|t| t.unwrap()))
    }

    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        for (generator, value) in self.iter().zip(value) {
            generator.mutate(driver, value)?;
        }
        Some(())
    }
}

impl<T: TypeGenerator, const LEN: usize> TypeGeneratorWithParams for [T; LEN] {
    type Output = [TypeValueGenerator<T>; LEN];

    fn gen_with() -> Self::Output {
        [T::gen(); LEN]
    }
}

#[test]
fn array_type_test() {
    let _ = generator_test!(gen::<[u8; 10]>());
}

#[test]
fn array_gen_test() {
    let _ = generator_test!([gen::<u8>(), gen::<u8>()]);
}
