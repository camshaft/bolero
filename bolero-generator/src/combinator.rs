use crate::{Rng, ValueGenerator};

#[derive(Clone, Debug)]
pub struct MapGenerator<Generator, Map> {
    pub(crate) generator: Generator,
    pub(crate) map: Map,
}

impl<G: ValueGenerator, M: Fn(G::Output) -> T, T> ValueGenerator for MapGenerator<G, M> {
    type Output = T;

    fn generate<R: Rng>(&self, rng: &mut R) -> Self::Output {
        (self.map)(self.generator.generate(rng))
    }
}

#[test]
fn map_test() {
    let _ = generator_test!(gen::<bool>().map(|value| !value));
    let _ = generator_test!(gen::<u8>().map(|value| value > 4));
}

#[derive(Clone, Debug)]
pub struct AndThenGenerator<Generator, AndThen> {
    pub(crate) generator: Generator,
    pub(crate) and_then: AndThen,
}

impl<G: ValueGenerator, H: ValueGenerator, F: Fn(G::Output) -> H> ValueGenerator
    for AndThenGenerator<G, F>
{
    type Output = H::Output;

    fn generate<R: Rng>(&self, rng: &mut R) -> Self::Output {
        let value = self.generator.generate(rng);
        (self.and_then)(value).generate(rng)
    }
}

#[test]
fn and_then_test() {
    let _ = generator_test!(gen::<bool>().and_then(|value| !value));
    let _ = generator_test!(gen::<u8>().and_then(|value| value..));
}
