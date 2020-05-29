use crate::{Driver, ValueGenerator};

#[derive(Clone, Debug)]
pub struct MapGenerator<Generator, Map> {
    pub(crate) generator: Generator,
    pub(crate) map: Map,
}

impl<G: ValueGenerator, M: Fn(G::Output) -> T, T> ValueGenerator for MapGenerator<G, M> {
    type Output = T;

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let value = self.generator.generate(driver)?;
        Some((self.map)(value))
    }
}

#[test]
fn map_test() {
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

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let value = self.generator.generate(driver)?;
        (self.and_then)(value).generate(driver)
    }
}

#[test]
fn and_then_test() {
    let _ = generator_test!(gen::<u8>().and_then(|value| value..));
}

#[derive(Clone, Debug)]
pub struct FilterGenerator<Generator, Filter> {
    pub(crate) generator: Generator,
    pub(crate) filter: Filter,
}

impl<G: ValueGenerator, F: Fn(&G::Output) -> bool> ValueGenerator for FilterGenerator<G, F> {
    type Output = G::Output;

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let value = self.generator.generate(driver)?;
        if (self.filter)(&value) {
            Some(value)
        } else {
            None
        }
    }
}

#[test]
fn filter_test() {
    let _ = generator_test!(gen::<u8>().filter(|value| *value > 40));
}

#[derive(Clone, Debug)]
pub struct FilterMapGenerator<Generator, FilterMap> {
    pub(crate) generator: Generator,
    pub(crate) filter_map: FilterMap,
}

impl<G: ValueGenerator, F: Fn(G::Output) -> Option<T>, T> ValueGenerator
    for FilterMapGenerator<G, F>
{
    type Output = T;

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let value = self.generator.generate(driver)?;
        (self.filter_map)(value)
    }
}

#[test]
fn filter_map_test() {
    let _ = generator_test!(gen::<u8>().filter_map(|value| Some(value > 40)));
}
