use crate::{
    alloc_generators::CharsGenerator, Driver, TypeGenerator, TypeGeneratorWithParams,
    ValueGenerator,
};
use alloc::{string::String, vec::Vec};
use core::ops::RangeInclusive;

pub struct StringGenerator<L>(CharsGenerator<L>);

impl<L> StringGenerator<L> {
    pub fn len<Gen: ValueGenerator<Output = Len>, Len: Into<usize>>(
        self,
        len: Gen,
    ) -> StringGenerator<Gen> {
        StringGenerator(self.0.len(len))
    }

    pub fn map_len<Gen: ValueGenerator<Output = Len>, F: Fn(L) -> Gen, Len: Into<usize>>(
        self,
        map: F,
    ) -> StringGenerator<Gen> {
        StringGenerator(self.0.map_len(map))
    }
}

impl<L: ValueGenerator<Output = Len>, Len: Into<usize>> ValueGenerator for StringGenerator<L> {
    type Output = String;

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        Some(to_string(self.0.generate(driver)?))
    }
}

impl TypeGeneratorWithParams for String {
    type Output = StringGenerator<RangeInclusive<usize>>;

    fn gen_with() -> Self::Output {
        StringGenerator(Vec::gen_with())
    }
}

impl ValueGenerator for String {
    type Output = Self;

    fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self> {
        Some(self.clone())
    }
}

impl TypeGenerator for String {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(to_string(driver.gen()?))
    }
}

fn to_string(mut vec: Vec<char>) -> String {
    vec.drain(..).collect()
}

#[test]
fn string_test() {
    let _ = generator_test!(gen::<String>());
    let string = generator_test!(gen::<String>().with().len(32usize)).unwrap();
    assert_eq!(string.chars().map(|_| 1usize).sum::<usize>(), 32usize);
}
