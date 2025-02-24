use crate::{
    bounded::{BoundedGenerator, BoundedValue},
    Driver, TypeGenerator, TypeGeneratorWithParams, ValueGenerator,
};
use core::ops::{Bound, Range};

impl TypeGenerator for char {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        driver.gen_char(Bound::Unbounded, Bound::Unbounded)
    }
}

impl BoundedValue for char {
    fn gen_bounded<D: Driver>(
        driver: &mut D,
        min: Bound<&Self>,
        max: Bound<&Self>,
    ) -> Option<Self> {
        driver.gen_char(min, max)
    }
}

impl ValueGenerator for char {
    type Output = char;

    fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self> {
        Some(*self)
    }
}

impl TypeGeneratorWithParams for char {
    type Output = BoundedGenerator<Self, Range<Self>>;

    fn gen_with() -> Self::Output {
        BoundedGenerator::new((0 as char)..core::char::MAX)
    }
}

#[test]
fn char_type_test() {
    let _ = generator_test!(produce::<char>());
}

#[test]
fn char_bounds_test() {
    let _ = generator_test!(produce::<char>().with().bounds('a'..='f'));
}
