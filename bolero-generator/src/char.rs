use crate::{
    bounded::{is_within, BoundedGenerator, BoundedValue},
    driver::DriverMode,
    Driver, TypeGenerator, TypeGeneratorWithParams, TypeValueGenerator, ValueGenerator,
};
use core::ops::{Range, RangeBounds};

impl TypeGenerator for char {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        if driver.mode() == DriverMode::Forced {
            Some(
                TypeGenerator::generate(driver)
                    .and_then(coerce_char)
                    .unwrap_or_default(),
            )
        } else {
            core::char::from_u32(TypeGenerator::generate(driver)?)
        }
    }
}

impl<R: RangeBounds<Self> + core::fmt::Debug> BoundedValue<R> for char {
    type BoundValue = char;

    fn is_within(&self, range_bounds: &R) -> bool {
        is_within(self, range_bounds)
    }

    fn bind_within(&mut self, range_bounds: &R) {
        use core::ops::Bound::*;

        let start = match range_bounds.start_bound() {
            Included(value) => Included(*value as u32),
            Excluded(value) => Excluded(*value as u32),
            Unbounded => Unbounded,
        };

        let end = match range_bounds.end_bound() {
            Included(value) => Included(*value as u32),
            Excluded(value) => Excluded(*value as u32),
            Unbounded => Unbounded,
        };

        let mut value = *self as u32;
        value.bind_within(&(start, end));

        *self = coerce_char(value).unwrap_or_default()
    }
}

impl ValueGenerator for char {
    type Output = char;

    fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self> {
        Some(*self)
    }
}

impl TypeGeneratorWithParams for char {
    type Output = BoundedGenerator<TypeValueGenerator<char>, Range<char>>;

    fn gen_with() -> Self::Output {
        BoundedGenerator::new(Default::default(), (0 as char)..core::char::MAX)
    }
}

fn coerce_char(mut value: u32) -> Option<char> {
    value &= core::char::MAX as u32;
    loop {
        if let Some(value) = core::char::from_u32(value) {
            return Some(value);
        } else if let Some(next_value) = value.checked_sub(1) {
            value = next_value;
        } else {
            return None;
        }
    }
}

#[test]
fn char_type_test() {
    let _ = generator_test!(gen::<char>());
}

#[test]
fn char_bounds_test() {
    let _ = generator_test!(gen::<char>().with().bounds('a'..='f'));
}
