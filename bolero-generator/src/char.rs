use crate::{
    bounded::{is_within, BoundedValue},
    driver::DriverMode,
    Driver, TypeGenerator, ValueGenerator,
};
use core::ops::RangeBounds;

impl TypeGenerator for char {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        if driver.mode() == DriverMode::Forced {
            Some(coerce_char(TypeGenerator::generate(driver)?).unwrap_or_default())
        } else {
            convert_char(TypeGenerator::generate(driver)?)
        }
    }
}

impl<R: RangeBounds<Self>> BoundedValue<R> for char {
    type BoundValue = char;

    fn is_within(&self, range_bounds: &R) -> bool {
        is_within(self, range_bounds)
    }

    fn bind_within(self, range_bounds: &R) -> Self {
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

        let value = (self as u32).bind_within(&(start, end));

        coerce_char(value).unwrap_or_default()
    }
}

impl ValueGenerator for char {
    type Output = char;

    fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self> {
        Some(*self)
    }
}

fn convert_char(value: u32) -> Option<char> {
    if value > core::char::MAX as u32 {
        return None;
    }

    if value >= 0xD800 && value <= 0xDFFF {
        return None;
    }

    Some(unsafe { core::char::from_u32_unchecked(value) })
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
