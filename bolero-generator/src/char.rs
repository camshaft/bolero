use crate::{BoundedValue, Rng, TypeGenerator, ValueGenerator};
use core::ops::Bound;

impl TypeGenerator for char {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        coerce_char(TypeGenerator::generate(rng))
    }
}

impl ValueGenerator for char {
    type Output = char;

    fn generate<R: Rng>(&self, _rng: &mut R) -> Self {
        *self
    }
}

impl BoundedValue for char {
    fn bounded(self, start: Bound<Self>, end: Bound<Self>) -> Self {
        use Bound::*;

        let start = match start {
            Included(value) => value as u32,
            Excluded(value) => (value as u32).saturating_add(1),
            Unbounded => 0,
        };

        let end = match end {
            Included(value) => value as u32,
            Excluded(value) => (value as u32).saturating_sub(1),
            Unbounded => core::char::MAX as u32,
        };

        let (lower, upper) = if start < end {
            (start, end)
        } else {
            (end, start)
        };

        let range = upper - lower;

        coerce_char((self as u32 % range) + lower)
    }
}

fn coerce_char(mut value: u32) -> char {
    value &= 0x001f_ffff;
    loop {
        if let Some(value) = core::char::from_u32(value) {
            return value;
        } else {
            if let Some(next_value) = value.checked_sub(1) {
                value = next_value;
            } else {
                return ' ';
            }
        }
    }
}
