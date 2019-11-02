use crate::{bounded::BoundedValue, Rng, TypeGenerator, ValueGenerator};
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
            Included(value) => Included(value as u32),
            Excluded(value) => Excluded(value as u32),
            Unbounded => Unbounded,
        };

        let end = match end {
            Included(value) => Included(value as u32),
            Excluded(value) => Excluded(value as u32),
            Unbounded => Unbounded,
        };

        let value = BoundedValue::bounded(self as u32, start, end);

        coerce_char(value)
    }
}

fn coerce_char(mut value: u32) -> char {
    value &= 0x001f_ffff;
    loop {
        if let Some(value) = core::char::from_u32(value) {
            return value;
        } else if let Some(next_value) = value.checked_sub(1) {
            value = next_value;
        } else {
            return ' ';
        }
    }
}
