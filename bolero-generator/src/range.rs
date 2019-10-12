use crate::{Rng, ValueGenerator};

macro_rules! range_generator {
    ($ty:ident, $name:ident, $new:expr) => {
        pub struct $name<Start, End> {
            start: Start,
            end: End,
        }

        impl<Start, End, T> ValueGenerator for $name<Start, End>
        where
            Start: ValueGenerator<Output = T>,
            End: ValueGenerator<Output = T>,
        {
            type Output = core::ops::$ty<T>;

            fn generate<R: Rng>(&mut self, rng: &mut R) -> Self::Output {
                let start = self.start.generate(rng);
                let end = self.end.generate(rng);
                $new(start, end)
            }
        }
    };
}

range_generator!(Range, RangeGenerator, |start, end| start..end);
range_generator!(RangeInclusive, RangeInclusiveGenerator, |start, end| start
    ..=end);

// TODO
