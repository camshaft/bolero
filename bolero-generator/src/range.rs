use crate::{Driver, TypeGenerator, TypeGeneratorWithParams, TypeValueGenerator, ValueGenerator};

macro_rules! range_generator {
    ($ty:ident, $generator:ident, $new:expr) => {
        pub struct $generator<Start, End> {
            start: Start,
            end: End,
        }

        impl<Start, End, T> $generator<Start, End>
        where
            Start: ValueGenerator<Output = T>,
            End: ValueGenerator<Output = T>,
        {
            pub fn start<NewS: ValueGenerator<Output = T>>(
                self,
                start: NewS,
            ) -> $generator<NewS, End> {
                $generator {
                    start,
                    end: self.end,
                }
            }

            pub fn map_start<NewS: ValueGenerator<Output = T>, F: Fn(Start) -> NewS>(
                self,
                map: F,
            ) -> $generator<NewS, End> {
                $generator {
                    start: map(self.start),
                    end: self.end,
                }
            }

            pub fn end<NewE: ValueGenerator<Output = T>>(
                self,
                end: NewE,
            ) -> $generator<Start, NewE> {
                $generator {
                    start: self.start,
                    end,
                }
            }

            pub fn map_end<NewE: ValueGenerator<Output = T>, F: Fn(End) -> NewE>(
                self,
                map: F,
            ) -> $generator<Start, NewE> {
                $generator {
                    start: self.start,
                    end: map(self.end),
                }
            }
        }

        impl<Start, End, T> ValueGenerator for $generator<Start, End>
        where
            Start: ValueGenerator<Output = T>,
            End: ValueGenerator<Output = T>,
        {
            type Output = core::ops::$ty<T>;

            fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
                let start = self.start.generate(driver)?;
                let end = self.end.generate(driver)?;
                #[allow(clippy::redundant_closure)]
                Some($new(start, end))
            }
        }

        impl<T: TypeGenerator> TypeGenerator for core::ops::$ty<T> {
            fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
                let start = driver.gen()?;
                let end = driver.gen()?;
                #[allow(clippy::redundant_closure)]
                Some($new(start, end))
            }
        }

        impl<T: TypeGenerator> TypeGeneratorWithParams for core::ops::$ty<T> {
            type Output = $generator<TypeValueGenerator<T>, TypeValueGenerator<T>>;

            fn gen_with() -> Self::Output {
                $generator {
                    start: Default::default(),
                    end: Default::default(),
                }
            }
        }
    };
}

range_generator!(Range, RangeGenerator, |start, end| start..end);
range_generator!(RangeInclusive, RangeInclusiveGenerator, |start, end| start
    ..=end);

#[test]
fn range_type_test() {
    use core::ops::Range;

    let _ = generator_test!(gen::<Range<usize>>());
}

#[test]
fn range_with_test() {
    use core::ops::Range;

    let _ = generator_test!(gen::<Range<usize>>().with().start(4..6).end(6..10));
}

#[test]
fn range_gen_test() {
    let _ = generator_test!(0usize..10);
}
