use crate::{Driver, TypeGenerator, TypeGeneratorWithParams, TypeValueGenerator, ValueGenerator};

#[cfg(feature = "either")]
use either::Either;

macro_rules! impl_either {
    (
        $generator:ident,
        $ty:ident,
        $A:ident,
        $with_a:ident,
        $map_a:ident,
        $B:ident,
        $with_b:ident,
        $map_b:ident
    ) => {
        #[derive(Debug, Clone)]
        pub struct $generator<$A, $B> {
            a: $A,
            b: $B,
        }

        impl<$A: ValueGenerator, $B: ValueGenerator> $generator<$A, $B> {
            pub fn $with_a<Gen: ValueGenerator<Output = $A::Output>>(
                self,
                gen: Gen,
            ) -> $generator<Gen, $B> {
                $generator { a: gen, b: self.b }
            }

            pub fn $map_a<Gen: ValueGenerator<Output = $A::Output>, F: Fn($A) -> Gen>(
                self,
                map: F,
            ) -> $generator<Gen, $B> {
                $generator {
                    a: map(self.a),
                    b: self.b,
                }
            }

            pub fn $with_b<Gen: ValueGenerator<Output = $B::Output>>(
                self,
                gen: Gen,
            ) -> $generator<$A, Gen> {
                $generator { a: self.a, b: gen }
            }

            pub fn $map_b<Gen: ValueGenerator<Output = $B::Output>, F: Fn($B) -> Gen>(
                self,
                map: F,
            ) -> $generator<$A, Gen> {
                $generator {
                    a: self.a,
                    b: map(self.b),
                }
            }
        }

        impl<$A: ValueGenerator, $B: ValueGenerator> ValueGenerator for $generator<$A, $B> {
            type Output = $ty<$A::Output, $B::Output>;

            #[inline]
            fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
                driver.enter_sum::<Self::Output, _, _>(
                    Some(&[stringify!($A), stringify!($B)]),
                    2,
                    0,
                    |driver, idx| {
                        if idx == 0 {
                            Some($ty::$A(self.a.generate(driver)?))
                        } else {
                            Some($ty::$B(self.b.generate(driver)?))
                        }
                    },
                )
            }

            #[inline]
            fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
                driver.enter_sum::<Self::Output, _, _>(
                    Some(&[stringify!($A), stringify!($B)]),
                    2,
                    0,
                    |driver, new_selection| {
                        #[allow(clippy::redundant_pattern_matching)]
                        let prev_selection = match value {
                            $ty::$A(_) => 0,
                            $ty::$B(_) => 1,
                        };

                        if prev_selection == new_selection {
                            match value {
                                $ty::$A(value) => self.a.mutate(driver, value),
                                $ty::$B(value) => self.b.mutate(driver, value),
                            }
                        } else {
                            let next = if new_selection == 0 {
                                $ty::$A(self.a.generate(driver)?)
                            } else {
                                $ty::$B(self.b.generate(driver)?)
                            };
                            match core::mem::replace(value, next) {
                                $ty::$A(v) => self.a.driver_cache(driver, v),
                                $ty::$B(v) => self.b.driver_cache(driver, v),
                            }
                            Some(())
                        }
                    },
                )
            }

            #[inline]
            fn driver_cache<D: Driver>(&self, driver: &mut D, value: Self::Output) {
                match value {
                    $ty::$A(v) => self.a.driver_cache(driver, v),
                    $ty::$B(v) => self.b.driver_cache(driver, v),
                }
            }
        }

        impl<$A: TypeGenerator, $B: TypeGenerator> TypeGenerator for $ty<$A, $B> {
            #[inline]
            fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
                crate::gen_with::<Self>().generate(driver)
            }

            #[inline]
            fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
                crate::gen_with::<Self>().mutate(driver, self)
            }

            #[inline]
            fn driver_cache<D: Driver>(self, driver: &mut D) {
                crate::gen_with::<Self>().driver_cache(driver, self)
            }
        }

        impl<$A: TypeGenerator, $B: TypeGenerator> TypeGeneratorWithParams for $ty<$A, $B> {
            type Output = $generator<TypeValueGenerator<$A>, TypeValueGenerator<$B>>;

            fn gen_with() -> Self::Output {
                $generator {
                    a: Default::default(),
                    b: Default::default(),
                }
            }
        }
    };
}

impl_either!(ResultGenerator, Result, Ok, ok, map_ok, Err, err, map_err);

#[cfg(feature = "either")]
impl_either!(
    EitherGenerator,
    Either,
    Left,
    left,
    map_left,
    Right,
    right,
    map_right
);

pub struct OptionGenerator<V> {
    value: V,
}

impl<V: ValueGenerator> OptionGenerator<V> {
    pub fn value<Gen: ValueGenerator<Output = V::Output>>(
        self,
        value: Gen,
    ) -> OptionGenerator<Gen> {
        OptionGenerator { value }
    }

    pub fn map_value<Gen: ValueGenerator<Output = V::Output>, F: Fn(V) -> Gen>(
        self,
        map: F,
    ) -> OptionGenerator<Gen> {
        OptionGenerator {
            value: map(self.value),
        }
    }
}

impl<V: ValueGenerator> ValueGenerator for OptionGenerator<V> {
    type Output = Option<V::Output>;

    #[inline]
    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        driver.enter_sum::<Self::Output, _, _>(Some(&["None", "Some"]), 2, 0, |driver, idx| {
            if idx == 0 {
                Some(None)
            } else {
                Some(Some(self.value.generate(driver)?))
            }
        })
    }

    #[inline]
    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        driver.enter_sum::<Self::Output, _, _>(
            Some(&["None", "Some"]),
            2,
            0,
            |driver, new_selection| {
                let prev_selection = usize::from(value.is_some());

                if prev_selection == new_selection {
                    match value {
                        Some(value) => self.value.mutate(driver, value),
                        None => Some(()),
                    }
                } else {
                    let next = if new_selection == 1 {
                        Some(self.value.generate(driver)?)
                    } else {
                        None
                    };
                    if let Some(prev) = core::mem::replace(value, next) {
                        self.value.driver_cache(driver, prev);
                    }
                    Some(())
                }
            },
        )
    }
}

impl<V: TypeGenerator> TypeGenerator for Option<V> {
    #[inline]
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        crate::gen_with::<Self>().generate(driver)
    }

    #[inline]
    fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
        crate::gen_with::<Self>().mutate(driver, self)
    }

    #[inline]
    fn driver_cache<D: Driver>(self, driver: &mut D) {
        crate::gen_with::<Self>().driver_cache(driver, self)
    }
}

impl<V: TypeGenerator> TypeGeneratorWithParams for Option<V> {
    type Output = OptionGenerator<TypeValueGenerator<V>>;

    fn gen_with() -> Self::Output {
        OptionGenerator {
            value: Default::default(),
        }
    }
}

#[test]
fn result_test() {
    let _ = generator_test!(gen::<Result<u8, u8>>());
}

#[test]
fn option_test() {
    let _ = generator_test!(gen::<Option<u8>>());
}
