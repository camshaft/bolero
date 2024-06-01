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
        pub struct $generator<$A, $B, Selector> {
            a: $A,
            b: $B,
            selector: Selector,
        }

        impl<$A: ValueGenerator, $B: ValueGenerator, Selector: ValueGenerator<Output = bool>>
            $generator<$A, $B, Selector>
        {
            pub fn $with_a<Gen: ValueGenerator<Output = $A::Output>>(
                self,
                gen: Gen,
            ) -> $generator<Gen, $B, Selector> {
                $generator {
                    a: gen,
                    b: self.b,
                    selector: self.selector,
                }
            }

            pub fn $map_a<Gen: ValueGenerator<Output = $A::Output>, F: Fn($A) -> Gen>(
                self,
                map: F,
            ) -> $generator<Gen, $B, Selector> {
                $generator {
                    a: map(self.a),
                    b: self.b,
                    selector: self.selector,
                }
            }

            pub fn $with_b<Gen: ValueGenerator<Output = $B::Output>>(
                self,
                gen: Gen,
            ) -> $generator<$A, Gen, Selector> {
                $generator {
                    a: self.a,
                    b: gen,
                    selector: self.selector,
                }
            }

            pub fn $map_b<Gen: ValueGenerator<Output = $B::Output>, F: Fn($B) -> Gen>(
                self,
                map: F,
            ) -> $generator<$A, Gen, Selector> {
                $generator {
                    a: self.a,
                    b: map(self.b),
                    selector: self.selector,
                }
            }

            pub fn with_selector<Gen: ValueGenerator<Output = bool>>(
                self,
                selector: Gen,
            ) -> $generator<$A, $B, Gen> {
                $generator {
                    a: self.a,
                    b: self.b,
                    selector,
                }
            }

            pub fn map_selector<Gen: ValueGenerator<Output = bool>, F: Fn(Selector) -> Gen>(
                self,
                map: F,
            ) -> $generator<$A, $B, Gen> {
                $generator {
                    a: self.a,
                    b: self.b,
                    selector: map(self.selector),
                }
            }
        }

        impl<$A: ValueGenerator, $B: ValueGenerator, Selector: ValueGenerator<Output = bool>>
            ValueGenerator for $generator<$A, $B, Selector>
        {
            type Output = $ty<$A::Output, $B::Output>;

            #[inline]
            fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
                Some(if self.selector.generate(driver)? {
                    $ty::$A(self.a.generate(driver)?)
                } else {
                    $ty::$B(self.b.generate(driver)?)
                })
            }

            #[inline]
            fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
                #[allow(clippy::redundant_pattern_matching)]
                let prev_selection = match value {
                    $ty::$A(_) => true,
                    $ty::$B(_) => false,
                };

                let mut new_selection = prev_selection;
                self.selector.mutate(driver, &mut new_selection)?;

                if prev_selection == new_selection {
                    match value {
                        $ty::$A(value) => self.a.mutate(driver, value),
                        $ty::$B(value) => self.b.mutate(driver, value),
                    }
                } else {
                    let next = if new_selection {
                        $ty::$A(self.a.generate(driver)?)
                    } else {
                        $ty::$B(self.b.generate(driver)?)
                    };
                    let prev = core::mem::replace(value, next);
                    self.driver_cache(driver, prev);
                    Some(())
                }
            }

            #[inline]
            fn driver_cache<D: Driver>(&self, driver: &mut D, value: Self::Output) {
                match value {
                    $ty::$A(value) => self.a.driver_cache(driver, value),
                    $ty::$B(value) => self.b.driver_cache(driver, value),
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
            type Output = $generator<
                TypeValueGenerator<$A>,
                TypeValueGenerator<$B>,
                TypeValueGenerator<bool>,
            >;

            fn gen_with() -> Self::Output {
                $generator {
                    a: Default::default(),
                    b: Default::default(),
                    selector: Default::default(),
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

pub struct OptionGenerator<V, Selector> {
    value: V,
    selector: Selector,
}

impl<V: ValueGenerator, Selector: ValueGenerator<Output = bool>> OptionGenerator<V, Selector> {
    pub fn value<Gen: ValueGenerator<Output = V::Output>>(
        self,
        value: Gen,
    ) -> OptionGenerator<Gen, Selector> {
        OptionGenerator {
            value,
            selector: self.selector,
        }
    }

    pub fn map_value<Gen: ValueGenerator<Output = V::Output>, F: Fn(V) -> Gen>(
        self,
        map: F,
    ) -> OptionGenerator<Gen, Selector> {
        OptionGenerator {
            value: map(self.value),
            selector: self.selector,
        }
    }

    pub fn selector<Gen: ValueGenerator<Output = bool>>(
        self,
        selector: Gen,
    ) -> OptionGenerator<V, Gen> {
        OptionGenerator {
            value: self.value,
            selector,
        }
    }

    pub fn map_selector<Gen: ValueGenerator<Output = bool>, F: Fn(Selector) -> Gen>(
        self,
        map: F,
    ) -> OptionGenerator<V, Gen> {
        OptionGenerator {
            value: self.value,
            selector: map(self.selector),
        }
    }
}

impl<V: ValueGenerator, Selector: ValueGenerator<Output = bool>> ValueGenerator
    for OptionGenerator<V, Selector>
{
    type Output = Option<V::Output>;

    #[inline]
    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        Some(if self.selector.generate(driver)? {
            Some(self.value.generate(driver)?)
        } else {
            None
        })
    }

    #[inline]
    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        let prev_selection = value.is_some();

        let mut new_selection = prev_selection;
        self.selector.mutate(driver, &mut new_selection)?;

        if prev_selection == new_selection {
            match value {
                Some(value) => self.value.mutate(driver, value),
                None => Some(()),
            }
        } else {
            let next = if new_selection {
                Some(self.value.generate(driver)?)
            } else {
                None
            };
            let prev = core::mem::replace(value, next);
            self.driver_cache(driver, prev);
            Some(())
        }
    }

    #[inline]
    fn driver_cache<D: Driver>(&self, driver: &mut D, value: Self::Output) {
        if let Some(value) = value {
            self.value.driver_cache(driver, value);
        }
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
    type Output = OptionGenerator<TypeValueGenerator<V>, TypeValueGenerator<bool>>;

    fn gen_with() -> Self::Output {
        OptionGenerator {
            value: Default::default(),
            selector: Default::default(),
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
