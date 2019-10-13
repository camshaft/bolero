use crate::{Rng, TypeGenerator, TypeGeneratorWithParams, TypeValueGenerator, ValueGenerator};

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

            fn generate<R: Rng>(&self, rng: &mut R) -> Self::Output {
                if self.selector.generate(rng) {
                    $ty::$A(self.a.generate(rng))
                } else {
                    $ty::$B(self.b.generate(rng))
                }
            }
        }

        impl<$A: TypeGenerator, $B: TypeGenerator> TypeGenerator for $ty<$A, $B> {
            fn generate<R: Rng>(rng: &mut R) -> Self {
                if rng.gen() {
                    $ty::$A(rng.gen())
                } else {
                    $ty::$B(rng.gen())
                }
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

    fn generate<R: Rng>(&self, rng: &mut R) -> Self::Output {
        if self.selector.generate(rng) {
            Some(self.value.generate(rng))
        } else {
            None
        }
    }
}

impl<V: TypeGenerator> TypeGenerator for Option<V> {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        if rng.gen() {
            Some(rng.gen())
        } else {
            None
        }
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
