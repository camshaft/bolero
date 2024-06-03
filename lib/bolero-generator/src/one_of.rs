use crate::{driver::Driver, ValueGenerator};

#[derive(Clone, Debug)]
pub struct OneOf<O>(O);

#[derive(Clone, Debug)]
pub struct OneValueOf<O>(O);

impl<O: OneOfGenerator> ValueGenerator for OneOf<O> {
    type Output = O::Output;

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        self.0.generate_one_of(driver)
    }

    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        self.0.mutate_one_of(driver, value)
    }
}

impl<O: OneValueOfGenerator> ValueGenerator for OneValueOf<O> {
    type Output = O::Output;

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        self.0.generate_one_value_of(driver)
    }

    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        self.0.mutate_one_value_of(driver, value)
    }
}

/// Extensions for picking a generator from a set of generators
pub trait OneOfExt {
    type Generator;

    /// Pick a generator for the provided set of generators
    fn one_of(self) -> OneOf<Self::Generator>;
}

/// Extensions for picking a value from a set of values
pub trait OneValueOfExt {
    type Generator;

    /// Pick a value for the provided set of values
    fn one_value_of(self) -> OneValueOf<Self::Generator>;
}

impl<O: OneOfGenerator> OneOfExt for O {
    type Generator = O;

    fn one_of(self) -> OneOf<Self> {
        OneOf(self)
    }
}

impl<O: OneValueOfGenerator> OneValueOfExt for O {
    type Generator = O;

    fn one_value_of(self) -> OneValueOf<Self> {
        OneValueOf(self)
    }
}

pub trait OneOfGenerator {
    type Output: 'static;

    fn generate_one_of<D: Driver>(&self, driver: &mut D) -> Option<Self::Output>;
    fn mutate_one_of<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()>;
}

pub trait OneValueOfGenerator {
    type Output: 'static;

    fn generate_one_value_of<D: Driver>(&self, _driver: &mut D) -> Option<Self::Output>;
    fn mutate_one_value_of<D: Driver>(
        &self,
        driver: &mut D,
        value: &mut Self::Output,
    ) -> Option<()>;
}

impl<Output: 'static, T: ValueGenerator<Output = Output>> OneOfGenerator for &[T] {
    type Output = Output;

    fn generate_one_of<D_: Driver>(&self, driver: &mut D_) -> Option<Self::Output> {
        driver.enter_sum::<Output, _, _>(None, self.len(), 0, |driver, idx| {
            self[idx].generate(driver)
        })
    }

    fn mutate_one_of<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        driver.enter_sum::<Output, _, _>(None, self.len(), 0, |driver, idx| {
            self[idx].mutate(driver, value)
        })
    }
}

impl<T: 'static + Clone> OneValueOfGenerator for &[T] {
    type Output = T;

    fn generate_one_value_of<D_: Driver>(&self, driver: &mut D_) -> Option<Self::Output> {
        driver.enter_sum::<T, _, _>(None, self.len(), 0, |_driver, idx| Some(self[idx].clone()))
    }

    fn mutate_one_value_of<D: Driver>(
        &self,
        driver: &mut D,
        value: &mut Self::Output,
    ) -> Option<()> {
        driver.enter_sum::<T, _, _>(None, self.len(), 0, |_driver, idx| {
            *value = self[idx].clone();
            Some(())
        })
    }
}

impl<Output: 'static, T: ValueGenerator<Output = Output>, const L: usize> OneOfGenerator
    for [T; L]
{
    type Output = Output;

    fn generate_one_of<D_: Driver>(&self, driver: &mut D_) -> Option<Self::Output> {
        driver.enter_sum::<Output, _, _>(None, L, 0, |driver, index| self[index].generate(driver))
    }

    fn mutate_one_of<D_: Driver>(&self, driver: &mut D_, value: &mut Self::Output) -> Option<()> {
        driver.enter_sum::<Output, _, _>(None, L, 0, |driver, index| {
            self[index].mutate(driver, value)
        })
    }
}

impl<T: 'static + Clone, const L: usize> OneValueOfGenerator for [T; L] {
    type Output = T;

    fn generate_one_value_of<D_: Driver>(&self, driver: &mut D_) -> Option<Self::Output> {
        driver.enter_sum::<T, _, _>(None, L, 0, |_driver, index| Some(self[index].clone()))
    }

    fn mutate_one_value_of<D: Driver>(
        &self,
        driver: &mut D,
        value: &mut Self::Output,
    ) -> Option<()> {
        driver.enter_sum::<T, _, _>(None, L, 0, |_driver, index| {
            *value = self[index].clone();
            Some(())
        })
    }
}

macro_rules! impl_selectors {
    ([$($acc:ident($a_value:tt),)*]) => {
        // done
    };
    ($head:ident($h_value:tt), $($tail:ident($t_value:tt), )* [$($acc:ident($a_value:tt),)*]) => {
        impl<Output: 'static, $head: ValueGenerator<Output = Output> $(, $acc: ValueGenerator<Output = Output>)*> OneOfGenerator for ($($acc, )* $head ,) {
            type Output = Output;

            fn generate_one_of<D_: Driver>(&self, driver: &mut D_) -> Option<Self::Output> {
                driver.enter_sum::<Output, _, _>(
                    None,
                    $h_value + 1,
                    0,
                    |driver, index| {
                        match index {
                            $(
                                $a_value => {
                                    self.$a_value.generate(driver)
                                },
                            )*
                            $h_value => {
                                self.$h_value.generate(driver)
                            }
                            _ => unreachable!("generated value out of bounds")
                        }
                    }
                )
            }

            fn mutate_one_of<D_: Driver>(&self, driver: &mut D_, value: &mut Self::Output) -> Option<()> {
                driver.enter_sum::<Output, _, _>(
                    None,
                    $h_value + 1,
                    0,
                    |driver, index| {
                        match index {
                            $(
                                $a_value => {
                                    self.$a_value.mutate(driver, value)
                                },
                            )*
                            $h_value => {
                                self.$h_value.mutate(driver, value)
                            }
                            _ => unreachable!("generated value out of bounds")
                        }
                    }
                )
            }
        }

        impl_selectors!($($tail($t_value),)* [$($acc($a_value),)* $head($h_value),]);
    };
}

impl_selectors!(
    A(0),
    B(1),
    C(2),
    D(3),
    E(4),
    F(5),
    G(6),
    H(7),
    I(8),
    J(9),
    K(10),
    L(11),
    M(12),
    N(13),
    O(14),
    P(15),
    Q(16),
    R(17),
    S(18),
    T(19),
    U(20),
    V(21),
    W(22),
    X(23),
    Y(24),
    Z(25),
    AA(26),
    AB(27),
    AC(28),
    AD(29),
    AE(30),
    AF(31),
    AG(32),
    []
);

#[inline]
/// Pick a generator for the provided set of generators
pub fn one_of<O: OneOfGenerator>(options: O) -> OneOf<O> {
    OneOf(options)
}

#[inline]
/// Pick a value for the provided set of values
pub fn one_value_of<O: OneValueOfGenerator>(options: O) -> OneValueOf<O> {
    OneValueOf(options)
}

#[test]
fn one_of_array_test() {
    use crate::gen;

    let options = [gen::<u8>(), gen(), gen()];
    let _ = generator_test!(one_of(options));
    let _ = generator_test!(options.one_of());
    let _ = generator_test!(one_of(&options[..]));

    let _ = generator_test!([1u8, 2, 3].one_of());
}

#[test]
fn one_of_slice_test() {
    use crate::constant;
    use core::cmp::Ordering;

    let options = [
        constant(Ordering::Equal),
        constant(Ordering::Less),
        constant(Ordering::Greater),
    ];

    let _ = generator_test!(one_of(&options[..]));
}

#[test]
fn one_of_tuple_test() {
    let _ = generator_test!(one_of((gen::<u8>(), 0..4, 8..9)));
}

#[test]
fn one_value_of_test() {
    use core::cmp::Ordering;

    generator_test!([Ordering::Equal, Ordering::Less, Ordering::Greater].one_value_of());
}
