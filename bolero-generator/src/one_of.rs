use crate::{driver::Driver, ValueGenerator};

#[derive(Clone, Debug)]
pub struct OneOf<O>(O);

#[derive(Clone, Debug)]
pub struct OneValueOf<O>(O);

impl<O: OneOfGenerator> ValueGenerator for OneOf<O> {
    type Output = O::Output;

    fn generate<R: Driver>(&self, driver: &mut R) -> Option<Self::Output> {
        self.0.generate_one_of(driver)
    }
}

impl<O: OneValueOfGenerator> ValueGenerator for OneValueOf<O> {
    type Output = O::Output;

    fn generate<R: Driver>(&self, driver: &mut R) -> Option<Self::Output> {
        self.0.generate_one_value_of(driver)
    }
}

pub trait OneOfExt {
    type Generator;

    fn one_of(self) -> OneOf<Self::Generator>;
}

pub trait OneValueOfExt {
    type Generator;

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
    type Output;

    fn generate_one_of<D: Driver>(&self, _driver: &mut D) -> Option<Self::Output>;
}

pub trait OneValueOfGenerator {
    type Output;

    fn generate_one_value_of<D: Driver>(&self, _driver: &mut D) -> Option<Self::Output>;
}

impl<Output, T: ValueGenerator<Output = Output>> OneOfGenerator for &[T] {
    type Output = Output;

    fn generate_one_of<D_: Driver>(&self, driver: &mut D_) -> Option<Self::Output> {
        let index = (0usize..self.len()).generate(driver)?;
        self[index].generate(driver)
    }
}

impl<T: Clone> OneValueOfGenerator for &[T] {
    type Output = T;

    fn generate_one_value_of<D_: Driver>(&self, driver: &mut D_) -> Option<Self::Output> {
        let index = (0usize..self.len()).generate(driver)?;
        Some(self[index].clone())
    }
}

macro_rules! impl_selectors {
    ([$($acc:ident($a_value:tt),)*]) => {
        // done
    };
    ($head:ident($h_value:tt), $($tail:ident($t_value:tt), )* [$($acc:ident($a_value:tt),)*]) => {
        impl<Output, $head: ValueGenerator<Output = Output> $(, $acc: ValueGenerator<Output = Output>)*> OneOfGenerator for ($($acc, )* $head ,) {
            type Output = Output;

            fn generate_one_of<D_: Driver>(&self, driver: &mut D_) -> Option<Self::Output> {
                match (0u8..=$h_value).generate(driver)? {
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
        }

        impl<Output, T: ValueGenerator<Output = Output>> OneOfGenerator for [T; $h_value + 1] {
            type Output = Output;

            fn generate_one_of<D_: Driver>(&self, driver: &mut D_) -> Option<Self::Output> {
                let index = (0u8..=$h_value).generate(driver)? as usize;
                self[index].generate(driver)
            }
        }

        impl<T: Clone> OneValueOfGenerator for [T; $h_value + 1] {
            type Output = T;

            fn generate_one_value_of<D_: Driver>(&self, driver: &mut D_) -> Option<Self::Output> {
                let index = (0u8..=$h_value).generate(driver)? as usize;
                Some(self[index].clone())
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
pub fn one_of<O: OneOfGenerator>(options: O) -> OneOf<O> {
    OneOf(options)
}

#[inline]
pub fn one_value_of<O: OneValueOfGenerator>(options: O) -> OneValueOf<O> {
    OneValueOf(options)
}

#[test]
fn one_of_test() {
    use crate::gen;
    use core::cmp::Ordering;

    let options = [gen(), gen(), gen()];
    let _: Option<u8> = generator_test!(one_of(options));
    let _: Option<u8> = generator_test!(options.one_of());
    let _: Option<u8> = generator_test!(one_of(&options[..]));

    let _: Option<u8> = generator_test!([1u8, 2, 3].one_of());

    let _: Option<Ordering> =
        generator_test!([constant(Ordering::Equal), constant(Ordering::Less)].one_of());

    let _: Option<Ordering> = generator_test!([Ordering::Equal, Ordering::Less].one_value_of());

    let _: Option<u8> = generator_test!(one_of((gen(), 0..4, 8..9)));
}
