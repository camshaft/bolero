use crate::{Driver, TypeGenerator, TypeGeneratorWithParams, TypeValueGenerator, ValueGenerator};

impl TypeGenerator for () {
    fn generate<D: Driver>(_driver: &mut D) -> Option<Self> {
        Some(())
    }
}

impl ValueGenerator for () {
    type Output = ();

    fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self> {
        Some(())
    }
}

impl TypeGeneratorWithParams for () {
    type Output = ();

    fn gen_with() -> Self::Output {}
}

macro_rules! impl_tuple {
    ([$($acc:ident($a_value:tt),)*]) => {
        // done
    };
    ($head:ident($h_value:tt), $($tail:ident($t_value:tt), )* [$($acc:ident($a_value:tt),)*]) => {
        impl<$head: TypeGenerator $(, $acc: TypeGenerator)*> TypeGenerator for ($($acc, )* $head ,) {
            fn generate<D_: Driver>(driver: &mut D_) -> Option<Self> {
                driver.enter_product::<Self, _, _>(|driver| {
                    Some(($(
                        $acc::generate(driver)?,
                    )* $head::generate(driver)?, ))
                })
            }

            fn mutate<D_: Driver>(&mut self, driver: &mut D_) -> Option<()> {
                driver.enter_product::<Self, _, _>(|driver| {
                    $(
                        self.$a_value.mutate(driver)?;
                    )*
                    self.$h_value.mutate(driver)?;
                    Some(())
                })
            }
        }

        impl<$head: ValueGenerator $(, $acc: ValueGenerator)*> ValueGenerator for ($($acc, )* $head ,) {
            type Output = ($( $acc::Output, )* $head::Output, );

            fn generate<D_: Driver>(&self, driver: &mut D_) -> Option<Self::Output> {
                driver.enter_product::<Self::Output, _, _>(|driver| {
                    Some(($(
                        self.$a_value.generate(driver)?,
                    )* self.$h_value.generate(driver)?,))
                })
            }

            fn mutate<D_: Driver>(&self, driver: &mut D_, value: &mut Self::Output) -> Option<()> {
                driver.enter_product::<Self::Output, _, _>(|driver| {
                    $(
                        self.$a_value.mutate(driver, &mut value.$a_value)?;
                    )*
                    self.$h_value.mutate(driver, &mut value.$h_value)?;
                    Some(())
                })
            }
        }

        impl<$head: TypeGenerator $(, $acc: TypeGenerator)*> TypeGeneratorWithParams for ($($acc, )* $head ,) {
            type Output = ($( TypeValueGenerator<$acc>, )* TypeValueGenerator<$head>, );

            fn gen_with() -> Self::Output {
                ($(
                    <TypeValueGenerator<$acc>>::default(),
                )* Default::default(),)
            }
        }

        impl_tuple!($($tail($t_value),)* [$($acc($a_value),)* $head($h_value),]);
    };
}

impl_tuple!(
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

#[test]
fn tuple_type_test() {
    let _ = generator_test!(gen::<(u8, u16, u32, u64)>());
}

#[test]
fn tuple_gen_test() {
    let _ = generator_test!((gen::<u8>(), gen::<u16>()));
}

#[test]
fn tuple_with_test() {
    let _ = generator_test!(gen::<(u8, u8)>().with());
}
