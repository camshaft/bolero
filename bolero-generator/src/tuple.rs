use crate::{Rng, TypeGenerator, TypeGeneratorWithParams, TypeValueGenerator, ValueGenerator};

impl TypeGenerator for () {
    fn generate<R: Rng>(_rng: &mut R) -> Self {}
}

impl ValueGenerator for () {
    type Output = ();

    fn generate<R: Rng>(&self, _rng: &mut R) -> Self {}
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
            fn generate<R_: Rng>(rng: &mut R_) -> Self {
                ($(
                    $acc::generate(rng),
                )* $head::generate(rng), )
            }
        }

        impl<$head: ValueGenerator $(, $acc: ValueGenerator)*> ValueGenerator for ($($acc, )* $head ,) {
            type Output = ($( $acc::Output, )* $head::Output, );

            fn generate<R_: Rng>(&self, rng: &mut R_) -> Self::Output {
                ($(
                    self.$a_value.generate(rng),
                )* self.$h_value.generate(rng),)
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
fn tuple_test() {
    let _ = generator_test!(gen::<(u8, u16, u32, u64)>());
    let _ = generator_test!((gen::<u8>(), gen::<u16>()));
}
