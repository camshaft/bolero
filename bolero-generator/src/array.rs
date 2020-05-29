use crate::{Driver, TypeGenerator, TypeGeneratorWithParams, TypeValueGenerator, ValueGenerator};

impl<T> TypeGenerator for [T; 0] {
    fn generate<D_: Driver>(_driver: &mut D_) -> Option<Self> {
        Some([])
    }
}

impl<T> ValueGenerator for [T; 0] {
    type Output = [T; 0];

    fn generate<D_: Driver>(&self, _driver: &mut D_) -> Option<Self::Output> {
        Some([])
    }
}

impl<T> TypeGeneratorWithParams for [T; 0] {
    type Output = [T; 0];

    fn gen_with() -> Self::Output {
        []
    }
}

macro_rules! impl_array {
    ([$($acc:ident($a_value:tt),)*]) => {
        // done
    };
    ($head:ident($h_index:tt), $($tail:ident($t_index:tt), )* [$($acc:ident($a_index:tt),)*]) => {
        impl<T: TypeGenerator> TypeGenerator for [T; $h_index + 1] {
            fn generate<D_: Driver>(driver: &mut D_) -> Option<Self> {
                $(
                    let $acc = T::generate(driver)?;
                )*
                let $head = T::generate(driver)?;
                Some([$($acc, )* $head])
            }

            fn mutate<D_: Driver>(&mut self, driver: &mut D_) -> Option<()> {
                $(
                    self[$a_index].mutate(driver)?;
                )*
                self[$h_index].mutate(driver)?;
                Some(())
            }
        }

        impl<G: ValueGenerator> ValueGenerator for [G; $h_index + 1] {
            type Output = [G::Output; $h_index + 1];

            fn generate<D_: Driver>(&self, driver: &mut D_) -> Option<Self::Output> {
                $(
                    let $acc = self[$a_index].generate(driver)?;
                )*
                let $head = self[$h_index].generate(driver)?;
                Some([$($acc, )* $head])
            }

            fn mutate<D_: Driver>(&self, driver: &mut D_, value: &mut Self::Output) -> Option<()> {
                $(
                    self[$a_index].mutate(driver, &mut value[$a_index])?;
                )*
                self[$h_index].mutate(driver, &mut value[$h_index])?;
                Some(())
            }
        }

        impl<T: TypeGenerator> TypeGeneratorWithParams for [T; $h_index + 1] {
            type Output = [TypeValueGenerator<T>; $h_index + 1];

            fn gen_with() -> Self::Output {
                $(
                    let $acc = T::gen();
                )*
                let $head = T::gen();
                [$($acc, )* $head]
            }
        }

        impl_array!($($tail($t_index),)* [$($acc($a_index),)* $head($h_index),]);
    };
}

impl_array!(
    a(0),
    b(1),
    c(2),
    d(3),
    e(4),
    f(5),
    g(6),
    h(7),
    i(8),
    j(9),
    k(10),
    l(11),
    m(12),
    n(13),
    o(14),
    p(15),
    q(16),
    r(17),
    s(18),
    t(19),
    u(20),
    v(21),
    w(22),
    x(23),
    y(24),
    z(25),
    aa(26),
    ab(27),
    ac(28),
    ad(29),
    ae(30),
    af(31),
    ag(32),
    []
);

#[test]
fn array_type_test() {
    let _ = generator_test!(gen::<[u8; 10]>());
}

#[test]
fn array_gen_test() {
    let _ = generator_test!([gen::<u8>(), gen::<u8>()]);
}
