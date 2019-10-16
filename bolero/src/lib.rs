pub use bolero_generator as generator;

mod fuzz;
mod test;

#[cfg(fuzzing)]
pub use fuzz::exec;

#[cfg(not(fuzzing))]
pub use test::exec;

#[macro_export]
macro_rules! fuzz {
    (for $value:pat in gen() { $($tt:tt)* }) => {
        $crate::fuzz!(for $value in ($crate::generator::gen()) { $($tt)* });
    };
    (for $value:pat in all() { $($tt:tt)* }) => {
        $crate::fuzz!(for $value in ($crate::generator::gen()) { $($tt)* });
    };
    (for $value:pat in all($gen:expr) { $($tt:tt)* }) => {
        $crate::fuzz!(for $value in ($gen) { $($tt)* });
    };
    (for $value:pat in every() { $($tt:tt)* }) => {
        $crate::fuzz!(for $value in ($crate::generator::gen()) { $($tt)* });
    };
    (for $value:pat in every($gen:expr) { $($tt:tt)* }) => {
        $crate::fuzz!(for $value in ($gen) { $($tt)* });
    };
    (for $value:pat in each($gen:expr) { $($tt:tt)* }) => {
        $crate::fuzz!(for $value in ($gen) { $($tt)* });
    };
    (for $value:pat in $gen:path { $($tt:tt)* }) => {
        $crate::fuzz!(for $value in ($gen) { $($tt)* });
    };
    (for $value:pat in ($gen:expr) { $($tt:tt)* }) => {
        $crate::fuzz!(|input| {
            use $crate::generator::{ValueGenerator, TypeGenerator, rng::FuzzRng, TypeGeneratorWithParams, gen, gen_with};
            let $value = ValueGenerator::generate(&($gen), &mut FuzzRng::new(input));

            $($tt)*
        });
    };
    ($fun:path) => {
        $crate::fuzz!(|input| { $fun(input); });
    };
    (|$input:ident $(: &[u8])?| $impl:expr) => {
        unsafe {
            $crate::exec(file!(), move |$input: &[u8]| {
                $impl
            })
        }
    };
    (|$input:ident: $ty:ty| $impl:expr) => {
        $crate::fuzz!(for $input in ($crate::generator::gen::<$ty>()) { $impl });
    };
}
