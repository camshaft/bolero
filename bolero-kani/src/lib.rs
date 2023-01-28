//! kani plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.

#![allow(unused_unsafe)] // nondet needs to be unsafe but it's currently not

#[cfg(not(kani))]
#[allow(dead_code)]
mod kani {
    pub fn any<T>() -> T {
        todo!()
    }

    pub fn assume(cond: bool) {
        // no-op
        let _ = cond;
    }

    pub mod vec {
        pub fn any_vec<T, const N: usize>() -> Vec<T> {
            todo!()
        }
    }
}

#[doc(hidden)]
#[cfg(any(test, all(feature = "lib", kani)))]
pub mod lib {
    #[allow(unused_imports)]
    use super::*;

    use bolero_engine::{
        Driver, DriverMode, Engine, TargetLocation, Test, TestInput, TypeGenerator,
    };
    use core::ops::{Bound, RangeBounds};

    #[derive(Debug, Default)]
    pub struct KaniEngine;

    impl KaniEngine {
        pub fn new(_location: TargetLocation) -> Self {
            Self::default()
        }
    }

    impl<T: Test> Engine<T> for KaniEngine
    where
        T::Value: core::fmt::Debug,
    {
        type Output = ();

        fn set_driver_mode(&mut self, mode: DriverMode) {
            // rmc doesn't have a mode
            let _ = mode;
        }

        fn set_shrink_time(&mut self, shrink_time: core::time::Duration) {
            // rmc does its own shrinking
            let _ = shrink_time;
        }

        fn run(self, mut test: T) -> Self::Output {
            let mut input = KaniInput;
            match test.test(&mut input) {
                Ok(was_valid) => {
                    // make sure the input that we generated was valid
                    kani::assume(was_valid);
                }
                Err(_) => {
                    panic!("test failed");
                }
            }
        }
    }

    struct KaniInput;

    impl<Output> TestInput<Output> for KaniInput {
        type Driver = KaniDriver;

        fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
            // TODO make this configurable
            const MAX_LEN: usize = 256;

            let array: [u8; MAX_LEN] = kani::any();
            let len = kani::any();
            kani::assume(len <= MAX_LEN);
            f(&array[..len])
        }

        fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
            f(&mut KaniDriver)
        }
    }

    struct KaniDriver;

    macro_rules! gen {
        ($name:ident, $ty:ident) => {
            fn $name(&mut self, min: Bound<&$ty>, max: Bound<&$ty>) -> Option<$ty> {
                let value: $ty = kani::any();
                kani::assume((min, max).contains(&value));
                Some(value)
            }
        };
    }

    impl Driver for KaniDriver {
        gen!(gen_u8, u8);

        gen!(gen_i8, i8);

        gen!(gen_u16, u16);

        gen!(gen_i16, i16);

        gen!(gen_u32, u32);

        gen!(gen_i32, i32);

        gen!(gen_u64, u64);

        gen!(gen_i64, i64);

        gen!(gen_u128, u128);

        gen!(gen_i128, i128);

        gen!(gen_usize, usize);

        gen!(gen_isize, isize);

        gen!(gen_f32, f32);

        gen!(gen_f64, f64);

        fn gen<T: TypeGenerator>(&mut self) -> Option<T> {
            let value = T::generate(self);
            kani::assume(value.is_some());
            value
        }

        fn gen_char(&mut self, min: Bound<&char>, max: Bound<&char>) -> Option<char> {
            let value = kani::any();
            kani::assume((min, max).contains(&value));
            Some(value)
        }

        fn gen_bool(&mut self, _probability: Option<f32>) -> Option<bool> {
            Some(kani::any())
        }

        fn gen_from_bytes<Gen, T>(
            &mut self,
            len: std::ops::RangeInclusive<usize>,
            mut gen: Gen,
        ) -> Option<T>
        where
            Gen: FnMut(&[u8]) -> Option<(usize, T)>,
        {
            let bytes = kani::vec::any_vec::<u8, 256>();
            kani::assume(len.contains(&bytes.len()));
            let value = gen(&bytes).map(|v| v.1);
            kani::assume(value.is_some());
            value
        }
    }
}

#[doc(hidden)]
#[cfg(all(feature = "lib", kani))]
pub use lib::*;
