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

    use bolero_engine::{Driver, Engine, Options, TargetLocation, Test, TestInput, TypeGenerator};
    use core::ops::{Bound, RangeBounds};

    #[derive(Debug, Default)]
    pub struct KaniEngine {
        options: Options,
    }

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

        fn set_options(&mut self, options: &Options) {
            self.options = options.clone();
        }

        fn run(self, mut test: T) -> Self::Output {
            let options = self.options;
            let mut input = KaniInput { options };
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

    struct KaniInput {
        options: Options,
    }

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
            let max_depth = self.options.max_depth_or_default();
            let mut driver = KaniDriver {
                max_depth,
                depth: 0,
            };
            f(&mut driver)
        }
    }

    struct KaniDriver {
        depth: usize,
        max_depth: usize,
    }

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

        fn gen_from_bytes<Hint, Gen, T>(&mut self, _hint: Hint, mut gen: Gen) -> Option<T>
        where
            Hint: FnOnce() -> (usize, Option<usize>),
            Gen: FnMut(&[u8]) -> Option<(usize, T)>,
        {
            let bytes = kani::vec::any_vec::<u8, 256>();
            let value = gen(&bytes).map(|v| v.1);
            kani::assume(value.is_some());
            value
        }

        #[inline]
        fn depth(&mut self) -> &mut usize {
            &mut self.depth
        }

        #[inline]
        fn max_depth(&self) -> usize {
            self.max_depth
        }
    }
}

#[doc(hidden)]
#[cfg(all(feature = "lib", kani))]
pub use lib::*;
