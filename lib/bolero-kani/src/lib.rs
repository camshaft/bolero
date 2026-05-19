//! kani plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.

#[doc(hidden)]
#[cfg(all(feature = "lib", kani))]
pub mod lib {
    #[allow(unused_imports)]
    use super::*;

    use bolero_engine::{
        driver, input, kani::Driver as KaniDriver, Engine, ScopedEngine, TargetLocation, Test,
    };

    #[derive(Debug, Default)]
    pub struct KaniEngine {}

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

        fn run(self, mut test: T, options: driver::Options) -> Self::Output {
            let mut input = KaniInput { options };
            match test.test(&mut input) {
                Ok(was_valid) => {
                    // show if the generator was satisfiable
                    // TODO fail the harness if it's not: https://github.com/model-checking/kani/issues/2792
                    #[cfg(kani)]
                    kani::cover!(
                        was_valid,
                        "the generator should produce at least one valid value"
                    );
                    let _ = was_valid;
                }
                Err(_) => {
                    panic!("test failed");
                }
            }
        }
    }

    impl ScopedEngine for KaniEngine {
        type Output = ();

        fn run<F, R>(self, test: F, options: driver::Options) -> Self::Output
        where
            F: FnMut() -> R,
            R: bolero_engine::IntoResult,
        {
            let driver = KaniDriver::new(&options);
            let (_driver, result) = bolero_engine::any::run(driver, test);
            match result {
                Ok(was_valid) => {
                    // show if the generator was satisfiable
                    // TODO fail the harness if it's not: https://github.com/model-checking/kani/issues/2792
                    #[cfg(kani)]
                    kani::cover!(
                        was_valid,
                        "the generator should produce at least one valid value"
                    );
                    let _ = was_valid;
                }
                Err(_) => {
                    panic!("test failed");
                }
            }
        }
    }

    struct KaniInput {
        options: driver::Options,
    }

    impl<Output> input::Input<Output> for KaniInput {
        type Driver = KaniDriver;

        fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
            // TODO make this configurable
            const MAX_LEN: usize = 256;

            let bytes = kani::any::<[u8; MAX_LEN]>();
            let len = kani::any::<usize>();
            let max_len = self.options.max_len_or_default().min(MAX_LEN);
            kani::assume(len <= max_len);

            f(&bytes[..len])
        }

        fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
            let mut driver = KaniDriver::new(&self.options);
            f(&mut driver)
        }
    }
}

#[doc(hidden)]
#[cfg(all(feature = "lib", kani))]
pub use lib::*;
