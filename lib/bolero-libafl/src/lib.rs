//! libafl plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.

#[doc(hidden)]
#[cfg(any(test, all(feature = "lib", fuzzing_libafl)))]
pub mod fuzzer {
    use bolero_engine::{
        driver, panic, ByteSliceTestInput, Engine, Never, TargetLocation, Test, TestFailure,
    };
    use core::ffi::c_void;

    type RunOnce = extern "C" fn(*const u8, usize, *mut c_void) -> u8;

    extern "C" {
        fn bolero_libafl_runtime_start(fun: RunOnce, ctx: *mut c_void);
    }

    fn start<F: FnMut(&[u8]) -> u8>(mut f: F) {
        extern "C" fn handle_input<F: FnMut(&[u8]) -> u8>(
            ptr: *const u8,
            len: usize,
            ctx: *mut c_void,
        ) -> u8 {
            unsafe {
                let f = &mut *(ctx as *mut F);
                let slice = core::slice::from_raw_parts(ptr, len);
                f(slice)
            }
        }

        unsafe { bolero_libafl_runtime_start(handle_input::<F>, &mut f as *mut _ as *mut _) }
    }

    #[derive(Debug, Default)]
    pub struct LibAflEngine {}

    impl LibAflEngine {
        pub fn new(_location: TargetLocation) -> Self {
            Self::default()
        }
    }

    impl<T: Test> Engine<T> for LibAflEngine
    where
        T::Value: core::fmt::Debug,
    {
        type Output = Never;

        fn run(self, mut test: T, options: driver::Options) -> Self::Output {
            panic::set_hook();
            panic::forward_panic(false);

            let options = &options;

            start(&mut |slice: &[u8]| {
                let mut input = ByteSliceTestInput::new(slice, options);

                match test.test(&mut input) {
                    Ok(true) => 0,
                    Ok(false) => 1,
                    Err(error) => {
                        eprintln!("test failed; shrinking input...");

                        let shrunken = test.shrink(slice.to_vec(), None, options);

                        if let Some(shrunken) = shrunken {
                            eprintln!("{:#}", shrunken);
                        } else {
                            eprintln!(
                                "{:#}",
                                TestFailure {
                                    seed: None,
                                    error,
                                    input
                                }
                            );
                        }

                        2
                    }
                }
            })
        }
    }
}

#[doc(hidden)]
#[cfg(all(feature = "lib", fuzzing_libafl))]
pub use fuzzer::*;

#[doc(hidden)]
#[cfg(feature = "bin")]
pub const RUNTIME_LIBRARY: &'static [u8] = include_bytes!(env!("BOLERO_LIBAFL_RUNTIME_PATH"));
