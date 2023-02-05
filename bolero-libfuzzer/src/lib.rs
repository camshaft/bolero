//! libfuzzer plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.

#[doc(hidden)]
#[cfg(any(test, all(feature = "lib", fuzzing_libfuzzer)))]
pub mod fuzzer {
    use bolero_engine::{
        panic, ByteSliceTestInput, DriverMode, Engine, Never, TargetLocation, Test, TestFailure,
    };
    use core::time::Duration;
    use std::{
        ffi::CString,
        os::raw::{c_char, c_int},
    };

    extern "C" {
        // entrypoint for libfuzzer
        pub fn LLVMFuzzerStartTest(a: c_int, b: *const *const c_char) -> c_int;
    }

    static mut TESTFN: Option<&mut dyn FnMut(&[u8]) -> bool> = None;

    #[derive(Debug, Default)]
    pub struct LibFuzzerEngine {
        driver_mode: Option<DriverMode>,
        shrink_time: Option<Duration>,
    }

    impl LibFuzzerEngine {
        pub fn new(_location: TargetLocation) -> Self {
            Self::default()
        }
    }

    impl<T: Test> Engine<T> for LibFuzzerEngine
    where
        T::Value: core::fmt::Debug,
    {
        type Output = Never;

        fn set_driver_mode(&mut self, mode: DriverMode) {
            self.driver_mode = Some(mode);
        }

        fn set_shrink_time(&mut self, shrink_time: Duration) {
            self.shrink_time = Some(shrink_time);
        }

        fn run(self, mut test: T) -> Self::Output {
            panic::set_hook();
            panic::forward_panic(false);

            let driver_mode = self.driver_mode;

            start(&mut |slice: &[u8]| -> bool {
                let mut input = ByteSliceTestInput::new(slice, driver_mode);

                match test.test(&mut input) {
                    Ok(_) => true,
                    Err(error) => {
                        eprintln!("test failed; shrinking input...");

                        let shrunken =
                            test.shrink(slice.to_vec(), None, driver_mode, self.shrink_time);

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

                        false
                    }
                }
            })
        }
    }

    fn start<F: FnMut(&[u8]) -> bool>(run_one_test: &mut F) -> Never {
        unsafe {
            TESTFN = Some(std::mem::transmute(
                run_one_test as &mut dyn FnMut(&[u8]) -> bool,
            ));
        }

        if std::env::var("__BOLERO_LIBFUZZER_RECURSE").is_ok() {
            eprintln!("LOOPING BINARY");
            std::process::exit(1);
        }

        std::env::set_var("__BOLERO_LIBFUZZER_RECURSE", "1");

        // create a vector of NULL terminated strings
        let args = std::env::args()
            .next()
            .as_deref()
            .into_iter()
            .chain(
                std::env::var("BOLERO_LIBFUZZER_ARGS")
                    .expect("missing libfuzzer args")
                    .split(' '),
            )
            .map(|arg| CString::new(arg).unwrap())
            .collect::<Vec<_>>();

        // convert the strings to raw pointers
        let c_args = args
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(Some(core::ptr::null())) // add a null pointer to the end
            .collect::<Vec<_>>();

        unsafe {
            LLVMFuzzerStartTest(args.len() as c_int, c_args.as_ptr());
        }

        std::process::exit(0);
    }

    #[doc(hidden)]
    #[no_mangle]
    pub unsafe extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
        let data_slice = std::slice::from_raw_parts(data, size);
        if (TESTFN.as_mut().expect("uninitialized test function"))(data_slice) {
            0
        } else {
            1
        }
    }

    #[doc(hidden)]
    #[no_mangle]
    pub unsafe extern "C" fn LLVMFuzzerInitialize(
        _argc: *const isize,
        _argv: *const *const *const u8,
    ) -> isize {
        0
    }
}

#[doc(hidden)]
#[cfg(all(feature = "lib", fuzzing_libfuzzer))]
pub use fuzzer::*;
