//! libfuzzer plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.

#[doc(hidden)]
#[cfg(any(test, all(feature = "lib", fuzzing_libfuzzer)))]
pub mod fuzzer {
    use bolero_engine::{
        panic, DriverMode, Engine, Instrument, Never, SliceTestInput, TargetLocation, Test,
    };
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

        fn run<I: Instrument + std::panic::RefUnwindSafe>(
            self,
            mut test: T,
            mut instrument: I,
        ) -> Self::Output {
            panic::set_hook();

            let driver_mode = self.driver_mode;

            start(&mut |slice: &[u8]| -> bool {
                let mut input = SliceTestInput::new(slice, driver_mode);
                if test.test(&mut input, &mut instrument).is_ok() {
                    return true;
                }

                let failure = test
                    .shrink(slice.to_vec(), None, driver_mode)
                    .expect("test should fail");

                eprintln!("{}", failure);
                instrument.finish();

                false
            })
        }
    }

    fn start<F: FnMut(&[u8]) -> bool>(run_one_test: &mut F) -> Never {
        unsafe {
            TESTFN = Some(std::mem::transmute(
                run_one_test as &mut dyn FnMut(&[u8]) -> bool,
            ));
        }

        // create a vector of zero terminated strings
        let args = std::env::args()
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
