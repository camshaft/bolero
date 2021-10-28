//! afl plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.

#[doc(hidden)]
#[cfg(any(test, all(feature = "lib", fuzzing_afl)))]
pub mod fuzzer {
    use bolero_engine::{
        panic, ByteSliceTestInput, DriverMode, Engine, Never, TargetLocation, Test,
    };
    use std::io::Read;

    extern "C" {
        // from the afl-llvm-rt
        fn __afl_persistent_loop(counter: usize) -> isize;
        fn __afl_manual_init();
    }

    #[used]
    static PERSIST_MARKER: &str = "##SIG_AFL_PERSISTENT##\0";

    #[used]
    static DEFERED_MARKER: &str = "##SIG_AFL_DEFER_FORKSRV##\0";

    #[derive(Debug, Default)]
    pub struct AflEngine {
        driver_mode: Option<DriverMode>,
    }

    impl AflEngine {
        pub fn new(_location: TargetLocation) -> Self {
            Self::default()
        }
    }

    impl<T: Test> Engine<T> for AflEngine
    where
        T::Value: core::fmt::Debug,
    {
        type Output = Never;

        fn set_driver_mode(&mut self, mode: DriverMode) {
            self.driver_mode = Some(mode);
        }

        fn set_shrink_time(&mut self, shrink_time: core::time::Duration) {
            // we don't shrink with afl currently
            let _ = shrink_time;
        }

        fn run(self, mut test: T) -> Self::Output {
            panic::set_hook();

            let mut input = AflInput::new(self.driver_mode);

            unsafe {
                __afl_manual_init();
            }

            while unsafe { __afl_persistent_loop(1000) } != 0 {
                if test.test(&mut input.test_input()).is_err() {
                    std::process::abort();
                }
            }

            std::process::exit(0);
        }
    }

    #[derive(Debug)]
    pub struct AflInput {
        driver_mode: Option<DriverMode>,
        input: Vec<u8>,
    }

    impl AflInput {
        fn new(driver_mode: Option<DriverMode>) -> Self {
            Self {
                driver_mode,
                input: vec![],
            }
        }

        fn reset(&mut self) {
            self.input.clear();
            std::io::stdin()
                .read_to_end(&mut self.input)
                .expect("could not read next input");
        }

        fn test_input(&mut self) -> ByteSliceTestInput {
            self.reset();
            ByteSliceTestInput::new(&self.input, self.driver_mode)
        }
    }
}

#[doc(hidden)]
#[cfg(all(feature = "lib", fuzzing_afl))]
pub use fuzzer::*;

#[doc(hidden)]
#[cfg(feature = "bin")]
pub mod bin {
    use std::{
        ffi::CString,
        os::raw::{c_char, c_int},
    };

    extern "C" {
        // entrypoint for afl
        pub fn afl_fuzz_main(a: c_int, b: *const *const c_char) -> c_int;
    }

    /// Should only be used by `cargo-bolero`
    ///
    /// # Safety
    ///
    /// Use `cargo-bolero`
    pub unsafe fn exec<Args: Iterator<Item = String>>(args: Args) {
        // create a vector of zero terminated strings
        let args = args
            .map(|arg| CString::new(arg).unwrap())
            .collect::<Vec<_>>();

        // convert the strings to raw pointers
        let c_args = args
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(Some(core::ptr::null())) // add a null pointer to the end
            .collect::<Vec<_>>();

        let status = afl_fuzz_main(args.len() as c_int, c_args.as_ptr());
        if status != 0 {
            std::process::exit(status);
        }
    }
}

#[doc(hidden)]
#[cfg(feature = "bin")]
pub use bin::*;
