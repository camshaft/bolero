//! honggfuzz plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.

#[doc(hidden)]
#[cfg(any(test, all(feature = "lib", fuzzing_honggfuzz)))]
pub mod fuzzer {
    use bolero_engine::{
        panic as bolero_panic, ByteSliceTestInput, DriverMode, Engine, Never, TargetLocation, Test,
    };
    use std::{mem::MaybeUninit, slice};

    extern "C" {
        fn HF_ITER(buf_ptr: *mut *const u8, len_ptr: *mut usize);
    }

    #[derive(Debug, Default)]
    pub struct HonggfuzzEngine {
        driver_mode: Option<DriverMode>,
    }

    impl HonggfuzzEngine {
        pub fn new(_location: TargetLocation) -> Self {
            Self::default()
        }
    }

    impl<T: Test> Engine<T> for HonggfuzzEngine {
        type Output = Never;

        fn set_driver_mode(&mut self, mode: DriverMode) {
            self.driver_mode = Some(mode);
        }

        fn run(self, mut test: T) -> Self::Output {
            bolero_panic::set_hook();

            let mut input = HonggfuzzInput::new(self.driver_mode);

            loop {
                if test.test(&mut input.test_input()).is_err() {
                    std::process::abort();
                }
            }
        }
    }

    pub struct HonggfuzzInput {
        buf_ptr: MaybeUninit<*const u8>,
        len_ptr: MaybeUninit<usize>,
        driver_mode: Option<DriverMode>,
    }

    impl HonggfuzzInput {
        fn new(driver_mode: Option<DriverMode>) -> Self {
            Self {
                driver_mode,
                buf_ptr: MaybeUninit::uninit(),
                len_ptr: MaybeUninit::uninit(),
            }
        }

        fn test_input(&mut self) -> ByteSliceTestInput {
            let input = unsafe {
                HF_ITER(self.buf_ptr.as_mut_ptr(), self.len_ptr.as_mut_ptr());
                slice::from_raw_parts(self.buf_ptr.assume_init(), self.len_ptr.assume_init())
            };
            ByteSliceTestInput::new(input, self.driver_mode)
        }
    }
}

#[doc(hidden)]
#[cfg(all(feature = "lib", fuzzing_honggfuzz))]
pub use fuzzer::*;

#[doc(hidden)]
#[cfg(feature = "bin")]
pub mod bin {
    use std::{
        ffi::CString,
        os::raw::{c_char, c_int},
    };

    extern "C" {
        // entrypoint for honggfuzz
        pub fn honggfuzz_main(a: c_int, b: *const *const c_char) -> c_int;
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

        let status = honggfuzz_main(args.len() as c_int, c_args.as_ptr());
        if status != 0 {
            std::process::exit(status);
        }
    }
}

#[doc(hidden)]
#[cfg(feature = "bin")]
pub use bin::*;
