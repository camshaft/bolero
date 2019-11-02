//! libfuzzer plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.

#[doc(hidden)]
#[cfg(fuzzing_libfuzzer)]
pub mod fuzzer {
    use std::{
        ffi::CString,
        os::raw::{c_char, c_int},
        panic::{self, catch_unwind, AssertUnwindSafe, RefUnwindSafe},
    };

    static mut TESTFN: Option<&mut dyn FnMut(&[u8])> = None;

    extern "C" {
        // entrypoint for libfuzzer
        pub fn LLVMFuzzerStartTest(a: c_int, b: *const *const c_char) -> c_int;
    }

    #[no_mangle]
    pub unsafe extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
        let exec = || {
            let data_slice = std::slice::from_raw_parts(data, size);
            (TESTFN.as_mut().expect("uninitialized test function"))(data_slice);
        };

        if catch_unwind(AssertUnwindSafe(exec)).is_err() {
            1
        } else {
            0
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn LLVMFuzzerInitialize(
        _argc: *const isize,
        _argv: *const *const *const u8,
    ) -> isize {
        panic::set_hook(Box::new(|_| {
            std::process::abort();
        }));

        0
    }

    pub unsafe fn fuzz<F: FnMut(&[u8])>(testfn: &mut F)
    where
        F: RefUnwindSafe,
    {
        TESTFN = Some(std::mem::transmute(testfn as &mut dyn FnMut(&[u8])));

        // create a vector of zero terminated strings
        let args = std::env::args()
            .map(|arg| CString::new(arg).unwrap())
            .collect::<Vec<_>>();

        // convert the strings to raw pointers
        let c_args = args
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(Some(0 as *const _)) // add a null pointer to the end
            .collect::<Vec<_>>();

        LLVMFuzzerStartTest(args.len() as c_int, c_args.as_ptr());
    }
}

#[doc(hidden)]
#[cfg(fuzzing_libfuzzer)]
pub use fuzzer::*;
