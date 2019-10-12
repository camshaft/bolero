#[cfg(fuzzing_libfuzzer)]
pub mod fuzzer {
    use std::{
        ffi::CString,
        os::raw::{c_char, c_int},
        panic::{self, catch_unwind, AssertUnwindSafe},
    };

    static mut TESTFN: fn(&[u8]) = uninit;

    fn uninit(_input: &[u8]) {
        panic!("uninitialized test");
    }

    extern "C" {
        // entrypoint for libfuzzer
        pub fn LLVMFuzzerStartTest(a: c_int, b: *const *const c_char) -> c_int;
    }

    #[no_mangle]
    pub unsafe extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
        let exec = || {
            let data_slice = std::slice::from_raw_parts(data, size);
            TESTFN(data_slice);
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

    pub unsafe fn fuzz(testfn: fn(&[u8])) {
        TESTFN = testfn;

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

#[cfg(fuzzing_libfuzzer)]
pub use fuzzer::*;
