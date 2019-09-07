#[cfg(fuzzing_libfuzzer)]
pub mod fuzzer {
    use std::{
        ffi::CString,
        os::raw::{c_char, c_int},
    };

    extern "C" {
        #[allow(improper_ctypes)]
        fn __BOLERO__test(input: &[u8]);

        // entrypoint for libfuzzer
        pub fn LLVMFuzzerStartTest(a: c_int, b: *const *const c_char) -> c_int;
    }

    #[no_mangle]
    pub unsafe extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
        let exec = || {
            let data_slice = std::slice::from_raw_parts(data, size);
            __BOLERO__test(data_slice);
        };

        if std::panic::catch_unwind(exec).is_err() {
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
        std::panic::set_hook(Box::new(|_| {
            std::process::abort();
        }));

        0
    }

    pub unsafe fn fuzz() {
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
