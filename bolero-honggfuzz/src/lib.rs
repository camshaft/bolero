//! honggfuzz plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.

#[doc(hidden)]
#[cfg(fuzzing_honggfuzz)]
pub mod fuzzer {
    use bolero_generator::driver::DriverMode;
    use std::{
        mem::MaybeUninit,
        panic::{catch_unwind, AssertUnwindSafe, RefUnwindSafe},
        slice,
    };

    extern "C" {
        fn HF_ITER(buf_ptr: *mut *const u8, len_ptr: *mut usize);
    }

    pub unsafe fn fuzz<F: FnMut(&[u8], Option<DriverMode>) -> bool>(testfn: &mut F) -> !
    where
        F: RefUnwindSafe,
    {
        std::panic::set_hook(Box::new(|info| {
            println!("{}", info);
            std::process::abort();
        }));

        let mut buf_ptr = MaybeUninit::<*const u8>::uninit();
        let mut len_ptr = MaybeUninit::<usize>::uninit();

        loop {
            HF_ITER(buf_ptr.as_mut_ptr(), len_ptr.as_mut_ptr());
            let input = slice::from_raw_parts(buf_ptr.assume_init(), len_ptr.assume_init());
            let panicked = catch_unwind(AssertUnwindSafe(|| {
                testfn(&input, None);
            }))
            .is_err();

            if panicked {
                std::process::abort();
            }
        }
    }
}

#[doc(hidden)]
#[cfg(fuzzing_honggfuzz)]
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

        honggfuzz_main(args.len() as c_int, c_args.as_ptr());
    }
}

#[doc(hidden)]
#[cfg(feature = "bin")]
pub use bin::*;
