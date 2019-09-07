#[cfg(fuzzing_afl)]
pub mod fuzzer {
    use std::io::Read;

    extern "C" {
        #[allow(improper_ctypes)]
        fn __BOLERO__test(input: &[u8]);

        // from the afl-llvm-rt
        fn __afl_persistent_loop(counter: usize) -> isize;
        fn __afl_manual_init();
    }

    #[used]
    static PERSIST_MARKER: &str = "##SIG_AFL_PERSISTENT##\0";

    #[used]
    static DEFERED_MARKER: &str = "##SIG_AFL_DEFER_FORKSRV##\0";

    pub unsafe fn fuzz() {
        std::panic::set_hook(Box::new(|info| {
            println!("{}", info);
            std::process::abort();
        }));

        let mut input = vec![];

        __afl_manual_init();

        while __afl_persistent_loop(1000) != 0 {
            if std::io::stdin().read_to_end(&mut input).is_err() {
                return;
            }

            let panicked = std::panic::catch_unwind(|| {
                __BOLERO__test(&input);
            })
            .is_err();

            if panicked {
                std::process::abort();
            }

            input.clear();
        }
    }
}

#[cfg(fuzzing_afl)]
pub use fuzzer::*;

#[cfg(feature = "bin")]
pub mod bin {
    use std::{
        ffi::CString,
        os::raw::{c_char, c_int},
    };

    extern "C" {
        // entrypoint for libfuzzer
        pub fn afl_fuzz_main(a: c_int, b: *const *const c_char) -> c_int;
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
            .chain(Some(0 as *const _)) // add a null pointer to the end
            .collect::<Vec<_>>();

        afl_fuzz_main(args.len() as c_int, c_args.as_ptr());
    }
}

#[cfg(feature = "bin")]
pub use bin::*;
