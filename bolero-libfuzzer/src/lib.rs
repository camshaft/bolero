//! libfuzzer plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.

#[doc(hidden)]
#[cfg(any(test, all(feature = "lib", fuzzing_libfuzzer)))]
pub mod fuzzer {
    use bolero_engine::{
        panic, ByteSliceTestInput, Engine, Never, Options, TargetLocation, Test, TestFailure,
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
        options: Options,
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

        fn set_options(&mut self, options: &Options) {
            self.options = options.clone();
        }

        fn run(self, mut test: T) -> Self::Output {
            panic::set_hook();
            panic::forward_panic(false);

            let options = &self.options;

            let print = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

            {
                let print = print.clone();
                std::thread::spawn(move || {
                    while std::sync::Arc::strong_count(&print) > 1 {
                        std::thread::sleep(core::time::Duration::from_secs(1));
                        print.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                });
            }

            let mut total_runs = 0u64;
            let mut window_runs = 0u64;
            let mut total_valid = 0u64;
            let mut window_valid = 0u64;

            start(&mut |slice: &[u8]| -> bool {
                let mut input = ByteSliceTestInput::new(slice, options);

                match test.test(&mut input) {
                    Ok(valid) => {
                        window_runs += 1;
                        if valid {
                            window_valid += 1;
                        }

                        // Print out stats for generator success
                        {
                            if window_runs != window_valid
                                && print.swap(false, std::sync::atomic::Ordering::Relaxed)
                            {
                                total_runs += window_runs;
                                total_valid += window_valid;

                                let total_perc = total_valid as f32 / total_runs as f32 * 100.0;
                                let window_perc = window_valid as f32 / window_runs as f32 * 100.0;
                                println!(
                                    "#{}\tGENERATE\tvalid: {} ({:.2}%) valid/s: {} ({:.2}%)",
                                    total_runs, total_valid, total_perc, window_valid, window_perc,
                                );
                                window_runs = 0;
                                window_valid = 0;
                            }
                        }

                        true
                    }
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
