//! honggfuzz plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.

#[doc(hidden)]
#[cfg(any(test, all(feature = "lib", fuzzing_honggfuzz)))]
pub mod fuzzer {
    use bolero_engine::{
        driver, input, panic as bolero_panic, Engine, Never, ScopedEngine, TargetLocation, Test,
    };
    use std::{mem::MaybeUninit, slice};

    extern "C" {
        fn HF_ITER(buf_ptr: *mut *const u8, len_ptr: *mut usize);
    }

    #[derive(Debug, Default)]
    pub struct HonggfuzzEngine {}

    impl HonggfuzzEngine {
        pub fn new(_location: TargetLocation) -> Self {
            Self::default()
        }
    }

    impl<T: Test> Engine<T> for HonggfuzzEngine {
        type Output = Never;

        fn run(self, mut test: T, options: driver::Options) -> Self::Output {
            bolero_panic::set_hook();

            let mut ctx = bolero_engine::TestRunContext::new(
                bolero_engine::EngineKind::Honggfuzz,
                bolero_engine::TestInput::default(),
                0,
                bolero_engine::RunPhase::Normal,
            );
            // Honggfuzz does not shrink inputs within bolero — it transitions straight
            // from Normal to Failure on a failing input.
            ctx.shrink_enabled = false;
            let _ctx_guard = bolero_engine::test_context::enter(ctx);

            let mut input = HonggfuzzInput::new(options);

            let mut iteration = 0u64;
            loop {
                // Clear any on_failure callback from the previous iteration, then reset
                // the per-iteration context fields before running this input.
                bolero_engine::test_context::clear_on_failure();
                bolero_engine::test_context::update(|ctx| {
                    ctx.iteration = iteration;
                    ctx.run_phase = bolero_engine::RunPhase::Normal;
                });
                iteration += 1;

                // `test_input()` fetches the next input via HF_ITER, so run it in a
                // scope that ends its borrow before any replay.
                let failed = {
                    let mut test_input = input.test_input();
                    test.test(&mut test_input).is_err()
                };
                if failed {
                    // No shrinking: set the Failure phase and replay the same input
                    // (without advancing HF_ITER) so the application can capture
                    // diagnostic output, then invoke the failure callback.
                    bolero_engine::test_context::update(|ctx| {
                        ctx.run_phase = bolero_engine::RunPhase::Failure;
                    });
                    let mut replay = input::Bytes::new(input.current_slice(), &input.options);
                    let _ = test.test(&mut replay);
                    bolero_engine::test_context::invoke_on_failure();
                    std::process::abort();
                }
            }
        }
    }

    impl ScopedEngine for HonggfuzzEngine {
        type Output = Never;

        fn run<F, R>(self, mut test: F, options: driver::Options) -> Self::Output
        where
            F: FnMut() -> R + core::panic::RefUnwindSafe,
            R: bolero_engine::IntoResult,
        {
            bolero_panic::set_hook();

            let mut ctx = bolero_engine::TestRunContext::new(
                bolero_engine::EngineKind::Honggfuzz,
                bolero_engine::TestInput::default(),
                0,
                bolero_engine::RunPhase::Normal,
            );
            // Honggfuzz does not shrink inputs within bolero.
            ctx.shrink_enabled = false;
            let _ctx_guard = bolero_engine::test_context::enter(ctx);

            // extend the lifetime of the bytes so it can be stored in local storage
            let driver = bolero_engine::driver::bytes::Driver::new(&[][..], &options);
            let driver = bolero_engine::driver::object::Object(driver);
            let mut driver = Box::new(driver);

            let mut input = HonggfuzzInput::new(options);

            let mut iteration = 0u64;
            loop {
                // Clear any on_failure callback from the previous iteration, then reset
                // the per-iteration context fields before running this input.
                bolero_engine::test_context::clear_on_failure();
                bolero_engine::test_context::update(|ctx| {
                    ctx.iteration = iteration;
                    ctx.run_phase = bolero_engine::RunPhase::Normal;
                });
                iteration += 1;

                let slice = input.get_slice();
                driver.reset(slice, &input.options);
                let (drv, result) = bolero_engine::any::run(driver, &mut test);
                driver = drv;

                if result.is_err() {
                    // No shrinking: set the Failure phase and replay the same input
                    // (without advancing HF_ITER) so the application can capture
                    // diagnostic output, then invoke the failure callback.
                    bolero_engine::test_context::update(|ctx| {
                        ctx.run_phase = bolero_engine::RunPhase::Failure;
                    });
                    driver.reset(slice, &input.options);
                    // The driver is dropped after the replay since the process aborts.
                    let (_drv, _) = bolero_engine::any::run(driver, &mut test);

                    bolero_engine::test_context::invoke_on_failure();
                    std::process::abort();
                }
            }
        }
    }

    pub struct HonggfuzzInput {
        buf_ptr: MaybeUninit<*const u8>,
        len_ptr: MaybeUninit<usize>,
        options: driver::Options,
    }

    impl HonggfuzzInput {
        fn new(options: driver::Options) -> Self {
            Self {
                options,
                buf_ptr: MaybeUninit::uninit(),
                len_ptr: MaybeUninit::uninit(),
            }
        }

        fn get_slice(&mut self) -> &'static [u8] {
            unsafe {
                HF_ITER(self.buf_ptr.as_mut_ptr(), self.len_ptr.as_mut_ptr());
                slice::from_raw_parts(self.buf_ptr.assume_init(), self.len_ptr.assume_init())
            }
        }

        /// Returns the most recently fetched input slice without advancing `HF_ITER`.
        ///
        /// Must only be called after at least one `get_slice`/`test_input` call has
        /// initialized the buffer pointers (as is the case on the failure-replay path).
        fn current_slice(&self) -> &'static [u8] {
            unsafe { slice::from_raw_parts(self.buf_ptr.assume_init(), self.len_ptr.assume_init()) }
        }

        fn test_input(&mut self) -> input::Bytes {
            let input = self.get_slice();
            input::Bytes::new(input, &self.options)
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
